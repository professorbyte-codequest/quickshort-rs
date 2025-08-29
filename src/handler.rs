use aws_config::BehaviorVersion;
use aws_sdk_dynamodb as ddb;
use aws_sdk_dynamodb::error::ProvideErrorMetadata; // for .code()
use aws_sdk_kms as kms;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ddb::types::AttributeValue as Av;
use hmac::{Hmac, Mac};
use kms::types::SigningAlgorithmSpec;
use lambda_http::{Body, Error, Request, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde_json::json;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn b64u_to_bytes(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(crate) fn get_cookie(header: &str, name: &str) -> Option<String> {
    // Ex: header = "a=1; qs_state=XYZ; other=2"
    for part in header.split(';') {
        let p = part.trim();
        if let Some(v) = p.strip_prefix(&format!("{}=", name)) {
            return Some(v.to_string());
        }
    }
    None
}

fn map_ddb_err<E: std::fmt::Display>(e: E) -> lambda_http::Error {
    lambda_http::Error::from(format!("ddb: {e}"))
}

use crate::{
    id::new_slug,
    model::{CreateReq, CreateResp},
    util::{epoch_now, valid_target},
};

#[derive(Clone)]
pub struct Ctx {
    pub ddb: ddb::Client,
    pub table: String,
    pub cache_max_age: u64,
    pub domain: String,               // e.g., go.codequesthub.io
    pub create_token: Option<String>, // bearer token for admin/control plane
}

impl Ctx {
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let ddb = ddb::Client::new(&config);
        let table = std::env::var("TABLE_NAME").expect("TABLE_NAME");
        let cache_max_age = std::env::var("CACHE_MAX_AGE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(86400);
        let domain =
            std::env::var("PUBLIC_DOMAIN").unwrap_or_else(|_| "go.codequesthub.io".to_string());
        let create_token = std::env::var("CREATE_TOKEN").ok().filter(|s| !s.is_empty());
        Self {
            ddb,
            table,
            cache_max_age,
            domain,
            create_token,
        }
    }
}

/// Lightweight auth helper: if CREATE_TOKEN is set, require `Authorization: Bearer <token>`
pub(crate) fn auth_ok(req: &Request, expected: &Option<String>) -> bool {
    if let Some(exp) = expected {
        if let Some(h) = req
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
        {
            if let Some(b) = h.strip_prefix("Bearer ") {
                return b == exp;
            }
        }
        return false;
    }
    true
}

pub(crate) async fn jwt_cookie_valid(req: &lambda_http::Request) -> bool {
    let cookie_hdr = req
        .headers()
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let token = match get_cookie(cookie_hdr, "qs_admin_api") {
        Some(t) if !t.is_empty() => t,
        _ => return false,
    };
    let mut parts = token.split('.');
    let h_b64 = parts.next().unwrap_or("");
    let p_b64 = parts.next().unwrap_or("");
    let s_b64 = parts.next().unwrap_or("");
    if h_b64.is_empty() || p_b64.is_empty() || s_b64.is_empty() {
        return false;
    }
    let signing_input = format!("{}.{}", h_b64, p_b64);
    let sig = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kmsc = kms::Client::new(&cfg);
    let key_id = std::env::var("JWT_KMS_KEY_ID").unwrap_or_default();
    match kmsc
        .verify()
        .key_id(key_id)
        .message(signing_input.as_bytes().to_vec().into())
        .signature(sig.into())
        .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
        .send()
        .await
    {
        Ok(v) => v.signature_valid(),
        Err(_) => false,
    }
}

pub(crate) async fn auth_admin(req: &lambda_http::Request, ctx: &Ctx) -> bool {
    auth_ok(req, &ctx.create_token) || jwt_cookie_valid(req).await
}

pub async fn router(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let method = req.method().as_str();
    let path = req.uri().path();

    match (method, path) {
        ("POST", "/v1/links") => create_link(req, ctx).await,
        ("GET", "/v1/links") => list_links(req, ctx).await,
        ("PUT", p) if p.starts_with("/v1/links/") => update_link(req, ctx).await,
        ("DELETE", p) if p.starts_with("/v1/links/") => delete_link(req, ctx).await,
        ("GET", "/v1/admin/oauth/start") => oauth_start(req, ctx).await,
        ("GET", "/v1/admin/oauth/callback") => oauth_callback(req, ctx).await,
        ("POST", "/v1/admin/logout") => admin_logout(req, ctx).await,
        ("GET", "/v1/admin/me") => admin_me(req, ctx).await,
        _ if method == "GET" => resolve_link(req, ctx).await,
        _ => Ok(Response::builder()
            .status(404)
            .body("Not Found".into())
            .unwrap()),
    }
}

async fn create_link(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    if !auth_admin(&req, ctx).await {
        return Ok(resp_json(401, json!({"error":"unauthorized"})));
    }

    let body_bytes = match req.body() {
        Body::Text(s) => s.as_bytes().to_vec(),
        Body::Binary(b) => b.clone(),
        _ => Vec::new(),
    };

    let payload: CreateReq =
        serde_json::from_slice(&body_bytes).map_err(|_| Error::from("bad json"))?;

    if !valid_target(&payload.target) {
        return Ok(resp_json(400, json!({"error":"invalid target"})));
    }

    let now = epoch_now();
    let mut attempt = 0u32;
    let slug = match &payload.slug {
        Some(s) => s.clone(),
        None => loop {
            attempt += 1;
            let candidate = new_slug(&payload.target, now, attempt);
            if try_put(ctx, &candidate, &payload.target, now, payload.expires_at).await? {
                break candidate;
            }
            if attempt > 6 {
                return Ok(resp_json(500, json!({"error":"exhausted attempts"})));
            }
        },
    };

    if payload.slug.is_some() {
        if !try_put(ctx, &slug, &payload.target, now, payload.expires_at).await? {
            return Ok(resp_json(409, json!({"error":"slug exists"})));
        }
    }

    let short = format!("https://{}/{}", ctx.domain, slug);
    let out = CreateResp {
        slug: slug.clone(),
        short_url: short,
        target: payload.target.clone(),
        expires_at: payload.expires_at,
    };
    Ok(resp_json(201, serde_json::to_value(out).unwrap()))
}

async fn try_put(
    ctx: &Ctx,
    slug: &str,
    target: &str,
    created_at: u64,
    expires_at: Option<u64>,
) -> Result<bool, Error> {
    let mut item = std::collections::HashMap::new();
    item.insert("slug".into(), Av::S(slug.to_string()));
    item.insert("target".into(), Av::S(target.to_string()));
    item.insert("created_at".into(), Av::N(created_at.to_string()));
    if let Some(ttl) = expires_at {
        item.insert("expires_at".into(), Av::N(ttl.to_string()));
    }
    item.insert("visits".into(), Av::N("0".into()));

    let r = ctx
        .ddb
        .put_item()
        .table_name(&ctx.table)
        .set_item(Some(item))
        .condition_expression("attribute_not_exists(slug)")
        .send()
        .await;

    match r {
        Ok(_) => Ok(true),
        Err(e) => {
            if e.code() == Some("ConditionalCheckFailedException") {
                return Ok(false);
            }
            Err(Error::from(format!("ddb put error: {e}")))
        }
    }
}

async fn resolve_link(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let path = req.uri().path();
    if path.starts_with("/v1/") {
        return Ok(Response::builder()
            .status(404)
            .body("Not Found".into())
            .unwrap());
    }
    let slug = path.trim_start_matches('/');
    if slug.is_empty() {
        return Ok(Response::builder()
            .status(404)
            .body("Not Found".into())
            .unwrap());
    }

    let key = std::collections::HashMap::from([(String::from("slug"), Av::S(slug.to_string()))]);
    let r = ctx
        .ddb
        .get_item()
        .table_name(&ctx.table)
        .set_key(Some(key))
        .send()
        .await
        .map_err(|e| Error::from(format!("ddb get error: {e}")))?;

    let Some(item) = r.item else {
        return Ok(Response::builder()
            .status(404)
            .body("Not Found".into())
            .unwrap());
    };

    let target = item
        .get("target")
        .and_then(|v| v.as_s().ok())
        .cloned()
        .unwrap_or_default();

    let expires_at = item
        .get("expires_at")
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse::<u64>().ok());

    if let Some(ttl) = expires_at {
        if epoch_now() > ttl {
            return Ok(Response::builder()
                .status(404)
                .body("Not Found".into())
                .unwrap());
        }
    }

    // Best-effort visit increment (ignore errors)
    let _ = ctx
        .ddb
        .update_item()
        .table_name(&ctx.table)
        .key("slug", Av::S(slug.to_string()))
        .update_expression("ADD visits :inc")
        .expression_attribute_values(":inc", Av::N("1".into()))
        .send()
        .await;

    let resp = Response::builder()
        .status(301)
        .header("Location", target)
        .header(
            "Cache-Control",
            format!("public, max-age={}", ctx.cache_max_age),
        )
        .body(Body::Empty)
        .unwrap();
    Ok(resp)
}

async fn update_link(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    if !auth_admin(&req, ctx).await {
        return Ok(resp_json(401, json!({"error":"unauthorized"})));
    }

    let path = req.uri().path();
    let slug = path.trim_start_matches("/v1/links/");
    if slug.is_empty() {
        return Ok(resp_json(400, json!({"error":"bad_slug"})));
    }

    let body_bytes = match req.body() {
        Body::Text(s) => s.as_bytes().to_vec(),
        Body::Binary(b) => b.clone(),
        _ => Vec::new(),
    };
    let v: serde_json::Value =
        serde_json::from_slice(&body_bytes).map_err(|_| Error::from("bad json"))?;

    let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("");
    let expires_at = v.get("expires_at").and_then(|x| x.as_u64());

    if target.is_empty() && expires_at.is_none() {
        return Ok(resp_json(400, json!({"error":"no_updates"})));
    }

    let mut expr = String::from("SET ");
    let mut names = std::collections::HashMap::new();
    let mut vals = std::collections::HashMap::new();
    let mut first = true;

    if !target.is_empty() {
        if !first {
            expr.push_str(", ");
        }
        first = false;
        expr.push_str("#t = :t");
        names.insert("#t".to_string(), "target".to_string());
        vals.insert(":t".to_string(), Av::S(target.to_string()));
    }
    if let Some(exp) = expires_at {
        if !first {
            expr.push_str(", ");
        }
        expr.push_str("#e = :e");
        names.insert("#e".to_string(), "expires_at".to_string());
        vals.insert(":e".to_string(), Av::N(exp.to_string()));
    }

    ctx.ddb
        .update_item()
        .table_name(&ctx.table)
        .key("slug", Av::S(slug.to_string()))
        .update_expression(expr)
        .set_expression_attribute_names(Some(names))
        .set_expression_attribute_values(Some(vals))
        .return_values(aws_sdk_dynamodb::types::ReturnValue::UpdatedNew)
        .send()
        .await
        .map_err(map_ddb_err)?;

    Ok(resp_json(204, json!({})))
}

async fn list_links(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    if !auth_admin(&req, ctx).await {
        return Ok(resp_json(401, json!({"error":"unauthorized"})));
    }

    let qp = req.uri().query().unwrap_or("");
    let params: std::collections::HashMap<_, _> = url::form_urlencoded::parse(qp.as_bytes())
        .into_owned()
        .collect();
    let q = params.get("q").cloned().unwrap_or_default();
    let limit: i32 = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(25);
    let next = params.get("next").cloned();

    let mut scan = ctx.ddb.scan().table_name(&ctx.table).limit(limit);

    if let Some(slug_tok) = next {
        let mut esk = std::collections::HashMap::new();
        esk.insert("slug".to_string(), Av::S(slug_tok));
        scan = scan.set_exclusive_start_key(Some(esk));
    }

    if !q.is_empty() {
        if let Some(rest) = q.strip_prefix("slug:") {
            scan = scan
                .filter_expression("begins_with(#s, :p)")
                .expression_attribute_names("#s", "slug")
                .expression_attribute_values(":p", Av::S(rest.to_string()));
        } else {
            scan = scan
                .filter_expression("contains(#t, :p)")
                .expression_attribute_names("#t", "target")
                .expression_attribute_values(":p", Av::S(q));
        }
    }

    let resp = scan.send().await.map_err(map_ddb_err)?;

    let items: Vec<_> = resp.items().iter().map(|it| {
        json!({
            "slug": it.get("slug").and_then(|v| v.as_s().ok()),
            "target": it.get("target").and_then(|v| v.as_s().ok()),
            "created_at": it.get("created_at").and_then(|v| v.as_n().ok()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
            "visits": it.get("visits").and_then(|v| v.as_n().ok()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
            "expires_at": it.get("expires_at").and_then(|v| v.as_n().ok()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0)
        })
    }).collect();

    let mut out = json!({ "items": items, "count": resp.count() });
    if let Some(lek) = resp.last_evaluated_key() {
        if let Some(Av::S(slug)) = lek.get("slug") {
            out["next"] = json!(slug);
        }
    }

    Ok(resp_json(200, out))
}

async fn delete_link(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    if !auth_admin(&req, ctx).await {
        return Ok(resp_json(401, json!({"error":"unauthorized"})));
    }

    let slug = req
        .uri()
        .path()
        .trim_start_matches("/v1/links/")
        .to_string();
    if slug.is_empty() {
        return Ok(resp_json(400, json!({"error":"missing slug"})));
    }

    ctx.ddb
        .delete_item()
        .table_name(&ctx.table)
        .key("slug", Av::S(slug))
        .send()
        .await
        .map_err(|e| Error::from(format!("ddb delete: {e}")))?;

    Ok(Response::builder().status(204).body(Body::Empty).unwrap())
}

fn resp_json(status: u16, v: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::Text(v.to_string()))
        .unwrap()
}

async fn oauth_start(_req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap_or_default();
    let iss = std::env::var("JWT_ISS").unwrap_or_else(|_| format!("https://{}", ctx.domain));

    // Create tamper-evident state using HMAC (Lambda only; no edge secret)
    let nonce = uuid::Uuid::new_v4().to_string();
    let exp = epoch() + 600; // 10 min
    let payload = format!("{{\"n\":\"{}\",\"exp\":{}}}", nonce, exp);
    let state_payload_b64 = b64u(payload.as_bytes());
    let mut mac = HmacSha256::new_from_slice(
        std::env::var("ADMIN_STATE_KEY")
            .unwrap_or_default()
            .as_bytes(),
    )
    .map_err(|_| Error::from("state key"))?;
    mac.update(state_payload_b64.as_bytes());
    let sig_b64 = b64u(&mac.finalize().into_bytes());
    let state = format!("{}.{}", state_payload_b64, sig_b64);
    let state_cookie = format!(
        "qs_state={}; Path=/v1/admin; Max-Age=600; HttpOnly; Secure; SameSite=Lax; Domain={}",
        state, ctx.domain
    );

    let redirect_uri = format!("{}/v1/admin/oauth/callback", iss);
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user&state={}&allow_signup=false",
        urlencoding::encode(&client_id), urlencoding::encode(&redirect_uri), urlencoding::encode(&state)
    );

    let resp = Response::builder()
        .status(302)
        .header("Location", url)
        .header("Set-Cookie", state_cookie)
        .header("Cache-Control", "no-store, no-cache, must-revalidate")
        .header("Pragma", "no-cache")
        .body(Body::Empty)
        .unwrap();
    Ok(resp)
}

async fn oauth_callback(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let qs = req.uri().query().unwrap_or("");
    let params: std::collections::HashMap<_, _> = url::form_urlencoded::parse(qs.as_bytes())
        .into_owned()
        .collect();
    let code = params.get("code").cloned().unwrap_or_default();
    let state = params.get("state").cloned().unwrap_or_default();
    if code.is_empty() || state.is_empty() {
        return Ok(resp_json(400, json!({"error":"bad_request"})));
    }

    let cookie_hdr = req
        .headers()
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let cookie_state = get_cookie(cookie_hdr, "qs_state").unwrap_or_default();

    if cookie_state.is_empty() || cookie_state != state {
        return Ok(resp_json(
            401,
            json!({"error":"unauthorized","reason":"state_cookie_mismatch"}),
        ));
    }

    // clear the cookie when issuing session
    let clear_state = format!(
        "qs_state=; Path=/v1/admin; Max-Age=0; HttpOnly; Secure; SameSite=Lax; Domain={}",
        ctx.domain
    );

    // Verify state
    let mut split = state.splitn(2, '.');
    let st_payload_b64 = split.next().unwrap_or("");
    let st_sig_b64 = split.next().unwrap_or("");
    let mut mac = HmacSha256::new_from_slice(
        std::env::var("ADMIN_STATE_KEY")
            .unwrap_or_default()
            .as_bytes(),
    )
    .map_err(|_| Error::from("state key"))?;
    mac.update(st_payload_b64.as_bytes());
    let ok = mac
        .verify_slice(&URL_SAFE_NO_PAD.decode(st_sig_b64).unwrap_or_default())
        .is_ok();
    if !ok {
        return Ok(resp_json(401, json!({"error":"unauthorized"})));
    }
    let st_json = String::from_utf8(URL_SAFE_NO_PAD.decode(st_payload_b64).unwrap_or_default())
        .unwrap_or_default();
    let st_val: serde_json::Value = serde_json::from_str(&st_json).unwrap_or(json!({}));
    let exp_ok = st_val
        .get("exp")
        .and_then(|v| v.as_u64())
        .map(|e| epoch() < e)
        .unwrap_or(false);
    if !exp_ok {
        return Ok(resp_json(401, json!({"error":"state_expired"})));
    }

    // Exchange code for token
    let client = Client::new();
    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("GITHUB_CLIENT_SECRET").unwrap_or_default();
    let iss = std::env::var("JWT_ISS").unwrap_or_else(|_| format!("https://{}", ctx.domain));
    let redirect_uri = format!("{}/v1/admin/oauth/callback", iss);

    // Build Basic auth: base64(client_id:client_secret)
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", client_id, client_secret))
    );

    let body = format!(
        "code={}&redirect_uri={}",
        urlencoding::encode(&code),
        urlencoding::encode(&redirect_uri)
    );

    let resp = client
        .post("https://github.com/login/oauth/access_token")
        .header(AUTHORIZATION, basic)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| Error::from(format!("oauth post: {e}")))?;

    let token_resp: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| Error::from(format!("oauth json: {e}")))?;

    // Helpful debug: log an error string if present (shows why GitHub denied)
    if let Some(err) = token_resp.get("error") {
        let desc = token_resp
            .get("error_description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        eprintln!("github oauth error: {err} {desc}");
    }

    let access = token_resp
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if access.is_empty() {
        // bubble exact reason while you’re setting up; switch back to generic 401 later
        return Ok(resp_json(401, token_resp));
    }

    // Fetch user
    let user: serde_json::Value = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", access))
        .header("User-Agent", "quickshort-rs")
        .send()
        .await
        .map_err(|e| Error::from(format!("gh user: {e}")))?
        .json()
        .await
        .map_err(|e| Error::from(format!("gh user json: {e}")))?;

    let login = user
        .get("login")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let allow = std::env::var("ADMIN_GITHUB_LOGINS").unwrap_or_default();
    let allowed: std::collections::HashSet<String> = allow
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if !allowed.contains(&login) {
        return Ok(resp_json(403, json!({"error":"forbidden"})));
    }

    // Build JWT
    let aud = std::env::var("JWT_AUD").unwrap_or_else(|_| "qs-admin".to_string());
    let ttl: u64 = std::env::var("JWT_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);
    let iat = epoch();
    let exp = iat + ttl;
    let header = json!({"alg":"RS256","typ":"JWT","kid": std::env::var("JWT_KMS_KEY_ID").unwrap_or_default()});
    let payload = json!({"iss": iss, "aud": aud, "sub": login, "iat": iat, "exp": exp});
    let h_b64 = b64u(serde_json::to_string(&header).unwrap().as_bytes());
    let p_b64 = b64u(serde_json::to_string(&payload).unwrap().as_bytes());
    let signing_input = format!("{}.{}", h_b64, p_b64);

    let cfg = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let kmsc = kms::Client::new(&cfg);
    use kms::types::{MessageType, SigningAlgorithmSpec};
    let sig = kmsc
        .sign()
        .key_id(std::env::var("JWT_KMS_KEY_ID").unwrap())
        .message(signing_input.as_bytes().to_vec().into())
        .message_type(MessageType::Raw)
        .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
        .send()
        .await
        .map_err(|e| Error::from(format!("kms sign: {e}")))?;

    let sig_bytes: &[u8] = sig.signature().map(|b| b.as_ref()).unwrap_or(&[]);
    let sig_b64 = b64u(sig_bytes);
    let token = format!("{}.{}.{}", h_b64, p_b64, sig_b64);

    let domain = ctx.domain.clone();

    let mut builder = Response::builder().status(302);
    let headers = builder.headers_mut().unwrap();
    let cookie = format!(
        "qs_admin={}; Path=/admin; Max-Age={}; HttpOnly; Secure; SameSite=Lax; Domain={}",
        token, ttl, domain
    );
    headers.append("Set-Cookie", cookie.parse().unwrap()); // session
    let cookie = format!(
        "qs_admin_api={}; Path=/v1; Max-Age={}; HttpOnly; Secure; SameSite=Strict; Domain={}",
        token, ttl, domain
    );
    headers.append("Set-Cookie", cookie.parse().unwrap()); // API session

    headers.append("Set-Cookie", clear_state.parse().unwrap()); // clear state
    let resp = builder
        .header("Location", "/admin/")
        .header("Cache-Control", "no-store, no-cache, must-revalidate")
        .header("Pragma", "no-cache")
        .body(Body::Empty)
        .unwrap();
    Ok(resp)
}

async fn admin_logout(_req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let mut builder = Response::builder().status(204);
    let headers = builder.headers_mut().unwrap();

    let cookie = format!(
        "qs_admin=deleted; Path=/admin; Max-Age=0; HttpOnly; Secure; SameSite=Lax; Domain={}",
        ctx.domain
    );
    headers.append("Set-Cookie", cookie.parse().unwrap()); // session

    let cookie = format!(
        "qs_admin_api=deleted; Path=/v1; Max-Age=0; HttpOnly; Secure; SameSite=Srtict; Domain={}",
        ctx.domain
    );
    headers.append("Set-Cookie", cookie.parse().unwrap()); // session

    let resp = builder.body(Body::Empty).unwrap();
    Ok(resp)
}

async fn admin_me(req: Request, _ctx: &Ctx) -> Result<Response<Body>, Error> {
    let cookie_hdr = req
        .headers()
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let token = match get_cookie(cookie_hdr, "qs_admin_api") {
        Some(t) if !t.is_empty() => t,
        _ => return Ok(resp_json(401, json!({"error":"unauthorized"}))),
    };

    // Split JWT
    let mut parts = token.split('.');
    let h_b64 = parts.next().unwrap_or("");
    let p_b64 = parts.next().unwrap_or("");
    let s_b64 = parts.next().unwrap_or("");
    if h_b64.is_empty() || p_b64.is_empty() || s_b64.is_empty() {
        return Ok(resp_json(401, json!({"error":"unauthorized"})));
    }

    // Verify with KMS (same key, RSASSA_PKCS1_V1_5_SHA_256)
    let cfg = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let kmsc = kms::Client::new(&cfg);
    let signing_input = format!("{}.{}", h_b64, p_b64);
    let sig = match b64u_to_bytes(s_b64) {
        Some(v) => v,
        None => return Ok(resp_json(401, json!({"error":"unauthorized"}))),
    };

    let key_id = std::env::var("JWT_KMS_KEY_ID").unwrap_or_default();
    let vr = kmsc
        .verify()
        .key_id(key_id)
        .message(signing_input.as_bytes().to_vec().into())
        .signature(sig.into())
        .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
        .send()
        .await
        .map_err(|e| Error::from(format!("kms verify: {e}")))?;

    if !vr.signature_valid {
        return Ok(resp_json(401, json!({"error":"unauthorized"})));
    }

    // Decode payload and read `sub`
    let payload_json = match b64u_to_bytes(p_b64).and_then(|b| String::from_utf8(b).ok()) {
        Some(s) => s,
        None => return Ok(resp_json(401, json!({"error":"unauthorized"}))),
    };
    let v: serde_json::Value = serde_json::from_str(&payload_json).unwrap_or(json!({}));
    let login = v.get("sub").and_then(|x| x.as_str()).unwrap_or("");

    if login.is_empty() {
        return Ok(resp_json(401, json!({"error":"unauthorized"})));
    }

    Ok(resp_json(200, json!({ "login": login })))
}

#[cfg(test)]
mod tests {
    use super::auth_ok;
    use lambda_http::{http::HeaderValue, Request};

    #[test]
    fn auth_passes_on_exact_bearer() {
        let mut req = Request::default();
        req.headers_mut()
            .insert("authorization", HeaderValue::from_static("Bearer abc"));
        assert!(auth_ok(&req, &Some("abc".into())));
    }

    #[test]
    fn auth_fails_on_missing_or_wrong_token() {
        let req = Request::default();
        assert!(!auth_ok(&req, &Some("abc".into())));

        let mut req2 = Request::default();
        req2.headers_mut()
            .insert("authorization", HeaderValue::from_static("Bearer wrong"));
        assert!(!auth_ok(&req2, &Some("abc".into())));
    }

    #[test]
    fn auth_is_open_when_unset() {
        let req = Request::default();
        assert!(auth_ok(&req, &None));
    }
}
