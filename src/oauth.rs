use aws_config::BehaviorVersion;
use aws_sdk_kms as kms;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use lambda_http::{Body, Error, Request, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde_json::json;
use sha2::Sha256;

use crate::{
    auth::{caller_id, require_auth, Caller, CallerSource},
    handler::{get_cookie, Ctx},
    id::new_slug,
    model::{CreateReq, CreateResp},
    util::{b64u, epoch_now, resp_json, valid_target},
};

type HmacSha256 = Hmac<Sha256>;

pub(crate) async fn oauth_start(_req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap_or_default();
    let iss = std::env::var("JWT_ISS").unwrap_or_else(|_| format!("https://{}", ctx.domain));

    // Create tamper-evident state using HMAC (Lambda only; no edge secret)
    let nonce = uuid::Uuid::new_v4().to_string();
    let exp = epoch_now() + 600; // 10 min
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

pub(crate) async fn oauth_callback(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
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
        .map(|e| epoch_now() < e)
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
    let iat = epoch_now();
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
