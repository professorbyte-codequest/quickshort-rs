use aws_config::BehaviorVersion;
use aws_sdk_dynamodb as ddb;
use aws_sdk_dynamodb::error::ProvideErrorMetadata;
use ddb::types::AttributeValue as Av;
use lambda_http::{Body, Error, Request, Response};
use serde_json::json;

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
    pub domain: String,
    pub create_token: Option<String>,
}

impl Ctx {
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let ddb = ddb::Client::new(&config);
        let table = std::env::var("TABLE_NAME").expect("TABLE_NAME");
        let cache_max_age = std::env::var("CACHE_MAX_AGE").ok().and_then(|s| s.parse().ok()).unwrap_or(86400);
        let domain = std::env::var("PUBLIC_DOMAIN").unwrap_or_else(|_| "go.codequesthub.io".to_string());
        let create_token = std::env::var("CREATE_TOKEN").ok().filter(|s| !s.is_empty());
        Self { ddb, table, cache_max_age, domain, create_token }
    }
}

pub async fn router(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let method = req.method().as_str();
    let path = req.uri().path();

    match (method, path) {
        ("POST", "/v1/links") => create_link(req, ctx).await,
        _ if method == "GET" => resolve_link(req, ctx).await,
        _ => Ok(Response::builder().status(404).body("Not Found".into()).unwrap()),
    }
}

async fn create_link(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    // --- Bearer auth (only if CREATE_TOKEN is set) ---
    if let Some(expected) = &ctx.create_token {
        let auth = req.headers().get("authorization").and_then(|h| h.to_str().ok()).unwrap_or("");
        let bearer = auth.strip_prefix("Bearer ").unwrap_or("");
        if bearer != expected {
            return Ok(resp_json(401, json!({"error":"unauthorized"})));
        }
    }

    // --- Decode body ---
    let body_bytes = match req.body() {
        Body::Text(s) => s.as_bytes().to_vec(),
        Body::Binary(b) => b.clone(),
        _ => Vec::new(),
    };

    let payload: CreateReq = serde_json::from_slice(&body_bytes)
        .map_err(|_| Error::from("bad json"))?;

    if !valid_target(&payload.target) {
        return Ok(resp_json(400, json!({"error":"invalid target"})));
    }

    // --- Generate slug with conditional put ---
    let now = epoch_now();
    let mut attempt = 0u32;
    let slug = match &payload.slug {
        Some(s) => s.clone(),
        None => loop {
            attempt += 1;
            let candidate = new_slug(&payload.target, now, attempt);
            if try_put(ctx, &candidate, &payload.target, now, payload.expires_at).await? { break candidate; }
            if attempt > 6 { return Ok(resp_json(500, json!({"error":"exhausted attempts"}))); }
        },
    };

    if payload.slug.is_some() {
        if !try_put(ctx, &slug, &payload.target, now, payload.expires_at).await? {
            return Ok(resp_json(409, json!({"error":"slug exists"})));
        }
    }

    let short = format!("https://{}/{}", ctx.domain, slug);
    let out = CreateResp { slug: slug.clone(), short_url: short, target: payload.target.clone(), expires_at: payload.expires_at };
    Ok(resp_json(201, serde_json::to_value(out).unwrap()))
}

async fn try_put(ctx: &Ctx, slug: &str, target: &str, created_at: u64, expires_at: Option<u64>) -> Result<bool, Error> {
    let mut item = std::collections::HashMap::new();
    item.insert("slug".into(), Av::S(slug.to_string()));
    item.insert("target".into(), Av::S(target.to_string()));
    item.insert("created_at".into(), Av::N(created_at.to_string()));
    if let Some(ttl) = expires_at { item.insert("expires_at".into(), Av::N(ttl.to_string())); }
    item.insert("visits".into(), Av::N("0".into()));

    let r = ctx.ddb
        .put_item()
        .table_name(&ctx.table)
        .set_item(Some(item))
        .condition_expression("attribute_not_exists(slug)")
        .send()
        .await;

    match r {
        Ok(_) => Ok(true),
        Err(e) => {
            if e.code() == Some("ConditionalCheckFailedException") { return Ok(false); }
            Err(Error::from(format!("ddb put error: {e}")))
        }
    }
}

async fn resolve_link(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let path = req.uri().path();
    if path.starts_with("/v1/") { return Ok(Response::builder().status(404).body("Not Found".into()).unwrap()); }
    let slug = path.trim_start_matches('/');
    if slug.is_empty() { return Ok(Response::builder().status(404).body("Not Found".into()).unwrap()); }

    let key = std::collections::HashMap::from([(String::from("slug"), Av::S(slug.to_string()))]);
    let r = ctx.ddb
        .get_item()
        .table_name(&ctx.table)
        .set_key(Some(key))
        .send()
        .await
        .map_err(|e| Error::from(format!("ddb get error: {e}")))?;

    let Some(item) = r.item else { return Ok(Response::builder().status(404).body("Not Found".into()).unwrap()) };

    let target = item.get("target").and_then(|v| v.as_s().ok()).cloned().unwrap_or_default();
    let expires_at = item.get("expires_at").and_then(|v| v.as_n().ok()).and_then(|s| s.parse::<u64>().ok());
    if let Some(ttl) = expires_at { if epoch_now() > ttl { return Ok(Response::builder().status(404).body("Not Found".into()).unwrap()); } }

    let _ = ctx.ddb.update_item()
        .table_name(&ctx.table)
        .key("slug", Av::S(slug.to_string()))
        .update_expression("ADD visits :inc")
        .expression_attribute_values(":inc", Av::N("1".into()))
        .send().await;

    let resp = Response::builder()
        .status(301)
        .header("Location", target)
        .header("Cache-Control", format!("public, max-age={}", ctx.cache_max_age))
        .body(Body::Empty)
        .unwrap();
    Ok(resp)
}

fn resp_json(status: u16, v: serde_json::Value) -> Response<Body> {
    Response::builder().status(status).header("Content-Type", "application/json").body(Body::Text(v.to_string())).unwrap()
}
