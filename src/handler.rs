use aws_config::BehaviorVersion;
use aws_sdk_dynamodb as ddb;
// for .code()
use lambda_http::{Body, Error, Request, Response};
use std::borrow::Cow;

use crate::{
    admin::{admin_logout, admin_me},
    api::{create_link, delete_link, list_links, resolve_link, update_link},
    oauth::{oauth_callback, oauth_start},
    users::{ensure_user, get_me},
    util::resp_json,
};

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

pub(crate) fn map_ddb_err<E: std::fmt::Display>(e: E) -> lambda_http::Error {
    lambda_http::Error::from(format!("ddb: {e}"))
}

#[derive(Clone)]
pub struct Ctx {
    pub ddb: ddb::Client,
    pub table: String,
    pub table_users: String,
    pub cache_max_age: u64,
    pub domain: String,
}

impl Ctx {
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let ddb = ddb::Client::new(&config);
        let table = std::env::var("TABLE_NAME").expect("TABLE_NAME");
        let table_users = std::env::var("TABLE_USERS").expect("TABLE_USERS");
        let cache_max_age = std::env::var("CACHE_MAX_AGE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(86400);
        let domain =
            std::env::var("PUBLIC_DOMAIN").unwrap_or_else(|_| "go.codequesthub.io".to_string());
        Self {
            ddb,
            table,
            table_users,
            cache_max_age,
            domain,
        }
    }
}

pub async fn router(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let method = req.method().as_str();
    let path = req.uri().path();

    match (method, path) {
        // from api module
        ("POST", "/v1/links") => create_link(req, ctx).await,
        ("GET", "/v1/links") => list_links(req, ctx).await,
        ("PUT", p) if p.starts_with("/v1/links/") => update_link(req, ctx).await,
        ("DELETE", p) if p.starts_with("/v1/links/") => delete_link(req, ctx).await,

        // from oauth module
        ("GET", "/v1/admin/oauth/start") => oauth_start(req, ctx).await,
        ("GET", "/v1/admin/oauth/callback") => oauth_callback(req, ctx).await,

        // from admin module
        ("POST", "/v1/admin/logout") => admin_logout(req, ctx).await,
        ("GET", "/v1/admin/me") => admin_me(req, ctx).await,

        // from users module
        ("GET", "/v1/users/me") => get_me(req, ctx).await,
        ("POST", "/v1/users/ensure") => ensure_user(req, ctx).await,

        _ if method == "GET" => resolve_link(req, ctx).await,
        _ => Ok(Response::builder()
            .status(302)
            .header("Location", ctx.domain.clone())
            .body(format!("Redirecting to {}", ctx.domain).into())
            .unwrap()),
    }
}

pub fn json_err(
    status: u16,
    code: &'static str,
    message: impl Into<Cow<'static, str>>,
) -> Result<lambda_http::Response<lambda_http::Body>, lambda_http::Error> {
    use lambda_http::{Body, Response};
    let payload = serde_json::json!({
    "error": code,
    "message": message.into(),
    });
    let body = serde_json::to_vec(&payload).map_err(|e| lambda_http::Error::from(e.to_string()))?;
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::Binary(body))
        .map_err(|e| lambda_http::Error::from(format!("resp: {e}")))
}

pub fn json_ok(v: serde_json::Value) -> Response<Body> {
    resp_json(200, v)
}
