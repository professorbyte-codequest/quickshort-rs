use aws_config::BehaviorVersion;
use aws_sdk_dynamodb as ddb;
use aws_sdk_dynamodb::error::ProvideErrorMetadata; // for .code()
use aws_sdk_kms as kms;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ddb::types::AttributeValue as Av;
use hmac::{Hmac, Mac};
use lambda_http::{Body, Error, Request, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde_json::json;
use sha2::Sha256;
use std::borrow::Cow;

use crate::{
    auth::{caller_id, require_auth, Caller, CallerSource},
    handler::{get_cookie, json_err, Ctx},
    id::new_slug,
    model::{CreateReq, CreateResp},
    oauth::{oauth_callback, oauth_start},
    util::{b64u, epoch_now, resp_json, valid_target},
};

type HmacSha256 = Hmac<Sha256>;

pub(crate) async fn admin_logout(_req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
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

pub(crate) async fn admin_me(req: Request, _ctx: &Ctx) -> Result<Response<Body>, Error> {
    if let Some(c) = caller_id(&req).await {
        let src = match c.source {
            CallerSource::Cognito => "cognito",
            CallerSource::AdminCookie => "legacy",
        };

        // NOTE: no `.to_string()` on serde_json::Value — everything here is a plain String
        let body = serde_json::json!({
            "user_id": c.user_id,       // preferred key
            "login":   c.user_id,       // compat with old client
            "email":   c.email,
            "source":  src,
            "is_admin": c.is_admin,
        });

        return Ok(resp_json(200, body));
    }

    json_err(401, "unauthorized", "Not signed in")
}
