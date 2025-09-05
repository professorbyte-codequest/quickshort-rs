use aws_config::BehaviorVersion;
use aws_sdk_dynamodb as ddb;
use aws_sdk_dynamodb::error::ProvideErrorMetadata; // for .code()
use aws_sdk_kms as kms;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use ddb::types::AttributeValue as Av;
use hmac::{Hmac, Mac};
use lambda_http::{Body, Error, Request, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde_json::json;
use sha2::Sha256;
use std::borrow::Cow;
use std::default;

use crate::{
    auth::{caller_id, require_auth, Caller, CallerSource},
    handler::{get_cookie, json_err, json_ok, Ctx},
    id::new_slug,
    model::{CreateReq, CreateResp},
    oauth::{oauth_callback, oauth_start},
    require_auth_or_return,
    util::{b64u, epoch_now, resp_json, valid_target},
};

type HmacSha256 = Hmac<Sha256>;

pub(crate) async fn ensure_user(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let caller = require_auth_or_return!(req, 401, "unauthorized", "Requires authentication");

    // For now, only Cognito/Google users register. Admin legacy cookie callers skip.
    if matches!(caller.source, CallerSource::AdminCookie) {
        return json_err(
            400,
            "unsupported",
            "Admin cookie auth does not create user accounts",
        );
    }

    let user_id = caller.user_id.clone(); // Cognito sub
    let provider = "google".to_string(); // We only expose Google for now
    let email = caller.email.clone().unwrap_or_default();
    let now = Utc::now().to_rfc3339();

    // Idempotent upsert: on first call, set initial fields; on subsequent calls, only update updated_at.
    // Using UpdateItem so it's safe to invoke repeatedly.
    let resp = ctx.ddb
        .update_item()
        .table_name(&ctx.table_users)
        .key("user_id", Av::S(user_id.clone()))
        .update_expression("SET #p = if_not_exists(#p, :p), email = if_not_exists(email, :e), plan = if_not_exists(plan, :plan), created_at = if_not_exists(created_at, :now), updated_at = :now")
        .expression_attribute_names("#p", "provider")
        .expression_attribute_values(":p", Av::S(provider.clone()))
        .expression_attribute_values(":e", Av::S(email.clone()))
        .expression_attribute_values(":plan", Av::S("free".into()))
        .expression_attribute_values(":now", Av::S(now.clone()))
        .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
        .send()
        .await
        .map_err(|e| lambda_http::Error::from(format!("ddb users update: {e}")))?;

    let item = resp.attributes.unwrap_or_default();
    let default_plan = "free".to_string();
    let out = serde_json::json!({
        "user_id": user_id,
        "provider": provider,
        "email": email,
        "plan": item.get("plan").and_then(|v| v.as_s().ok()).unwrap_or(&default_plan),
        "created_at": item.get("created_at").and_then(|v| v.as_s().ok()),
        "updated_at": item.get("updated_at").and_then(|v| v.as_s().ok()),
    });

    Ok(json_ok(out))
}

pub(crate) async fn get_me(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let caller = require_auth_or_return!(req, 401, "unauthorized", "Requires authentication");
    let key = Av::S(caller.user_id.clone());

    let got = ctx
        .ddb
        .get_item()
        .table_name(&ctx.table_users)
        .key("user_id", key)
        .send()
        .await
        .map_err(|e| lambda_http::Error::from(format!("ddb users get: {e}")))?;

    let default_plan = "free".to_string();
    let default_provider = "google".to_string();
    let default_email = "".to_string();
    if let Some(item) = got.item() {
        let provider = item
            .get("provider")
            .and_then(|v| v.as_s().ok())
            .unwrap_or(&default_provider);
        let email = item
            .get("email")
            .and_then(|v| v.as_s().ok())
            .unwrap_or(&default_email);
        let plan = item
            .get("plan")
            .and_then(|v| v.as_s().ok())
            .unwrap_or(&default_plan);
        let created = item.get("created_at").and_then(|v| v.as_s().ok());
        let updated = item.get("updated_at").and_then(|v| v.as_s().ok());
        return Ok(json_ok(serde_json::json!({
            "user_id": caller.user_id,
            "provider": provider,
            "email": email,
            "plan": plan,
            "created_at": created,
            "updated_at": updated,
        })));
    }

    // Not found – suggest running ensure
    json_err(
        404,
        "not_found",
        "User not registered; call POST /v1/users/ensure after sign-in",
    )
}
