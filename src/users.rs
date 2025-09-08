use std::default;

use aws_sdk_dynamodb as ddb;
// for .code()
use aws_sdk_dynamodb::error::ProvideErrorMetadata;
use aws_sdk_dynamodb::types::ReturnValue;
use chrono::Utc;
use ddb::types::AttributeValue as Av;
use lambda_http::{Body, Error, Request, Response};

use crate::{
    auth::{require_auth, CallerSource},
    handler::Ctx,
    require_auth_or_return,
    util::{json_err, json_ok},
};

pub async fn get_user_plan(ddb: &ddb::Client, table_users: &str, user_id: &str) -> Option<String> {
    if table_users.is_empty() {
        return None;
    }
    let got = ddb
        .get_item()
        .table_name(table_users)
        .key("user_id", Av::S(user_id.to_string()))
        .send()
        .await
        .ok()?;
    got.item()
        .and_then(|m| m.get("plan").and_then(|v| v.as_s().ok()))
        .map(|s| s.to_string())
}

pub async fn ensure_user(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let caller = require_auth(&req).await?;

    // We don't create "users" for legacy admin cookie callers
    if matches!(caller.source, CallerSource::AdminCookie) {
        return Ok(json_err(
            400,
            "unsupported",
            "Admin cookie auth does not create user accounts",
        ));
    }

    let table = ctx.table_users.as_str();
    if table.is_empty() {
        return Ok(json_err(500, "config", "TABLE_USERS not set"));
    }

    let user_id = caller.user_id.clone(); // Cognito sub
    let provider = "google".to_string(); // current IdP
    let email = caller.email.clone().unwrap_or_default();
    let now = Utc::now().to_rfc3339();

    // 1) Try to CREATE the item if it doesn't exist (idempotent on first visit)
    let put = ctx
        .ddb
        .put_item()
        .table_name(table)
        .item("user_id", Av::S(user_id.clone()))
        .item("provider", Av::S(provider.clone()))
        .item("email", Av::S(email.clone()))
        .item("plan", Av::S("free".into()))
        .item("created_at", Av::S(now.clone()))
        .item("updated_at", Av::S(now.clone()))
        .condition_expression("attribute_not_exists(user_id)")
        .send()
        .await;

    match put {
        Ok(_) => {
            let out = serde_json::json!({
                "user_id": user_id,
                "provider": provider,
                "email": email,
                "plan": "free",
                "created_at": now,
                "updated_at": now,
                "_created": true
            });
            return Ok(json_ok(out));
        }
        Err(e) => {
            // If the user already exists, fall through to UpdateItem; otherwise, surface details.
            let code = e.code().unwrap_or("unknown");
            if code != "ConditionalCheckFailedException" {
                let msg = e.message().unwrap_or("");
                tracing::error!(table=%table, err_code=%code, err_msg=%msg, "DDB PutItem failed");
                return Ok(json_err(
                    500,
                    "ddb_put",
                    format!("code={} msg={}", code, msg),
                ));
            }
        }
    }

    // 2) The item already exists — UPDATE missing fields and bump updated_at
    let upd = ctx
        .ddb
        .update_item()
        .table_name(table)
        .key("user_id", Av::S(user_id.clone()))
        .update_expression(
            "SET #provider = if_not_exists(#provider, :p), \
                  #email    = if_not_exists(#email, :e), \
                  #plan     = if_not_exists(#plan, :plan), \
                  created_at = if_not_exists(created_at, :now), \
                  updated_at = :now",
        )
        .expression_attribute_names("#provider", "provider")
        .expression_attribute_names("#email", "email")
        .expression_attribute_names("#plan", "plan")
        .expression_attribute_values(":p", Av::S(provider.clone()))
        .expression_attribute_values(":e", Av::S(email.clone()))
        .expression_attribute_values(":plan", Av::S("free".into()))
        .expression_attribute_values(":now", Av::S(now.clone()))
        .return_values(ReturnValue::AllNew)
        .send()
        .await;

    match upd {
        Ok(resp) => {
            let default_plan = "free".to_string();
            let item = resp.attributes.unwrap_or_default();
            let plan = item
                .get("plan")
                .and_then(|v| v.as_s().ok())
                .unwrap_or(&default_plan);
            let created = item.get("created_at").and_then(|v| v.as_s().ok());
            let updated = item.get("updated_at").and_then(|v| v.as_s().ok());
            let out = serde_json::json!({
                "user_id": user_id, "provider": provider, "email": email,
                "plan": plan, "created_at": created, "updated_at": updated,
                "_created": false
            });
            Ok(json_ok(out))
        }
        Err(e) => {
            let code = e.code().unwrap_or("unknown");
            let msg = e.message().unwrap_or("");
            tracing::error!(table=%table, err_code=%code, err_msg=%msg, "DDB UpdateItem failed");
            Ok(json_err(
                500,
                "ddb_update",
                format!("code={} msg={}", code, msg),
            ))
        }
    }
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
    Ok(json_err(
        404,
        "not_found",
        "User not registered; call POST /v1/users/ensure after sign-in",
    ))
}
