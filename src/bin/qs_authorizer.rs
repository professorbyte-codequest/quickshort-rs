use lambda_runtime::{service_fn, Error as LambdaError, LambdaEvent};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::collections::HashMap;

use quickshort::auth::{verify_legacy_cookie_subject, verify_cognito_id_token, Caller, CallerSource};

#[derive(Serialize)]
struct SimpleAuthz {
    #[serde(rename = "isAuthorized")]
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<HashMap<String, String>>,
}

fn get_header<'a>(evt: &'a JsonValue, name: &str) -> Option<&'a str> {
    let headers = evt.get("headers")?.as_object()?;
    headers.get(&name.to_ascii_lowercase())?.as_str()
}
fn get_cookie<'a>(evt: &'a JsonValue, name: &str) -> Option<String> {
    let cookie_hdr = get_header(evt, "cookie")?;
    for part in cookie_hdr.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    lambda_runtime::run(service_fn(handler)).await
}

async fn handler(event: LambdaEvent<JsonValue>) -> Result<JsonValue, LambdaError> {
    let evt = event.payload;

    // 1) Cognito ID token path (Authorization: Bearer <id_token>)
    if let Some(authz) = get_header(&evt, "authorization") {
        if let Some(tok) = authz.strip_prefix("Bearer ") {
            if let Ok(claims) = verify_cognito_id_token(tok).await {
                let mut ctx = HashMap::new();
                ctx.insert("sub".into(), claims.sub.clone());
                if let Some(e) = claims.email.clone() {
                    ctx.insert("email".into(), e);
                }
                ctx.insert("source".into(), "cognito".into());
                ctx.insert(
                    "is_admin".into(),
                    "false".into(), // default to false; your app can elevate if needed
                );
                return Ok(json!(SimpleAuthz {
                    ok: true,
                    context: Some(ctx)
                }));
            }
        }
    }

    tracing::info!("No valid Cognito ID token found");

    // 2) Legacy admin cookie path (qs_admin_api), reuse your existing verifier via auth.rs
    if let Some(jwt) = get_cookie(&evt, "qs_admin_api") {
        tracing::info!("Found legacy admin cookie, verifying {}", &jwt);
        if let Some(sub) = verify_legacy_cookie_subject(&jwt).await {
            let mut ctx = HashMap::new();
            ctx.insert("sub".into(), sub);
            ctx.insert("source".into(), "legacy".into());
            ctx.insert("is_admin".into(), "true".into());
            return Ok(json!(SimpleAuthz {
                ok: true,
                context: Some(ctx)
            }));
        }
    }
    tracing::info!("No valid legacy admin cookie found");
    Ok(json!({"isAuthorized": false}))
}
