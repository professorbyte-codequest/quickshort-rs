use aws_sdk_kms as kms;
use aws_sdk_kms::types::SigningAlgorithmSpec;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use lambda_http::request::RequestContext;
use lambda_http::Error;
use lambda_http::Request;
use lambda_http::RequestExt;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::io::{Error as IoError, ErrorKind};

use crate::util::b64u_to_bytes;

#[derive(Debug, Deserialize)]
pub struct CognitoIdClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<JsonValue>,
    #[serde(default)]
    pub token_use: Option<String>,
    #[serde(default, rename = "custom:role")]
    pub custom_role: Option<String>,
    #[serde(default)]
    pub groups: Option<JsonValue>,
    #[serde(default, rename = "cognito:groups")]
    pub cognito_groups: Option<JsonValue>,
}

/// Where the caller identity came from.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum CallerSource {
    Cognito,
    AdminCookie,
}

/// Normalized caller identity returned by `caller_id()`.
#[derive(Debug, Clone, Serialize)]
pub struct Caller {
    pub user_id: String,
    pub source: CallerSource,
    /// Optional email if the provider supplies it (Cognito often does)
    pub email: Option<String>,
    pub is_admin: bool,
}

fn caller_from_apigw(req: &Request) -> Option<Caller> {
    let ctx = match req.request_context_ref()? {
        RequestContext::ApiGatewayV2(c) => c,
        _ => return None,
    };

    let authz = ctx.authorizer.as_ref()?;

    // 1) Custom Lambda authorizer (simple responses): values come as strings in `fields`
    if !authz.fields.is_empty() {
        let fields = &authz.fields; // HashMap<String, String>
        let sub = fields.get("sub")?.to_string();
        let email = fields.get("email").map(|v| v.to_string());
        let source = match fields.get("source").map(|s| s.as_str()).unwrap_or_default() {
            Some("legacy") => CallerSource::AdminCookie,
            _ => CallerSource::Cognito,
        };
        let is_admin = fields
            .get("is_admin")
            .map(|s| s.as_str().unwrap_or_default().eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        return Some(Caller {
            user_id: sub,
            email,
            source,
            is_admin,
        });
    }
    None
}

/// Central entry point: get the caller identity (if any) from the request.
/// Preference order: Cognito JWT authorizer -> legacy cookie
pub async fn caller_id(req: &Request) -> Option<Caller> {
    if let Some(c) = caller_from_apigw(req) {
        return Some(c);
    }

    // 1) Cognito JWT authorizer (HTTP API v2)
    if let Some(c) = cognito_caller(req) {
        return Some(c);
    }
    // 2) Legacy KMS-signed cookie (qs_admin_api)
    if let Some(c) = legacy_cookie_caller(req).await {
        return Some(c);
    }
    None
}

pub fn err_unauthorized(msg: &str) -> Error {
    // Produce a concrete error type; lambda_http::Error can wrap std::io::Error.
    IoError::new(ErrorKind::PermissionDenied, msg.to_owned()).into()
}

#[macro_export]
macro_rules! require_auth_or_return {
    ($req:expr, $status:expr, $err:expr, $msg:expr) => {
        match require_auth(&$req).await {
            Ok(c) => c,
            Err(_) => {
                return json_err($status, $err, $msg);
            }
        }
    };
}

/// Convenience: require auth and return a unified Caller (use in write/admin paths).
pub async fn require_auth(req: &Request) -> Result<Caller, lambda_http::Error> {
    caller_id(req)
        .await
        .ok_or_else(|| err_unauthorized("Unauthorized"))
}

fn cognito_caller(req: &Request) -> Option<Caller> {
    let ctx_v2 = match req.request_context_ref()? {
        RequestContext::ApiGatewayV2(ctx) => ctx,
        _ => {
            tracing::debug!("Not an APIGWv2 request");
            return None;
        }
    };
    let authz = ctx_v2.authorizer.as_ref()?;
    let jwt = authz.jwt.as_ref()?;
    let claims = &jwt.claims;

    let sub = claims.get("sub").map(|v| v.as_str())?;
    let email = claims.get("email").map(|v| v.to_owned());

    // Optional hardening: verify issuer if you set COGNITO_ISS
    if let Ok(expected) = std::env::var("COGNITO_ISS") {
        if !expected.is_empty() {
            let iss = claims.get("iss").map(|v| v.as_str());
            if iss != Some(expected.as_str()) {
                tracing::error!(
                    "Cognito Issuer mismatch: expected {}, got {:?}",
                    expected,
                    iss
                );
                return None;
            }
        }
    }

    Some(Caller {
        user_id: sub.to_string(),
        source: CallerSource::Cognito,
        email,
        is_admin: false,
    })
}

pub async fn verify_cognito_id_token(token: &str) -> Result<CognitoIdClaims, String> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
    use once_cell::sync::OnceCell;
    use reqwest::Client;
    use std::time::{Duration, Instant};

    static JWKS: OnceCell<(Vec<(String, String, String)>, Instant, String)> = OnceCell::new();
    const JWKS_TTL: Duration = Duration::from_secs(3600);

    let iss = std::env::var("COGNITO_ISS").map_err(|_| "COGNITO_ISS not set")?;
    let client_id = std::env::var("COGNITO_CLIENT_ID").map_err(|_| "COGNITO_CLIENT_ID not set")?;

    let header = decode_header(token).map_err(|e| format!("jwt header: {e}"))?;
    let kid = header.kid.ok_or_else(|| "jwt missing kid".to_string())?;

    // load/cached jwks by issuer
    let (keys, fetched_at, cached_iss) =
        JWKS.get_or_init(|| (Vec::new(), Instant::now() - JWKS_TTL * 2, String::new()));
    let keys_current = if *cached_iss == iss && fetched_at.elapsed() < JWKS_TTL {
        Some(keys.clone())
    } else {
        None
    };

    let keys = if let Some(k) = keys_current {
        k
    } else {
        let url = format!("{}/.well-known/jwks.json", iss);
        let v: JsonValue = Client::new()
            .get(url)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        if let Some(arr) = v.get("keys").and_then(|k| k.as_array()) {
            for k in arr {
                if k.get("kty").and_then(|x| x.as_str()) == Some("RSA") {
                    if let (Some(kid), Some(n), Some(e)) = (
                        k.get("kid").and_then(|x| x.as_str()),
                        k.get("n").and_then(|x| x.as_str()),
                        k.get("e").and_then(|x| x.as_str()),
                    ) {
                        out.push((kid.to_string(), n.to_string(), e.to_string()));
                    }
                }
            }
        }
        let _ = JWKS.set((out.clone(), Instant::now(), iss.clone()));
        out
    };

    let (n, e) = keys
        .iter()
        .find_map(|(k, n, e)| if k == &kid { Some((n, e)) } else { None })
        .ok_or_else(|| "kid not found".to_string())?;
    let dk = DecodingKey::from_rsa_components(n, e).map_err(|e| format!("dec key: {e}"))?;

    let mut val = Validation::new(Algorithm::RS256);
    val.set_issuer(&[iss.as_str()]);
    val.set_audience(&[client_id.clone()]);

    let data =
        decode::<CognitoIdClaims>(token, &dk, &val).map_err(|e| format!("jwt verify: {e}"))?;
    let claims = data.claims;
    if claims.token_use.as_deref() != Some("id") {
        return Err("token_use != id".into());
    }
    Ok(claims)
}

#[cfg(test)]
fn parse_jwt_sub_unsafe(jwt: &str) -> Option<(String, Option<String>)> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
    use serde_json::Value as JsonValue;

    let mut parts = jwt.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    // ignore signature part
    let payload_bytes = B64.decode(payload).ok()?;
    let v: JsonValue = serde_json::from_slice(&payload_bytes).ok()?;
    let sub = v.get("sub")?.as_str()?.to_owned();
    let email = v
        .get("email")
        .and_then(|x| x.as_str())
        .map(|s| s.to_owned());
    Some((sub, email))
}

#[cfg(test)]
pub async fn verify_legacy_cookie_subject(jwt: &str) -> Option<String> {
    parse_jwt_sub_unsafe(jwt).map(|(sub, _)| sub)
}

// ------------------------
// Legacy cookie helpers
// ------------------------
async fn legacy_cookie_caller(req: &Request) -> Option<Caller> {
    // Reuse your existing cookie verification (KMS/HMAC) if present.
    // We only need the subject string here; adapt the function name below to yours.
    let cookie_val = cookie(req, "qs_admin_api");

    match cookie_val {
        Some(jwt) => {
            tracing::info!("Found legacy cookie {jwt}, verifying");
            if let Some(sub) = verify_legacy_cookie_subject(&jwt).await {
                return Some(Caller {
                    user_id: sub,
                    source: CallerSource::AdminCookie,
                    email: None,
                    is_admin: true,
                });
            }
        }
        None => tracing::info!("No legacy cookie found"),
    }

    None
}

#[cfg(not(test))]
pub async fn verify_legacy_cookie_subject(jwt: &str) -> Option<String> {
    let mut parts = jwt.split('.');
    let h_b64 = parts.next().unwrap_or("");
    let p_b64 = parts.next().unwrap_or("");
    let s_b64 = parts.next().unwrap_or("");
    if h_b64.is_empty() || p_b64.is_empty() || s_b64.is_empty() {
        tracing::info!("JWT parts missing");
        return None;
    }
    let signing_input = format!("{}.{}", h_b64, p_b64);
    let sig = match URL_SAFE_NO_PAD.decode(s_b64) {
        Ok(v) => v,
        Err(_) => {
            tracing::info!("JWT signature base64 decode failed");
            return None;
        }
    };
    let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kmsc = kms::Client::new(&cfg);
    let key_id = std::env::var("JWT_KMS_KEY_ID").unwrap_or_default();
    let verify_resp = kmsc
        .verify()
        .key_id(key_id)
        .message(signing_input.as_bytes().to_vec().into())
        .signature(sig.into())
        .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
        .send()
        .await;

    // If verification failed, return None
    if verify_resp.is_err() {
        tracing::error!("KMS verify failed: {:?}", verify_resp.err());
        return None;
    }

    // Decode payload and read `sub`
    let payload_json = match b64u_to_bytes(p_b64).and_then(|b| String::from_utf8(b).ok()) {
        Some(s) => s,
        None => {
            tracing::info!("JWT payload base64 decode failed");
            return None;
        }
    };
    let v: serde_json::Value = serde_json::from_str(&payload_json).unwrap_or(json!({}));
    let login = v.get("sub").and_then(|x| x.as_str()).unwrap_or("");

    if login.is_empty() {
        tracing::info!("JWT sub claim missing");
        return None;
    }
    Some(login.to_string())
}

/// Scan all Cookie headers (there can be multiple) and parse a single cookie by name.
fn cookie(req: &Request, name: &str) -> Option<String> {
    let mut out: Option<String> = None;
    for val in req.headers().get_all("Cookie").iter() {
        if let Ok(s) = val.to_str() {
            for part in s.split(';') {
                let kv = part.trim();
                if let Some((k, v)) = kv.split_once('=') {
                    if k == name {
                        out = Some(v.to_string());
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};

    use aws_lambda_events::event::apigw::{
        ApiGatewayRequestAuthorizer, ApiGatewayRequestAuthorizerJwtDescription,
        ApiGatewayV2httpRequestContext,
    };
    use lambda_http::Body;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::env;

    // tiny RAII guard to restore env at the end of each test
    struct EnvGuard {
        k: String,
        v: Option<String>,
    }
    impl EnvGuard {
        fn set(k: &str, v: &str) -> Self {
            let old = std::env::var(k).ok();
            env::set_var(k, v);
            Self {
                k: k.to_string(),
                v: old,
            }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.v {
                Some(val) => env::set_var(&self.k, val),
                None => env::remove_var(&self.k),
            }
        }
    }

    fn build_cognito_request(sub: &str, email: Option<&str>, iss: Option<&str>) -> Request {
        let mut claims: HashMap<String, String> = HashMap::new();
        claims.insert("sub".to_string(), sub.to_string());
        if let Some(email) = email {
            claims.insert("email".to_string(), email.to_string());
        }
        if let Some(iss) = iss {
            claims.insert("iss".to_string(), iss.to_string());
        }

        let jwt = ApiGatewayRequestAuthorizerJwtDescription {
            claims,
            scopes: None,
        };
        let authorizer = ApiGatewayRequestAuthorizer {
            jwt: Some(jwt),
            ..Default::default()
        };

        let ctx = ApiGatewayV2httpRequestContext {
            authorizer: Some(authorizer),
            ..Default::default()
        };

        // Build a request and attach the APIGWv2 request context
        Request::new(Body::Empty).with_request_context(RequestContext::ApiGatewayV2(ctx))
    }

    fn make_test_jwt(sub: &str, email: Option<&str>) -> String {
        let header = r#"{"alg":"none","typ":"JWT"}"#;
        let payload = match email {
            Some(e) => format!(r#"{{"sub":"{}","email":"{}"}}"#, sub, e),
            None => format!(r#"{{"sub":"{}"}}"#, sub),
        };
        let h = B64.encode(header);
        let p = B64.encode(payload);
        format!("{}.{}.", h, p) // empty signature
    }

    fn build_cookie_request(cookie_val: &str) -> Request {
        let mut req = Request::default();
        let jwt = make_test_jwt(cookie_val, None);
        req.headers_mut().insert(
            "Cookie",
            format!("qs_admin_api={jwt}; Path=/; HttpOnly")
                .parse()
                .unwrap(),
        );
        req
    }

    fn build_bearer_request(token: &str) -> Request {
        let mut req = Request::default();
        req.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", token).parse().unwrap(),
        );
        req
    }

    #[test]
    #[serial(env)]
    fn test_cognito_caller_success() {
        let req = build_cognito_request("user123", Some("user@example.com"), None);
        let caller = cognito_caller(&req).unwrap();
        assert_eq!(caller.user_id, "user123");
        assert_eq!(caller.source, CallerSource::Cognito);
        assert_eq!(caller.email.as_deref(), Some("user@example.com"));
    }

    #[test]
    #[serial(env)]
    fn test_cognito_caller_with_issuer() {
        let _g = EnvGuard::set("COGNITO_ISS", "expected_issuer");
        let req = build_cognito_request("user456", Some("foo@bar.com"), Some("expected_issuer"));
        let caller = cognito_caller(&req).unwrap();
        assert_eq!(caller.user_id, "user456");
        assert_eq!(caller.email.as_deref(), Some("foo@bar.com"));
    }

    #[test]
    #[serial(env)]
    fn test_cognito_caller_wrong_issuer() {
        let _g = EnvGuard::set("COGNITO_ISS", "expected_issuer");
        let req = build_cognito_request("user789", Some("baz@qux.com"), Some("wrong_issuer"));
        assert!(cognito_caller(&req).is_none());
    }

    #[tokio::test]
    async fn test_legacy_cookie_caller_success() {
        let req = build_cookie_request("dummyjwt");
        let caller = legacy_cookie_caller(&req).await.unwrap();
        assert_eq!(caller.user_id, "dummyjwt");
        assert_eq!(caller.source, CallerSource::AdminCookie);
        assert!(caller.email.is_none());
    }

    #[tokio::test]
    async fn test_legacy_cookie_caller_missing_cookie() {
        let req = Request::default();
        assert!(legacy_cookie_caller(&req).await.is_none());
    }

    #[tokio::test]
    #[serial(env)]
    async fn test_caller_id_priority_cognito() {
        let req = build_cognito_request("user999", Some("a@b.com"), None);
        let caller = caller_id(&req).await.unwrap();
        assert_eq!(caller.source, CallerSource::Cognito);
    }

    #[tokio::test]
    async fn test_caller_id_priority_legacy_cookie() {
        let req = build_cookie_request("dummyjwt");
        let caller = caller_id(&req).await.unwrap();
        assert_eq!(caller.source, CallerSource::AdminCookie);
        assert_eq!(caller.user_id, "dummyjwt");
    }

    #[tokio::test]
    async fn test_caller_id_none() {
        let req = Request::default();
        assert!(caller_id(&req).await.is_none());
    }

    #[tokio::test]
    async fn test_require_auth_failure() {
        let req = Request::default();
        let err = require_auth(&req).await.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Unauthorized"));
    }

    #[test]
    fn test_cookie_parsing_single() {
        let mut req = Request::default();
        req.headers_mut()
            .insert("Cookie", "foo=bar; qs_admin_api=tokenval".parse().unwrap());
        assert_eq!(cookie(&req, "qs_admin_api").unwrap(), "tokenval");
    }

    #[test]
    fn test_cookie_parsing_multiple_headers() {
        let mut req = Request::default();
        req.headers_mut()
            .append("Cookie", "foo=bar".parse().unwrap());
        req.headers_mut()
            .append("Cookie", "qs_admin_api=tokenval".parse().unwrap());
        assert_eq!(cookie(&req, "qs_admin_api").unwrap(), "tokenval");
    }

    #[test]
    fn test_cookie_not_found() {
        let mut req = Request::default();
        req.headers_mut()
            .insert("Cookie", "foo=bar".parse().unwrap());
        assert!(cookie(&req, "qs_admin_api").is_none());
    }
}
