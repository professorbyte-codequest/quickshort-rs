use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use lambda_http::{Body, Response};
use std::borrow::Cow;
use url::Url;

pub fn epoch_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64u_to_bytes(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

pub fn resp_json(status: u16, v: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::Text(v.to_string()))
        .unwrap()
}

pub fn validate_target_url(raw: &str) -> Result<String, &'static str> {
    let s = raw.trim();
    if s.len() < 8 || s.len() > 2048 {
        return Err("Enter a full http(s) URL");
    }
    let parsed = Url::parse(s).map_err(|_| "Invalid URL")?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("URL must start with http:// or https://"),
    }
    if parsed.host_str().is_none() {
        return Err("Missing host in URL");
    }
    // Optional hardening: disallow userinfo (user:pass@)
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("User info in URL is not allowed");
    }

    Ok(String::from(parsed))
}

pub fn json_ok_with_status(v: serde_json::Value, status: u16) -> Response<Body> {
    resp_json(status, v)
}

pub fn json_ok(v: serde_json::Value) -> Response<Body> {
    resp_json(200, v)
}

pub fn json_ok_no_content() -> Response<Body> {
    Response::builder()
        .status(204)
        .header("Content-Type", "application/json")
        .body(Body::Empty)
        .unwrap()
}

pub fn json_err(
    status: u16,
    code: &'static str,
    message: impl Into<Cow<'static, str>>,
) -> Response<Body> {
    let payload = serde_json::json!({
    "error": code,
    "message": message.into(),
    });
    resp_json(status, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_epoch_now_increases() {
        let t1 = epoch_now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = epoch_now();
        assert!(t2 >= t1);
    }

    #[test]
    fn test_b64u_and_b64u_to_bytes_roundtrip() {
        let data = b"hello world!";
        let encoded = b64u(data);
        let decoded = b64u_to_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_b64u_to_bytes_invalid_input() {
        // Not valid base64
        assert!(b64u_to_bytes("!@#$%^&*()").is_none());
        // Empty string is valid and decodes to empty vec
        assert_eq!(b64u_to_bytes("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_resp_json_sets_status_and_content_type() {
        let v = json!({"foo": "bar"});
        let resp = resp_json(201, v.clone());
        assert_eq!(resp.status(), 201);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        match resp.body() {
            Body::Text(s) => {
                let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
                assert_eq!(parsed, v);
            }
            _ => panic!("Expected Body::Text"),
        }
    }

    #[test]
    fn test_validate_target_url_happy_path() {
        let url = "https://example.com/path?query=1";
        let res = validate_target_url(url);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), url);
    }

    #[test]
    fn test_validate_target_url_http() {
        let url = "http://example.com";
        let clean_url = "http://example.com/";
        let res = validate_target_url(url);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), clean_url);
    }

    #[test]
    fn test_validate_target_url_too_short() {
        let url = "http:";
        let res = validate_target_url(url);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "Enter a full http(s) URL");
    }

    #[test]
    fn test_validate_target_url_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(2048));
        let res = validate_target_url(&long_url);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "Enter a full http(s) URL");
    }

    #[test]
    fn test_validate_target_url_invalid_scheme() {
        let url = "ftp://example.com";
        let res = validate_target_url(url);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "URL must start with http:// or https://");
    }

    #[test]
    fn test_validate_target_url_with_userinfo() {
        let url = "https://user:pass@example.com";
        let res = validate_target_url(url);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "User info in URL is not allowed");
    }

    #[test]
    fn test_validate_target_url_with_username_only() {
        let url = "https://user@example.com";
        let res = validate_target_url(url);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "User info in URL is not allowed");
    }

    #[test]
    fn test_validate_target_url_with_password_only() {
        let url = "https://:pass@example.com";
        let res = validate_target_url(url);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "User info in URL is not allowed");
    }

    #[test]
    fn test_json_ok_with_status() {
        let v = json!({"foo": "bar"});
        let resp = json_ok_with_status(v.clone(), 202);
        assert_eq!(resp.status(), 202);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        match resp.body() {
            Body::Text(s) => {
                let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
                assert_eq!(parsed, v);
            }
            _ => panic!("Expected Body::Text"),
        }
    }

    #[test]
    fn test_json_ok() {
        let v = json!({"hello": "world"});
        let resp = json_ok(v.clone());
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        match resp.body() {
            Body::Text(s) => {
                let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
                assert_eq!(parsed, v);
            }
            _ => panic!("Expected Body::Text"),
        }
    }

    #[test]
    fn test_json_ok_no_content() {
        let resp = json_ok_no_content();
        assert_eq!(resp.status(), 204);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        match resp.body() {
            Body::Empty => {}
            _ => panic!("Expected Body::Empty"),
        }
    }

    #[test]
    fn test_json_err() {
        let resp = json_err(403, "forbidden", "You shall not pass");
        assert_eq!(resp.status(), 403);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        match resp.body() {
            Body::Text(s) => {
                let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
                assert_eq!(parsed["error"], "forbidden");
                assert_eq!(parsed["message"], "You shall not pass");
            }
            _ => panic!("Expected Body::Text"),
        }
    }
}
