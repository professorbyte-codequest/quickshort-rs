use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use lambda_http::{Body, Response};
use url::Url;

pub fn valid_target(u: &str) -> bool {
    if let Ok(parsed) = Url::parse(u) {
        match parsed.scheme() {
            "http" | "https" => {}
            _ => return false,
        }
        return parsed.host().is_some();
    }
    false
}

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

#[cfg(test)]
mod tests {
    use super::valid_target;

    #[test]
    fn accepts_https() {
        assert!(valid_target("https://example.com"));
    }

    #[test]
    fn rejects_javascript_urls() {
        assert!(!valid_target("javascript:alert(1)"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!valid_target(""));
    }
}
