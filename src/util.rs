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
