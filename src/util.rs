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
