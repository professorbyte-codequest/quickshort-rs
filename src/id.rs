use blake3::Hasher;
use rand::{rngs::StdRng, RngCore, SeedableRng};

const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub fn base62(bytes: &[u8], len: usize) -> String {
    // Convert hash bytes to base62 by repeated division; for small len, take modulus stream
    let mut out = String::with_capacity(len);
    let mut acc: u128 = 0;
    for (i, b) in bytes.iter().enumerate() {
        acc ^= (*b as u128) << ((i % 16) * 8);
    }
    for _ in 0..len {
        let idx = (acc % 62) as usize;
        out.push(ALPHABET[idx] as char);
        acc /= 62;
        if acc == 0 {
            acc = 0x9E3779B97F4A7C15;
        }
    }
    out
}

pub fn new_slug(url: &str, created_at: u64, attempt: u32) -> String {
    let mut hasher = Hasher::new();
    hasher.update(url.as_bytes());
    hasher.update(&created_at.to_be_bytes());
    hasher.update(&attempt.to_be_bytes());
    let mut rng = StdRng::seed_from_u64((created_at as u64) ^ (attempt as u64) ^ 0xA5A5);
    let mut salt = [0u8; 8];
    rng.fill_bytes(&mut salt);
    hasher.update(&salt);
    let digest = hasher.finalize();
    base62(digest.as_bytes(), 6)
}

#[cfg(test)]
mod tests {
    use super::new_slug;

    #[test]
    fn slug_is_stable_for_same_inputs() {
        let a = new_slug("https://example.com/x", 1_700_000_000, 1);
        let b = new_slug("https://example.com/x", 1_700_000_000, 1);
        assert_eq!(a, b);
    }

    #[test]
    fn slug_changes_when_attempt_changes() {
        let a = new_slug("https://example.com/x", 1_700_000_000, 1);
        let b = new_slug("https://example.com/x", 1_700_000_000, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn slug_has_reasonable_length() {
        let s = new_slug(
            "https://example.com/very/long/path?and=params",
            1_700_000_000,
            3,
        );
        assert!(s.len() >= 5 && s.len() <= 16, "slug len={}", s.len());
    }
}
