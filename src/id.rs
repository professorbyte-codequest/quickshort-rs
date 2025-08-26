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
