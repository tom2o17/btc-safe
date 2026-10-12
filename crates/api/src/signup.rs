//! Password rules (every place a password is set) and the signup proof-of-work.
//!
//! Proof-of-work is a bot speed bump that needs no third-party service: `GET /auth/signup` hands
//! out a challenge `"<expiry>.<random>.<mac>"` (HMAC-SHA256 under a server key, so it's stateless
//! until spent). The browser finds a decimal nonce with SHA-256(challenge ":" nonce) starting
//! with `bits` zero bits (~2^bits hashes; 20 bits is about a second). Each challenge is spent in
//! Postgres on use (`pow_spent`), so one solution buys one signup attempt.

use std::collections::HashSet;
use std::sync::OnceLock;

use bitcoin::hashes::{hmac, sha256, Hash, HashEngine};
use bitcoin::hex::DisplayHex;

use crate::auth::constant_time_eq;
use crate::{ApiError, ApiResult};

pub const MIN_PASSWORD: usize = 12;
pub const MAX_PASSWORD: usize = 1024;

static COMMON: &str = include_str!("../data/common-passwords.txt");

fn common() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| COMMON.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).collect())
}

fn weak(msg: impl Into<String>) -> ApiError {
    ApiError::new(axum::http::StatusCode::BAD_REQUEST, "weak_password", msg)
}

/// Length, the bundled common/breached list (~47k entries of 12+ chars), and a few
/// context checks (one repeated character, mostly the account's own email).
pub fn check_password(pw: &str, email: Option<&str>) -> ApiResult<()> {
    let n = pw.chars().count();
    if n < MIN_PASSWORD {
        return Err(weak(format!("password must be at least {MIN_PASSWORD} characters")));
    }
    if pw.len() > MAX_PASSWORD {
        return Err(weak("password too long"));
    }
    let lower = pw.to_lowercase();
    if common().contains(lower.as_str()) {
        return Err(weak("that password is on a list of common or breached passwords; pick another"));
    }
    let mut chars = lower.chars();
    let first = chars.next();
    if chars.all(|c| Some(c) == first) {
        return Err(weak("password is one repeated character"));
    }
    if let Some(email) = email {
        let email = email.to_lowercase();
        let local = email.split('@').next().unwrap_or("");
        let rest = if local.len() >= 3 { lower.replace(&email, "").replace(local, "") } else { lower.replace(&email, "") };
        if rest.chars().count() < 8 {
            return Err(weak("password is mostly your email address"));
        }
    }
    Ok(())
}

/// Seconds since the epoch.
pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn mac(key: &[u8; 32], msg: &str) -> String {
    let mut e = hmac::HmacEngine::<sha256::Hash>::new(key);
    e.input(msg.as_bytes());
    hmac::Hmac::<sha256::Hash>::from_engine(e).to_byte_array().to_lower_hex_string()
}

pub fn issue_challenge(key: &[u8; 32], ttl_secs: i64) -> String {
    let body = format!("{}.{}", now_unix() + ttl_secs, crate::mfa::random_bytes::<16>().to_lower_hex_string());
    let m = mac(key, &body);
    format!("{body}.{m}")
}

/// Leading zero bits of SHA-256(challenge ":" nonce).
pub fn work_bits(challenge: &str, nonce: &str) -> u32 {
    let h = sha256::Hash::hash(format!("{challenge}:{nonce}").as_bytes()).to_byte_array();
    let mut bits = 0;
    for b in h {
        if b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

/// Check a solved challenge (authentic, unexpired, enough work). Spending it is the caller's job
/// (`btc_safe_store::limits::spend_challenge` on [`challenge_id`]).
pub fn check_solution(key: &[u8; 32], bits: u32, challenge: &str, nonce: &str) -> ApiResult<()> {
    let bad = |m: &str| ApiError::new(axum::http::StatusCode::BAD_REQUEST, "bad_pow", m.to_string());
    let (body, m) = challenge.rsplit_once('.').ok_or_else(|| bad("malformed challenge"))?;
    if !constant_time_eq(mac(key, body).as_bytes(), m.as_bytes()) {
        return Err(bad("unknown challenge"));
    }
    let exp: i64 = body.split('.').next().and_then(|e| e.parse().ok()).ok_or_else(|| bad("malformed challenge"))?;
    if exp < now_unix() {
        return Err(bad("challenge expired; fetch a new one"));
    }
    if nonce.is_empty() || nonce.len() > 20 || !nonce.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("nonce must be a decimal number"));
    }
    if work_bits(challenge, nonce) < bits {
        return Err(bad("not enough work"));
    }
    Ok(())
}

pub fn challenge_id(challenge: &str) -> Vec<u8> {
    sha256::Hash::hash(challenge.as_bytes()).to_byte_array().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_rules() {
        assert!(check_password("short", None).is_err());
        assert!(check_password("password1234", None).is_err(), "common list");
        assert!(check_password("PASSWORD1234", None).is_err(), "case-insensitive");
        assert!(check_password("qwertyuiopasdfgh", None).is_err());
        assert!(check_password("aaaaaaaaaaaaaaaa", None).is_err());
        assert!(check_password("satoshi.nakamoto1", Some("satoshi.nakamoto@example.test")).is_err());
        assert!(check_password("satoshi.nakamoto plus horse battery", Some("satoshi.nakamoto@example.test")).is_ok());
        assert!(check_password("a long enough password", None).is_ok());
        assert!(common().len() > 40_000, "bundled list loaded");
    }

    #[test]
    fn pow_roundtrip() {
        let key = [7u8; 32];
        let c = issue_challenge(&key, 60);
        let nonce = (0u64..).find(|n| work_bits(&c, &n.to_string()) >= 8).unwrap().to_string();
        assert!(check_solution(&key, 8, &c, &nonce).is_ok());
        assert!(check_solution(&[8u8; 32], 8, &c, &nonce).is_err(), "other key");
        let tampered = c.replacen(&c[..2], "99", 1);
        assert!(check_solution(&key, 8, &tampered, &nonce).is_err(), "expiry is under the mac");
        let weak_nonce = (0u64..).find(|n| work_bits(&c, &n.to_string()) == 0).unwrap().to_string();
        assert!(check_solution(&key, 8, &c, &weak_nonce).is_err());
        let old = issue_challenge(&key, -1);
        let n2 = (0u64..).find(|n| work_bits(&old, &n.to_string()) >= 1).unwrap().to_string();
        assert!(check_solution(&key, 1, &old, &n2).is_err(), "expired");
    }
}
