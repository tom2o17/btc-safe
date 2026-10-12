//! TOTP (RFC 6238: HMAC-SHA1, 30-second steps, 6 digits) and one-time recovery codes.
//!
//! - A code is accepted for the current step or one step either side (clock skew), and only if
//!   that step is later than the last step accepted for the account (`users.totp_last_step`), so
//!   a code can't be replayed, not even concurrently (the step advance is one conditional UPDATE).
//! - Recovery codes: 10 per enrolment, 80 random bits each, shown once, stored as
//!   SHA-256(user id || code). Spending one is one conditional UPDATE, so each works once.
//! - The TOTP secret itself is stored as raw bytes: the server has to recompute codes, so it
//!   can't be hashed. A database leak exposes it (see docs/ARCHITECTURE.md §6.1).

use bitcoin::hashes::{hmac, sha1, sha256, Hash, HashEngine};
use uuid::Uuid;

pub const STEP_SECS: i64 = 30;
pub const SECRET_LEN: usize = 20;
pub const RECOVERY_CODES: usize = 10;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, no padding.
pub fn base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS randomness");
    b
}

/// The 6-digit code for `step`.
pub fn code_at(secret: &[u8], step: i64) -> String {
    let mut e = hmac::HmacEngine::<sha1::Hash>::new(secret);
    e.input(&step.to_be_bytes());
    let mac = hmac::Hmac::<sha1::Hash>::from_engine(e).to_byte_array();
    let off = (mac[19] & 0x0f) as usize;
    let bin = (u32::from(mac[off] & 0x7f) << 24) | (u32::from(mac[off + 1]) << 16) | (u32::from(mac[off + 2]) << 8) | u32::from(mac[off + 3]);
    format!("{:06}", bin % 1_000_000)
}

pub fn step_at(unix: i64) -> i64 {
    unix.div_euclid(STEP_SECS)
}

/// The step `code` is valid for (now ± 1 step), or None. Does not check replay; the caller must
/// then advance `totp_last_step` to the returned step and refuse if that fails.
pub fn verify(secret: &[u8], code: &str, unix_now: i64) -> Option<i64> {
    let code = code.trim().replace(' ', "");
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = step_at(unix_now);
    let mut hit = None;
    for s in [now - 1, now, now + 1] {
        if crate::auth::constant_time_eq(code_at(secret, s).as_bytes(), code.as_bytes()) {
            hit = Some(s);
        }
    }
    hit
}

pub fn otpauth_uri(secret: &[u8], email: &str) -> String {
    let enc = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
    format!("otpauth://totp/BTC%20Safe:{}?secret={}&issuer=BTC%20Safe&algorithm=SHA1&digits=6&period=30", enc(email), base32(secret))
}

/// A fresh recovery code, formatted `xxxx-xxxx-xxxx-xxxx` (16 base32 chars = 80 bits).
pub fn new_recovery_code() -> String {
    let s = base32(&random_bytes::<10>()).to_lowercase();
    format!("{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16])
}

/// Normalize user input (case, dashes, spaces). None if it can't be a recovery code.
pub fn normalize_recovery_code(input: &str) -> Option<String> {
    let s: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_uppercase();
    (s.len() == 16 && s.bytes().all(|b| B32.contains(&b))).then_some(s)
}

pub fn recovery_hash(user: Uuid, normalized: &str) -> Vec<u8> {
    let mut e = sha256::Hash::engine();
    e.input(user.as_bytes());
    e.input(normalized.as_bytes());
    sha256::Hash::from_engine(e).to_byte_array().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B (SHA-1 seed "12345678901234567890"), last 6 digits.
    #[test]
    fn rfc6238_vectors() {
        let k = b"12345678901234567890";
        for (t, want) in [(59i64, "287082"), (1111111109, "081804"), (1111111111, "050471"), (1234567890, "005924"), (2000000000, "279037"), (20000000000, "353130")] {
            assert_eq!(code_at(k, step_at(t)), want, "t={t}");
        }
    }

    #[test]
    fn window_and_format() {
        let k = b"12345678901234567890";
        let now = 1111111109;
        let s = step_at(now);
        assert_eq!(verify(k, &code_at(k, s), now), Some(s));
        assert_eq!(verify(k, &code_at(k, s - 1), now), Some(s - 1));
        assert_eq!(verify(k, &code_at(k, s + 1), now), Some(s + 1));
        assert_eq!(verify(k, &code_at(k, s - 2), now), None);
        assert_eq!(verify(k, &code_at(k, s + 2), now), None);
        assert_eq!(verify(k, "12345", now), None);
        assert_eq!(verify(k, "abcdef", now), None);
    }

    #[test]
    fn base32_rfc4648() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn recovery_codes_normalize() {
        let c = new_recovery_code();
        assert_eq!(c.len(), 19);
        let n = normalize_recovery_code(&c).unwrap();
        assert_eq!(normalize_recovery_code(&c.to_uppercase().replace('-', " ")), Some(n.clone()));
        assert_eq!(normalize_recovery_code("not-a-code"), None);
        let u = Uuid::new_v4();
        assert_ne!(recovery_hash(u, &n), recovery_hash(Uuid::new_v4(), &n), "hash is bound to the user");
    }
}
