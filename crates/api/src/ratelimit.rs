//! Token-bucket rate limits stored in Postgres (`rate_limits`), so every API process shares
//! them: per client IP on every route, per user on logged-in routes, a much stricter bucket for
//! login/setup/2FA (keyed by IP and by email), and per-IP and global buckets for signup. Over the
//! limit → 429 with `Retry-After`. A refused request spends nothing. If the database can't be
//! reached the request fails (closed), it is not waved through.
//!
//! IPv6 clients are keyed by their /64, since one host usually controls a whole /64.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use btc_safe_store::sqlx::PgPool;
use serde_json::json;

use crate::auth::AuthConfig;
use crate::{ApiError, AppState};

#[derive(Debug, Clone)]
pub struct Limiter {
    /// Tokens added per second.
    per_sec: f64,
    /// Bucket size.
    burst: f64,
    /// Key prefix: namespace + bucket name.
    prefix: String,
}

impl Limiter {
    fn new(ns: &str, name: &str, per_sec: f64, burst: u32) -> Self {
        Limiter { per_sec, burst: f64::from(burst.max(1)), prefix: format!("{ns}:{name}:") }
    }

    fn unlimited() -> Self {
        Limiter { per_sec: f64::INFINITY, burst: f64::INFINITY, prefix: String::new() }
    }

    pub fn is_unlimited(&self) -> bool {
        self.burst.is_infinite()
    }

    /// Take one token for `key`, or return the 429 response to send.
    #[allow(clippy::result_large_err)]
    pub async fn check(&self, pool: &PgPool, key: &str) -> Result<(), Response> {
        if self.is_unlimited() {
            return Ok(());
        }
        let k = format!("{}{key}", self.prefix);
        let res = match pool.acquire().await {
            Ok(mut c) => btc_safe_store::limits::take(&mut c, &k, self.per_sec, self.burst).await.map_err(ApiError::from),
            Err(e) => Err(ApiError::from(e)),
        };
        match res {
            Ok(None) => Ok(()),
            Ok(Some(wait)) => Err(too_many(wait.ceil().max(1.0) as u64, "too many requests")),
            Err(e) => Err(e.into_response()),
        }
    }
}

pub fn too_many(retry_after: u64, message: &str) -> Response {
    let mut r = (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "rate_limited", "message": message, "retry_after_secs": retry_after })))
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
        r.headers_mut().insert(header::RETRY_AFTER, v);
    }
    r
}

#[derive(Debug, Clone)]
pub struct RateLimits {
    pub ip: Limiter,
    pub user: Limiter,
    pub login: Limiter,
    /// Signups per client IP.
    pub signup: Limiter,
    /// Signups from everyone together.
    pub signup_global: Limiter,
}

fn per_min(x: (u32, u32)) -> (f64, u32) {
    (f64::from(x.0) / 60.0, x.1)
}

impl RateLimits {
    /// Production limits with a fixed key namespace, so every process shares the buckets.
    /// `ip`, `user`, `login` are (per minute, burst); `signup`, `signup_global` are (per hour, burst).
    pub fn shared(ip: (u32, u32), user: (u32, u32), login: (u32, u32), signup: (u32, u32), signup_global: (u32, u32)) -> Self {
        Self::build("rl", ip, user, login, Some((signup, signup_global)))
    }

    /// Production defaults: 300/min per IP (burst 120), 600/min per user (burst 200), 10/min for
    /// login/setup/2FA per IP and per email (burst 5), 5/hour signups per IP (burst 3), 60/hour
    /// signups overall (burst 20).
    pub fn standard() -> Self {
        Self::shared((300, 120), (600, 200), (10, 5), (5, 3), (60, 20))
    }

    /// Test helper: these limits in a fresh random namespace (so runs against a shared database
    /// don't see each other's buckets), signup unlimited.
    pub fn custom(ip: (u32, u32), user: (u32, u32), login: (u32, u32)) -> Self {
        Self::build(&crate::auth::random_token()[..16], ip, user, login, None)
    }

    /// Test helper: set the signup limits (per hour, burst).
    pub fn with_signup(mut self, per_ip: (u32, u32), global: (u32, u32)) -> Self {
        let ns = self.ns();
        self.signup = Limiter::new(&ns, "signup", f64::from(per_ip.0) / 3600.0, per_ip.1);
        self.signup_global = Limiter::new(&ns, "signup_all", f64::from(global.0) / 3600.0, global.1);
        self
    }

    fn ns(&self) -> String {
        self.ip.prefix.split(':').next().filter(|s| !s.is_empty()).map(str::to_string).unwrap_or_else(|| crate::auth::random_token()[..16].to_string())
    }

    fn build(ns: &str, ip: (u32, u32), user: (u32, u32), login: (u32, u32), signup: Option<((u32, u32), (u32, u32))>) -> Self {
        let l = |name: &str, x: (u32, u32)| {
            let (r, b) = per_min(x);
            Limiter::new(ns, name, r, b)
        };
        let (signup, signup_global) = match signup {
            Some((s, g)) => (Limiter::new(ns, "signup", f64::from(s.0) / 3600.0, s.1), Limiter::new(ns, "signup_all", f64::from(g.0) / 3600.0, g.1)),
            None => (Limiter::unlimited(), Limiter::unlimited()),
        };
        RateLimits { ip: l("ip", ip), user: l("user", user), login: l("login", login), signup, signup_global }
    }

    pub fn unlimited() -> Self {
        RateLimits {
            ip: Limiter::unlimited(),
            user: Limiter::unlimited(),
            login: Limiter::unlimited(),
            signup: Limiter::unlimited(),
            signup_global: Limiter::unlimited(),
        }
    }
}

/// The client IP: the configured proxy header (its last comma-separated entry, which is the one
/// the trusted proxy wrote), else the TCP peer, else "unknown".
pub fn client_ip(cfg: &AuthConfig, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if let Some(h) = &cfg.client_ip_header {
        if let Some(v) = headers.get(h).and_then(|v| v.to_str().ok()) {
            if let Some(last) = v.rsplit(',').next().map(str::trim).filter(|s| !s.is_empty()) {
                return last.to_string();
            }
        }
    }
    peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unknown".into())
}

/// Rate-limit key for an IP: IPv4 as is, IPv6 by its /64.
pub fn ip_key(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Err(_) => ip.chars().take(64).collect(),
    }
}

/// The resolved client IP, put in request extensions by [`per_ip`].
#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

/// Middleware: per-IP limit on every request; records [`ClientIp`] for handlers.
pub async fn per_ip(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    let ip = client_ip(&st.auth, req.headers(), peer);
    if let Err(r) = st.limits.ip.check(&st.pool, &ip_key(&ip)).await {
        return r;
    }
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v6_keyed_by_64() {
        assert_eq!(ip_key("2001:db8:1:2:aaaa::1"), ip_key("2001:db8:1:2:ffff::9"));
        assert_ne!(ip_key("2001:db8:1:2::1"), ip_key("2001:db8:1:3::1"));
        assert_eq!(ip_key("::ffff:192.0.2.1"), "192.0.2.1");
        assert_eq!(ip_key("192.0.2.1"), "192.0.2.1");
    }
}
