//! Security headers on every API response (429s and errors included). The API only serves
//! JSON, so its CSP allows nothing at all; the web app sets its own page CSP (web/proxy.ts).

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::AppState;

pub const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
pub const PERMISSIONS: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), payment=(), usb=(), serial=(), bluetooth=()";
pub const HSTS: &str = "max-age=63072000; includeSubDomains";

pub async fn security_headers(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: &'static str, v: &'static str| {
        h.insert(header::HeaderName::from_static(k), HeaderValue::from_static(v));
    };
    set(h, "content-security-policy", API_CSP);
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "no-referrer");
    set(h, "permissions-policy", PERMISSIONS);
    set(h, "cross-origin-opener-policy", "same-origin");
    if !h.contains_key(header::CACHE_CONTROL) {
        set(h, "cache-control", "no-store");
    }
    if st.auth.cookie_secure {
        set(h, "strict-transport-security", HSTS);
    }
    res
}
