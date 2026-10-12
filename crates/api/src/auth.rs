//! Accounts, sessions, CSRF, second factor and wallet roles.
//!
//! - Accounts: an admin invite (`POST /auth/invites`, the `invite` CLI, or the `ADMIN_EMAIL`
//!   bootstrap) creates a user with a one-time setup token. With `OPEN_SIGNUP` on, anyone can
//!   also sign up (`signup.rs`: password rules, proof-of-work, honeypot, per-IP/global limits,
//!   a user cap). There is no email delivery: the email is a username, never verified.
//! - Passwords: argon2id (RustCrypto defaults, m=19 MiB, t=2, p=1), hashed off the async runtime,
//!   checked against a bundled common/breached list.
//! - Failed logins are audit-logged (`login_failed`). Each account backs off exponentially after
//!   a few failures, but a browser that has logged in to that account before (device cookie)
//!   isn't held back, so an attacker can't lock the owner out.
//! - Sessions: 32 random bytes in an HttpOnly, SameSite=Strict cookie (`__Host-bsid`, Secure,
//!   when `cookie_secure`), stored server-side as SHA-256. Absolute lifetime and idle timeout.
//!   A new session id on every login, password change, 2FA change and setup; the old one dies.
//! - CSRF: every state-changing request (not GET/HEAD/OPTIONS) must carry `X-CSRF-Token` equal to
//!   the session's token, which the client reads from `GET /auth/me` or the login response.
//! - Second factor: optional TOTP plus one-time recovery codes (`mfa.rs`).
//! - Wallet scope: `/wallets/{id}/…` and `/proposals/{id}/…` need membership of that wallet;
//!   non-members get 404 so wallet ids can't be probed. The member's role must reach the route's
//!   minimum (`roles.rs`), else 403. Unknown paths are denied by default.

use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use btc_safe_store::sqlx::PgConnection;
use btc_safe_store::users as db;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::mfa;
use crate::ratelimit::{ip_key, too_many, ClientIp};
use crate::roles::{self, Role, WalletAccess};
use crate::signup;
use crate::{ApiError, ApiResult, AppState};

pub use crate::signup::{MAX_PASSWORD, MIN_PASSWORD};

#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Set the Secure flag (and the `__Host-` prefix) on the session cookie, and send HSTS. Off
    /// only for local http development.
    pub cookie_secure: bool,
    /// Absolute session lifetime.
    pub session_ttl: Duration,
    /// A session unused for this long ends.
    pub session_idle: Duration,
    pub invite_ttl: Duration,
    /// Header carrying the real client IP when behind a proxy that overwrites it (e.g.
    /// `x-real-ip`). None: use the TCP peer address.
    pub client_ip_header: Option<HeaderName>,
    /// Public web origin, used to print setup links.
    pub web_origin: Option<String>,
    /// Self-service signup (`OPEN_SIGNUP`).
    pub open_signup: bool,
    /// Signup refuses once this many accounts exist (all accounts, invited ones included).
    pub max_users: i64,
    /// Wallets a non-admin user may create or import. 0 = no limit.
    pub max_wallets_per_user: i64,
    /// Signup proof-of-work difficulty in leading zero bits.
    pub pow_bits: u32,
    /// HMAC key for signup challenges.
    pub pow_key: [u8; 32],
    /// Failures allowed before an account backs off, and the longest backoff.
    pub backoff_free: i32,
    pub backoff_max: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            cookie_secure: true,
            session_ttl: Duration::from_secs(12 * 3600),
            session_idle: Duration::from_secs(30 * 60),
            invite_ttl: Duration::from_secs(72 * 3600),
            client_ip_header: None,
            web_origin: None,
            open_signup: false,
            max_users: 1000,
            max_wallets_per_user: 20,
            pow_bits: 20,
            pow_key: mfa::random_bytes::<32>(),
            backoff_free: 5,
            backoff_max: Duration::from_secs(15 * 60),
        }
    }
}

const POW_TTL_SECS: i64 = 600;
const MFA_TTL_SECS: i64 = 300;
const MFA_ATTEMPTS: i32 = 5;
const TOTP_PENDING_SECS: i64 = 600;
const DEVICE_DAYS: i32 = 180;

impl AuthConfig {
    pub fn cookie_name(&self) -> &'static str {
        if self.cookie_secure {
            "__Host-bsid"
        } else {
            "bsid"
        }
    }

    pub fn device_cookie_name(&self) -> &'static str {
        if self.cookie_secure {
            "__Host-bsdev"
        } else {
            "bsdev"
        }
    }

    fn cookie(&self, name: &str, token: &str, max_age: u64) -> HeaderValue {
        let secure = if self.cookie_secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!("{name}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}")).expect("cookie is ascii")
    }

    fn session_cookie(&self, token: &str, max_age: u64) -> HeaderValue {
        self.cookie(self.cookie_name(), token, max_age)
    }

    fn idle_secs(&self) -> i64 {
        self.session_idle.as_secs() as i64
    }
}

/// The logged-in user, inserted into request extensions by [`require_user`].
#[derive(Clone, Debug)]
pub struct CurrentUser {
    pub id: Uuid,
    pub email: String,
    pub is_admin: bool,
    /// SHA-256 of this request's session token.
    pub session: Vec<u8>,
}

pub fn random_token() -> String {
    mfa::random_bytes::<32>().to_lower_hex_string()
}

pub fn token_hash(token: &str) -> Vec<u8> {
    sha256::Hash::hash(token.as_bytes()).to_byte_array().to_vec()
}

pub fn normalize_email(e: &str) -> ApiResult<String> {
    let e = e.trim().to_lowercase();
    let ok = e.len() <= 254
        && e.split_once('@').is_some_and(|(l, d)| !l.is_empty() && !d.contains('@') && d.contains('.') && !d.starts_with('.') && !d.ends_with('.'))
        && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(e)
    } else {
        Err(ApiError::bad_request("invalid email"))
    }
}

pub async fn hash_password(pw: String) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default().hash_password(pw.as_bytes(), &salt).map(|h| h.to_string())
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::internal(e.to_string()))
}

/// Verify off the runtime. With no stored hash we still run argon2 on a fixed dummy hash, so
/// unknown and password-less accounts take as long as wrong passwords.
pub async fn verify_password(pw: String, stored: Option<String>) -> bool {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let real = stored.is_some();
    let ok = tokio::task::spawn_blocking(move || {
        let h = stored.unwrap_or_else(|| {
            DUMMY
                .get_or_init(|| {
                    let salt = SaltString::generate(&mut OsRng);
                    Argon2::default().hash_password(random_token().as_bytes(), &salt).map(|h| h.to_string()).unwrap_or_default()
                })
                .clone()
        });
        match PasswordHash::new(&h) {
            Ok(parsed) => Argon2::default().verify_password(pw.as_bytes(), &parsed).is_ok(),
            Err(_) => false,
        }
    })
    .await
    .unwrap_or(false);
    ok && real
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

pub fn unauthorized(msg: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized", "message": msg }))).into_response()
}

fn forbidden(code: &'static str, msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, code, msg)
}

/// Create a session for `user_id`. Returns (raw token for the cookie, csrf token).
pub async fn create_session(conn: &mut PgConnection, cfg: &AuthConfig, user_id: Uuid) -> ApiResult<(String, String)> {
    let token = random_token();
    let csrf = random_token();
    let exp = Utc::now() + chrono::Duration::from_std(cfg.session_ttl).map_err(|e| ApiError::internal(e.to_string()))?;
    db::insert_session(conn, &token_hash(&token), user_id, &csrf, exp).await?;
    Ok((token, csrf))
}

/// Create (or find) a user and issue a one-time setup token. Returns the raw token. Used by the
/// admin invite route, the `invite` CLI and tests.
pub async fn issue_setup_token(conn: &mut PgConnection, email: &str, is_admin: bool, ttl: Duration) -> ApiResult<(db::UserRow, String)> {
    let email = normalize_email(email)?;
    if is_admin {
        refuse_implicit_promotion(conn, &email).await?;
    }
    let user = db::ensure_user(conn, &email, is_admin).await?;
    let token = random_token();
    let exp = Utc::now() + chrono::Duration::from_std(ttl).map_err(|e| ApiError::internal(e.to_string()))?;
    db::insert_setup_token(conn, &token_hash(&token), user.id, exp).await?;
    Ok((user, token))
}

/// Startup bootstrap: make sure `email` exists as an admin and, while it has no password, that
/// `token` is a valid setup token for it. Idempotent across restarts; a redeemed token stays dead.
pub async fn bootstrap_admin(conn: &mut PgConnection, email: &str, token: &str, ttl: Duration) -> ApiResult<bool> {
    let email = normalize_email(email)?;
    refuse_implicit_promotion(conn, &email).await?;
    let user = db::ensure_user(conn, &email, true).await?;
    if user.password_hash.is_some() {
        return Ok(false);
    }
    if token.len() < 32 {
        return Err(ApiError::bad_request("ADMIN_SETUP_TOKEN must be at least 32 characters"));
    }
    let exp = Utc::now() + chrono::Duration::from_std(ttl).map_err(|e| ApiError::internal(e.to_string()))?;
    db::insert_setup_token(conn, &token_hash(token), user.id, exp).await?;
    Ok(true)
}

/// An admin invite (or the bootstrap) must not turn an existing non-admin account that already
/// has a password, or was self-registered, into a server admin: with open signup, anyone can
/// register the email an admin is about to invite and would be promoted along with it. Promote
/// deliberately with the `promote` CLI after checking who owns the account.
async fn refuse_implicit_promotion(conn: &mut PgConnection, email: &str) -> ApiResult<()> {
    if let Some(u) = db::user_by_email(conn, email).await? {
        if !u.is_admin && (u.password_hash.is_some() || u.self_signup) {
            return Err(ApiError::conflict(
                "existing_account",
                format!("{email} already has an account (created {}{}); an invite won't make it admin. Check who owns it, then use `btc-safe-api promote`", u.created_at.format("%Y-%m-%d"), if u.self_signup { " by self-signup, email unverified" } else { "" }),
            ));
        }
    }
    Ok(())
}

/// Test/CLI helper: a user with a password already set.
pub async fn create_user_with_password(conn: &mut PgConnection, email: &str, password: &str, is_admin: bool) -> ApiResult<db::UserRow> {
    let email = normalize_email(email)?;
    signup::check_password(password, Some(&email))?;
    let user = db::ensure_user(conn, &email, is_admin).await?;
    let h = hash_password(password.to_string()).await?;
    db::set_password_hash(conn, user.id, &h).await?;
    Ok(user)
}

/// Middleware: resolve the session cookie to a [`CurrentUser`], enforce CSRF on state-changing
/// methods, and apply the per-user rate limit.
pub async fn require_user(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let Some(token) = cookie_value(req.headers(), st.auth.cookie_name()).map(str::to_owned) else {
        return unauthorized("login required");
    };
    let found = match st.pool.acquire().await {
        Ok(mut c) => db::session_user(&mut c, &token_hash(&token), st.auth.idle_secs()).await,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let s = match found {
        Ok(Some(x)) => x,
        Ok(None) => return unauthorized("session expired or invalid"),
        Err(e) => return ApiError::from(e).into_response(),
    };
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        let sent = req.headers().get("x-csrf-token").and_then(|v| v.to_str().ok()).unwrap_or("");
        if !constant_time_eq(sent.as_bytes(), s.csrf.as_bytes()) {
            return (StatusCode::FORBIDDEN, Json(json!({ "error": "csrf", "message": "missing or bad X-CSRF-Token" }))).into_response();
        }
    }
    if let Err(r) = st.limits.user.check(&st.pool, &s.user.id.to_string()).await {
        return r;
    }
    req.extensions_mut().insert(CurrentUser { id: s.user.id, email: s.user.email, is_admin: s.user.is_admin, session: s.token_hash });
    next.run(req).await
}

/// Middleware (runs after [`require_user`]): wallet-scoped routes need membership (else 404)
/// and a role at least the route's minimum (else 403). Deny by default.
pub async fn require_membership(State(st): State<AppState>, Extension(user): Extension<CurrentUser>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().trim_matches('/').to_string();
    let segs: Vec<&str> = path.split('/').collect();
    let wallet = match segs.as_slice() {
        ["wallets"] | ["wallets", "import"] | ["dev", ..] => None,
        ["wallets", id, ..] => match Uuid::parse_str(id) {
            Ok(id) => Some(Ok(id)),
            Err(_) => Some(Err(())),
        },
        ["proposals", id, ..] => match id.parse::<i64>() {
            Ok(pid) => match st.pool.acquire().await {
                Ok(mut c) => match db::proposal_wallet(&mut c, pid).await {
                    Ok(Some(w)) => Some(Ok(w)),
                    Ok(None) => Some(Err(())),
                    Err(e) => return ApiError::from(e).into_response(),
                },
                Err(e) => return ApiError::from(e).into_response(),
            },
            Err(_) => Some(Err(())),
        },
        _ => Some(Err(())),
    };
    match wallet {
        None => next.run(req).await,
        Some(Err(())) => ApiError::not_found().into_response(),
        Some(Ok(wid)) => {
            let role = match st.pool.acquire().await {
                Ok(mut c) => db::member_role(&mut c, wid, user.id).await,
                Err(e) => return ApiError::from(e).into_response(),
            };
            let role = match role {
                Ok(Some(r)) => Role::parse(&r).unwrap_or(Role::Viewer),
                Ok(None) => return ApiError::not_found().into_response(),
                Err(e) => return ApiError::from(e).into_response(),
            };
            match roles::required(req.method(), &segs) {
                Some(min) if role >= min => {
                    req.extensions_mut().insert(WalletAccess { wallet_id: wid, role });
                    next.run(req).await
                }
                Some(min) => forbidden("forbidden", format!("your role in this wallet is {}; this needs {}", role.as_str(), min.as_str())).into_response(),
                None => forbidden("forbidden", "not allowed").into_response(),
            }
        }
    }
}

// ---------------------------------------------------------------- login helpers

fn user_json(u: &db::UserRow, csrf: &str) -> Value {
    json!({ "email": u.email, "is_admin": u.is_admin, "csrf_token": csrf, "totp_enabled": u.totp_enabled })
}

fn no_store(res: &mut Response) {
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

/// End the session the request arrived with, if any (whoever's it is). Called before issuing
/// a new one, so a session id is never carried across a login (fixation).
async fn drop_incoming_session(conn: &mut PgConnection, cfg: &AuthConfig, headers: &HeaderMap) -> ApiResult<()> {
    if let Some(t) = cookie_value(headers, cfg.cookie_name()) {
        db::delete_session(conn, &token_hash(t)).await?;
    }
    Ok(())
}

/// The account the request's device cookie has logged in to before, if any.
async fn known_device(conn: &mut PgConnection, cfg: &AuthConfig, headers: &HeaderMap) -> ApiResult<Option<(Vec<u8>, Uuid)>> {
    let Some(t) = cookie_value(headers, cfg.device_cookie_name()) else { return Ok(None) };
    let h = token_hash(t);
    Ok(db::known_device_user(conn, &h, DEVICE_DAYS).await?.map(|u| (h, u)))
}

/// Issue a fresh session (and remember this browser for `user`): the end of every login path.
async fn start_session(conn: &mut PgConnection, st: &AppState, headers: &HeaderMap, user: &db::UserRow, mut body: Value) -> ApiResult<Response> {
    drop_incoming_session(conn, &st.auth, headers).await?;
    let (token, csrf) = create_session(conn, &st.auth, user.id).await?;
    body["csrf_token"] = json!(csrf);
    let mut res = (StatusCode::OK, Json(body)).into_response();
    res.headers_mut().append(header::SET_COOKIE, st.auth.session_cookie(&token, st.auth.session_ttl.as_secs()));
    let known = known_device(conn, &st.auth, headers).await?.is_some_and(|(_, u)| u == user.id);
    if !known {
        let dev = random_token();
        db::insert_known_device(conn, &token_hash(&dev), user.id).await?;
        res.headers_mut().append(header::SET_COOKIE, st.auth.cookie(st.auth.device_cookie_name(), &dev, u64::from(DEVICE_DAYS as u32) * 86400));
    }
    no_store(&mut res);
    Ok(res)
}

/// Replace all of `user`'s sessions with one new one (password or 2FA change).
async fn rotate_all(conn: &mut PgConnection, st: &AppState, headers: &HeaderMap, user: Uuid) -> ApiResult<(String, String)> {
    drop_incoming_session(conn, &st.auth, headers).await?;
    db::delete_user_sessions(conn, user).await?;
    create_session(conn, &st.auth, user).await
}

fn with_session(st: &AppState, token: &str, body: Value) -> Response {
    let mut res = (StatusCode::OK, Json(body)).into_response();
    res.headers_mut().append(header::SET_COOKIE, st.auth.session_cookie(token, st.auth.session_ttl.as_secs()));
    no_store(&mut res);
    res
}

fn backoff_response(until: chrono::DateTime<Utc>) -> Response {
    let secs = (until - Utc::now()).num_seconds().max(1) as u64;
    too_many(secs, &format!("too many failed attempts for this account; try again in {secs} s"))
}

fn audit_actor(email: &str) -> String {
    email.trim().to_lowercase().chars().take(254).collect()
}

async fn login_failed(conn: &mut PgConnection, st: &AppState, user: Option<&db::UserRow>, email: &str, ip: &str, reason: &str) -> ApiResult<()> {
    let mut payload = json!({ "ip": ip, "reason": reason });
    if let Some(u) = user {
        let (n, until) = db::record_login_failure(conn, u.id, st.auth.backoff_free, st.auth.backoff_max.as_secs() as i64).await?;
        payload["failures"] = json!(n);
        payload["locked_until"] = json!(until);
    }
    btc_safe_store::audit(conn, None, &audit_actor(email), "login_failed", payload).await?;
    tracing::info!(%ip, reason, "login failed");
    Ok(())
}

const REAUTH_TRIES: i32 = 5;

/// Re-check the logged-in user's password for a sensitive account change. The session already
/// proves who this is, so the account's login backoff doesn't apply (an outsider failing logins
/// can't block the owner from changing their password). Instead wrong answers count against the
/// session: after a few, it ends, so a stolen session can't be used to guess the password.
/// Wrong password → 403 `bad_password` (not 401: the session is still fine until then).
async fn reauth(conn: &mut PgConnection, st: &AppState, me: &CurrentUser, ip: &str, password: String) -> ApiResult<Result<db::UserRow, Response>> {
    if let Err(r) = st.limits.login.check(&st.pool, &format!("reauth:{}", me.id)).await {
        return Ok(Err(r));
    }
    let user = db::user_by_id(conn, me.id).await?;
    if password.len() > MAX_PASSWORD || !verify_password(password, user.password_hash.clone()).await {
        return Ok(Err(reauth_failed(conn, st, me, ip, "reauth_bad_password").await?));
    }
    Ok(Ok(user))
}

async fn reauth_failed(conn: &mut PgConnection, st: &AppState, me: &CurrentUser, ip: &str, reason: &str) -> ApiResult<Response> {
    login_failed(conn, st, None, &me.email, ip, reason).await?;
    if db::session_reauth_failure(conn, &me.session).await? >= REAUTH_TRIES {
        db::delete_session(conn, &me.session).await?;
        btc_safe_store::audit(conn, None, &me.email, "session_ended", json!({ "ip": ip, "reason": "too_many_reauth_failures" })).await?;
        let mut r = unauthorized("too many wrong answers; this session has ended. Log in again");
        r.headers_mut().insert(header::SET_COOKIE, st.auth.session_cookie("", 0));
        return Ok(r);
    }
    let (code, msg) = if reason == "reauth_bad_password" { ("bad_password", "current password is wrong") } else { ("bad_code", "wrong or already-used code") };
    Ok(forbidden(code, msg).into_response())
}

/// Forget every browser trusted for `user` (credentials changed) and trust only this one.
async fn retrust_this_device(conn: &mut PgConnection, st: &AppState, user: Uuid) -> ApiResult<HeaderValue> {
    db::delete_known_devices(conn, user).await?;
    let dev = random_token();
    db::insert_known_device(conn, &token_hash(&dev), user).await?;
    Ok(st.auth.cookie(st.auth.device_cookie_name(), &dev, u64::from(DEVICE_DAYS as u32) * 86400))
}

/// Check a TOTP code (no replay) or a recovery code (one use). Some(method) when accepted.
async fn second_factor(conn: &mut PgConnection, user: Uuid, code: Option<&str>, recovery: Option<&str>) -> ApiResult<Option<&'static str>> {
    if let Some(code) = code.filter(|c| !c.trim().is_empty()) {
        let Some(secret) = db::totp_secret(conn, user).await? else { return Ok(None) };
        let Some(step) = mfa::verify(&secret, code, signup::now_unix()) else { return Ok(None) };
        return Ok(db::advance_totp_step(conn, user, step).await?.then_some("totp"));
    }
    if let Some(rc) = recovery {
        let Some(n) = mfa::normalize_recovery_code(rc) else { return Ok(None) };
        return Ok(db::use_recovery_code(conn, user, &mfa::recovery_hash(user, &n)).await?.then_some("recovery_code"));
    }
    Ok(None)
}

async fn new_recovery_codes(conn: &mut PgConnection, user: Uuid) -> ApiResult<Vec<String>> {
    let codes: Vec<String> = (0..mfa::RECOVERY_CODES).map(|_| mfa::new_recovery_code()).collect();
    let hashes: Vec<Vec<u8>> = codes.iter().map(|c| mfa::recovery_hash(user, &mfa::normalize_recovery_code(c).expect("well-formed"))).collect();
    db::replace_recovery_codes(conn, user, &hashes).await?;
    Ok(codes)
}

// ---------------------------------------------------------------- login / logout

#[derive(Deserialize)]
pub struct LoginIn {
    email: String,
    password: String,
}

pub async fn login(State(st): State<AppState>, Extension(ClientIp(ip)): Extension<ClientIp>, headers: HeaderMap, Json(b): Json<LoginIn>) -> Response {
    if let Err(r) = st.limits.login.check(&st.pool, &format!("ip:{}", ip_key(&ip))).await {
        return r;
    }
    let email = b.email.trim().to_lowercase();
    let res: ApiResult<Response> = async {
        let mut conn = st.pool.acquire().await?;
        let user = db::user_by_email(&mut conn, &email).await?;
        // A browser that has logged in to this account before isn't subject to the account's
        // shared buckets (per-email limit, failure backoff): only to its own.
        let trusted = match (&user, known_device(&mut conn, &st.auth, &headers).await?) {
            (Some(u), Some((dev, owner))) if owner == u.id => Some(dev),
            _ => None,
        };
        let bucket = match &trusted {
            Some(dev) => format!("dev:{}", dev.to_lower_hex_string()),
            None => format!("email:{email}"),
        };
        if let Err(r) = st.limits.login.check(&st.pool, &bucket).await {
            return Ok(r);
        }
        if b.password.len() > MAX_PASSWORD {
            return Ok(unauthorized("bad email or password"));
        }
        if trusted.is_none() {
            if let Some(until) = user.as_ref().and_then(|u| u.locked_until).filter(|u| *u > Utc::now()) {
                login_failed(&mut conn, &st, None, &email, &ip, "backoff").await?;
                return Ok(backoff_response(until));
            }
        }
        let ok = verify_password(b.password, user.as_ref().and_then(|u| u.password_hash.clone())).await;
        let user = match user {
            Some(u) if ok => u,
            other => {
                let reason = match &other {
                    None => "unknown_user",
                    Some(u) if u.password_hash.is_none() => "no_password",
                    Some(_) => "bad_password",
                };
                login_failed(&mut conn, &st, other.as_ref(), &email, &ip, reason).await?;
                return Ok(unauthorized("bad email or password"));
            }
        };
        if user.totp_enabled {
            let t = random_token();
            db::insert_login_challenge(&mut conn, &token_hash(&t), user.id, Utc::now() + chrono::Duration::seconds(MFA_TTL_SECS)).await?;
            let mut res = Json(json!({ "mfa_required": true, "mfa_token": t })).into_response();
            no_store(&mut res);
            return Ok(res);
        }
        let mut tx = st.pool.begin().await?;
        db::reset_login_failures(&mut tx, user.id).await?;
        btc_safe_store::audit(&mut tx, None, &user.email, "login", json!({ "ip": ip })).await?;
        let res = start_session(&mut tx, &st, &headers, &user, user_json(&user, "")).await?;
        tx.commit().await?;
        Ok(res)
    }
    .await;
    res.unwrap_or_else(IntoResponse::into_response)
}

#[derive(Deserialize)]
pub struct MfaIn {
    mfa_token: String,
    code: Option<String>,
    recovery_code: Option<String>,
}

/// Second step of a login with 2FA on: exchange the challenge plus a TOTP or recovery code for
/// a session. A challenge allows a few attempts within a few minutes; failures count toward the
/// account's backoff (and a new challenge needs the password again).
pub async fn login_mfa(State(st): State<AppState>, Extension(ClientIp(ip)): Extension<ClientIp>, headers: HeaderMap, Json(b): Json<MfaIn>) -> Response {
    if let Err(r) = st.limits.login.check(&st.pool, &format!("ip:{}", ip_key(&ip))).await {
        return r;
    }
    let res: ApiResult<Response> = async {
        let mut tx = st.pool.begin().await?;
        let ch = token_hash(&b.mfa_token);
        let Some(uid) = db::attempt_login_challenge(&mut tx, &ch, MFA_ATTEMPTS).await? else {
            tx.commit().await?;
            return Ok((StatusCode::UNAUTHORIZED, Json(json!({ "error": "mfa_expired", "message": "login expired; enter your password again" }))).into_response());
        };
        let user = db::user_by_id(&mut tx, uid).await?;
        // The second factor gets the same protection as the password: the account backoff
        // (unless this browser has logged in to it before) and a per-account bucket.
        let trusted = known_device(&mut tx, &st.auth, &headers).await?.filter(|(_, u)| *u == uid);
        let bucket = match &trusted {
            Some((dev, _)) => format!("dev:{}", dev.to_lower_hex_string()),
            None => format!("mfa:{uid}"),
        };
        if let Err(r) = st.limits.login.check(&st.pool, &bucket).await {
            tx.commit().await?;
            return Ok(r);
        }
        if trusted.is_none() {
            if let Some(until) = user.locked_until.filter(|u| *u > Utc::now()) {
                login_failed(&mut tx, &st, None, &user.email, &ip, "backoff").await?;
                tx.commit().await?;
                return Ok(backoff_response(until));
            }
        }
        let Some(how) = second_factor(&mut tx, uid, b.code.as_deref(), b.recovery_code.as_deref()).await? else {
            login_failed(&mut tx, &st, Some(&user), &user.email, &ip, "bad_second_factor").await?;
            tx.commit().await?;
            return Ok((StatusCode::UNAUTHORIZED, Json(json!({ "error": "bad_code", "message": "wrong or already-used code" }))).into_response());
        };
        db::delete_login_challenge(&mut tx, &ch).await?;
        db::reset_login_failures(&mut tx, uid).await?;
        btc_safe_store::audit(&mut tx, None, &user.email, "login", json!({ "ip": ip, "second_factor": how })).await?;
        let mut body = user_json(&user, "");
        body["recovery_codes_left"] = json!(db::recovery_codes_left(&mut tx, uid).await?);
        let res = start_session(&mut tx, &st, &headers, &user, body).await?;
        tx.commit().await?;
        Ok(res)
    }
    .await;
    res.unwrap_or_else(IntoResponse::into_response)
}

pub async fn logout(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = cookie_value(&headers, st.auth.cookie_name()) {
        let mut conn = st.pool.acquire().await?;
        db::delete_session(&mut conn, &token_hash(token)).await?;
    }
    let mut res = StatusCode::NO_CONTENT.into_response();
    res.headers_mut().insert(header::SET_COOKIE, st.auth.session_cookie("", 0));
    Ok(res)
}

/// End every session of the logged-in user, this one included.
pub async fn logout_all(State(st): State<AppState>, Extension(me): Extension<CurrentUser>, Extension(ClientIp(ip)): Extension<ClientIp>) -> ApiResult<Response> {
    let mut tx = st.pool.begin().await?;
    db::delete_user_sessions(&mut tx, me.id).await?;
    db::delete_known_devices(&mut tx, me.id).await?;
    btc_safe_store::audit(&mut tx, None, &me.email, "logout_all", json!({ "ip": ip })).await?;
    tx.commit().await?;
    let mut res = StatusCode::NO_CONTENT.into_response();
    res.headers_mut().insert(header::SET_COOKIE, st.auth.session_cookie("", 0));
    Ok(res)
}

pub async fn me(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let Some(token) = cookie_value(&headers, st.auth.cookie_name()) else {
        return Ok(unauthorized("login required"));
    };
    let mut conn = st.pool.acquire().await?;
    match db::session_user(&mut conn, &token_hash(token), st.auth.idle_secs()).await? {
        Some(s) => {
            let mut body = user_json(&s.user, &s.csrf);
            body["recovery_codes_left"] = json!(db::recovery_codes_left(&mut conn, s.user.id).await?);
            body["session_expires_at"] = json!(s.expires_at);
            body["idle_timeout_secs"] = json!(st.auth.idle_secs());
            let mut res = Json(body).into_response();
            no_store(&mut res);
            Ok(res)
        }
        None => Ok(unauthorized("session expired or invalid")),
    }
}

// ---------------------------------------------------------------- setup links

#[derive(Deserialize)]
pub struct SetupQuery {
    token: String,
}

/// Check a setup token without consuming it (the setup page shows which account it's for).
pub async fn setup_check(State(st): State<AppState>, Extension(ClientIp(ip)): Extension<ClientIp>, Query(q): Query<SetupQuery>) -> Response {
    if let Err(r) = st.limits.login.check(&st.pool, &format!("ip:{}", ip_key(&ip))).await {
        return r;
    }
    let res: ApiResult<Response> = async {
        let mut conn = st.pool.acquire().await?;
        Ok(match db::setup_token_valid(&mut conn, &token_hash(&q.token)).await? {
            Some(email) => Json(json!({ "email": email })).into_response(),
            None => ApiError::new(StatusCode::NOT_FOUND, "bad_setup_token", "setup link is invalid, used or expired").into_response(),
        })
    }
    .await;
    res.unwrap_or_else(IntoResponse::into_response)
}

#[derive(Deserialize)]
pub struct SetupIn {
    token: String,
    password: String,
}

/// Redeem a setup token: set the password, end the user's other sessions, log in. A setup link
/// is also the admin reset path, so it clears 2FA and recovery codes and the failure backoff.
pub async fn setup(State(st): State<AppState>, Extension(ClientIp(ip)): Extension<ClientIp>, headers: HeaderMap, Json(b): Json<SetupIn>) -> Response {
    if let Err(r) = st.limits.login.check(&st.pool, &format!("ip:{}", ip_key(&ip))).await {
        return r;
    }
    let res: ApiResult<Response> = async {
        if b.password.len() > MAX_PASSWORD {
            return Err(ApiError::bad_request("password too long"));
        }
        let mut tx = st.pool.begin().await?;
        let Some(email) = db::setup_token_valid(&mut tx, &token_hash(&b.token)).await? else {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "bad_setup_token", "setup link is invalid, used or expired"));
        };
        signup::check_password(&b.password, Some(&email))?;
        let h = hash_password(b.password).await?;
        let Some(uid) = db::redeem_setup_token(&mut tx, &token_hash(&b.token)).await? else {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "bad_setup_token", "setup link is invalid, used or expired"));
        };
        db::set_password_hash(&mut tx, uid, &h).await?;
        db::delete_user_sessions(&mut tx, uid).await?;
        db::disable_totp(&mut tx, uid).await?;
        db::reset_login_failures(&mut tx, uid).await?;
        db::delete_known_devices(&mut tx, uid).await?;
        let user = db::user_by_id(&mut tx, uid).await?;
        btc_safe_store::audit(&mut tx, None, &user.email, "password_set", json!({ "ip": ip })).await?;
        let res = start_session(&mut tx, &st, &headers, &user, user_json(&user, "")).await?;
        tx.commit().await?;
        Ok(res)
    }
    .await;
    res.unwrap_or_else(IntoResponse::into_response)
}

// ---------------------------------------------------------------- signup

/// Whether signup is open, and a fresh proof-of-work challenge if it is.
pub async fn signup_info(State(st): State<AppState>) -> Response {
    let pow = st.auth.open_signup.then(|| json!({ "challenge": signup::issue_challenge(&st.auth.pow_key, POW_TTL_SECS), "bits": st.auth.pow_bits }));
    let mut res = Json(json!({ "open": st.auth.open_signup, "min_password": MIN_PASSWORD, "pow": pow })).into_response();
    no_store(&mut res);
    res
}

#[derive(Deserialize)]
pub struct SignupIn {
    email: String,
    password: String,
    /// Honeypot: a hidden form field people never fill in.
    #[serde(default)]
    website: String,
    #[serde(default)]
    pow_challenge: String,
    #[serde(default)]
    pow_nonce: String,
}

pub async fn signup(State(st): State<AppState>, Extension(ClientIp(ip)): Extension<ClientIp>, headers: HeaderMap, Json(b): Json<SignupIn>) -> Response {
    if !st.auth.open_signup {
        return ApiError::new(StatusCode::NOT_FOUND, "signup_closed", "signup is invite-only on this server").into_response();
    }
    let res: ApiResult<Response> = async {
        if !b.website.is_empty() {
            let mut conn = st.pool.acquire().await?;
            btc_safe_store::audit(&mut conn, None, &audit_actor(&b.email), "signup_refused", json!({ "ip": ip, "reason": "honeypot" })).await?;
            return Err(ApiError::bad_request("signup refused"));
        }
        if let Err(r) = st.limits.signup.check(&st.pool, &ip_key(&ip)).await {
            return Ok(r);
        }
        if let Err(r) = st.limits.signup_global.check(&st.pool, "all").await {
            return Ok(r);
        }
        let email = normalize_email(&b.email)?;
        if !email.is_ascii() {
            // No look-alike (homoglyph) addresses for accounts nobody verified.
            return Err(ApiError::bad_request("signup needs a plain ASCII email address"));
        }
        signup::check_password(&b.password, Some(&email))?;
        signup::check_solution(&st.auth.pow_key, st.auth.pow_bits, &b.pow_challenge, &b.pow_nonce)?;
        {
            let mut conn = st.pool.acquire().await?;
            if !btc_safe_store::limits::spend_challenge(&mut conn, &signup::challenge_id(&b.pow_challenge)).await? {
                return Err(ApiError::new(StatusCode::BAD_REQUEST, "bad_pow", "challenge already used; fetch a new one"));
            }
        }
        let h = hash_password(b.password).await?;
        let mut tx = st.pool.begin().await?;
        // Serialize signups so the user cap can't be overshot by concurrent requests.
        btc_safe_store::sqlx::query("SELECT pg_advisory_xact_lock(724300101)").execute(&mut *tx).await?;
        if db::count_users(&mut tx).await? >= st.auth.max_users {
            return Err(forbidden("user_cap", "this server isn't taking new accounts right now"));
        }
        let Some(user) = db::insert_new_user(&mut tx, &email, &h).await? else {
            return Err(ApiError::conflict("email_taken", "an account with that email already exists"));
        };
        btc_safe_store::audit(&mut tx, None, &user.email, "signup", json!({ "ip": ip })).await?;
        let mut res = start_session(&mut tx, &st, &headers, &user, user_json(&user, "")).await?;
        tx.commit().await?;
        *res.status_mut() = StatusCode::CREATED;
        Ok(res)
    }
    .await;
    res.unwrap_or_else(IntoResponse::into_response)
}

// ---------------------------------------------------------------- account (logged in)

#[derive(Deserialize)]
pub struct PasswordIn {
    current_password: String,
    new_password: String,
}

/// Change the password: needs the current one; every session is replaced by one new one.
pub async fn change_password(
    State(st): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(b): Json<PasswordIn>,
) -> ApiResult<Response> {
    let mut tx = st.pool.begin().await?;
    let user = match reauth(&mut tx, &st, &me, &ip, b.current_password.clone()).await? {
        Ok(u) => u,
        Err(r) => {
            tx.commit().await?;
            return Ok(r);
        }
    };
    signup::check_password(&b.new_password, Some(&user.email))?;
    if b.new_password == b.current_password {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "weak_password", "new password is the same as the current one"));
    }
    let h = hash_password(b.new_password).await?;
    db::set_password_hash(&mut tx, user.id, &h).await?;
    db::reset_login_failures(&mut tx, user.id).await?;
    db::revoke_setup_tokens(&mut tx, user.id).await?;
    let (token, csrf) = rotate_all(&mut tx, &st, &headers, user.id).await?;
    let dev = retrust_this_device(&mut tx, &st, user.id).await?;
    btc_safe_store::audit(&mut tx, None, &user.email, "password_changed", json!({ "ip": ip })).await?;
    tx.commit().await?;
    let mut res = with_session(&st, &token, user_json(&user, &csrf));
    res.headers_mut().append(header::SET_COOKIE, dev);
    Ok(res)
}

#[derive(Deserialize)]
pub struct PasswordOnly {
    password: String,
}

/// Start TOTP enrolment: needs the password (a stolen session alone can't bind the account to
/// the thief's authenticator). The secret is pending until confirmed with a code.
pub async fn totp_setup(
    State(st): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(b): Json<PasswordOnly>,
) -> ApiResult<Response> {
    let mut tx = st.pool.begin().await?;
    let user = match reauth(&mut tx, &st, &me, &ip, b.password).await? {
        Ok(u) => u,
        Err(r) => {
            tx.commit().await?;
            return Ok(r);
        }
    };
    if user.totp_enabled {
        return Err(ApiError::conflict("totp_enabled", "two-factor is already on; turn it off first"));
    }
    let secret = mfa::random_bytes::<{ mfa::SECRET_LEN }>();
    db::set_totp_pending(&mut tx, user.id, &secret, Utc::now() + chrono::Duration::seconds(TOTP_PENDING_SECS)).await?;
    tx.commit().await?;
    let mut res = Json(json!({ "secret": mfa::base32(&secret), "otpauth_uri": mfa::otpauth_uri(&secret, &user.email) })).into_response();
    no_store(&mut res);
    Ok(res)
}

#[derive(Deserialize)]
pub struct CodeIn {
    code: String,
}

/// Confirm enrolment with a code from the authenticator. Returns the recovery codes (once).
/// Other sessions end (they were opened without the second factor).
pub async fn totp_enable(
    State(st): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(b): Json<CodeIn>,
) -> ApiResult<Response> {
    if let Err(r) = st.limits.login.check(&st.pool, &format!("totp:{}", me.id)).await {
        return Ok(r);
    }
    let mut tx = st.pool.begin().await?;
    let user = db::user_by_id(&mut tx, me.id).await?;
    if user.totp_enabled {
        return Err(ApiError::conflict("totp_enabled", "two-factor is already on"));
    }
    let Some(secret) = db::totp_pending(&mut tx, me.id).await? else {
        return Err(ApiError::conflict("no_pending_totp", "start two-factor setup again"));
    };
    let Some(step) = mfa::verify(&secret, &b.code, signup::now_unix()) else {
        return Err(forbidden("bad_code", "that code doesn't match; check the authenticator's clock"));
    };
    db::enable_totp(&mut tx, me.id, &secret, step).await?;
    let codes = new_recovery_codes(&mut tx, me.id).await?;
    let (token, csrf) = rotate_all(&mut tx, &st, &headers, me.id).await?;
    let dev = retrust_this_device(&mut tx, &st, me.id).await?;
    btc_safe_store::audit(&mut tx, None, &me.email, "totp_enabled", json!({ "ip": ip })).await?;
    tx.commit().await?;
    let mut res = with_session(&st, &token, json!({ "csrf_token": csrf, "recovery_codes": codes, "totp_enabled": true }));
    res.headers_mut().append(header::SET_COOKIE, dev);
    Ok(res)
}

#[derive(Deserialize)]
pub struct FactorIn {
    password: String,
    code: Option<String>,
    recovery_code: Option<String>,
}

/// Turn 2FA off: password plus a current code or a recovery code.
pub async fn totp_disable(
    State(st): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Json(b): Json<FactorIn>,
) -> ApiResult<Response> {
    let mut tx = st.pool.begin().await?;
    let user = match reauth(&mut tx, &st, &me, &ip, b.password).await? {
        Ok(u) => u,
        Err(r) => {
            tx.commit().await?;
            return Ok(r);
        }
    };
    if !user.totp_enabled {
        return Err(ApiError::conflict("totp_disabled", "two-factor is not on"));
    }
    if second_factor(&mut tx, me.id, b.code.as_deref(), b.recovery_code.as_deref()).await?.is_none() {
        let r = reauth_failed(&mut tx, &st, &me, &ip, "reauth_bad_second_factor").await?;
        tx.commit().await?;
        return Ok(r);
    }
    db::disable_totp(&mut tx, me.id).await?;
    let (token, csrf) = rotate_all(&mut tx, &st, &headers, me.id).await?;
    let dev = retrust_this_device(&mut tx, &st, me.id).await?;
    btc_safe_store::audit(&mut tx, None, &me.email, "totp_disabled", json!({ "ip": ip })).await?;
    tx.commit().await?;
    let mut res = with_session(&st, &token, json!({ "csrf_token": csrf, "totp_enabled": false }));
    res.headers_mut().append(header::SET_COOKIE, dev);
    Ok(res)
}

/// New recovery codes (the old ones stop working): password plus a current TOTP code.
pub async fn recovery_codes(
    State(st): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(b): Json<FactorIn>,
) -> ApiResult<Response> {
    let mut tx = st.pool.begin().await?;
    let user = match reauth(&mut tx, &st, &me, &ip, b.password).await? {
        Ok(u) => u,
        Err(r) => {
            tx.commit().await?;
            return Ok(r);
        }
    };
    if !user.totp_enabled {
        return Err(ApiError::conflict("totp_disabled", "two-factor is not on"));
    }
    if second_factor(&mut tx, me.id, b.code.as_deref(), None).await?.is_none() {
        let r = reauth_failed(&mut tx, &st, &me, &ip, "reauth_bad_second_factor").await?;
        tx.commit().await?;
        return Ok(r);
    }
    let codes = new_recovery_codes(&mut tx, me.id).await?;
    btc_safe_store::audit(&mut tx, None, &me.email, "recovery_codes_regenerated", json!({ "ip": ip })).await?;
    tx.commit().await?;
    let mut res = Json(json!({ "recovery_codes": codes })).into_response();
    no_store(&mut res);
    Ok(res)
}

// ---------------------------------------------------------------- admin

#[derive(Deserialize)]
pub struct InviteIn {
    email: String,
    #[serde(default)]
    admin: bool,
}

/// Admin only: create a user (or reset an existing one) and return a one-time setup link.
pub async fn invite(State(st): State<AppState>, Extension(me): Extension<CurrentUser>, Json(b): Json<InviteIn>) -> ApiResult<(StatusCode, Json<Value>)> {
    if !me.is_admin {
        return Err(forbidden("forbidden", "admin only"));
    }
    let mut tx = st.pool.begin().await?;
    let (user, token) = issue_setup_token(&mut tx, &b.email, b.admin, st.auth.invite_ttl).await?;
    btc_safe_store::audit(&mut tx, None, &me.email, "invite", json!({ "email": user.email, "admin": b.admin })).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "email": user.email,
            "setup_token": token,
            "setup_path": format!("/setup?token={token}"),
            "expires_in_hours": st.auth.invite_ttl.as_secs() / 3600,
        })),
    ))
}

pub async fn users(State(st): State<AppState>, Extension(me): Extension<CurrentUser>) -> ApiResult<Json<Value>> {
    if !me.is_admin {
        return Err(forbidden("forbidden", "admin only"));
    }
    let mut conn = st.pool.acquire().await?;
    let rows = db::list_users(&mut conn).await?;
    Ok(Json(json!(rows
        .iter()
        .map(|u| json!({ "id": u.id, "email": u.email, "is_admin": u.is_admin, "active": u.password_hash.is_some(), "totp_enabled": u.totp_enabled, "created_at": u.created_at }))
        .collect::<Vec<_>>())))
}

// ---------------------------------------------------------------- wallet members

pub async fn members_list(State(st): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let mut conn = st.pool.acquire().await?;
    let rows = db::members(&mut conn, id).await?;
    Ok(Json(json!(rows.iter().map(|m| json!({ "user_id": m.user_id, "email": m.email, "role": m.role, "added_at": m.added_at, "self_signup": m.self_signup })).collect::<Vec<_>>())))
}

fn parse_role(r: Option<&str>) -> ApiResult<Role> {
    match r {
        None => Ok(Role::Viewer),
        Some(r) => Role::parse(r).ok_or_else(|| ApiError::bad_request("role must be admin, proposer or viewer")),
    }
}

#[derive(Deserialize)]
pub struct MemberIn {
    email: String,
    role: Option<String>,
    /// Required to share with a self-registered account (its email was never verified).
    #[serde(default)]
    confirm_unverified: bool,
}

/// Admins share the wallet with an existing account, as viewer by default. A self-registered
/// account needs `confirm_unverified`: anyone could have signed up with that email first.
pub async fn members_add(
    State(st): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(b): Json<MemberIn>,
) -> ApiResult<Response> {
    // Sharing reveals whether an email has an account; keep it to human speed.
    if let Err(r) = st.limits.login.check(&st.pool, &format!("share:{}", me.id)).await {
        return Ok(r);
    }
    let email = normalize_email(&b.email)?;
    let role = parse_role(b.role.as_deref())?;
    let mut tx = st.pool.begin().await?;
    db::lock_members_count_admins(&mut tx, id).await?;
    let user = db::user_by_email(&mut tx, &email)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no_such_user", "no account with that email; they need to sign up (or be invited) first"))?;
    if user.self_signup && !b.confirm_unverified {
        return Err(ApiError::conflict(
            "unverified_account",
            format!(
                "{email} signed itself up on {} and its email was never verified: anyone could have registered that address. Check with the person (e.g. ask them to read you their account page) before sharing",
                user.created_at.format("%Y-%m-%d")
            ),
        ));
    }
    if !db::add_member(&mut tx, id, user.id, role.as_str()).await? {
        return Err(ApiError::conflict("already_member", "already a member; change their role instead"));
    }
    btc_safe_store::audit(&mut tx, Some(id), &me.email, "member_added", json!({ "email": email, "role": role.as_str(), "self_signup": user.self_signup })).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "user_id": user.id, "email": email, "role": role.as_str(), "self_signup": user.self_signup }))).into_response())
}

#[derive(Deserialize)]
pub struct RoleIn {
    role: String,
}

/// Admins change a member's role. The last admin can't be demoted.
pub async fn members_update(
    State(st): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Path((id, uid)): Path<(Uuid, Uuid)>,
    Json(b): Json<RoleIn>,
) -> ApiResult<Json<Value>> {
    let role = parse_role(Some(&b.role))?;
    let mut tx = st.pool.begin().await?;
    let admins = db::lock_members_count_admins(&mut tx, id).await?;
    let current = db::member_role(&mut tx, id, uid).await?.ok_or_else(ApiError::not_found)?;
    if current == "admin" && role != Role::Admin && admins <= 1 {
        return Err(ApiError::conflict("last_admin", "a wallet needs at least one admin; make someone else admin first"));
    }
    db::set_role(&mut tx, id, uid, role.as_str()).await?;
    btc_safe_store::audit(&mut tx, Some(id), &me.email, "member_role_changed", json!({ "user_id": uid, "from": current, "to": role.as_str() })).await?;
    tx.commit().await?;
    Ok(Json(json!({ "user_id": uid, "role": role.as_str() })))
}

/// Admins remove members; anyone may remove themselves (leave). Never the last admin.
pub async fn members_remove(
    State(st): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Extension(access): Extension<WalletAccess>,
    Path((id, uid)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    if uid != me.id && access.role != Role::Admin {
        return Err(forbidden("forbidden", "only wallet admins can remove other members"));
    }
    let mut tx = st.pool.begin().await?;
    let admins = db::lock_members_count_admins(&mut tx, id).await?;
    let current = db::member_role(&mut tx, id, uid).await?.ok_or_else(ApiError::not_found)?;
    if current == "admin" && admins <= 1 {
        return Err(ApiError::conflict("last_admin", "can't remove the last admin"));
    }
    db::remove_member(&mut tx, id, uid).await?;
    btc_safe_store::audit(&mut tx, Some(id), &me.email, "member_removed", json!({ "user_id": uid, "role": current })).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub type SharedAuth = Arc<AuthConfig>;
