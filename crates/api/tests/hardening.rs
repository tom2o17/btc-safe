//! Public signup, Postgres rate limits, login backoff + audit, session rotation/idle/absolute
//! expiry, password change, TOTP + recovery codes, wallet roles, wallet cap, security headers.
//! Over HTTP against real Postgres ($BTC_SAFE_TEST_DATABASE_URL).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use bitcoin::Network;
use btc_safe_api::auth::{self, AuthConfig};
use btc_safe_api::mfa;
use btc_safe_api::ratelimit::RateLimits;
use btc_safe_api::signup::work_bits;
use btc_safe_api::{router, AppState};
use btc_safe_chain::MemoryChain;
use btc_safe_store::sqlx::PgPool;
use btc_safe_testkit::three_owners;
use btc_safe_watcher::WalletCache;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const RCPT: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
const PW: &str = "correct horse battery staple 42";

fn db_url() -> String {
    std::env::var("BTC_SAFE_TEST_DATABASE_URL").unwrap_or_else(|_| {
        format!("postgres:///btc_safe_test?host=/tmp&user={}", std::env::var("USER").unwrap_or_else(|_| "postgres".into()))
    })
}

fn test_cfg() -> AuthConfig {
    AuthConfig {
        client_ip_header: Some("x-real-ip".parse().unwrap()),
        open_signup: true,
        pow_bits: 4,
        max_users: i64::MAX,
        ..AuthConfig::default()
    }
}

struct T {
    app: Router,
    pool: PgPool,
    cfg: AuthConfig,
}

#[derive(Debug)]
struct Res {
    status: StatusCode,
    body: Value,
    cookies: Vec<String>,
    headers: axum::http::HeaderMap,
}

impl Res {
    /// `name=value` of the Set-Cookie for `name`, if any.
    fn cookie(&self, name: &str) -> Option<String> {
        self.cookies.iter().find(|c| c.starts_with(&format!("{name}="))).map(|c| c.split(';').next().unwrap().to_string())
    }
}

/// A browser: its cookie jar and CSRF token.
#[derive(Clone, Default, Debug)]
struct B {
    session: Option<String>,
    device: Option<String>,
    csrf: String,
    ip: String,
}

impl B {
    fn new(ip: &str) -> Self {
        B { ip: ip.into(), ..Default::default() }
    }
}

async fn setup(f: impl FnOnce(&mut AppState)) -> T {
    let pool = btc_safe_store::connect(&db_url()).await.unwrap();
    let mem = MemoryChain::new(Network::Signet);
    let mut st = AppState::new(pool.clone(), Arc::new(WalletCache::new()), Arc::new(mem.clone()), Some(mem.clone()));
    st.auth = Arc::new(test_cfg());
    f(&mut st);
    T { cfg: (*st.auth).clone(), app: router(st), pool }
}

fn email() -> String {
    format!("h-{}@example.test", uuid::Uuid::new_v4())
}

fn solve(challenge: &str, bits: u32) -> String {
    (0u64..).find(|n| work_bits(challenge, &n.to_string()) >= bits).unwrap().to_string()
}

impl T {
    async fn raw(&self, method: &str, path: &str, body: Option<Value>, headers: &[(&str, String)]) -> Res {
        let mut r = Request::builder().method(method).uri(path);
        for (k, v) in headers {
            r = r.header(*k, v.as_str());
        }
        let body = match body {
            Some(b) => {
                r = r.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let res = self.app.clone().oneshot(r.body(body).unwrap()).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let cookies = headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_string()).collect();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(json!({ "raw": String::from_utf8_lossy(&bytes) })) };
        Res { status, body, cookies, headers }
    }

    /// A request from browser `b`; stores any cookies and CSRF token it is handed.
    async fn go(&self, b: &mut B, method: &str, path: &str, body: Option<Value>) -> Res {
        let jar: Vec<String> = [b.session.clone(), b.device.clone()].into_iter().flatten().collect();
        let mut h = vec![("x-real-ip", b.ip.clone()), ("x-csrf-token", b.csrf.clone())];
        if !jar.is_empty() {
            h.push(("cookie", jar.join("; ")));
        }
        let r = self.raw(method, path, body, &h).await;
        if let Some(c) = r.cookie(self.cfg.cookie_name()) {
            b.session = Some(c).filter(|c| !c.ends_with('='));
        }
        if let Some(c) = r.cookie(self.cfg.device_cookie_name()) {
            b.device = Some(c);
        }
        if let Some(t) = r.body.get("csrf_token").and_then(Value::as_str) {
            b.csrf = t.to_string();
        }
        r
    }

    async fn signup(&self, b: &mut B, email: &str, pw: &str) -> Res {
        let info = self.go(b, "GET", "/auth/signup", None).await.body;
        let ch = info["pow"]["challenge"].as_str().unwrap().to_string();
        let nonce = solve(&ch, info["pow"]["bits"].as_u64().unwrap() as u32);
        self.go(b, "POST", "/auth/signup", Some(json!({ "email": email, "password": pw, "pow_challenge": ch, "pow_nonce": nonce }))).await
    }

    /// A fresh signed-up, logged-in user.
    async fn user(&self, ip: &str) -> (B, String) {
        let mut b = B::new(ip);
        let e = email();
        let r = self.signup(&mut b, &e, PW).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        (b, e)
    }

    async fn login(&self, b: &mut B, email: &str, pw: &str) -> Res {
        self.go(b, "POST", "/auth/login", Some(json!({ "email": email, "password": pw }))).await
    }

    async fn wallet(&self, b: &mut B) -> String {
        let owners: Vec<Value> = three_owners()
            .iter()
            .map(|o| json!({ "name": o.name, "xpub": o.xpub.to_string(), "fingerprint": o.fingerprint.to_string(), "path": "m/48'/1'/0'/2'" }))
            .collect();
        let r = self.go(b, "POST", "/wallets", Some(json!({ "name": "W", "network": "signet", "threshold": 2, "owners": owners }))).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        r.body["id"].as_str().unwrap().to_string()
    }

    async fn user_id(&self, email: &str) -> uuid::Uuid {
        let mut c = self.pool.acquire().await.unwrap();
        btc_safe_store::users::user_by_email(&mut c, email).await.unwrap().unwrap().id
    }

    async fn audit(&self, actor: &str) -> Vec<(String, Value)> {
        btc_safe_store::sqlx::query_as("SELECT action, payload FROM audit_log WHERE actor = $1 ORDER BY id")
            .bind(actor)
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    /// Turn on TOTP for `b`; returns the secret and the recovery codes.
    async fn enable_totp(&self, b: &mut B, email: &str) -> (Vec<u8>, Vec<String>) {
        let r = self.go(b, "POST", "/auth/totp/setup", Some(json!({ "password": PW }))).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert!(r.body["otpauth_uri"].as_str().unwrap().starts_with("otpauth://totp/"));
        let secret: Vec<u8> = btc_safe_store::sqlx::query_scalar("SELECT totp_pending FROM users WHERE email = $1").bind(email).fetch_one(&self.pool).await.unwrap();
        assert_eq!(mfa::base32(&secret), r.body["secret"].as_str().unwrap());
        let r = self.go(b, "POST", "/auth/totp/enable", Some(json!({ "code": mfa::code_at(&secret, now_step()) }))).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let codes = r.body["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
        (secret, codes)
    }
}

fn now_step() -> i64 {
    mfa::step_at(chrono::Utc::now().timestamp())
}

// ------------------------------------------------------------------------------------- signup

#[tokio::test]
async fn signup_closed_by_default() {
    let t = setup(|st| st.auth = Arc::new(AuthConfig::default())).await;
    let r = t.raw("GET", "/auth/signup", None, &[]).await;
    assert_eq!((r.body["open"].as_bool(), r.body["pow"].is_null()), (Some(false), true));
    let r = t.raw("POST", "/auth/signup", Some(json!({ "email": email(), "password": PW })), &[]).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::NOT_FOUND, Some("signup_closed")));
}

#[tokio::test]
async fn signup_creates_a_logged_in_account() {
    let t = setup(|_| {}).await;
    let mut b = B::new("198.18.0.1");
    let e = email();
    let r = t.signup(&mut b, &e.to_uppercase(), PW).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.body["email"], json!(e), "normalized");
    assert!(r.cookie(t.cfg.cookie_name()).is_some() && r.cookie(t.cfg.device_cookie_name()).is_some());
    assert_eq!(t.go(&mut b, "GET", "/wallets", None).await.status, StatusCode::OK);
    // It's a real password account: log in elsewhere with it.
    assert_eq!(t.login(&mut B::new("198.18.0.2"), &e, PW).await.status, StatusCode::OK);
    assert!(t.audit(&e).await.iter().any(|(a, p)| a == "signup" && p["ip"] == "198.18.0.1"));
}

#[tokio::test]
async fn signup_rejects_bots_and_weak_passwords() {
    let t = setup(|_| {}).await;
    let mut b = B::new("198.18.1.1");
    let info = t.go(&mut b, "GET", "/auth/signup", None).await.body;
    let ch = info["pow"]["challenge"].as_str().unwrap().to_string();
    let nonce = solve(&ch, 4);
    let post = |e: String, pw: &str, extra: Value| {
        let mut v = json!({ "email": e, "password": pw, "pow_challenge": ch, "pow_nonce": nonce });
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    // Honeypot filled in.
    let r = t.go(&mut b, "POST", "/auth/signup", Some(post(email(), PW, json!({ "website": "http://spam" })))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // No / wrong / insufficient proof of work.
    for extra in [json!({ "pow_challenge": "", "pow_nonce": "" }), json!({ "pow_challenge": format!("{ch}x") }), json!({ "pow_nonce": solve_bad(&ch) })] {
        let r = t.go(&mut b, "POST", "/auth/signup", Some(post(email(), PW, extra))).await;
        assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("bad_pow")), "{}", r.body);
    }
    // Weak passwords (checked before the challenge is spent).
    for pw in ["short", "password1234", "Qwertyuiopasdfgh", "zzzzzzzzzzzzzzzz"] {
        let r = t.go(&mut b, "POST", "/auth/signup", Some(post(email(), pw, json!({})))).await;
        assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("weak_password")), "{pw}");
    }
    // The good solution works once; replaying it is refused.
    let e = email();
    assert_eq!(t.go(&mut b, "POST", "/auth/signup", Some(post(e, PW, json!({})))).await.status, StatusCode::CREATED);
    let r = t.go(&mut B::new("198.18.1.2"), "POST", "/auth/signup", Some(post(email(), PW, json!({})))).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("bad_pow")));
}

fn solve_bad(ch: &str) -> String {
    (0u64..).find(|n| work_bits(ch, &n.to_string()) == 0).unwrap().to_string()
}

/// Signup never touches an existing account, including an invited one that hasn't set a
/// password yet (that would be an account takeover).
#[tokio::test]
async fn signup_cannot_claim_an_existing_or_invited_email() {
    let t = setup(|_| {}).await;
    let (_, taken) = t.user("198.18.2.1").await;
    let r = t.signup(&mut B::new("198.18.2.2"), &taken, "another long password").await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::CONFLICT, Some("email_taken")));
    assert_eq!(t.login(&mut B::new("198.18.2.3"), &taken, PW).await.status, StatusCode::OK, "old password still works");

    let invited = email();
    let mut c = t.pool.acquire().await.unwrap();
    let (_, tok) = auth::issue_setup_token(&mut c, &invited, false, Duration::from_secs(600)).await.unwrap();
    let r = t.signup(&mut B::new("198.18.2.4"), &invited, PW).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(btc_safe_store::users::user_by_email(&mut c, &invited).await.unwrap().unwrap().password_hash.is_none());
    // The invite flow still works.
    let r = t.go(&mut B::new("198.18.2.5"), "POST", "/auth/setup", Some(json!({ "token": tok, "password": PW }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

#[tokio::test]
async fn signup_caps_and_rate_limits() {
    // Per-IP limit (burst 2 per hour) and a global one (burst 3).
    let t = setup(|st| st.limits = RateLimits::custom((1000, 1000), (1000, 1000), (1000, 1000)).with_signup((1, 2), (1, 3))).await;
    let mut a = B::new("198.18.3.1");
    assert_eq!(t.signup(&mut a, &email(), PW).await.status, StatusCode::CREATED);
    assert_eq!(t.signup(&mut a, &email(), PW).await.status, StatusCode::CREATED);
    let r = t.signup(&mut a, &email(), PW).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers.get("retry-after").is_some());
    // Same /64 = same client.
    let mut v6 = B::new("2001:db8:5:6::1");
    assert_eq!(t.signup(&mut v6, &email(), PW).await.status, StatusCode::CREATED);
    let r = t.signup(&mut B::new("2001:db8:5:6:ffff::2"), &email(), PW).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "global bucket (3) is now empty as well");
    let r = t.signup(&mut B::new("198.18.3.99"), &email(), PW).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "global");

    // User cap.
    let mut c = t.pool.acquire().await.unwrap();
    let n = btc_safe_store::users::count_users(&mut c).await.unwrap();
    let t = setup(|st| st.auth = Arc::new(AuthConfig { max_users: n, ..test_cfg() })).await;
    let r = t.signup(&mut B::new("198.18.3.2"), &email(), PW).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("user_cap")));
}

#[tokio::test]
async fn wallet_cap_per_user() {
    let t = setup(|st| st.auth = Arc::new(AuthConfig { max_wallets_per_user: 1, ..test_cfg() })).await;
    let (mut b, _) = t.user("198.18.4.1").await;
    let w = t.wallet(&mut b).await;
    let owners: Vec<Value> = three_owners()
        .iter()
        .map(|o| json!({ "name": o.name, "xpub": o.xpub.to_string(), "fingerprint": o.fingerprint.to_string(), "path": "m/48'/1'/0'/2'" }))
        .collect();
    let body = json!({ "name": "W2", "network": "signet", "threshold": 2, "owners": owners });
    let r = t.go(&mut b, "POST", "/wallets", Some(body.clone())).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("wallet_cap")));
    // Deleting frees the slot.
    assert_eq!(t.go(&mut b, "DELETE", &format!("/wallets/{w}"), None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(t.go(&mut b, "POST", "/wallets", Some(body)).await.status, StatusCode::CREATED);
}

// ------------------------------------------------------------------------------- rate limits

/// Two API processes (two routers, one database) share the buckets.
#[tokio::test]
async fn rate_limits_are_shared_across_processes() {
    let limits = RateLimits::custom((1, 3), (1000, 1000), (1000, 1000));
    let l2 = limits.clone();
    let t1 = setup(|st| st.limits = limits).await;
    let t2 = setup(|st| st.limits = l2).await;
    let ip = [("x-real-ip", "198.18.5.1".to_string())];
    assert_eq!(t1.raw("GET", "/health", None, &ip).await.status, StatusCode::OK);
    assert_eq!(t2.raw("GET", "/health", None, &ip).await.status, StatusCode::OK);
    assert_eq!(t1.raw("GET", "/health", None, &ip).await.status, StatusCode::OK);
    let r = t2.raw("GET", "/health", None, &ip).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.body["error"], "rate_limited");
    // A refused request spends nothing: ten refusals, then one refill period, then a pass.
    let fast = RateLimits::custom((60, 1), (1000, 1000), (1000, 1000));
    let t3 = setup(|st| st.limits = fast).await;
    assert_eq!(t3.raw("GET", "/health", None, &ip).await.status, StatusCode::OK);
    for _ in 0..10 {
        assert_eq!(t3.raw("GET", "/health", None, &ip).await.status, StatusCode::TOO_MANY_REQUESTS);
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(t3.raw("GET", "/health", None, &ip).await.status, StatusCode::OK, "ten refusals cost nothing");
}

// ------------------------------------------------------------------------ backoff and audit

#[tokio::test]
async fn failed_logins_are_audited_and_back_off_without_locking_out_the_owner() {
    let t = setup(|st| st.auth = Arc::new(AuthConfig { backoff_free: 3, backoff_max: Duration::from_secs(60), ..test_cfg() })).await;
    let (_, e) = t.user("198.18.6.1").await;
    // The owner's browser has logged in before (it holds a device cookie).
    let mut owner = B::new("198.18.6.2");
    assert_eq!(t.login(&mut owner, &e, PW).await.status, StatusCode::OK);
    assert!(owner.device.is_some());

    // An attacker from many IPs.
    for i in 0..3 {
        let r = t.login(&mut B::new(&format!("203.0.113.{i}")), &e, "wrong password guess").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    // Backed off now: even the right password, from a new browser, is refused for a while.
    let r = t.login(&mut B::new("203.0.113.50"), &e, PW).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
    assert!(r.headers.get("retry-after").is_some());
    // A device cookie for another account doesn't help.
    let (mut other, _) = t.user("198.18.6.3").await;
    t.go(&mut other, "POST", "/auth/logout", None).await;
    assert_eq!(t.login(&mut other, &e, PW).await.status, StatusCode::TOO_MANY_REQUESTS);
    // The owner's known browser still gets in (which also resets the counter).
    let r = t.login(&mut owner, &e, PW).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    let log = t.audit(&e).await;
    let failed: Vec<&Value> = log.iter().filter(|(a, _)| a == "login_failed").map(|(_, p)| p).collect();
    assert!(failed.iter().filter(|p| p["reason"] == "bad_password").count() >= 3, "{failed:?}");
    assert!(failed.iter().any(|p| p["reason"] == "backoff" && p["ip"] == "203.0.113.50"));
    assert!(failed.iter().any(|p| p["ip"] == "203.0.113.0"));
    // Unknown accounts are logged too.
    let ghost = email();
    t.login(&mut B::new("203.0.113.9"), &ghost, "whatever password").await;
    assert_eq!(t.audit(&ghost).await[0].1["reason"], "unknown_user");
    // A successful login resets the counter.
    let mut c = t.pool.acquire().await.unwrap();
    assert_eq!(btc_safe_store::users::user_by_email(&mut c, &e).await.unwrap().unwrap().failed_logins, 0);
}

#[tokio::test]
async fn backoff_grows_exponentially_and_is_capped() {
    let t = setup(|st| st.auth = Arc::new(AuthConfig { backoff_free: 2, backoff_max: Duration::from_secs(8), ..test_cfg() })).await;
    let (_, e) = t.user("198.18.7.1").await;
    let uid = t.user_id(&e).await;
    let mut c = t.pool.acquire().await.unwrap();
    let mut waits = vec![];
    for _ in 0..7 {
        let (_, until) = btc_safe_store::users::record_login_failure(&mut c, uid, 2, 8).await.unwrap();
        waits.push(until.map(|u| (u - chrono::Utc::now()).num_milliseconds()));
    }
    let secs: Vec<i64> = waits.iter().map(|w| w.map(|ms| (ms as f64 / 1000.0).round() as i64).unwrap_or(0)).collect();
    assert_eq!(secs, vec![0, 1, 2, 4, 8, 8, 8]);
}

// ---------------------------------------------------------------------------------- sessions

#[tokio::test]
async fn login_rotates_the_session_id() {
    let t = setup(|_| {}).await;
    let (mut b, e) = t.user("198.18.8.1").await;
    let before = b.session.clone().unwrap();
    // Logging in again (same browser) issues a new id and kills the one it arrived with.
    let r = t.login(&mut b, &e, PW).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_ne!(b.session.clone().unwrap(), before);
    let r = t.raw("GET", "/auth/me", None, &[("cookie", before.clone())]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "old id is dead");
    // Fixation: an attacker's planted session id doesn't survive the victim's login either.
    let (mut attacker, _) = t.user("198.18.8.2").await;
    let planted = attacker.session.clone().unwrap();
    let mut victim = B { session: Some(planted.clone()), ..B::new("198.18.8.3") };
    assert_eq!(t.login(&mut victim, &e, PW).await.status, StatusCode::OK);
    assert_ne!(victim.session.as_ref(), Some(&planted));
    assert_eq!(t.go(&mut attacker, "GET", "/auth/me", None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn idle_timeout_and_absolute_lifetime() {
    let t = setup(|st| st.auth = Arc::new(AuthConfig { session_idle: Duration::from_secs(2), ..test_cfg() })).await;
    let (mut b, _) = t.user("198.18.9.1").await;
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert_eq!(t.go(&mut b, "GET", "/wallets", None).await.status, StatusCode::OK, "activity keeps it alive");
    }
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(t.go(&mut b, "GET", "/wallets", None).await.status, StatusCode::UNAUTHORIZED, "idle");

    let t = setup(|st| st.auth = Arc::new(AuthConfig { session_ttl: Duration::from_secs(2), ..test_cfg() })).await;
    let (mut b, _) = t.user("198.18.9.2").await;
    let me = t.go(&mut b, "GET", "/auth/me", None).await.body;
    assert!(me["session_expires_at"].is_string() && me["idle_timeout_secs"].as_i64() == Some(1800));
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        t.go(&mut b, "GET", "/wallets", None).await;
    }
    assert_eq!(t.go(&mut b, "GET", "/wallets", None).await.status, StatusCode::UNAUTHORIZED, "absolute");
}

#[tokio::test]
async fn logout_everywhere_and_admin_upgrade_end_sessions() {
    let t = setup(|_| {}).await;
    let (mut b1, e) = t.user("198.18.10.1").await;
    let mut b2 = B::new("198.18.10.2");
    assert_eq!(t.login(&mut b2, &e, PW).await.status, StatusCode::OK);
    // CSRF applies.
    let r = t.raw("POST", "/auth/logout-all", None, &[("cookie", b1.session.clone().unwrap())]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(t.go(&mut b1, "POST", "/auth/logout-all", None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(t.go(&mut b2, "GET", "/wallets", None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.go(&mut b1, "GET", "/wallets", None).await.status, StatusCode::UNAUTHORIZED);
    assert!(t.audit(&e).await.iter().any(|(a, _)| a == "logout_all"));

    // Privilege change: an account upgraded to admin (invite --admin) logs in again.
    let mut b3 = B::new("198.18.10.3");
    t.login(&mut b3, &e, PW).await;
    let mut c = t.pool.acquire().await.unwrap();
    btc_safe_store::users::ensure_user(&mut c, &e, true).await.unwrap();
    assert_eq!(t.go(&mut b3, "GET", "/wallets", None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.login(&mut b3, &e, PW).await.body["is_admin"], true);
}

// ------------------------------------------------------------------------- password change

#[tokio::test]
async fn password_change_needs_current_and_revokes_other_sessions() {
    let t = setup(|_| {}).await;
    let (mut b1, e) = t.user("198.18.11.1").await;
    let mut b2 = B::new("198.18.11.2");
    t.login(&mut b2, &e, PW).await;

    let r = t.go(&mut b1, "POST", "/auth/password", Some(json!({ "current_password": "not my password", "new_password": "a brand new password" }))).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("bad_password")));
    assert!(t.audit(&e).await.iter().any(|(a, p)| a == "login_failed" && p["reason"] == "reauth_bad_password"));
    let r = t.go(&mut b1, "POST", "/auth/password", Some(json!({ "current_password": PW, "new_password": "password1234" }))).await;
    assert_eq!(r.body["error"], "weak_password");
    assert_eq!(t.go(&mut b2, "GET", "/wallets", None).await.status, StatusCode::OK, "nothing changed yet");

    let old = b1.session.clone();
    let r = t.go(&mut b1, "POST", "/auth/password", Some(json!({ "current_password": PW, "new_password": "a brand new password" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_ne!(b1.session, old, "rotated");
    assert_eq!(t.go(&mut b1, "GET", "/wallets", None).await.status, StatusCode::OK);
    assert_eq!(t.go(&mut b2, "GET", "/wallets", None).await.status, StatusCode::UNAUTHORIZED, "other session revoked");
    assert_eq!(t.go(&mut b1, "POST", "/auth/logout-all", None).await.status, StatusCode::NO_CONTENT, "new csrf works");
    assert_eq!(t.login(&mut B::new("198.18.11.3"), &e, PW).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.login(&mut B::new("198.18.11.4"), &e, "a brand new password").await.status, StatusCode::OK);
}

// ------------------------------------------------------------------------------------- TOTP

#[tokio::test]
async fn totp_login_replay_and_recovery_codes() {
    let t = setup(|_| {}).await;
    let (mut b, e) = t.user("198.18.12.1").await;
    // Setup needs the password.
    let r = t.go(&mut b, "POST", "/auth/totp/setup", Some(json!({ "password": "wrong password!!" }))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let mut other = B::new("198.18.12.9");
    t.login(&mut other, &e, PW).await;
    let (secret, codes) = t.enable_totp(&mut b, &e).await;
    assert_eq!(codes.len(), 10);
    assert_eq!(t.go(&mut other, "GET", "/wallets", None).await.status, StatusCode::UNAUTHORIZED, "enabling 2FA ends other sessions");
    assert_eq!(t.go(&mut b, "GET", "/auth/me", None).await.body["recovery_codes_left"], 10);
    // Codes are stored hashed.
    let stored: Vec<Vec<u8>> = btc_safe_store::sqlx::query_scalar("SELECT code_hash FROM recovery_codes r JOIN users u ON u.id = r.user_id WHERE u.email = $1")
        .bind(&e)
        .fetch_all(&t.pool)
        .await
        .unwrap();
    assert_eq!(stored.len(), 10);
    assert!(stored.iter().all(|h| h.len() == 32 && !codes.iter().any(|c| c.as_bytes() == h.as_slice())));

    // Password alone no longer logs in.
    let mut l = B::new("198.18.12.2");
    let r = t.login(&mut l, &e, PW).await;
    assert_eq!(r.body["mfa_required"], true);
    assert!(l.session.is_none(), "no session before the second factor");
    let tok = r.body["mfa_token"].as_str().unwrap().to_string();
    // The challenge isn't a session.
    assert_eq!(t.raw("GET", "/wallets", None, &[("cookie", format!("{}={tok}", t.cfg.cookie_name()))]).await.status, StatusCode::UNAUTHORIZED);
    let r = t.go(&mut l, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": tok, "code": "000000" }))).await;
    assert_eq!(r.body["error"], "bad_code");
    // The enrolment code's step is spent; the next step's code works...
    let next = mfa::code_at(&secret, now_step() + 1);
    let r = t.go(&mut l, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": tok, "code": next }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(t.go(&mut l, "GET", "/wallets", None).await.status, StatusCode::OK);
    // ...once. Replaying it (new password step, same code) fails.
    let mut l2 = B::new("198.18.12.3");
    let tok2 = t.login(&mut l2, &e, PW).await.body["mfa_token"].as_str().unwrap().to_string();
    let r = t.go(&mut l2, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": tok2, "code": next }))).await;
    assert_eq!(r.body["error"], "bad_code", "replay");
    let r = t.go(&mut l2, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": tok2, "code": mfa::code_at(&secret, now_step() - 1) }))).await;
    assert_eq!(r.body["error"], "bad_code", "older step");
    // A recovery code works, once.
    let r = t.go(&mut l2, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": tok2, "recovery_code": codes[0].to_uppercase() }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["recovery_codes_left"], 9);
    let mut l3 = B::new("198.18.12.4");
    let tok3 = t.login(&mut l3, &e, PW).await.body["mfa_token"].as_str().unwrap().to_string();
    let r = t.go(&mut l3, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": tok3, "recovery_code": codes[0] }))).await;
    assert_eq!(r.body["error"], "bad_code", "recovery code reuse");
    // Another user's code doesn't work for this account.
    let (mut x, xe) = t.user("198.18.12.5").await;
    let (_, xcodes) = t.enable_totp(&mut x, &xe).await;
    let r = t.go(&mut l3, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": tok3, "recovery_code": xcodes[0] }))).await;
    assert_eq!(r.body["error"], "bad_code");
    let log = t.audit(&e).await;
    assert!(log.iter().any(|(a, p)| a == "login_failed" && p["reason"] == "bad_second_factor"));
    assert!(log.iter().any(|(a, p)| a == "login" && p["second_factor"] == "recovery_code"));
}

#[tokio::test]
async fn mfa_challenge_attempts_expire_and_admin_reset_clears_2fa() {
    let t = setup(|st| st.auth = Arc::new(AuthConfig { backoff_free: 100, ..test_cfg() })).await;
    let (mut b, e) = t.user("198.18.13.1").await;
    let (secret, codes) = t.enable_totp(&mut b, &e).await;
    let mut l = B::new("198.18.13.2");
    let tok = t.login(&mut l, &e, PW).await.body["mfa_token"].as_str().unwrap().to_string();
    for _ in 0..5 {
        assert_eq!(t.go(&mut l, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": tok, "code": "999999" }))).await.body["error"], "bad_code");
    }
    // Five tries per challenge: then even the right code is too late.
    let r = t.go(&mut l, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": tok, "code": mfa::code_at(&secret, now_step() + 1) }))).await;
    assert_eq!(r.body["error"], "mfa_expired");

    // Turning 2FA off needs the password and a code.
    let r = t.go(&mut b, "POST", "/auth/totp/disable", Some(json!({ "password": PW, "code": "123456" }))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t.go(&mut b, "POST", "/auth/recovery-codes", Some(json!({ "password": PW, "code": mfa::code_at(&secret, now_step() + 1) }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let fresh: Vec<String> = r.body["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().into()).collect();
    assert!(!fresh.contains(&codes[1]));
    let r = t.go(&mut b, "POST", "/auth/totp/disable", Some(json!({ "password": PW, "recovery_code": codes[1] }))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "old codes died with the regeneration");
    let r = t.go(&mut b, "POST", "/auth/totp/disable", Some(json!({ "password": PW, "recovery_code": fresh[0] }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(t.login(&mut B::new("198.18.13.3"), &e, PW).await.body["mfa_required"], Value::Null);

    // Admin reset (setup link) is the other way back in, and it clears 2FA.
    let (mut b2, e2) = t.user("198.18.13.4").await;
    t.enable_totp(&mut b2, &e2).await;
    let mut c = t.pool.acquire().await.unwrap();
    let (_, tok) = auth::issue_setup_token(&mut c, &e2, false, Duration::from_secs(600)).await.unwrap();
    let r = t.go(&mut B::new("198.18.13.5"), "POST", "/auth/setup", Some(json!({ "token": tok, "password": "a reset password here" }))).await;
    assert_eq!((r.status, r.body["totp_enabled"].as_bool()), (StatusCode::OK, Some(false)));
    assert_eq!(t.go(&mut b2, "GET", "/wallets", None).await.status, StatusCode::UNAUTHORIZED);
}

// ------------------------------------------------------------------------------------- roles

struct Crew {
    t: T,
    admin: B,
    proposer: B,
    proposer_email: String,
    viewer: B,
    w: String,
}

async fn crew() -> Crew {
    let t = setup(|_| {}).await;
    let (mut admin, _) = t.user("198.18.14.1").await;
    let (proposer, pe) = t.user("198.18.14.2").await;
    let (viewer, ve) = t.user("198.18.14.3").await;
    let w = t.wallet(&mut admin).await;
    for (e, role) in [(&pe, "proposer"), (&ve, "viewer")] {
        let r = t.go(&mut admin, "POST", &format!("/wallets/{w}/members"), Some(json!({ "email": e, "role": role, "confirm_unverified": true }))).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    }
    for _ in 0..3 {
        let addr = t.go(&mut admin, "GET", &format!("/wallets/{w}/addresses?kind=receive&next=true"), None).await.body;
        t.go(&mut admin, "POST", "/dev/fund", Some(json!({ "address": addr["address"], "amount_sats": 200_000 }))).await;
    }
    t.go(&mut admin, "POST", "/dev/mine", Some(json!({}))).await;
    t.go(&mut admin, "POST", &format!("/wallets/{w}/sync"), None).await;
    Crew { t, admin, proposer, proposer_email: pe, viewer, w }
}

fn spend(sats: u64) -> Value {
    json!({ "outputs": [{ "address": RCPT, "amount_sats": sats }], "fee_rate_sat_vb": 2.0 })
}

#[tokio::test]
async fn viewer_can_only_look() {
    let Crew { t, mut admin, mut viewer, w, .. } = crew().await;
    let p = t.go(&mut admin, "POST", &format!("/wallets/{w}/proposals"), Some(spend(10_000))).await;
    let pid = p.body["id"].as_i64().unwrap();
    let psbt = p.body["psbt"].as_str().unwrap().to_string();
    // Reads work and say the role.
    let s = t.go(&mut viewer, "GET", &format!("/wallets/{w}"), None).await;
    assert_eq!((s.status, s.body["my_role"].as_str()), (StatusCode::OK, Some("viewer")));
    let list = t.go(&mut viewer, "GET", "/wallets", None).await.body;
    assert_eq!(list[0]["role"], "viewer");
    for path in [format!("/wallets/{w}/history"), format!("/wallets/{w}/proposals"), format!("/proposals/{pid}"), format!("/wallets/{w}/members"), format!("/wallets/{w}/backup")] {
        assert_eq!(t.go(&mut viewer, "GET", &path, None).await.status, StatusCode::OK, "{path}");
    }
    assert_eq!(t.go(&mut viewer, "POST", &format!("/wallets/{w}/sync"), None).await.status, StatusCode::OK);
    // Nothing that changes anything.
    let uid = uuid::Uuid::new_v4();
    for (m, path, body) in [
        ("POST", format!("/wallets/{w}/proposals"), Some(spend(10_000))),
        ("POST", format!("/proposals/{pid}/signatures"), Some(json!({ "psbt": psbt }))),
        ("POST", format!("/proposals/{pid}/execute"), None),
        ("DELETE", format!("/proposals/{pid}"), None),
        ("DELETE", format!("/wallets/{w}"), None),
        ("PATCH", format!("/wallets/{w}"), Some(json!({ "ordering_mode": "strict" }))),
        ("POST", format!("/wallets/{w}/members"), Some(json!({ "email": "x@example.test", "role": "admin" }))),
        ("PATCH", format!("/wallets/{w}/members/{uid}"), Some(json!({ "role": "admin" }))),
        ("DELETE", format!("/wallets/{w}/members/{uid}"), None),
        ("POST", format!("/wallets/{w}/address-book"), Some(json!({ "label": "x", "address": RCPT }))),
        ("POST", format!("/wallets/{w}/addresses/0/label"), Some(json!({ "label": "x" }))),
        ("PUT", format!("/wallets/{w}/ledger/owners/{uid}"), Some(json!({}))),
    ] {
        let r = t.go(&mut viewer, m, &path, body).await;
        assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("forbidden")), "{m} {path}: {}", r.body);
    }
    assert_eq!(t.go(&mut admin, "GET", &format!("/proposals/{pid}"), None).await.body["status"], "pending", "untouched");
}

#[tokio::test]
async fn proposer_proposes_signs_executes_but_does_not_administer() {
    let Crew { t, mut admin, mut proposer, proposer_email, mut viewer, w } = crew().await;
    let mine = t.go(&mut proposer, "POST", &format!("/wallets/{w}/proposals"), Some(spend(10_000))).await;
    assert_eq!(mine.status, StatusCode::CREATED, "{}", mine.body);
    assert_eq!(mine.body["created_by"], json!(proposer_email));
    let theirs = t.go(&mut admin, "POST", &format!("/wallets/{w}/proposals"), Some(spend(20_000))).await;
    let (mine, theirs) = (mine.body["id"].as_i64().unwrap(), theirs.body["id"].as_i64().unwrap());
    // Sign and execute: allowed.
    use bitcoin::psbt::Psbt;
    use std::str::FromStr;
    let psbt_s = t.go(&mut proposer, "GET", &format!("/proposals/{theirs}"), None).await.body["psbt"].as_str().unwrap().to_string();
    let mut psbt = Psbt::from_str(&psbt_s).unwrap();
    three_owners()[0].sign(&mut psbt);
    three_owners()[1].sign(&mut psbt);
    let r = t.go(&mut proposer, "POST", &format!("/proposals/{theirs}/signatures"), Some(json!({ "psbt": psbt.to_string() }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = t.go(&mut proposer, "POST", &format!("/proposals/{theirs}/execute"), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // Delete: own yes, others' no.
    let other = t.go(&mut admin, "POST", &format!("/wallets/{w}/proposals"), Some(spend(5_000))).await.body["id"].as_i64().unwrap();
    let r = t.go(&mut proposer, "DELETE", &format!("/proposals/{other}"), None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    assert_eq!(t.go(&mut proposer, "DELETE", &format!("/proposals/{mine}"), None).await.status, StatusCode::OK);
    assert_eq!(t.go(&mut admin, "DELETE", &format!("/proposals/{other}"), None).await.status, StatusCode::OK, "admins delete anyone's");
    // Address book: yes. Members, settings, wallet delete: no.
    assert_eq!(t.go(&mut proposer, "POST", &format!("/wallets/{w}/address-book"), Some(json!({ "label": "rcpt", "address": RCPT }))).await.status, StatusCode::CREATED);
    let vid = t.go(&mut viewer, "GET", "/auth/me", None).await.body["email"].as_str().map(str::to_string).unwrap();
    let vid = t.user_id(&vid).await;
    for (m, path, body) in [
        ("PATCH", format!("/wallets/{w}/members/{vid}"), Some(json!({ "role": "admin" }))),
        ("DELETE", format!("/wallets/{w}/members/{vid}"), None),
        ("POST", format!("/wallets/{w}/members"), Some(json!({ "email": "x@example.test" }))),
        ("PATCH", format!("/wallets/{w}"), Some(json!({ "ordering_mode": "strict" }))),
        ("DELETE", format!("/wallets/{w}"), None),
    ] {
        assert_eq!(t.go(&mut proposer, m, &path, body).await.status, StatusCode::FORBIDDEN, "{m} {path}");
    }
}

#[tokio::test]
async fn member_management_and_last_admin() {
    let Crew { t, mut admin, mut proposer, proposer_email, mut viewer, w } = crew().await;
    let me = t.go(&mut admin, "GET", "/auth/me", None).await.body["email"].as_str().unwrap().to_string();
    let (aid, pid) = (t.user_id(&me).await, t.user_id(&proposer_email).await);
    // The only admin can't demote or remove themself.
    let r = t.go(&mut admin, "PATCH", &format!("/wallets/{w}/members/{aid}"), Some(json!({ "role": "viewer" }))).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::CONFLICT, Some("last_admin")));
    let r = t.go(&mut admin, "DELETE", &format!("/wallets/{w}/members/{aid}"), None).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::CONFLICT, Some("last_admin")));
    // Promote the proposer; now the first admin may step down.
    assert_eq!(t.go(&mut admin, "PATCH", &format!("/wallets/{w}/members/{pid}"), Some(json!({ "role": "admin" }))).await.status, StatusCode::OK);
    assert_eq!(t.go(&mut proposer, "GET", &format!("/wallets/{w}"), None).await.body["my_role"], "admin");
    assert_eq!(t.go(&mut admin, "PATCH", &format!("/wallets/{w}/members/{aid}"), Some(json!({ "role": "viewer" }))).await.status, StatusCode::OK);
    assert_eq!(t.go(&mut admin, "DELETE", &format!("/wallets/{w}"), None).await.status, StatusCode::FORBIDDEN, "demotion is immediate");
    // Bad role, duplicate member.
    let r = t.go(&mut proposer, "PATCH", &format!("/wallets/{w}/members/{aid}"), Some(json!({ "role": "owner" }))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = t.go(&mut proposer, "POST", &format!("/wallets/{w}/members"), Some(json!({ "email": me, "role": "admin", "confirm_unverified": true }))).await;
    assert_eq!(r.body["error"], "already_member");
    // A viewer may leave.
    let ve = t.go(&mut viewer, "GET", "/auth/me", None).await.body["email"].as_str().unwrap().to_string();
    let vid = t.user_id(&ve).await;
    assert_eq!(t.go(&mut viewer, "DELETE", &format!("/wallets/{w}/members/{vid}"), None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(t.go(&mut viewer, "GET", &format!("/wallets/{w}"), None).await.status, StatusCode::NOT_FOUND);
    let log = t.audit(&proposer_email).await;
    assert!(log.is_empty() || !log.iter().any(|(a, _)| a == "member_role_changed"), "role changes are logged under the wallet, by the actor");
    let n: i64 = btc_safe_store::sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'member_role_changed' AND wallet_id = $1")
        .bind(uuid::Uuid::parse_str(&w).unwrap())
        .fetch_one(&t.pool)
        .await
        .unwrap();
    assert_eq!(n, 2);
}

/// Wallet A's admin can't reach into wallet B through member routes (IDOR).
#[tokio::test]
async fn member_routes_are_scoped_to_their_wallet() {
    let t = setup(|_| {}).await;
    let (mut a, _) = t.user("198.18.15.1").await;
    let (mut b, be) = t.user("198.18.15.2").await;
    let wa = t.wallet(&mut a).await;
    let wb = t.wallet(&mut b).await;
    let bid = t.user_id(&be).await;
    // Non-member: 404 on B's wallet, whatever the route.
    for (m, path) in [("PATCH", format!("/wallets/{wb}/members/{bid}")), ("DELETE", format!("/wallets/{wb}/members/{bid}")), ("GET", format!("/wallets/{wb}/members"))] {
        let r = t.go(&mut a, m, &path, Some(json!({ "role": "viewer" }))).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{m} {path}");
    }
    // Through A's own wallet, B (not a member of A) isn't found either.
    let r = t.go(&mut a, "PATCH", &format!("/wallets/{wa}/members/{bid}"), Some(json!({ "role": "viewer" }))).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t.go(&mut a, "DELETE", &format!("/wallets/{wa}/members/{bid}"), None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(t.go(&mut b, "GET", &format!("/wallets/{wb}"), None).await.body["my_role"], "admin");
}

// ----------------------------------------------------------------------------------- headers

#[tokio::test]
async fn security_headers_on_every_response() {
    let t = setup(|st| st.limits = RateLimits::custom((1, 1), (1000, 1000), (1000, 1000))).await;
    let ip = |x: &str| vec![("x-real-ip", x.to_string())];
    let ok = t.raw("GET", "/health", None, &ip("198.18.16.1")).await;
    let unauth = t.raw("GET", "/wallets", None, &ip("198.18.16.2")).await;
    let limited = t.raw("GET", "/health", None, &ip("198.18.16.1")).await;
    assert_eq!((ok.status, unauth.status, limited.status), (StatusCode::OK, StatusCode::UNAUTHORIZED, StatusCode::TOO_MANY_REQUESTS));
    for r in [&ok, &unauth, &limited] {
        let h = |k: &str| r.headers.get(k).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        assert!(h("content-security-policy").contains("default-src 'none'") && h("content-security-policy").contains("frame-ancestors 'none'"));
        assert_eq!(h("x-content-type-options"), "nosniff");
        assert_eq!(h("x-frame-options"), "DENY");
        assert_eq!(h("referrer-policy"), "no-referrer");
        assert!(h("permissions-policy").contains("camera=()"));
        assert!(h("strict-transport-security").starts_with("max-age="));
        assert_eq!(h("cache-control"), "no-store");
    }
    // No HSTS over plain-http dev mode.
    let t = setup(|st| st.auth = Arc::new(AuthConfig { cookie_secure: false, ..test_cfg() })).await;
    assert!(t.raw("GET", "/health", None, &[]).await.headers.get("strict-transport-security").is_none());
}

// ------------------------------------------------------------- adversarial review regressions
// Each `fixed_*` test reproduces a finding from the fresh-context review of this change; each
// passed as an exploit before its fix.

async fn admin(t: &T, ip: &str) -> B {
    let e = email();
    let mut c = t.pool.acquire().await.unwrap();
    auth::create_user_with_password(&mut c, &e, PW, true).await.unwrap();
    let mut b = B::new(ip);
    assert_eq!(t.login(&mut b, &e, PW).await.status, StatusCode::OK);
    b
}

/// Finding 1 (high): sign up under the email an admin is about to invite as admin → become a
/// server admin. An admin invite (or the bootstrap) no longer promotes an existing account.
#[tokio::test]
async fn fixed_invite_does_not_promote_a_squatter() {
    let t = setup(|_| {}).await;
    let mut boss = admin(&t, "198.19.0.1").await;
    let (_, squatted) = t.user("198.19.0.2").await;
    let r = t.go(&mut boss, "POST", "/auth/invites", Some(json!({ "email": squatted, "admin": true }))).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::CONFLICT, Some("existing_account")), "{}", r.body);
    let mut c = t.pool.acquire().await.unwrap();
    assert!(!btc_safe_store::users::user_by_email(&mut c, &squatted).await.unwrap().unwrap().is_admin);
    assert!(auth::bootstrap_admin(&mut c, &squatted, &"x".repeat(40), Duration::from_secs(60)).await.is_err());
    assert!(auth::issue_setup_token(&mut c, &squatted, true, Duration::from_secs(60)).await.is_err(), "CLI path too");
    assert!(!btc_safe_store::users::user_by_email(&mut c, &squatted).await.unwrap().unwrap().is_admin);
    // A plain (non-admin) invite is still the reset path, and promoting a fresh invitee works.
    assert_eq!(t.go(&mut boss, "POST", "/auth/invites", Some(json!({ "email": squatted }))).await.status, StatusCode::CREATED);
    let r = t.go(&mut boss, "POST", "/auth/invites", Some(json!({ "email": email(), "admin": true }))).await;
    assert_eq!(r.status, StatusCode::CREATED);
}

/// Finding 2 (medium): a self-registered (unverified) email gets wallet access when an admin
/// shares to it. Sharing now needs explicit confirmation and lists the account as self-signup.
#[tokio::test]
async fn fixed_share_with_self_signup_needs_confirmation() {
    let t = setup(|_| {}).await;
    let (mut a, _) = t.user("198.19.1.1").await;
    let (_, cfo) = t.user("198.19.1.2").await;
    let w = t.wallet(&mut a).await;
    let r = t.go(&mut a, "POST", &format!("/wallets/{w}/members"), Some(json!({ "email": cfo, "role": "proposer" }))).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::CONFLICT, Some("unverified_account")));
    assert!(r.body["message"].as_str().unwrap().contains("never verified"));
    let r = t.go(&mut a, "POST", &format!("/wallets/{w}/members"), Some(json!({ "email": cfo, "role": "proposer", "confirm_unverified": true }))).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let m = t.go(&mut a, "GET", &format!("/wallets/{w}/members"), None).await.body;
    assert!(m.as_array().unwrap().iter().any(|x| x["email"] == json!(cfo) && x["self_signup"] == true));
    // Invited accounts were created by an admin: no confirmation needed.
    let invited = email();
    let mut c = t.pool.acquire().await.unwrap();
    auth::issue_setup_token(&mut c, &invited, false, Duration::from_secs(60)).await.unwrap();
    assert_eq!(t.go(&mut a, "POST", &format!("/wallets/{w}/members"), Some(json!({ "email": invited }))).await.status, StatusCode::CREATED);
}

/// Finding 3 (medium): TOTP guesses ignored the account backoff and could be spread over many
/// stockpiled challenges. Now: one open challenge per account, backoff applies to the code step.
#[tokio::test]
async fn fixed_mfa_respects_backoff_and_one_challenge_at_a_time() {
    let t = setup(|st| st.auth = Arc::new(AuthConfig { backoff_free: 3, ..test_cfg() })).await;
    let (mut owner, e) = t.user("198.19.2.1").await;
    let (secret, _) = t.enable_totp(&mut owner, &e).await;
    let mut x = B::new("203.0.113.70");
    let c1 = t.login(&mut x, &e, PW).await.body["mfa_token"].as_str().unwrap().to_string();
    let c2 = t.login(&mut B::new("203.0.113.71"), &e, PW).await.body["mfa_token"].as_str().unwrap().to_string();
    let r = t.go(&mut x, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": c1, "code": "111111" }))).await;
    assert_eq!(r.body["error"], "mfa_expired", "a new challenge replaces the old one");
    for _ in 0..3 {
        t.go(&mut x, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": c2, "code": "111111" }))).await;
    }
    let r = t.go(&mut x, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": c2, "code": mfa::code_at(&secret, now_step() + 1) }))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "right code, but the account is backing off: {}", r.body);
    // The owner's known browser isn't held back.
    let mut o = owner.clone();
    o.session = None;
    let c = t.login(&mut o, &e, PW).await.body["mfa_token"].as_str().unwrap().to_string();
    let r = t.go(&mut o, "POST", "/auth/login/mfa", Some(json!({ "mfa_token": c, "code": mfa::code_at(&secret, now_step() + 1) }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

/// Finding 4 (medium): failed logins by an outsider blocked the logged-in owner from changing
/// their password or 2FA. Reauth no longer uses the account lock; a stolen session gets only a
/// few guesses before it ends.
#[tokio::test]
async fn fixed_outsider_cannot_block_owner_reauth_and_session_thief_gets_few_guesses() {
    let t = setup(|st| st.auth = Arc::new(AuthConfig { backoff_free: 2, ..test_cfg() })).await;
    let (mut owner, e) = t.user("198.19.3.1").await;
    for i in 0..4 {
        t.login(&mut B::new(&format!("203.0.113.8{i}")), &e, "wrong password guess").await;
    }
    assert_eq!(t.login(&mut B::new("203.0.113.89"), &e, PW).await.status, StatusCode::TOO_MANY_REQUESTS, "locked for outsiders");
    let r = t.go(&mut owner, "POST", "/auth/totp/setup", Some(json!({ "password": PW }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = t.go(&mut owner, "POST", "/auth/password", Some(json!({ "current_password": PW, "new_password": "a brand new password" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    // A session thief guessing the current password: 4 tries get 403, the 5th ends the session.
    let mut thief = owner.clone();
    for _ in 0..4 {
        let r = t.go(&mut thief, "POST", "/auth/password", Some(json!({ "current_password": "guess guess guess", "new_password": "thief password here" }))).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }
    let r = t.go(&mut thief, "POST", "/auth/password", Some(json!({ "current_password": "guess guess guess", "new_password": "thief password here" }))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.go(&mut thief, "GET", "/wallets", None).await.status, StatusCode::UNAUTHORIZED);
    assert!(t.audit(&e).await.iter().any(|(a, p)| a == "session_ended" && p["reason"] == "too_many_reauth_failures"));
}

/// Finding 5 (low): a browser trusted once kept its backoff bypass through password change,
/// admin reset and logout-all.
#[tokio::test]
async fn fixed_device_trust_is_revoked_when_credentials_change() {
    let t = setup(|st| st.auth = Arc::new(AuthConfig { backoff_free: 2, ..test_cfg() })).await;
    let (mut owner, e) = t.user("198.19.4.1").await;
    let mut old = B::new("198.19.4.2");
    assert_eq!(t.login(&mut old, &e, PW).await.status, StatusCode::OK);
    old.session = None;
    let r = t.go(&mut owner, "POST", "/auth/password", Some(json!({ "current_password": PW, "new_password": "a brand new password" }))).await;
    assert_eq!(r.status, StatusCode::OK);
    for i in 0..3 {
        t.login(&mut B::new(&format!("203.0.113.9{i}")), &e, "wrong password guess").await;
    }
    let r = t.login(&mut old, &e, "a brand new password").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "the old browser lost its trust");
    let mut o = owner.clone();
    o.session = None;
    assert_eq!(t.login(&mut o, &e, "a brand new password").await.status, StatusCode::OK, "the browser that changed it keeps it");
    // logout-all forgets every browser.
    assert_eq!(t.go(&mut o, "POST", "/auth/logout-all", None).await.status, StatusCode::NO_CONTENT);
    let n: i64 = btc_safe_store::sqlx::query_scalar("SELECT count(*) FROM known_devices d JOIN users u ON u.id = d.user_id WHERE u.email = $1")
        .bind(&e)
        .fetch_one(&t.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

/// Finding 6 (low): a viewer could move the receive index with GET …/addresses?next=true.
#[tokio::test]
async fn fixed_viewer_cannot_allocate_addresses() {
    let Crew { t, mut proposer, mut viewer, w, .. } = crew().await;
    let r = t.go(&mut viewer, "GET", &format!("/wallets/{w}/addresses?kind=receive&next=true"), None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(t.go(&mut viewer, "GET", &format!("/wallets/{w}/addresses?kind=receive"), None).await.status, StatusCode::OK);
    assert_eq!(t.go(&mut proposer, "GET", &format!("/wallets/{w}/addresses?kind=receive&next=true"), None).await.status, StatusCode::OK);
}

/// Info findings: a password change revokes pending reset links; signup refuses look-alike
/// (non-ASCII) emails.
#[tokio::test]
async fn fixed_password_change_revokes_reset_links_and_signup_is_ascii() {
    let t = setup(|_| {}).await;
    let (mut b, e) = t.user("198.19.5.1").await;
    let mut c = t.pool.acquire().await.unwrap();
    let (_, tok) = auth::issue_setup_token(&mut c, &e, false, Duration::from_secs(600)).await.unwrap();
    t.go(&mut b, "POST", "/auth/password", Some(json!({ "current_password": PW, "new_password": "a brand new password" }))).await;
    let r = t.go(&mut B::new("198.19.5.2"), "POST", "/auth/setup", Some(json!({ "token": tok, "password": "a reset password here" }))).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t.signup(&mut B::new("198.19.5.3"), "cfо@example.test", PW).await; // Cyrillic о
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}
