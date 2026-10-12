//! Login, sessions, CSRF, wallet membership and rate limits (crates/api/src/auth.rs,
//! ratelimit.rs) over HTTP against real Postgres.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use bitcoin::Network;
use btc_safe_api::auth::{self, AuthConfig};
use btc_safe_api::ratelimit::RateLimits;
use btc_safe_api::{router, AppState};
use btc_safe_chain::MemoryChain;
use btc_safe_store::sqlx::PgPool;
use btc_safe_testkit::three_owners;
use btc_safe_watcher::WalletCache;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;
use common::Session;

const RCPT: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

fn db_url() -> String {
    std::env::var("BTC_SAFE_TEST_DATABASE_URL").unwrap_or_else(|_| {
        format!("postgres:///btc_safe_test?host=/tmp&user={}", std::env::var("USER").unwrap_or_else(|_| "postgres".into()))
    })
}

struct T {
    app: Router,
    pool: PgPool,
    cfg: AuthConfig,
}

async fn setup(f: impl FnOnce(&mut AppState)) -> T {
    let pool = btc_safe_store::connect(&db_url()).await.unwrap();
    let mem = MemoryChain::new(Network::Signet);
    let mut st = AppState::new(pool.clone(), Arc::new(WalletCache::new()), Arc::new(mem.clone()), Some(mem.clone()));
    f(&mut st);
    T { cfg: (*st.auth).clone(), app: router(st), pool }
}

struct Res {
    status: StatusCode,
    body: Value,
    set_cookie: Option<String>,
    retry_after: Option<String>,
}

impl T {
    async fn req(&self, method: &str, path: &str, body: Option<Value>, headers: &[(&str, &str)]) -> Res {
        let mut r = Request::builder().method(method).uri(path);
        for (k, v) in headers {
            r = r.header(*k, *v);
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
        let set_cookie = res.headers().get("set-cookie").map(|v| v.to_str().unwrap().to_string());
        let retry_after = res.headers().get("retry-after").map(|v| v.to_str().unwrap().to_string());
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(json!({ "raw": String::from_utf8_lossy(&bytes) })) };
        Res { status, body, set_cookie, retry_after }
    }

    async fn as_(&self, s: &Session, method: &str, path: &str, body: Option<Value>) -> Res {
        self.req(method, path, body, &[("cookie", &s.cookie), ("x-csrf-token", &s.csrf)]).await
    }

    async fn user(&self) -> Session {
        common::login(&self.pool, &self.cfg).await
    }

    async fn wallet(&self, s: &Session) -> String {
        let owners: Vec<Value> = three_owners()
            .iter()
            .map(|o| json!({ "name": o.name, "xpub": o.xpub.to_string(), "fingerprint": o.fingerprint.to_string(), "path": "m/48'/1'/0'/2'" }))
            .collect();
        let r = self.as_(s, "POST", "/wallets", Some(json!({ "name": "W", "network": "signet", "threshold": 2, "owners": owners }))).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        r.body["id"].as_str().unwrap().to_string()
    }
}

fn cookie_pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn unauthenticated_gets_401() {
    let t = setup(|_| {}).await;
    let s = t.user().await;
    let wid = t.wallet(&s).await;
    for (m, p) in [
        ("GET", "/wallets".to_string()),
        ("POST", "/wallets".to_string()),
        ("GET", format!("/wallets/{wid}")),
        ("POST", format!("/wallets/{wid}/proposals")),
        ("GET", "/proposals/1".to_string()),
        ("POST", "/proposals/1/signatures".to_string()),
        ("POST", "/proposals/1/execute".to_string()),
        ("GET", "/auth/users".to_string()),
        ("POST", "/dev/mine".to_string()),
    ] {
        let r = t.req(m, &p, Some(json!({})), &[]).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{m} {p}");
    }
    // A bogus or logged-out cookie is no better.
    let bogus = format!("{}={}", t.cfg.cookie_name(), "00".repeat(32));
    assert_eq!(t.req("GET", "/wallets", None, &[("cookie", &bogus)]).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.req("GET", "/health", None, &[]).await.status, StatusCode::OK);
}

#[tokio::test]
async fn cross_wallet_access_is_404() {
    let t = setup(|_| {}).await;
    let (a, b) = (t.user().await, t.user().await);
    let wa = t.wallet(&a).await;
    let wb = t.wallet(&b).await;

    // Fund A's wallet and queue a proposal there.
    let addr = t.as_(&a, "GET", &format!("/wallets/{wa}/addresses?kind=receive&next=true"), None).await.body;
    t.as_(&a, "POST", "/dev/fund", Some(json!({ "address": addr["address"], "amount_sats": 100_000 }))).await;
    t.as_(&a, "POST", "/dev/mine", Some(json!({}))).await;
    t.as_(&a, "POST", &format!("/wallets/{wa}/sync"), None).await;
    let p = t.as_(&a, "POST", &format!("/wallets/{wa}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 10_000 }], "fee_rate_sat_vb": 2.0 }))).await;
    assert_eq!(p.status, StatusCode::CREATED, "{}", p.body);
    let pid = p.body["id"].as_i64().unwrap();

    // B can't see or touch any of it, and gets the same 404 as for a wallet that doesn't exist.
    let list: Vec<String> = t.as_(&b, "GET", "/wallets", None).await.body.as_array().unwrap().iter().map(|w| w["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(list, vec![wb.clone()]);
    for (m, path, body) in [
        ("GET", format!("/wallets/{wa}"), None),
        ("GET", format!("/wallets/{wa}/backup"), None),
        ("GET", format!("/wallets/{wa}/utxos"), None),
        ("POST", format!("/wallets/{wa}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 1000 }] }))),
        ("PATCH", format!("/wallets/{wa}"), Some(json!({ "ordering_mode": "strict" }))),
        ("DELETE", format!("/wallets/{wa}"), None),
        ("GET", format!("/wallets/{wa}/members"), None),
        ("POST", format!("/wallets/{wa}/members"), Some(json!({ "email": b.email }))),
        ("GET", format!("/proposals/{pid}"), None),
        ("POST", format!("/proposals/{pid}/signatures"), Some(json!({ "psbt": "cHNidP8BAAoCAAAAAAAAAAAAAAAA" }))),
        ("POST", format!("/proposals/{pid}/execute"), None),
        ("DELETE", format!("/proposals/{pid}"), None),
        ("GET", format!("/wallets/{}", uuid::Uuid::new_v4()), None),
        ("GET", "/wallets/not-a-uuid".to_string(), None),
    ] {
        let r = t.as_(&b, m, &path, body).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{m} {path}: {}", r.body);
    }
    assert_eq!(t.as_(&a, "GET", &format!("/proposals/{pid}"), None).await.body["status"], "pending");

    // A shares the wallet with B; now B sees it.
    let r = t.as_(&a, "POST", &format!("/wallets/{wa}/members"), Some(json!({ "email": b.email.to_uppercase() }))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(t.as_(&b, "GET", &format!("/proposals/{pid}"), None).await.status, StatusCode::OK);
    let m = t.as_(&b, "GET", &format!("/wallets/{wa}/members"), None).await.body;
    assert_eq!(m.as_array().unwrap().len(), 2);
    // Sharing with an email that has no account is refused.
    let r = t.as_(&a, "POST", &format!("/wallets/{wa}/members"), Some(json!({ "email": "nobody@example.test" }))).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::NOT_FOUND, Some("no_such_user")));
    // B removes themself; access is gone again. The last member can't be removed.
    let r = t.as_(&b, "DELETE", &format!("/wallets/{wa}/members/{}", b.user_id), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.as_(&b, "GET", &format!("/wallets/{wa}"), None).await.status, StatusCode::NOT_FOUND);
    let r = t.as_(&a, "DELETE", &format!("/wallets/{wa}/members/{}", a.user_id), None).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn csrf_required_on_state_changes() {
    let t = setup(|_| {}).await;
    let s = t.user().await;
    let wid = t.wallet(&s).await;
    let body = Some(json!({ "label": "x", "address": RCPT }));
    let path = format!("/wallets/{wid}/address-book");
    let r = t.req("POST", &path, body.clone(), &[("cookie", &s.cookie)]).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("csrf")));
    let r = t.req("POST", &path, body.clone(), &[("cookie", &s.cookie), ("x-csrf-token", &"0".repeat(64))]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Another session's token doesn't work either.
    let other = t.user().await;
    let r = t.req("POST", &path, body.clone(), &[("cookie", &s.cookie), ("x-csrf-token", &other.csrf)]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t.req("DELETE", &format!("/wallets/{wid}"), None, &[("cookie", &s.cookie)]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Reads don't need it; writes with it succeed.
    assert_eq!(t.req("GET", &path, None, &[("cookie", &s.cookie)]).await.status, StatusCode::OK);
    assert_eq!(t.as_(&s, "POST", &path, body).await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn password_hashing_is_argon2id() {
    let h1 = auth::hash_password("correct horse battery".into()).await.unwrap();
    let h2 = auth::hash_password("correct horse battery".into()).await.unwrap();
    assert!(h1.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h1}");
    assert_ne!(h1, h2, "salted");
    assert!(!h1.contains("correct"));
    assert!(auth::verify_password("correct horse battery".into(), Some(h1.clone())).await);
    assert!(!auth::verify_password("correct horse batterY".into(), Some(h1.clone())).await);
    assert!(!auth::verify_password("anything".into(), None).await, "no stored hash never verifies");
    assert!(!auth::verify_password("x".into(), Some("not a phc string".into())).await);
}

#[tokio::test]
async fn invite_setup_login_logout() {
    let t = setup(|_| {}).await;
    let email = format!("New-{}@Example.test", uuid::Uuid::new_v4());
    let mut c = t.pool.acquire().await.unwrap();
    let (user, token) = auth::issue_setup_token(&mut c, &email, false, std::time::Duration::from_secs(600)).await.unwrap();
    assert_eq!(user.email, email.to_lowercase());
    assert!(user.password_hash.is_none());

    // No password yet: login fails like a wrong password.
    let r = t.req("POST", "/auth/login", Some(json!({ "email": email, "password": "whatever-whatever" })), &[]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let r = t.req("GET", &format!("/auth/setup?token={token}"), None, &[]).await;
    assert_eq!(r.body["email"], email.to_lowercase());
    let r = t.req("POST", "/auth/setup", Some(json!({ "token": token, "password": "short" })), &[]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = t.req("POST", "/auth/setup", Some(json!({ "token": token, "password": "a long enough password" })), &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let sc = r.set_cookie.unwrap();
    assert!(sc.starts_with("__Host-bsid=") && sc.contains("HttpOnly") && sc.contains("SameSite=Strict") && sc.contains("Secure") && sc.contains("Path=/"), "{sc}");
    let setup_cookie = cookie_pair(&sc);

    // The token is single-use.
    let r = t.req("POST", "/auth/setup", Some(json!({ "token": token, "password": "another long password" })), &[]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(t.req("GET", &format!("/auth/setup?token={token}"), None, &[]).await.status, StatusCode::NOT_FOUND);

    let r = t.req("POST", "/auth/login", Some(json!({ "email": email, "password": "wrong password here" })), &[]).await;
    assert_eq!((r.status, r.set_cookie.is_none()), (StatusCode::UNAUTHORIZED, true));
    let r = t.req("POST", "/auth/login", Some(json!({ "email": email.to_uppercase(), "password": "a long enough password" })), &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let cookie = cookie_pair(&r.set_cookie.unwrap());
    let csrf = r.body["csrf_token"].as_str().unwrap().to_string();

    let me = t.req("GET", "/auth/me", None, &[("cookie", &cookie)]).await;
    assert_eq!((me.body["email"].as_str(), me.body["csrf_token"].as_str()), (Some(email.to_lowercase().as_str()), Some(csrf.as_str())));
    assert_eq!(t.req("GET", "/wallets", None, &[("cookie", &setup_cookie)]).await.status, StatusCode::OK);

    let r = t.req("POST", "/auth/logout", None, &[("cookie", &cookie)]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.set_cookie.unwrap().contains("Max-Age=0"));
    assert_eq!(t.req("GET", "/wallets", None, &[("cookie", &cookie)]).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.req("GET", "/auth/me", None, &[("cookie", &cookie)]).await.status, StatusCode::UNAUTHORIZED);
    // Logging out one session leaves the other.
    assert_eq!(t.req("GET", "/wallets", None, &[("cookie", &setup_cookie)]).await.status, StatusCode::OK);

    // A re-issued setup token (password reset) revokes the old sessions once redeemed.
    let (_, t2) = auth::issue_setup_token(&mut c, &email, false, std::time::Duration::from_secs(600)).await.unwrap();
    let r = t.req("POST", "/auth/setup", Some(json!({ "token": t2, "password": "a brand new password" })), &[]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(t.req("GET", "/wallets", None, &[("cookie", &setup_cookie)]).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invites_are_admin_only_and_bootstrap_is_one_shot() {
    let t = setup(|_| {}).await;
    let plain = t.user().await;
    let r = t.as_(&plain, "POST", "/auth/invites", Some(json!({ "email": "x@example.test" }))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(t.as_(&plain, "GET", "/auth/users", None).await.status, StatusCode::FORBIDDEN);

    // Bootstrap an admin from env-style inputs.
    let admin_email = format!("admin-{}@example.test", uuid::Uuid::new_v4());
    let boot = auth::random_token();
    let mut c = t.pool.acquire().await.unwrap();
    assert!(auth::bootstrap_admin(&mut c, &admin_email, "too-short", std::time::Duration::from_secs(600)).await.is_err());
    assert!(auth::bootstrap_admin(&mut c, &admin_email, &boot, std::time::Duration::from_secs(600)).await.unwrap());
    // A restart re-runs it: still the same valid token.
    assert!(auth::bootstrap_admin(&mut c, &admin_email, &boot, std::time::Duration::from_secs(600)).await.unwrap());
    let r = t.req("POST", "/auth/setup", Some(json!({ "token": boot, "password": "admin password 123" })), &[]).await;
    assert_eq!((r.status, r.body["is_admin"].as_bool()), (StatusCode::OK, Some(true)), "{}", r.body);
    let admin = Session {
        user_id: uuid::Uuid::nil(),
        email: admin_email.clone(),
        cookie: cookie_pair(&r.set_cookie.unwrap()),
        csrf: r.body["csrf_token"].as_str().unwrap().to_string(),
    };
    // After a password exists, a restart doesn't revive the token.
    assert!(!auth::bootstrap_admin(&mut c, &admin_email, &boot, std::time::Duration::from_secs(600)).await.unwrap());
    assert_eq!(t.req("GET", &format!("/auth/setup?token={boot}"), None, &[]).await.status, StatusCode::NOT_FOUND);

    let r = t.as_(&admin, "POST", "/auth/invites", Some(json!({ "email": "Friend@Example.test" }))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.body["email"], "friend@example.test");
    let tok = r.body["setup_token"].as_str().unwrap();
    assert_eq!(t.req("GET", &format!("/auth/setup?token={tok}"), None, &[]).await.body["email"], "friend@example.test");
    let users = t.as_(&admin, "GET", "/auth/users", None).await.body;
    assert!(users.as_array().unwrap().iter().any(|u| u["email"] == "friend@example.test" && u["active"] == false));
    assert!(!users.to_string().contains("argon2"), "hashes never leave the server");
    let r = t.as_(&admin, "POST", "/auth/invites", Some(json!({ "email": "not-an-email" }))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_rate_limited_429() {
    let t = setup(|st| {
        st.limits = RateLimits::custom((1000, 1000), (1000, 1000), (1, 3));
        st.auth = Arc::new(AuthConfig { client_ip_header: Some("x-real-ip".parse().unwrap()), ..AuthConfig::default() });
    })
    .await;
    let bad = |e: &str| json!({ "email": e, "password": "wrong password here" });
    let ip1 = [("x-real-ip", "203.0.113.1")];
    for i in 0..3 {
        let r = t.req("POST", "/auth/login", Some(bad(&format!("u{i}@example.test"))), &ip1).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    let r = t.req("POST", "/auth/login", Some(bad("u9@example.test")), &ip1).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));
    assert!(r.retry_after.unwrap().parse::<u64>().unwrap() >= 1);
    // Setup-token guessing shares the login bucket.
    let r = t.req("GET", "/auth/setup?token=abc", None, &ip1).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);

    // Another IP is unaffected...
    let ip2 = [("x-real-ip", "203.0.113.2")];
    assert_eq!(t.req("POST", "/auth/login", Some(bad("v@example.test")), &ip2).await.status, StatusCode::UNAUTHORIZED);
    // ...but the per-email bucket stops one account being hammered from many IPs.
    for i in 0..2 {
        let ip = format!("198.51.100.{i}");
        t.req("POST", "/auth/login", Some(bad("target@example.test")), &[("x-real-ip", &ip)]).await;
    }
    let r = t.req("POST", "/auth/login", Some(bad("target@example.test")), &[("x-real-ip", "198.51.100.77")]).await;
    // That was target@'s 3rd attempt (bucket of 3), each from a fresh IP; the 4th is refused.
    let r2 = t.req("POST", "/auth/login", Some(bad("target@example.test")), &[("x-real-ip", "198.51.100.78")]).await;
    assert_eq!((r.status, r2.status), (StatusCode::UNAUTHORIZED, StatusCode::TOO_MANY_REQUESTS));
}

#[tokio::test]
async fn per_ip_and_per_user_limits_429() {
    let t = setup(|st| {
        st.limits = RateLimits::custom((1, 4), (1, 3), (1000, 1000));
        st.auth = Arc::new(AuthConfig { client_ip_header: Some("x-real-ip".parse().unwrap()), ..AuthConfig::default() });
    })
    .await;
    for _ in 0..4 {
        assert_eq!(t.req("GET", "/health", None, &[("x-real-ip", "192.0.2.1")]).await.status, StatusCode::OK);
    }
    let r = t.req("GET", "/health", None, &[("x-real-ip", "192.0.2.1")]).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.retry_after.is_some());
    // The proxy header's last entry is the one used (a client-supplied prefix can't dodge it).
    let r = t.req("GET", "/health", None, &[("x-real-ip", "1.2.3.4, 192.0.2.1")]).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);

    // Per user: the same session from different IPs still hits its own bucket.
    let s = t.user().await;
    for i in 0..3 {
        let ip = format!("192.0.2.{}", 10 + i);
        let r = t.req("GET", "/wallets", None, &[("cookie", &s.cookie), ("x-real-ip", &ip)]).await;
        assert_eq!(r.status, StatusCode::OK);
    }
    let r = t.req("GET", "/wallets", None, &[("cookie", &s.cookie), ("x-real-ip", "192.0.2.99")]).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn network_pin_and_wallet_delete() {
    let t = setup(|st| st.pinned_network = Some(Network::Signet)).await;
    let s = t.user().await;
    let owners: Vec<Value> = three_owners()
        .iter()
        .map(|o| json!({ "name": o.name, "xpub": o.xpub.to_string(), "fingerprint": o.fingerprint.to_string(), "path": "m/48'/1'/0'/2'" }))
        .collect();
    for net in ["testnet4", "regtest", "bitcoin", "mainnet"] {
        let r = t.as_(&s, "POST", "/wallets", Some(json!({ "name": "W", "network": net, "threshold": 2, "owners": owners }))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{net}: {}", r.body);
    }
    let wid = t.wallet(&s).await;
    // A queued proposal blocks deletion.
    let addr = t.as_(&s, "GET", &format!("/wallets/{wid}/addresses?kind=receive&next=true"), None).await.body;
    t.as_(&s, "POST", "/dev/fund", Some(json!({ "address": addr["address"], "amount_sats": 50_000 }))).await;
    t.as_(&s, "POST", "/dev/mine", Some(json!({}))).await;
    t.as_(&s, "POST", &format!("/wallets/{wid}/sync"), None).await;
    let p = t.as_(&s, "POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 10_000 }], "fee_rate_sat_vb": 2.0 }))).await;
    assert_eq!(p.status, StatusCode::CREATED, "{}", p.body);
    assert_eq!(t.as_(&s, "DELETE", &format!("/wallets/{wid}"), None).await.status, StatusCode::CONFLICT);
    t.as_(&s, "DELETE", &format!("/proposals/{}", p.body["id"]), None).await;
    assert_eq!(t.as_(&s, "DELETE", &format!("/wallets/{wid}"), None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(t.as_(&s, "GET", &format!("/wallets/{wid}"), None).await.status, StatusCode::NOT_FOUND);
    assert!(t.as_(&s, "GET", "/wallets", None).await.body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn insecure_cookie_mode_for_local_http() {
    let t = setup(|st| st.auth = Arc::new(AuthConfig { cookie_secure: false, ..AuthConfig::default() })).await;
    let mut c = t.pool.acquire().await.unwrap();
    let email = format!("dev-{}@example.test", uuid::Uuid::new_v4());
    let (_, tok) = auth::issue_setup_token(&mut c, &email, false, std::time::Duration::from_secs(60)).await.unwrap();
    let r = t.req("POST", "/auth/setup", Some(json!({ "token": tok, "password": "local dev password" })), &[]).await;
    let sc = r.set_cookie.unwrap();
    assert!(sc.starts_with("bsid=") && !sc.contains("Secure") && sc.contains("HttpOnly"), "{sc}");
}

#[tokio::test]
async fn delete_user_refused_while_sole_member() {
    let t = setup(|_| {}).await;
    let (a, b) = (t.user().await, t.user().await);
    let wid = t.wallet(&a).await;
    let mut c = t.pool.acquire().await.unwrap();
    let r = btc_safe_store::users::delete_user(&mut c, a.user_id).await.unwrap();
    assert_eq!(r, Err(vec![wid.parse().unwrap()]));
    // Roles: B as a viewer isn't enough (A would leave the wallet without an admin)...
    t.as_(&a, "POST", &format!("/wallets/{wid}/members"), Some(json!({ "email": b.email }))).await;
    assert_eq!(btc_safe_store::users::delete_user(&mut c, a.user_id).await.unwrap(), Err(vec![wid.parse().unwrap()]));
    // ...B as a second admin is.
    t.as_(&a, "PATCH", &format!("/wallets/{wid}/members/{}", b.user_id), Some(json!({ "role": "admin" }))).await;
    assert_eq!(btc_safe_store::users::delete_user(&mut c, a.user_id).await.unwrap(), Ok(()));
    assert_eq!(t.as_(&a, "GET", "/wallets", None).await.status, StatusCode::UNAUTHORIZED, "sessions go with the user");
    assert_eq!(t.as_(&b, "GET", &format!("/wallets/{wid}"), None).await.status, StatusCode::OK);
}

/// The proposer and every audit-log actor come from the session, never from the request body.
#[tokio::test]
async fn proposer_and_audit_actor_are_the_logged_in_user() {
    use bitcoin::psbt::Psbt;
    use std::str::FromStr;
    let t = setup(|_| {}).await;
    let (a, b) = (t.user().await, t.user().await);
    let w = t.wallet(&a).await;
    // Roles: B needs admin here (B deletes A's proposal and changes a wallet setting).
    t.as_(&a, "POST", &format!("/wallets/{w}/members"), Some(json!({ "email": b.email, "role": "admin" }))).await;
    let addr = t.as_(&a, "GET", &format!("/wallets/{w}/addresses?kind=receive&next=true"), None).await.body;
    t.as_(&a, "POST", "/dev/fund", Some(json!({ "address": addr["address"], "amount_sats": 100_000 }))).await;
    t.as_(&a, "POST", "/dev/mine", Some(json!({}))).await;
    t.as_(&a, "POST", &format!("/wallets/{w}/sync"), None).await;
    let body = |by: Option<&str>| {
        let mut v = json!({ "outputs": [{ "address": RCPT, "amount_sats": 10_000 }], "fee_rate_sat_vb": 2.0 });
        if let Some(by) = by {
            v["created_by"] = json!(by);
        }
        Some(v)
    };

    // A tries to file a proposal in B's name (or an owner's name): refused.
    for spoof in [b.email.as_str(), "Alice", "api"] {
        let r = t.as_(&a, "POST", &format!("/wallets/{w}/proposals"), body(Some(spoof))).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{spoof}: {}", r.body);
    }
    // Omitted (or A's own email): the server records A.
    let p = t.as_(&a, "POST", &format!("/wallets/{w}/proposals"), body(None)).await;
    assert_eq!(p.status, StatusCode::CREATED, "{}", p.body);
    assert_eq!(p.body["created_by"], json!(a.email));
    let pid = p.body["id"].as_i64().unwrap();
    assert_eq!(t.as_(&b, "GET", &format!("/proposals/{pid}"), None).await.body["created_by"], json!(a.email));

    // B uploads a signature, then B deletes it: the audit log names B, not "signer"/"api".
    let psbt_s = t.as_(&b, "GET", &format!("/proposals/{pid}"), None).await.body["psbt"].as_str().unwrap().to_string();
    let mut psbt = Psbt::from_str(&psbt_s).unwrap();
    assert!(three_owners()[0].sign(&mut psbt) > 0);
    let r = t.as_(&b, "POST", &format!("/proposals/{pid}/signatures"), Some(json!({ "psbt": psbt.to_string() }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = t.as_(&b, "DELETE", &format!("/proposals/{pid}"), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = t.as_(&b, "PATCH", &format!("/wallets/{w}"), Some(json!({ "ordering_mode": "strict" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    let wid = uuid::Uuid::parse_str(&w).unwrap();
    let rows: Vec<(String, String)> = btc_safe_store::sqlx::query_as("SELECT action, actor FROM audit_log WHERE wallet_id = $1 ORDER BY id")
        .bind(wid)
        .fetch_all(&t.pool)
        .await
        .unwrap();
    let actor_of = |action: &str| rows.iter().filter(|(a, _)| a == action).map(|(_, who)| who.clone()).collect::<Vec<_>>();
    assert_eq!(actor_of("proposal_created"), vec![a.email.clone()]);
    assert_eq!(actor_of("signatures_added"), vec![b.email.clone()]);
    assert_eq!(actor_of("ordering_mode"), vec![b.email.clone()]);
    // Status changes: "ready" after B's signature isn't reached (1 of 2); the delete is B's.
    assert_eq!(actor_of("proposal_status").last(), Some(&b.email));
    for (action, who) in &rows {
        assert!(who != "api" && who != "signer", "{action} logged as {who}");
    }
}
