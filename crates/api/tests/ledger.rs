//! Ledger policy registration endpoints (crates/api/src/ledger.rs) over HTTP, real Postgres.
//! The HMACs here are arbitrary 32-byte values: the server can't verify them (they're keyed
//! by the device's seed), so what's under test is the policy check and the wallet scoping.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use bitcoin::Network;
use btc_safe_api::{router, AppState};
use btc_safe_chain::MemoryChain;
use btc_safe_testkit::three_owners;
use btc_safe_watcher::WalletCache;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

struct App {
    router: Router,
    s: common::Session,
}

async fn app() -> App {
    let url = std::env::var("BTC_SAFE_TEST_DATABASE_URL").unwrap_or_else(|_| {
        format!("postgres:///btc_safe_test?host=/tmp&user={}", std::env::var("USER").unwrap_or_else(|_| "postgres".into()))
    });
    let mem = MemoryChain::new(Network::Signet);
    let pool = btc_safe_store::connect(&url).await.unwrap();
    let st = AppState::new(pool.clone(), Arc::new(WalletCache::new()), Arc::new(mem.clone()), Some(mem));
    let s = common::login(&pool, &st.auth).await;
    App { router: router(st), s }
}

async fn call(app: &App, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path).header("cookie", &app.s.cookie).header("x-csrf-token", &app.s.csrf);
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let res = app.router.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() })
}

async fn wallet(app: &App, name: &str) -> Value {
    let owners: Vec<Value> = three_owners()
        .iter()
        .map(|o| json!({ "name": o.name, "xpub": o.xpub.to_string(), "fingerprint": o.fingerprint.to_string(), "path": "m/48'/1'/0'/2'" }))
        .collect();
    let (s, v) = call(app, "POST", "/wallets", Some(json!({ "name": name, "network": "signet", "threshold": 2, "owners": owners }))).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let (_, w) = call(app, "GET", &format!("/wallets/{}", v["id"].as_str().unwrap()), None).await;
    w
}

const HMAC: &str = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

#[tokio::test]
async fn register_store_and_scope() {
    let app = app().await;
    let w = wallet(&app, "  Treasury ✓ ").await;
    let wid = w["id"].as_str().unwrap();
    let owner0 = w["owners"][0]["id"].as_str().unwrap();

    let (s, g) = call(&app, "GET", &format!("/wallets/{wid}/ledger"), None).await;
    assert_eq!(s, StatusCode::OK, "{g}");
    let policy = g["policy"].clone();
    assert_eq!(policy["name"], "Treasury", "device-safe name");
    assert_eq!(policy["descriptor_template"], "wsh(sortedmulti(2,@0/**,@1/**,@2/**))");
    let o = &three_owners()[0];
    assert_eq!(policy["keys"][0], format!("[{}/48'/1'/0'/2']{}", o.fingerprint, o.xpub));
    assert!(g["registrations"].as_array().unwrap().is_empty());
    let pid = g["policy_id"].as_str().unwrap().to_string();
    let body = |p: &Value, id: &str, h: &str| json!({ "policy": p, "policy_id": id, "hmac": h });

    // Wrong policy: swapped key order, a different threshold, or another name.
    let mut swapped = policy.clone();
    swapped["keys"].as_array_mut().unwrap().swap(0, 1);
    let mut one_of = policy.clone();
    one_of["descriptor_template"] = json!("wsh(sortedmulti(1,@0/**,@1/**,@2/**))");
    let mut renamed = policy.clone();
    renamed["name"] = json!("Other");
    for bad in [&swapped, &one_of, &renamed] {
        let (s, v) = call(&app, "PUT", &format!("/wallets/{wid}/ledger/owners/{owner0}"), Some(body(bad, &pid, HMAC))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    }
    // Right policy, wrong id; short hmac; non-hex hmac.
    let (s, _) = call(&app, "PUT", &format!("/wallets/{wid}/ledger/owners/{owner0}"), Some(body(&policy, HMAC, HMAC))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(&app, "PUT", &format!("/wallets/{wid}/ledger/owners/{owner0}"), Some(body(&policy, &pid, &HMAC[..62]))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(&app, "PUT", &format!("/wallets/{wid}/ledger/owners/{owner0}"), Some(body(&policy, &pid, &"zz".repeat(32)))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Owner of another wallet can't be registered here, and vice versa.
    let other = wallet(&app, "Other").await;
    let other_owner = other["owners"][0]["id"].as_str().unwrap();
    let (s, _) = call(&app, "PUT", &format!("/wallets/{wid}/ledger/owners/{other_owner}"), Some(body(&policy, &pid, HMAC))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Good registration, then an overwrite.
    let (s, v) = call(&app, "PUT", &format!("/wallets/{wid}/ledger/owners/{owner0}"), Some(body(&policy, &pid, HMAC))).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let h2 = "ff".repeat(32);
    let (s, _) = call(&app, "PUT", &format!("/wallets/{wid}/ledger/owners/{owner0}"), Some(body(&policy, &pid, &h2))).await;
    assert_eq!(s, StatusCode::CREATED);
    let (_, g) = call(&app, "GET", &format!("/wallets/{wid}/ledger"), None).await;
    let regs = g["registrations"].as_array().unwrap();
    assert_eq!(regs.len(), 1);
    assert_eq!(regs[0]["hmac"], h2);
    assert_eq!(regs[0]["fingerprint"], o.fingerprint.to_string());
    assert_eq!(regs[0]["matches_wallet"], true);

    // Scoped: the other wallet sees none of it.
    let (_, g2) = call(&app, "GET", &format!("/wallets/{}/ledger", other["id"].as_str().unwrap()), None).await;
    assert!(g2["registrations"].as_array().unwrap().is_empty());

    // Behind login, and the HMAC never goes to the audit log.
    let open = Request::builder().uri(format!("/wallets/{wid}/ledger")).body(Body::empty()).unwrap();
    assert_eq!(app.router.clone().oneshot(open).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    let (s, _) = call(&app, "DELETE", &format!("/wallets/{wid}/ledger/owners/{owner0}"), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(&app, "DELETE", &format!("/wallets/{wid}/ledger/owners/{owner0}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn hmac_not_in_audit_log() {
    let app = app().await;
    let w = wallet(&app, "Audit").await;
    let wid = w["id"].as_str().unwrap();
    let owner = w["owners"][1]["id"].as_str().unwrap();
    let (_, g) = call(&app, "GET", &format!("/wallets/{wid}/ledger"), None).await;
    let (s, _) = call(
        &app,
        "PUT",
        &format!("/wallets/{wid}/ledger/owners/{owner}"),
        Some(json!({ "policy": g["policy"], "policy_id": g["policy_id"], "hmac": HMAC })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let url = std::env::var("BTC_SAFE_TEST_DATABASE_URL").unwrap_or_else(|_| {
        format!("postgres:///btc_safe_test?host=/tmp&user={}", std::env::var("USER").unwrap_or_else(|_| "postgres".into()))
    });
    let pool = btc_safe_store::connect(&url).await.unwrap();
    let n: i64 = btc_safe_store::sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE wallet_id = $1::uuid AND payload::text LIKE '%' || $2 || '%'")
        .bind(wid)
        .bind(HMAC)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}
