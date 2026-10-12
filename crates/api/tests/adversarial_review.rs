//! Adversarial review (2026-10-07), HTTP level. In-process router, MemoryChain, real Postgres
//! ($BTC_SAFE_TEST_DATABASE_URL, else the local socket DB btc_safe_test as $USER).
//!
//! Tests named `fixed_*` started as repros written by the reviewer (they asserted the defect);
//! after the fixes they assert the corrected behaviour and stay as regression tests.
//! Tests named `rejects_*` assert an attack is correctly refused.

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use bitcoin::psbt::Psbt;
use bitcoin::{Network, OutPoint, Transaction, Txid};
use btc_safe_api::{router, AppState};
use btc_safe_chain::{ChainSource, FeeEstimates, MemoryChain, ScanRequest, Spend, TxState};
use btc_safe_store::sqlx::{self, Connection, PgPool};
use btc_safe_testkit::{three_owners, TestOwner};
use btc_safe_watcher::WalletCache;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokio::sync::Notify;
use tower::ServiceExt;

mod common;

const RCPT: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

fn db_url() -> String {
    std::env::var("BTC_SAFE_TEST_DATABASE_URL").unwrap_or_else(|_| {
        format!("postgres:///btc_safe_test?host=/tmp&user={}", std::env::var("USER").unwrap_or_else(|_| "postgres".into()))
    })
}

#[derive(Clone)]
struct Env {
    app: Router,
    s: common::Session,
    mem: MemoryChain,
    pool: PgPool,
    owners: Vec<TestOwner>,
}

async fn env_on(mem: MemoryChain, session: Option<common::Session>) -> Env {
    let pool = btc_safe_store::connect(&db_url()).await.unwrap();
    let state = AppState::new(pool.clone(), Arc::new(WalletCache::new()), Arc::new(mem.clone()), Some(mem.clone()));
    let s = match session {
        Some(s) => s,
        None => common::login(&pool, &state.auth).await,
    };
    Env { app: router(state), s, mem, pool, owners: three_owners() }
}

async fn env() -> Env {
    env_on(MemoryChain::new(Network::Signet), None).await
}

/// A separate connection, outside the app's pool, to hold row locks.
async fn side_conn() -> sqlx::PgConnection {
    sqlx::PgConnection::connect(&db_url()).await.unwrap()
}

impl Env {
    /// `_auth` is a leftover of the static-token era; every call now carries the session.
    async fn call_h(&self, method: &str, path: &str, body: Option<Value>, _auth: Option<&str>) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path).header("cookie", &self.s.cookie).header("x-csrf-token", &self.s.csrf);
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let res = self.app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let v = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(json!({ "raw": String::from_utf8_lossy(&bytes) })) };
        (status, v)
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call_h(method, path, body, None).await
    }

    async fn ok(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let (s, v) = self.call(method, path, body).await;
        assert!(s.is_success(), "{method} {path} -> {s}: {v}");
        v
    }

    async fn create_wallet(&self, ordering: &str) -> String {
        let owners: Vec<Value> = self
            .owners
            .iter()
            .map(|o| json!({ "name": o.name, "xpub": o.xpub.to_string(), "fingerprint": o.fingerprint.to_string(), "path": "m/48'/1'/0'/2'" }))
            .collect();
        let v = self
            .ok("POST", "/wallets", Some(json!({ "name": "Treasury", "network": "signet", "threshold": 2, "owners": owners, "ordering_mode": ordering })))
            .await;
        v["id"].as_str().unwrap().to_string()
    }

    async fn fund(&self, wid: &str, n: usize, sats: u64) {
        for _ in 0..n {
            let a = self.ok("GET", &format!("/wallets/{wid}/addresses?kind=receive&next=true"), None).await;
            self.ok("POST", "/dev/fund", Some(json!({ "address": a["address"], "amount_sats": sats }))).await;
        }
        self.ok("POST", "/dev/mine", Some(json!({ "blocks": 1 }))).await;
        self.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    }

    async fn propose(&self, wid: &str, sats: u64) -> (StatusCode, Value) {
        self.call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": sats }], "fee_rate_sat_vb": 2.0 })))
            .await
    }

    async fn sign(&self, pid: i64, i: usize) -> (StatusCode, Value) {
        let p = self.ok("GET", &format!("/proposals/{pid}"), None).await;
        let mut psbt = Psbt::from_str(p["psbt"].as_str().unwrap()).unwrap();
        assert!(self.owners[i].sign(&mut psbt) > 0);
        self.call("POST", &format!("/proposals/{pid}/signatures"), Some(json!({ "psbt": psbt.to_string() }))).await
    }

    async fn status(&self, pid: i64) -> String {
        self.ok("GET", &format!("/proposals/{pid}"), None).await["status"].as_str().unwrap().to_string()
    }
}

fn pid(v: &Value) -> i64 {
    v["id"].as_i64().unwrap()
}

fn finalize_locally(psbt_b64: &str) -> Transaction {
    use btc_safe_core::miniscript::psbt::PsbtExt;
    let mut p = Psbt::from_str(psbt_b64).unwrap();
    p.finalize_mut(&bitcoin::secp256k1::Secp256k1::verification_only()).unwrap();
    p.extract_tx().unwrap()
}

// ===================================================================== findings (bugs)

/// HIGH (availability). Lock-order inversion: `proposals::create` takes the wallet row lock
/// (SELECT .. FOR UPDATE) and then the in-process BDK mutex; `watcher::sync_wallet` takes the
/// BDK mutex and then UPDATEs the wallet row (save_changeset). Interleave them and both hang
/// forever; the hung create keeps the row lock, so every later op on the wallet (incl. the
/// watcher tick, which iterates wallets sequentially) hangs too.
/// The side connection only holds a proposal row lock to make the interleaving deterministic;
/// in production the window is create's work between lock_wallet and cache lock vs a
/// watcher tick's apply_update.
#[tokio::test]
async fn fixed_create_vs_sync_no_deadlock() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 2, 100_000).await;
    let (_, a) = e.propose(&wid, 20_000).await;
    let aid = pid(&a);
    // New chain activity so the next sync has staged BDK changes to persist.
    let addr = e.ok("GET", &format!("/wallets/{wid}/addresses?kind=receive&next=true"), None).await;
    e.ok("POST", "/dev/fund", Some(json!({ "address": addr["address"], "amount_sats": 5_000 }))).await;
    e.ok("POST", "/dev/mine", Some(json!({}))).await;

    // 1. Hold proposal #a's row lock on a side connection.
    let mut side = side_conn().await;
    sqlx::query("BEGIN").execute(&mut side).await.unwrap();
    sqlx::query("SELECT id FROM proposals WHERE id = $1 FOR UPDATE").bind(aid).execute(&mut side).await.unwrap();

    // 2. A replacement of #a: takes the WALLET row lock, then blocks on #a's row lock.
    let e1 = e.clone();
    let w1 = wid.clone();
    let create = tokio::spawn(async move {
        e1.call("POST", &format!("/wallets/{w1}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 15_000 }], "replaces": aid, "fee_rate_sat_vb": 3.0 })))
            .await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 3. A sync (what the watcher does every tick): takes the BDK mutex, then blocks on the
    //    wallet row (UPDATE wallets SET bdk_changeset ...), held by the create.
    let e2 = e.clone();
    let w2 = wid.clone();
    let sync = tokio::spawn(async move { e2.call("POST", &format!("/wallets/{w2}/sync"), None).await });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 4. Release #a. The create proceeds to `cache.get(..).lock()` -> waits on the BDK mutex
    //    held by the sync, which waits on the row lock held by the create.
    sqlx::query("COMMIT").execute(&mut side).await.unwrap();

    // Fixed: one lock order (row lock, then mutex) everywhere; both finish.
    let (c, y) = tokio::time::timeout(Duration::from_secs(15), async { (create.await.unwrap(), sync.await.unwrap()) })
        .await
        .expect("create and sync must not deadlock");
    assert_eq!(c.0, StatusCode::CREATED, "{}", c.1);
    assert_eq!(y.0, StatusCode::OK, "{}", y.1);
}

/// HIGH (availability). Same inversion, no helper needed: two concurrent POST /proposals on
/// one wallet. #1 commits, then (still holding the BDK mutex) persists its staged changeset
/// with UPDATE wallets; #2 was queued on the row lock, gets it first, then waits for the
/// BDK mutex held by #1. Every create stages a newly revealed change index, so the persist
/// always runs.
#[tokio::test]
async fn fixed_two_concurrent_creates() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 2, 100_000).await;
    let (e1, e2, w1, w2) = (e.clone(), e.clone(), wid.clone(), wid.clone());
    let a = tokio::spawn(async move { e1.propose(&w1, 10_000).await });
    let b = tokio::spawn(async move { e2.propose(&w2, 11_000).await });
    let (ra, rb) = tokio::time::timeout(Duration::from_secs(15), async { (a.await.unwrap(), b.await.unwrap()) })
        .await
        .expect("concurrent creates must not deadlock");
    assert_eq!((ra.0, rb.0), (StatusCode::CREATED, StatusCode::CREATED), "{} {}", ra.1, rb.1);
    // Serialized by the wallet row lock: disjoint coins.
    let ia: Vec<&Value> = ra.1["inputs"].as_array().unwrap().iter().map(|i| &i["outpoint"]).collect();
    assert!(rb.1["inputs"].as_array().unwrap().iter().all(|i| !ia.contains(&&i["outpoint"])));
    // The watcher's work on the wallet still runs.
    tokio::time::timeout(Duration::from_secs(5), e.call("POST", &format!("/wallets/{wid}/sync"), None)).await.expect("sync");
    let wu = uuid::Uuid::parse_str(&wid).unwrap();
    tokio::time::timeout(Duration::from_secs(5), btc_safe_watcher::reconcile(&e.pool, &e.mem, wu, btc_safe_watcher::DEFAULT_CONFIRMATIONS_FINAL)).await.expect("reconcile").unwrap();
}

/// MEDIUM (availability, needs a crash/persist failure first). `WalletCache::get` on a cold
/// cache persists staged BDK changes with an UPDATE on the wallet row through a separate pool
/// connection. When called from inside `create` (which already holds that row FOR UPDATE) and
/// there is something to persist, the request deadlocks against its own transaction.
/// Precondition simulated here: an index was allocated and committed (address handout or a
/// proposal) but the BDK changeset wasn't persisted (crash/pool error between commit and
/// `persist`), then the server restarted (fresh cache).
#[tokio::test]
async fn fixed_cold_cache_create() {
    let mem = MemoryChain::new(Network::Signet);
    let e = env_on(mem.clone(), None).await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 1, 100_000).await;
    // Commit of alloc_index without the matching BDK persist.
    sqlx::query("UPDATE wallets SET next_receive_idx = next_receive_idx + 1 WHERE id = $1::uuid")
        .bind(&wid)
        .execute(&e.pool)
        .await
        .unwrap();
    // "Restart": same DB and chain, fresh cache.
    let fresh = env_on(mem.clone(), Some(e.s.clone())).await;
    let (f2, w2) = (fresh.clone(), wid.clone());
    let h = tokio::spawn(async move { f2.propose(&w2, 10_000).await });
    let (st, v) = tokio::time::timeout(Duration::from_secs(15), h).await.expect("cold cache create must not hang").unwrap();
    assert_eq!(st, StatusCode::CREATED, "{v}");
}

/// Chain source that pauses inside the first `outspend` call, i.e. after reconcile has read
/// `tx_state` but before it takes the wallet lock to apply transitions.
struct GateChain {
    inner: MemoryChain,
    armed: AtomicBool,
    reached: Notify,
    resume: Notify,
}

#[async_trait]
impl ChainSource for GateChain {
    fn describe(&self) -> String {
        "gate".into()
    }
    async fn tip(&self) -> btc_safe_chain::Result<u32> {
        self.inner.tip().await
    }
    async fn fee_estimates(&self) -> btc_safe_chain::Result<FeeEstimates> {
        self.inner.fee_estimates().await
    }
    async fn broadcast(&self, tx: &Transaction) -> btc_safe_chain::Result<()> {
        self.inner.broadcast(tx).await
    }
    async fn tx_state(&self, txid: Txid) -> btc_safe_chain::Result<TxState> {
        self.inner.tx_state(txid).await
    }
    async fn outspend(&self, op: OutPoint) -> btc_safe_chain::Result<Option<Spend>> {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.reached.notify_one();
            self.resume.notified().await;
        }
        self.inner.outspend(op).await
    }
    async fn get_tx(&self, txid: Txid) -> btc_safe_chain::Result<Option<Transaction>> {
        self.inner.get_tx(txid).await
    }
    async fn scan(&self, req: ScanRequest) -> btc_safe_chain::Result<btc_safe_wallet::bdk_wallet::Update> {
        self.inner.scan(req).await
    }
}

/// MEDIUM (state integrity). `watcher::reconcile` reads chain facts without locks, then
/// applies them under the lock to a freshly re-read row. If `execute` lands in between, the
/// stale "tx not found" + fresh status BROADCAST = `Dropped` -> READY although the tx is in
/// the mempool. READY can be deleted: the tx then confirms but the proposal stays DELETED
/// forever (reconcile skips inactive rows), reservations are released while the coins are
/// in flight, and in strict-order mode its descendants are cascaded to INVALIDATED.
#[tokio::test]
async fn fixed_reconcile_race_keeps_broadcast() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 1, 100_000).await;
    let (_, p) = e.propose(&wid, 20_000).await;
    let id = pid(&p);
    e.sign(id, 0).await;
    e.sign(id, 1).await;
    assert_eq!(e.status(id).await, "ready");

    let gate = Arc::new(GateChain { inner: e.mem.clone(), armed: AtomicBool::new(true), reached: Notify::new(), resume: Notify::new() });
    let (pool, g2) = (e.pool.clone(), gate.clone());
    let w = uuid::Uuid::parse_str(&wid).unwrap();
    let rec = tokio::spawn(async move { btc_safe_watcher::reconcile(&pool, g2.as_ref(), w, btc_safe_watcher::DEFAULT_CONFIRMATIONS_FINAL).await });
    gate.reached.notified().await; // reconcile has seen tx_state = NotFound

    let x = e.ok("POST", &format!("/proposals/{id}/execute"), None).await;
    assert_eq!(x["status"], "broadcast");
    let txid: Txid = x["txid"].as_str().unwrap().parse().unwrap();
    assert_eq!(e.mem.tx_state(txid).await.unwrap(), TxState::Mempool);

    gate.resume.notify_one();
    let changes = rec.await.unwrap().unwrap();
    eprintln!("reconcile transitions: {changes:?}");
    // Fixed: stale chain facts are discarded when the status moved under us.
    assert!(changes.is_empty(), "{changes:?}");
    assert_eq!(e.status(id).await, "broadcast");
    let (s, _) = e.call("DELETE", &format!("/proposals/{id}"), None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    e.ok("POST", "/dev/mine", Some(json!({}))).await;
    e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert!(matches!(e.mem.tx_state(txid).await.unwrap(), TxState::Confirmed { .. }));
    assert_eq!(e.status(id).await, "soft_confirmed");
    e.ok("POST", "/dev/mine", Some(json!({}))).await;
    e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(e.status(id).await, "confirmed");
}

/// LOW (liveness, strict-order). The cascade for "a sibling replacement was broadcast" only
/// runs in `execute`. If the replacement reaches the mempool any other way (an owner
/// finalizes and broadcasts it from Sparrow), the watcher just marks it BROADCAST and the
/// original's descendants stay queued and executable until the replacement confirms.
#[tokio::test]
async fn fixed_strict_cascade_when_replacement_broadcast_externally() {
    let e = env().await;
    let wid = e.create_wallet("strict").await;
    e.fund(&wid, 1, 300_000).await;
    let (_, a) = e.propose(&wid, 50_000).await;
    let (_, b) = e.propose(&wid, 40_000).await;
    let (ia, ib) = (pid(&a), pid(&b));
    assert_eq!(b["predecessor"], ia);
    for id in [ia, ib] {
        e.sign(id, 0).await;
        e.sign(id, 1).await;
    }
    e.ok("POST", &format!("/proposals/{ia}/execute"), None).await;
    let (s, r) = e.call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "replaces": ia, "replace_mode": "bump", "fee_rate_sat_vb": 6.0 }))).await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    let ir = pid(&r);
    e.sign(ir, 1).await;
    e.sign(ir, 2).await;
    // Out-of-band broadcast of the bump.
    let signed = e.ok("GET", &format!("/proposals/{ir}"), None).await;
    let tx = finalize_locally(signed["psbt"].as_str().unwrap());
    e.ok("POST", "/dev/inject", Some(json!({ "tx_hex": bitcoin::consensus::encode::serialize_hex(&tx) }))).await;
    e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(e.status(ir).await, "broadcast");
    // Fixed: the watcher runs the same cascade as execute.
    assert_eq!(e.status(ib).await, "invalidated");
    // The original is conflicted once the bump is final (2 confirmations by default).
    e.ok("POST", "/dev/mine", Some(json!({ "blocks": 2 }))).await;
    e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(e.status(ia).await, "conflicted");
    assert_eq!(e.status(ib).await, "invalidated");
}

/// LOW (liveness, parallel mode). A proposal may spend the unconfirmed change of a broadcast
/// proposal (no predecessor link in parallel mode). If the parent is RBF-replaced, the child's
/// input never exists: nothing ever spends it, so reconcile never invalidates the child and
/// it stays queued (and signable/executable) forever.
#[tokio::test]
async fn fixed_parallel_child_of_replaced_parent_invalidated() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 1, 100_000).await;
    let (_, a) = e.propose(&wid, 20_000).await;
    let ia = pid(&a);
    e.sign(ia, 0).await;
    e.sign(ia, 1).await;
    e.ok("POST", &format!("/proposals/{ia}/execute"), None).await;
    e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    let a = e.ok("GET", &format!("/proposals/{ia}"), None).await;
    let cv = a["outputs"].as_array().unwrap().iter().find(|o| o["is_change"] == true).unwrap()["vout"].as_i64().unwrap();
    let change = format!("{}:{}", a["unsigned_txid"].as_str().unwrap(), cv);
    let (s, b) = e
        .call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 10_000 }], "utxos": [change], "fee_rate_sat_vb": 2.0 })))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let ib = pid(&b);
    let (_, r) = e.call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "replaces": ia, "replace_mode": "bump", "fee_rate_sat_vb": 6.0 }))).await;
    let ir = pid(&r);
    e.sign(ir, 0).await;
    e.sign(ir, 1).await;
    e.ok("POST", &format!("/proposals/{ir}/execute"), None).await;
    for _ in 0..2 {
        e.ok("POST", "/dev/mine", Some(json!({}))).await;
        e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    }
    assert_eq!(e.status(ir).await, "confirmed");
    assert_eq!(e.status(ia).await, "conflicted");
    // Fixed: its parent died off-chain, so its input will never exist.
    let pb = e.ok("GET", &format!("/proposals/{ib}"), None).await;
    assert_eq!((pb["status"].as_str(), pb["status_reason"].as_str()), (Some("invalidated"), Some("parent_replaced")), "{pb}");
}

/// MEDIUM (availability, unauthenticated). POST /proposals/{id}/signatures is open by design,
/// ids are sequential, and the handler takes a pool connection and the wallet's row lock
/// BEFORE any cheap check of the submitted PSBT. A few concurrent junk submissions queue
/// on the row lock while each holding one of the pool's 10 connections, starving every
/// other request on every wallet (and the watcher).
#[tokio::test]
async fn fixed_signature_flood_doesnt_starve_pool() {
    let e = env_on(MemoryChain::new(Network::Signet), None).await;
    // Two unrelated wallets. Authenticated setup.
    let mut owners_json = vec![];
    for o in &e.owners {
        owners_json.push(json!({ "name": o.name, "xpub": o.xpub.to_string(), "fingerprint": o.fingerprint.to_string(), "path": "m/48'/1'/0'/2'" }));
    }
    let mk = |name: &str| json!({ "name": name, "network": "signet", "threshold": 2, "owners": owners_json, "ordering_mode": "parallel" });
    let (_, w1) = e.call_h("POST", "/wallets", Some(mk("victim")), Some("tok")).await;
    let (_, w2) = e.call_h("POST", "/wallets", Some(mk("bystander")), Some("tok")).await;
    let (w1, w2) = (w1["id"].as_str().unwrap().to_string(), w2["id"].as_str().unwrap().to_string());
    let a = e.call_h("GET", &format!("/wallets/{w1}/addresses?kind=receive&next=true"), None, Some("tok")).await.1;
    e.call_h("POST", "/dev/fund", Some(json!({ "address": a["address"], "amount_sats": 100_000 })), Some("tok")).await;
    e.call_h("POST", "/dev/mine", Some(json!({})), Some("tok")).await;
    e.call_h("POST", &format!("/wallets/{w1}/sync"), None, Some("tok")).await;
    let (s, p) = e
        .call_h("POST", &format!("/wallets/{w1}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 1000 }], "fee_rate_sat_vb": 2.0 })), Some("tok"))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{p}");
    let id = pid(&p);

    // Junk an attacker can make without the proposal: any parseable PSBT.
    let junk = "cHNidP8BAAoCAAAAAAAAAAAAAAAA";
    // Since login: unknown ids (and other wallets' ids) are 404 from the membership check, so
    // probing ids needs an account that is a member; junk on a real id is still refused cheaply.
    let (s1, _) = e.call("POST", "/proposals/999999999/signatures", Some(json!({ "psbt": junk }))).await;
    let (s2, _) = e.call("POST", &format!("/proposals/{id}/signatures"), Some(json!({ "psbt": junk }))).await;
    assert_eq!((s1, s2), (StatusCode::NOT_FOUND, StatusCode::UNPROCESSABLE_ENTITY));

    // Simulate the victim wallet's row lock being busy (any legit create/execute does this,
    // or the attacker's own previous request).
    let mut side = side_conn().await;
    sqlx::query("BEGIN").execute(&mut side).await.unwrap();
    sqlx::query("SELECT id FROM wallets WHERE id = $1::uuid FOR UPDATE").bind(&w1).execute(&mut side).await.unwrap();

    let mut floods = vec![];
    for _ in 0..12 {
        let e = e.clone();
        floods.push(tokio::spawn(async move { e.call("POST", &format!("/proposals/{id}/signatures"), Some(json!({ "psbt": junk }))).await }));
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    // An authenticated read on a DIFFERENT wallet now can't get a connection.
    let t = Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(4), e.call_h("GET", &format!("/wallets/{w2}"), None, Some("tok"))).await;
    eprintln!("bystander GET after {:?}: {:?}", t.elapsed(), r.as_ref().map(|x| x.0));
    let starved = r.is_err();
    sqlx::query("COMMIT").execute(&mut side).await.unwrap();
    for f in floods {
        let (s, _) = f.await.unwrap();
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert!(!starved, "unrelated wallet starved by unauthenticated junk submissions");
}

/// LOW (robustness, authenticated). Recipient amounts are unbounded u64; two outputs whose sum
/// overflows u64 hit an arithmetic overflow inside coin selection instead of a 400.
#[tokio::test]
async fn fixed_huge_amounts_rejected() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 1, 100_000).await;
    let e1 = e.clone();
    let h = tokio::spawn(async move {
        e1.call(
            "POST",
            &format!("/wallets/{wid}/proposals"),
            Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 1u64 << 63 }, { "address": RCPT, "amount_sats": 1u64 << 63 }], "fee_rate_sat_vb": 2.0 })),
        )
        .await
    });
    let (s, v) = h.await.expect("no panic");
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

// ===================================================================== correctly rejected

#[tokio::test]
async fn rejects_illegal_transitions_over_http() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 2, 100_000).await;
    let (_, p) = e.propose(&wid, 20_000).await;
    let id = pid(&p);
    // Execute with 0 and 1 signatures.
    assert_eq!(e.call("POST", &format!("/proposals/{id}/execute"), None).await.0, StatusCode::CONFLICT);
    e.sign(id, 0).await;
    assert_eq!(e.call("POST", &format!("/proposals/{id}/execute"), None).await.0, StatusCode::CONFLICT);
    e.sign(id, 1).await;
    let x1 = e.ok("POST", &format!("/proposals/{id}/execute"), None).await;
    // Double execute: idempotent rebroadcast, same txid, still broadcast.
    let x2 = e.ok("POST", &format!("/proposals/{id}/execute"), None).await;
    assert_eq!((x1["txid"].clone(), x2["status"].clone()), (x2["txid"].clone(), json!("broadcast")));
    assert_eq!(e.mem.broadcasts().len(), 1);
    // Delete after broadcast; sign after broadcast; rebuild-replace after broadcast.
    assert_eq!(e.call("DELETE", &format!("/proposals/{id}"), None).await.0, StatusCode::CONFLICT);
    assert_eq!(e.sign(id, 2).await.0, StatusCode::CONFLICT);
    let (s, _) = e
        .call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 1000 }], "replaces": id, "replace_mode": "rebuild", "fee_rate_sat_vb": 9.0 })))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Soft-confirmed (1 block), then final (2): delete / execute / sign / replace all refused.
    for want in ["soft_confirmed", "confirmed"] {
        e.ok("POST", "/dev/mine", Some(json!({}))).await;
        e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
        assert_eq!(e.status(id).await, want);
        assert_eq!(e.call("DELETE", &format!("/proposals/{id}"), None).await.0, StatusCode::CONFLICT);
        assert_eq!(e.call("POST", &format!("/proposals/{id}/execute"), None).await.0, StatusCode::CONFLICT);
        assert_eq!(e.sign(id, 2).await.0, StatusCode::CONFLICT);
        for mode in ["bump", "cancel"] {
            let (s, _) = e.call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "replaces": id, "replace_mode": mode, "fee_rate_sat_vb": 9.0 }))).await;
            assert_eq!(s, StatusCode::CONFLICT, "{want} {mode}");
        }
        assert_eq!(e.mem.broadcasts().len(), 1, "nothing re-sent");
    }
    // Deleted: execute / sign / double delete refused, even when fully signed.
    let (_, q) = e.propose(&wid, 10_000).await;
    let q = pid(&q);
    e.sign(q, 0).await;
    e.sign(q, 1).await;
    e.ok("DELETE", &format!("/proposals/{q}"), None).await;
    assert_eq!(e.call("POST", &format!("/proposals/{q}/execute"), None).await.0, StatusCode::CONFLICT);
    assert_eq!(e.sign(q, 2).await.0, StatusCode::CONFLICT);
    assert_eq!(e.call("DELETE", &format!("/proposals/{q}"), None).await.0, StatusCode::CONFLICT);
}

#[tokio::test]
async fn rejects_reservation_bypass() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 2, 100_000).await;
    let (_, a) = e.propose(&wid, 20_000).await;
    let (_, b) = e.propose(&wid, 20_000).await;
    let b_coin = b["inputs"][0]["outpoint"].as_str().unwrap().to_string();
    // Replacement of #a that also pulls in #b's coin (different group).
    let (s, v) = e
        .call(
            "POST",
            &format!("/wallets/{wid}/proposals"),
            Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 150_000 }], "replaces": pid(&a), "utxos": [b_coin], "fee_rate_sat_vb": 2.0 })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    // Second claim on a freed-then-reclaimed coin (the concurrent version is
    // `rejects_concurrent_double_reservation`; the DB EXCLUDE backstop is in store/tests/db.rs).
    e.ok("DELETE", &format!("/proposals/{}", pid(&b)), None).await;
    let body = json!({ "outputs": [{ "address": RCPT, "amount_sats": 5_000 }], "utxos": [b_coin], "manual_only": true, "fee_rate_sat_vb": 2.0 });
    let path = format!("/wallets/{wid}/proposals");
    assert_eq!(e.call("POST", &path, Some(body.clone())).await.0, StatusCode::CREATED);
    assert_eq!(e.call("POST", &path, Some(body.clone())).await.0, StatusCode::CONFLICT);
    // Strict-order: executing a descendant before its predecessor is refused (and the
    // predecessor check can't be skipped by replacing the descendant).
    let e = env().await;
    let wid = e.create_wallet("strict").await;
    e.fund(&wid, 1, 300_000).await;
    let (_, a) = e.propose(&wid, 50_000).await;
    let (_, b) = e.propose(&wid, 40_000).await;
    let (_, rb) = e
        .call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 30_000 }], "replaces": pid(&b), "fee_rate_sat_vb": 3.0 })))
        .await;
    assert_eq!(rb["predecessor"], pid(&a));
    for id in [pid(&b), pid(&rb)] {
        e.sign(id, 0).await;
        e.sign(id, 1).await;
        let (s, v) = e.call("POST", &format!("/proposals/{id}/execute"), None).await;
        assert_eq!((s, v["error"].as_str()), (StatusCode::CONFLICT, Some("predecessor_not_broadcast")));
    }
}

#[tokio::test]
async fn rejects_concurrent_double_reservation() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 1, 100_000).await;
    let u = e.ok("GET", &format!("/wallets/{wid}/utxos"), None).await;
    let coin = u[0]["outpoint"].clone();
    let path = format!("/wallets/{wid}/proposals");
    let mut hs = vec![];
    for k in 0..6u64 {
        let (e, path, coin) = (e.clone(), path.clone(), coin.clone());
        hs.push(tokio::spawn(async move {
            e.call("POST", &path, Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 5_000 + k }], "utxos": [coin], "manual_only": true, "fee_rate_sat_vb": 2.0 })))
                .await
        }));
    }
    let mut created = 0;
    for h in hs {
        let (s, v) = tokio::time::timeout(Duration::from_secs(20), h).await.expect("no hang").unwrap();
        match s {
            StatusCode::CREATED => created += 1,
            StatusCode::CONFLICT => {}
            _ => panic!("{s} {v}"),
        }
    }
    assert_eq!(created, 1, "exactly one proposal may hold the coin");
}
