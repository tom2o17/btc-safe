//! End-to-end over HTTP: in-process router, MemoryChain, real Postgres
//! ($BTC_SAFE_TEST_DATABASE_URL, else the local socket DB btc_safe_test as $USER).
//! Owner keys exist only inside this test (testkit) and sign offline.

use std::str::FromStr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, Network};
use btc_safe_api::{router, AppState};
use btc_safe_chain::{ChainSource, MemoryChain, TxState};
use btc_safe_testkit::{three_owners, TestOwner};
use btc_safe_watcher::WalletCache;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const RCPT: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

struct Env {
    app: Router,
    s: common::Session,
    mem: MemoryChain,
    owners: Vec<TestOwner>,
}

async fn env() -> Env {
    let url = std::env::var("BTC_SAFE_TEST_DATABASE_URL").unwrap_or_else(|_| {
        format!("postgres:///btc_safe_test?host=/tmp&user={}", std::env::var("USER").unwrap_or_else(|_| "postgres".into()))
    });
    let pool = btc_safe_store::connect(&url).await.unwrap();
    let mem = MemoryChain::new(Network::Signet);
    let state = AppState::new(pool.clone(), Arc::new(WalletCache::new()), Arc::new(mem.clone()), Some(mem.clone()));
    let s = common::login(&pool, &state.auth).await;
    Env { app: router(state), s, mem, owners: three_owners() }
}

impl Env {
    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call_as(Some(&self.s), method, path, body).await
    }

    async fn call_as(&self, who: Option<&common::Session>, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(s) = who {
            req = req.header("cookie", &s.cookie).header("x-csrf-token", &s.csrf);
        }
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
        assert_eq!(v["first_addresses"].as_array().unwrap().len(), 3);
        assert!(v["backup"]["bsms"].as_str().unwrap().starts_with("BSMS 1.0"));
        v["id"].as_str().unwrap().to_string()
    }

    /// Fund `n` fresh receive addresses with `sats` each and confirm.
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

    /// Owner `i` downloads the PSBT, signs on their device, and uploads it.
    async fn sign(&self, pid: i64, i: usize) -> (StatusCode, Value) {
        let p = self.ok("GET", &format!("/proposals/{pid}"), None).await;
        let mut psbt = Psbt::from_str(p["psbt"].as_str().unwrap()).unwrap();
        assert!(self.owners[i].sign(&mut psbt) > 0);
        self.call("POST", &format!("/proposals/{pid}/signatures"), Some(json!({ "psbt": psbt.to_string() }))).await
    }
}

fn pid(v: &Value) -> i64 {
    v["id"].as_i64().unwrap()
}

#[tokio::test]
async fn full_flow_over_http() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 2, 100_000).await;

    let w = e.ok("GET", &format!("/wallets/{wid}"), None).await;
    assert_eq!(w["balance"]["confirmed_sats"], 200_000);
    assert_eq!(w["policy"], "P2WSH sortedmulti 2-of-3");

    let (s, p) = e.propose(&wid, 150_000).await;
    assert_eq!(s, StatusCode::CREATED, "{p}");
    let id = pid(&p);
    assert_eq!(p["status"], "pending");
    assert_eq!(p["confirmations"]["count"], 0);
    let change: Vec<&Value> = p["outputs"].as_array().unwrap().iter().filter(|o| o["is_change"] == true).collect();
    assert_eq!(change.len(), 1);

    // Execute before enough signatures is refused.
    let (s, _) = e.call("POST", &format!("/proposals/{id}/execute"), None).await;
    assert_eq!(s, StatusCode::CONFLICT);

    let (s, v) = e.sign(id, 0).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "signing");
    assert_eq!(v["confirmations"]["count"], 1);
    // Re-upload is idempotent.
    let (_, v) = e.sign(id, 0).await;
    assert_eq!(v["accepted"]["new_signatures"], 0);

    let (_, v) = e.sign(id, 2).await;
    assert_eq!(v["status"], "ready");
    assert_eq!(v["confirmations"]["count"], 2);

    let x = e.ok("POST", &format!("/proposals/{id}/execute"), None).await;
    assert_eq!(x["status"], "broadcast");
    let txid = x["txid"].as_str().unwrap().to_string();
    assert_eq!(e.mem.tx_state(txid.parse().unwrap()).await.unwrap(), TxState::Mempool);

    e.ok("POST", "/dev/mine", Some(json!({}))).await;
    let sync = e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(sync["transitions"][0]["status"], "soft_confirmed", "{sync}");
    let p = e.ok("GET", &format!("/proposals/{id}"), None).await;
    assert_eq!(p["status"], "soft_confirmed");
    assert_eq!(p["block_confirmations"], json!({ "count": 1, "final_at": 2, "final": false }));
    let queue = e.ok("GET", &format!("/wallets/{wid}/proposals?status=queue"), None).await;
    assert!(queue.as_array().unwrap().iter().any(|q| q["id"] == id), "soft-confirmed stays in the queue until final");

    // A reorg takes the block away: back to broadcast, then confirmed again.
    e.ok("POST", "/dev/reorg", Some(json!({ "depth": 1, "back_to_mempool": true }))).await;
    let sync = e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(sync["transitions"][0]["status"], "broadcast", "{sync}");
    let p = e.ok("GET", &format!("/proposals/{id}"), None).await;
    assert_eq!((p["status_reason"].as_str(), &p["block_confirmations"]["count"]), (Some("reorged_back_to_mempool"), &Value::Null));

    e.ok("POST", "/dev/mine", Some(json!({ "blocks": 2 }))).await;
    let sync = e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(sync["transitions"][0]["status"], "confirmed", "{sync}");
    let p = e.ok("GET", &format!("/proposals/{id}"), None).await;
    assert_eq!(p["status"], "confirmed");
    assert_eq!(p["block_confirmations"], json!({ "count": 2, "final_at": 2, "final": true }));
    assert!(p["final_tx_hex"].is_string());
    let fee = p["fee_sats"].as_u64().unwrap();
    let w = e.ok("GET", &format!("/wallets/{wid}"), None).await;
    assert_eq!(w["balance"]["confirmed_sats"].as_u64().unwrap(), 200_000 - 150_000 - fee);
    let h = e.ok("GET", &format!("/wallets/{wid}/history"), None).await;
    assert!(h["transactions"].as_array().unwrap().iter().any(|t| t["txid"] == txid.as_str() && t["origin"] == "proposal"));
    let q = e.ok("GET", &format!("/wallets/{wid}/proposals?status=history"), None).await;
    assert_eq!(q.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn bad_psbts_rejected_over_http() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 1, 100_000).await;
    let (_, p) = e.propose(&wid, 40_000).await;
    let id = pid(&p);
    let base = Psbt::from_str(p["psbt"].as_str().unwrap()).unwrap();

    // 1. Mutated tx (recipient amount changed) signed by an owner.
    let mut m = base.clone();
    m.unsigned_tx.output[0].value = Amount::from_sat(m.unsigned_tx.output[0].value.to_sat() - 1);
    e.owners[0].sign(&mut m);
    let (s, v) = e.call("POST", &format!("/proposals/{id}/signatures"), Some(json!({ "psbt": m.to_string() }))).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid_psbt")), "{v}");

    // 2. nSequence / locktime differences.
    for f in [
        (|p: &mut Psbt| p.unsigned_tx.input[0].sequence = bitcoin::Sequence::MAX) as fn(&mut Psbt),
        |p: &mut Psbt| p.unsigned_tx.lock_time = bitcoin::absolute::LockTime::ZERO,
    ] {
        let mut m = base.clone();
        f(&mut m);
        e.owners[1].sign(&mut m);
        let (s, _) = e.call("POST", &format!("/proposals/{id}/signatures"), Some(json!({ "psbt": m.to_string() }))).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // 3. Stranger's signature mixed in with a real one.
    let mut m = base.clone();
    e.owners[0].sign(&mut m);
    let stranger = btc_safe_testkit::stranger();
    let ws = m.inputs[0].witness_script.clone().unwrap();
    let amt = m.inputs[0].witness_utxo.as_ref().unwrap().value;
    let sk = stranger.secret_for(&(stranger.fingerprint, "m/48'/1'/0'/2'/0/0".parse().unwrap())).unwrap();
    let (pk, sig) = btc_safe_testkit::sign_p2wsh(&sk, &m.unsigned_tx, 0, &ws, amt, bitcoin::sighash::EcdsaSighashType::All);
    m.inputs[0].partial_sigs.insert(pk, sig);
    let (s, v) = e.call("POST", &format!("/proposals/{id}/signatures"), Some(json!({ "psbt": m.to_string() }))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(v["message"].as_str().unwrap().contains("not an owner key"), "{v}");

    // 4. Garbage.
    let (s, _) = e.call("POST", &format!("/proposals/{id}/signatures"), Some(json!({ "psbt": "cHNidP8BAAoCAAAAAAAAAAAAAAAA" }))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    // Nothing was stored by any of the above.
    let p = e.ok("GET", &format!("/proposals/{id}"), None).await;
    assert_eq!(p["status"], "pending");
    assert!(p["signature_log"].as_array().unwrap().is_empty());

    // Fee overpay is blocked unless overridden.
    let (s, v) = e
        .call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 1000 }], "fee_rate_sat_vb": 100.0 })))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "coin is reserved by #{id}: {v}");
    e.ok("DELETE", &format!("/proposals/{id}"), None).await;
    let (s, v) = e
        .call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 10_000 }], "fee_rate_sat_vb": 100.0 })))
        .await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("fee_cap")), "{v}");
    let (s, v) = e
        .call(
            "POST",
            &format!("/wallets/{wid}/proposals"),
            Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 10_000 }], "fee_rate_sat_vb": 100.0, "fee_override": true })),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert!(v["warnings"].as_array().unwrap().iter().any(|w| w["kind"] == "cap_overridden"));
}

#[tokio::test]
async fn reservations_over_http() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 2, 100_000).await;
    let (s1, a) = e.propose(&wid, 60_000).await;
    let (s2, b) = e.propose(&wid, 60_000).await;
    assert_eq!((s1, s2), (StatusCode::CREATED, StatusCode::CREATED), "{a} {b}");
    let ia: Vec<&Value> = a["inputs"].as_array().unwrap().iter().map(|i| &i["outpoint"]).collect();
    let ib: Vec<&Value> = b["inputs"].as_array().unwrap().iter().map(|i| &i["outpoint"]).collect();
    assert!(ia.iter().all(|o| !ib.contains(o)), "queued proposals share a coin");

    let (s, v) = e.propose(&wid, 10_000).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["error"], "insufficient_funds");
    assert_eq!(v["details"]["reserved_sats"], 200_000);

    let u = e.ok("GET", &format!("/wallets/{wid}/utxos"), None).await;
    assert!(u.as_array().unwrap().iter().all(|c| c["status"] == "reserved"));
    let w = e.ok("GET", &format!("/wallets/{wid}"), None).await;
    assert_eq!(w["balance"]["reserved_sats"], 200_000);
    assert_eq!(w["queue_count"], 2);

    // Coin control on a reserved coin is refused.
    let (s, _) = e
        .call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 1000 }], "utxos": [ia[0]], "fee_rate_sat_vb": 1.0 })))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Explicit replacement may reuse the coins (same group), and only one can confirm.
    let (s, r) = e
        .call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "outputs": [{ "address": RCPT, "amount_sats": 55_000 }], "replaces": pid(&a), "fee_rate_sat_vb": 3.0 })))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    assert_eq!(r["replaces"], pid(&a));
    assert_eq!(r["replacement_group"], a["replacement_group"]);

    // The replacement gets signed and confirmed → the original becomes conflicted.
    let rid = pid(&r);
    e.sign(rid, 1).await;
    e.sign(rid, 2).await;
    e.ok("POST", &format!("/proposals/{rid}/execute"), None).await;
    e.ok("POST", "/dev/mine", Some(json!({ "blocks": 2 }))).await;
    e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(e.ok("GET", &format!("/proposals/{rid}"), None).await["status"], "confirmed");
    let orig = e.ok("GET", &format!("/proposals/{}", pid(&a)), None).await;
    assert_eq!(orig["status"], "conflicted", "{orig}");
    assert_eq!(e.ok("GET", &format!("/proposals/{}", pid(&b)), None).await["status"], "pending");
}

#[tokio::test]
async fn strict_order_over_http() {
    let e = env().await;
    let wid = e.create_wallet("strict").await;
    e.fund(&wid, 1, 300_000).await;

    let (_, a) = e.propose(&wid, 50_000).await;
    let (sb, b) = e.propose(&wid, 40_000).await;
    let (sc, c) = e.propose(&wid, 30_000).await;
    assert_eq!((sb, sc), (StatusCode::CREATED, StatusCode::CREATED), "{b} {c}");
    let (ia, ib, ic) = (pid(&a), pid(&b), pid(&c));
    assert_eq!(b["predecessor"], ia);
    assert_eq!(c["predecessor"], ib);
    // #B spends #A's change.
    let a_change = a["outputs"].as_array().unwrap().iter().find(|o| o["is_change"] == true).unwrap()["vout"].as_i64().unwrap();
    let a_out = format!("{}:{}", a["unsigned_txid"].as_str().unwrap(), a_change);
    assert!(b["inputs"].as_array().unwrap().iter().any(|i| i["outpoint"] == a_out.as_str()));

    // Sign all three; executing out of order is refused.
    for id in [ia, ib, ic] {
        e.sign(id, 0).await;
        e.sign(id, 1).await;
    }
    let (s, v) = e.call("POST", &format!("/proposals/{ib}/execute"), None).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::CONFLICT, Some("predecessor_not_broadcast")));
    e.ok("POST", &format!("/proposals/{ia}/execute"), None).await;
    e.ok("POST", &format!("/proposals/{ib}/execute"), None).await;

    // RBF bump of #B (broadcast) → #C chained on B's old change must be rebuilt.
    let (s, bump) = e
        .call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "replaces": ib, "replace_mode": "bump", "fee_rate_sat_vb": 6.0 })))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{bump}");
    assert!(bump["warnings"].as_array().unwrap().iter().any(|w| w["kind"] == "strict_order_descendants"));
    let ibump = pid(&bump);
    e.sign(ibump, 1).await;
    e.sign(ibump, 2).await;
    let x = e.ok("POST", &format!("/proposals/{ibump}/execute"), None).await;
    assert_eq!(x["invalidated_descendants"], json!([ic]));
    let pc = e.ok("GET", &format!("/proposals/{ic}"), None).await;
    assert_eq!((pc["status"].as_str(), pc["status_reason"].as_str()), (Some("invalidated"), Some("predecessor_replaced")));

    e.ok("POST", "/dev/mine", Some(json!({ "blocks": 2 }))).await;
    e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(e.ok("GET", &format!("/proposals/{ia}"), None).await["status"], "confirmed");
    assert_eq!(e.ok("GET", &format!("/proposals/{ibump}"), None).await["status"], "confirmed");
    assert_eq!(e.ok("GET", &format!("/proposals/{ib}"), None).await["status"], "conflicted");

    // Deleting a queued head cascades too.
    let (_, d1) = e.propose(&wid, 10_000).await;
    let (_, d2) = e.propose(&wid, 10_000).await;
    let del = e.ok("DELETE", &format!("/proposals/{}", pid(&d1)), None).await;
    assert_eq!(del["invalidated_descendants"], json!([pid(&d2)]));
    assert_eq!(e.ok("GET", &format!("/proposals/{}", pid(&d2)), None).await["status"], "invalidated");
}

#[tokio::test]
async fn external_spend_invalidates() {
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 1, 100_000).await;
    let (_, p) = e.propose(&wid, 20_000).await;
    let id = pid(&p);

    // A second coordinator (or Sparrow) with the same descriptor spends the same coin.
    let backup = e.ok("GET", &format!("/wallets/{wid}/backup"), None).await;
    let (s, w2) = e.call("POST", "/wallets/import", Some(json!({ "name": "Elsewhere", "network": "signet", "data": backup["bsms"] }))).await;
    assert_eq!(s, StatusCode::CREATED, "{w2}");
    let w2 = w2["id"].as_str().unwrap().to_string();
    e.ok("POST", &format!("/wallets/{w2}/sync"), None).await;
    let (s, other) = e.propose(&w2, 30_000).await;
    assert_eq!(s, StatusCode::CREATED, "{other}");
    let oid = pid(&other);
    e.sign(oid, 1).await;
    e.sign(oid, 2).await;
    let x = e.ok("POST", &format!("/proposals/{oid}/execute"), None).await;

    let sync = e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    let p = e.ok("GET", &format!("/proposals/{id}"), None).await;
    assert_eq!(p["status"], "invalidated", "{sync}");
    assert_eq!(p["status_reason"], "input_spent_elsewhere");
    assert_eq!(p["invalidated_by_txid"], x["txid"]);
    // Its coin reservation is released.
    let w = e.ok("GET", &format!("/wallets/{wid}"), None).await;
    assert_eq!(w["balance"]["reserved_sats"], 0);
    assert_eq!(w["queue_count"], 0);
}

#[tokio::test]
async fn deleted_but_signed_proposal_can_still_land() {
    // DESIGN.md §2 rule 5: deleting doesn't revoke signatures. If someone broadcasts the
    // deleted-but-signed replacement, the original ends up conflicted once it confirms.
    let e = env().await;
    let wid = e.create_wallet("parallel").await;
    e.fund(&wid, 1, 100_000).await;
    let (_, p) = e.propose(&wid, 20_000).await;
    let id = pid(&p);
    let (_, c) = e
        .call("POST", &format!("/wallets/{wid}/proposals"), Some(json!({ "replaces": id, "replace_mode": "cancel", "fee_rate_sat_vb": 3.0 })))
        .await;
    let cid = pid(&c);
    e.sign(cid, 0).await;
    e.sign(cid, 1).await;
    let signed = e.ok("GET", &format!("/proposals/{cid}"), None).await;
    let del = e.ok("DELETE", &format!("/proposals/{cid}"), None).await;
    assert!(del["warning"].as_str().unwrap().contains("does not revoke"));
    // An owner who kept the signed PSBT finalizes and broadcasts it out of band.
    let psbt = Psbt::from_str(signed["psbt"].as_str().unwrap()).unwrap();
    let mut fin = psbt.clone();
    use btc_safe_core::miniscript::psbt::PsbtExt;
    fin.finalize_mut(&bitcoin::secp256k1::Secp256k1::verification_only()).unwrap();
    let tx = fin.extract_tx().unwrap();
    e.ok("POST", "/dev/inject", Some(json!({ "tx_hex": bitcoin::consensus::encode::serialize_hex(&tx) }))).await;
    e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(e.ok("GET", &format!("/proposals/{id}"), None).await["status"], "pending", "sibling unconfirmed: wait");
    e.ok("POST", "/dev/mine", Some(json!({}))).await;
    e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(e.ok("GET", &format!("/proposals/{id}"), None).await["status"], "pending", "sibling soft-confirmed: a reorg could undo it");
    e.ok("POST", "/dev/mine", Some(json!({}))).await;
    e.ok("POST", &format!("/wallets/{wid}/sync"), None).await;
    assert_eq!(e.ok("GET", &format!("/proposals/{id}"), None).await["status"], "conflicted");
}

#[tokio::test]
async fn import_and_auth() {
    let e = env().await;
    let (s, _) = e.call_as(None, "GET", "/wallets", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = e.call_as(None, "GET", "/health", None).await;
    assert_eq!(s, StatusCode::OK);

    let p = btc_safe_core::policy::WalletPolicy::new(
        Network::Signet,
        2,
        e.owners.iter().map(|o| btc_safe_core::policy::OwnerKey { name: o.name.clone(), fingerprint: o.fingerprint, path: o.path.clone(), xpub: o.xpub }).collect(),
    )
    .unwrap();
    let bsms = btc_safe_core::import::export_bsms(&p).unwrap();
    let (s, v) = e.call("POST", "/wallets/import", Some(json!({ "name": "From BSMS", "network": "signet", "data": bsms }))).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["import"]["format"], "bsms");
    let (s, v) = e.call("POST", "/wallets/import", Some(json!({ "network": "bitcoin", "data": bsms }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let xprv = e.owners[0].master.to_string();
    let (s, _) = e
        .call("POST", "/wallets", Some(json!({ "name": "x", "network": "signet", "threshold": 2, "owners": [
            { "name": "a", "xpub": xprv, "fingerprint": e.owners[0].fingerprint.to_string(), "path": "m/48'/1'/0'/2'" },
            { "name": "b", "xpub": e.owners[1].xpub.to_string(), "fingerprint": e.owners[1].fingerprint.to_string(), "path": "m/48'/1'/0'/2'" }
        ] })))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "private keys are refused");

    let wid = v_id(&e).await;
    let a = e.ok("GET", &format!("/wallets/{wid}/addresses?kind=receive&next=true"), None).await;
    e.ok("POST", &format!("/wallets/{wid}/addresses/{}/label", a["index"]), Some(json!({ "label": "invoice 42" }))).await;
    let ab = e.ok("POST", &format!("/wallets/{wid}/address-book"), Some(json!({ "label": "Alice", "address": RCPT }))).await;
    assert_eq!(e.ok("GET", &format!("/wallets/{wid}/address-book"), None).await.as_array().unwrap().len(), 1);
    let (s, _) = e.call("DELETE", &format!("/wallets/{wid}/address-book/{}", ab["id"].as_str().unwrap()), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let f = e.ok("GET", &format!("/wallets/{wid}/fees"), None).await;
    assert_eq!(f["fast_sat_vb"], 5.0);
}

async fn v_id(e: &Env) -> String {
    e.create_wallet("parallel").await
}
