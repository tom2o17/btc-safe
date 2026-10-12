//! Runs against a real Postgres: $BTC_SAFE_TEST_DATABASE_URL, else the local socket DB btc_safe_test as $USER.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use btc_safe_core::policy::{OwnerKey, WalletPolicy};
use btc_safe_core::state::Status;
use btc_safe_core::validate::{self, ChangeSpec, InputSpec, ProposalSpec};
use btc_safe_core::Keychain;
use btc_safe_store::{self as store, NewProposal, OrderingMode, StatusUpdate, StoreError};

async fn pool() -> store::sqlx::PgPool {
    let url = std::env::var("BTC_SAFE_TEST_DATABASE_URL").unwrap_or_else(|_| {
        format!("postgres:///btc_safe_test?host=/tmp&user={}", std::env::var("USER").unwrap_or_else(|_| "postgres".into()))
    });
    store::connect(&url).await.unwrap()
}

fn policy() -> WalletPolicy {
    let owners = btc_safe_testkit::three_owners();
    WalletPolicy::new(
        Network::Signet,
        2,
        owners.iter().map(|o| OwnerKey { name: o.name.clone(), fingerprint: o.fingerprint, path: o.path.clone(), xpub: o.xpub }).collect(),
    )
    .unwrap()
}

/// A funding tx with a random txid (tests share the DB) and a spend of its outputs.
fn spend(p: &WalletPolicy, fund_vouts: &[u32], pay: u64, salt: u64) -> (ProposalSpec, BTreeMap<Txid, Transaction>) {
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array(*uuid::Uuid::new_v4().as_bytes().repeat(2).first_chunk::<32>().unwrap()), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: (0..3).map(|i| TxOut { value: Amount::from_sat(100_000), script_pubkey: p.derive(Keychain::External, i).unwrap().script_pubkey }).collect(),
    };
    let txid = funding.compute_txid();
    let total = 100_000 * fund_vouts.len() as u64;
    let rcpt = Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap().assume_checked().script_pubkey();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(salt as u32 % 400_000),
        input: fund_vouts.iter().map(|v| TxIn { previous_output: OutPoint { txid, vout: *v }, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new() }).collect(),
        output: vec![
            TxOut { value: Amount::from_sat(pay), script_pubkey: rcpt },
            TxOut { value: Amount::from_sat(total - pay - 1000), script_pubkey: p.derive(Keychain::Internal, 0).unwrap().script_pubkey },
        ],
    };
    let spec = ProposalSpec {
        unsigned_tx: tx,
        inputs: fund_vouts.iter().map(|v| InputSpec { outpoint: OutPoint { txid, vout: *v }, amount: Amount::from_sat(100_000), keychain: Keychain::External, index: *v }).collect(),
        change: vec![ChangeSpec { vout: 1, index: 0 }],
    };
    (spec, BTreeMap::from([(txid, funding)]))
}

fn respend(base: &ProposalSpec, prev: &BTreeMap<Txid, Transaction>, p: &WalletPolicy, pay: u64) -> ProposalSpec {
    let mut s = base.clone();
    s.unsigned_tx.output[0].value = Amount::from_sat(pay);
    let total: u64 = s.inputs.iter().map(|i| i.amount.to_sat()).sum();
    s.unsigned_tx.output[1].value = Amount::from_sat(total - pay - 1000);
    let _ = (prev, p);
    s
}

async fn insert(conn: &mut store::sqlx::PgConnection, w: uuid::Uuid, p: &WalletPolicy, spec: &ProposalSpec, prev: &BTreeMap<Txid, Transaction>, replaces: Option<i64>, predecessor: Option<i64>) -> Result<i64, StoreError> {
    let psbt = validate::build_canonical_psbt(p, spec, prev).unwrap();
    let summary = validate::check_spec(p, spec).unwrap();
    store::insert_proposal(conn, NewProposal { wallet_id: w, created_by: "test", spec, psbt: &psbt, summary: &summary, fee_override: false, replaces, predecessor }).await
}

#[tokio::test]
async fn wallet_roundtrip_and_indices() {
    let pool = pool().await;
    let mut c = pool.acquire().await.unwrap();
    let p = policy();
    let id = store::insert_wallet(&mut c, "T", &p, OrderingMode::Parallel).await.unwrap();
    let w = store::get_wallet(&mut c, id).await.unwrap();
    assert_eq!(w.policy().unwrap(), p);
    assert_eq!(store::alloc_index(&mut c, id, Keychain::External).await.unwrap(), 0);
    assert_eq!(store::alloc_index(&mut c, id, Keychain::External).await.unwrap(), 1);
    assert_eq!(store::alloc_index(&mut c, id, Keychain::Internal).await.unwrap(), 0);

    // Tampered row: the policy no longer reproduces the stored descriptor.
    store::sqlx::query("UPDATE wallets SET threshold = 3 WHERE id = $1").bind(id).execute(&mut *c).await.unwrap();
    assert!(matches!(store::get_wallet(&mut c, id).await.unwrap().policy(), Err(StoreError::Corrupt(_))));
}

#[tokio::test]
async fn reservation_conflicts_enforced_by_db() {
    let pool = pool().await;
    let mut c = pool.acquire().await.unwrap();
    let p = policy();
    let w = store::insert_wallet(&mut c, "R", &p, OrderingMode::Parallel).await.unwrap();
    let (a, prev) = spend(&p, &[0, 1], 50_000, 1);
    let ida = insert(&mut c, w, &p, &a, &prev, None, None).await.unwrap();
    assert_eq!(store::reserved_outpoints(&mut c, w, None).await.unwrap().len(), 2);

    // A different proposal sharing input 1 → refused by the exclusion constraint.
    let mut b = respend(&a, &prev, &p, 40_000);
    b.unsigned_tx.input.truncate(1);
    b.unsigned_tx.input[0].previous_output.vout = 1;
    b.inputs = vec![a.inputs[1].clone()];
    b.unsigned_tx.output[1].value = Amount::from_sat(100_000 - 40_000 - 1000);
    let mut tx = pool.begin().await.unwrap();
    assert!(matches!(insert(&mut tx, w, &p, &b, &prev, None, None).await, Err(StoreError::ReservationConflict)));
    tx.rollback().await.unwrap();

    // The same coins as an explicit replacement of A → allowed (same group).
    let r = respend(&a, &prev, &p, 45_000);
    let idr = insert(&mut c, w, &p, &r, &prev, Some(ida), None).await.unwrap();
    let sib = store::group_siblings(&mut c, idr).await.unwrap();
    assert_eq!(sib.iter().map(|s| s.id).collect::<Vec<_>>(), vec![ida]);
    assert_eq!(store::reserved_outpoints(&mut c, w, Some(sib[0].group_id.unwrap())).await.unwrap().len(), 0);

    // Deleting both releases the coins.
    store::set_status(&mut c, ida, Status::Pending, Status::Deleted, StatusUpdate::default()).await.unwrap();
    store::set_status(&mut c, idr, Status::Pending, Status::Deleted, StatusUpdate::default()).await.unwrap();
    assert!(store::reserved_outpoints(&mut c, w, None).await.unwrap().is_empty());
    insert(&mut c, w, &p, &b, &prev, None, None).await.unwrap();

    // CAS: stale expected status is refused.
    assert!(matches!(store::set_status(&mut c, ida, Status::Pending, Status::Deleted, StatusUpdate::default()).await, Err(StoreError::StaleStatus { .. })));
    // Re-activating a deleted proposal whose coin is now held by another group is refused.
    let mut tx = pool.begin().await.unwrap();
    assert!(matches!(store::set_status(&mut tx, ida, Status::Deleted, Status::Pending, StatusUpdate::default()).await, Err(StoreError::ReservationConflict)));
    tx.rollback().await.unwrap();

    // Spec round-trips through the DB.
    let row = store::get_proposal(&mut c, ida).await.unwrap();
    assert_eq!(row.spec().unwrap(), a);
    assert_eq!(row.change_output().unwrap().2, 0);
}

#[tokio::test]
async fn strict_order_descendants_and_tail() {
    let pool = pool().await;
    let mut c = pool.acquire().await.unwrap();
    let p = policy();
    let w = store::insert_wallet(&mut c, "S", &p, OrderingMode::Strict).await.unwrap();
    let (a, prev) = spend(&p, &[0], 10_000, 2);
    let (b, prev_b) = spend(&p, &[1], 10_000, 3);
    let (d, prev_d) = spend(&p, &[2], 10_000, 4);
    let ia = insert(&mut c, w, &p, &a, &prev, None, None).await.unwrap();
    let ib = insert(&mut c, w, &p, &b, &prev_b, None, Some(ia)).await.unwrap();
    let id = insert(&mut c, w, &p, &d, &prev_d, None, Some(ib)).await.unwrap();
    assert_eq!(store::queue_tail(&mut c, w).await.unwrap().unwrap().id, id);
    assert_eq!(store::active_descendants(&mut c, ia).await.unwrap(), vec![ib, id]);
    store::set_status(&mut c, id, Status::Pending, Status::Deleted, StatusUpdate::default()).await.unwrap();
    assert_eq!(store::active_descendants(&mut c, ia).await.unwrap(), vec![ib]);
    assert_eq!(store::queue_tail(&mut c, w).await.unwrap().unwrap().id, ib);
}
