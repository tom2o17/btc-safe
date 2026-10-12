//! Watcher against a real Postgres ($BTC_SAFE_TEST_DATABASE_URL, else the local socket DB
//! btc_safe_test as $USER) and the in-process MemoryChain.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use btc_safe_chain::{ChainSource, MemoryChain};
use btc_safe_core::policy::{OwnerKey, WalletPolicy};
use btc_safe_core::state::Status;
use btc_safe_core::validate;
use btc_safe_core::Keychain;
use btc_safe_store::{self as store, sqlx::PgPool, NewProposal, OrderingMode};
use btc_safe_testkit::three_owners;
use btc_safe_wallet::{BuildRequest, BuiltProposal, ChainInput};
use btc_safe_watcher::{parse_confirmations_final, reconcile, sync_wallet, WalletCache, DEFAULT_CONFIRMATIONS_FINAL};
use uuid::Uuid;

async fn pool() -> PgPool {
    let url = std::env::var("BTC_SAFE_TEST_DATABASE_URL").unwrap_or_else(|_| {
        format!("postgres:///btc_safe_test?host=/tmp&user={}", std::env::var("USER").unwrap_or_else(|_| "postgres".into()))
    });
    store::connect(&url).await.unwrap()
}

fn policy() -> WalletPolicy {
    WalletPolicy::new(
        Network::Signet,
        2,
        three_owners().iter().map(|o| OwnerKey { name: o.name.clone(), fingerprint: o.fingerprint, path: o.path.clone(), xpub: o.xpub }).collect(),
    )
    .unwrap()
}

fn recipient() -> ScriptBuf {
    Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap().assume_checked().script_pubkey()
}

struct Env {
    pool: PgPool,
    cache: WalletCache,
    chain: MemoryChain,
    wallet: Uuid,
    policy: WalletPolicy,
    /// CONFIRMATIONS_FINAL for this env.
    confs: u32,
}

/// A fresh wallet funded with `coins` confirmed outputs of 100k sats each.
async fn setup(ordering: OrderingMode, coins: u32) -> Env {
    let pool = pool().await;
    let policy = policy();
    let mut conn = pool.acquire().await.unwrap();
    let wallet = store::insert_wallet(&mut conn, "watcher-test", &policy, ordering).await.unwrap();
    let chain = MemoryChain::new(Network::Signet);
    for _ in 0..coins {
        let idx = store::alloc_index(&mut conn, wallet, Keychain::External).await.unwrap();
        chain.fund(policy.derive(Keychain::External, idx).unwrap().script_pubkey, Amount::from_sat(100_000));
    }
    chain.mine(1);
    drop(conn);
    let env = Env { pool, cache: WalletCache::new(), chain, wallet, policy, confs: DEFAULT_CONFIRMATIONS_FINAL };
    sync_wallet(&env.pool, &env.cache, &env.chain, wallet).await.unwrap();
    env
}

impl Env {
    async fn sync(&self) -> Vec<(i64, Status)> {
        sync_wallet(&self.pool, &self.cache, &self.chain, self.wallet).await.unwrap();
        reconcile(&self.pool, &self.chain, self.wallet, self.confs).await.unwrap()
    }

    async fn propose(&self, pay: u64, chain_input: Option<ChainInput>, predecessor: Option<i64>) -> (i64, BuiltProposal) {
        let mut conn = self.pool.acquire().await.unwrap();
        let reserved = store::reserved_outpoints(&mut conn, self.wallet, None).await.unwrap();
        let change_index = store::alloc_index(&mut conn, self.wallet, Keychain::Internal).await.unwrap();
        let lw = self.cache.get(&self.pool, self.wallet).await.unwrap();
        let built = lw
            .lock()
            .await
            .wallet
            .build_proposal(&BuildRequest {
                recipients: vec![(recipient(), Amount::from_sat(pay))],
                fee_rate: Some(FeeRate::from_sat_per_vb(2).unwrap()),
                reserved,
                chain_input,
                change_index,
                rbf: true,
                ..Default::default()
            })
            .unwrap();
        let id = self.insert(&built, None, predecessor).await;
        (id, built)
    }

    async fn insert(&self, built: &BuiltProposal, replaces: Option<i64>, predecessor: Option<i64>) -> i64 {
        let mut conn = self.pool.acquire().await.unwrap();
        store::insert_proposal(
            &mut conn,
            NewProposal { wallet_id: self.wallet, created_by: "test", spec: &built.spec, psbt: &built.psbt, summary: &built.summary, fee_override: false, replaces, predecessor },
        )
        .await
        .unwrap()
    }

    fn signed(&self, built: &BuiltProposal) -> Transaction {
        let owners = three_owners();
        let mut stored = built.psbt.clone();
        for o in &owners[..2] {
            let mut theirs = built.psbt.clone();
            o.sign(&mut theirs);
            let sub = validate::validate_submission(&self.policy, &built.spec, &stored, &theirs).unwrap();
            validate::apply_signatures(&mut stored, &sub);
        }
        validate::finalize(&self.policy, &built.spec, &stored).unwrap()
    }

    async fn status(&self, id: i64) -> store::ProposalRow {
        let mut conn = self.pool.acquire().await.unwrap();
        store::get_proposal(&mut conn, id).await.unwrap()
    }

    async fn reserved(&self) -> usize {
        self.reserved_set().await.len()
    }

    async fn reserved_set(&self) -> std::collections::BTreeSet<OutPoint> {
        let mut conn = self.pool.acquire().await.unwrap();
        store::reserved_outpoints(&mut conn, self.wallet, None).await.unwrap()
    }

    /// (from, to) of every status audit entry for a proposal, in order.
    async fn audit_trail(&self, id: i64) -> Vec<(String, String)> {
        let mut conn = self.pool.acquire().await.unwrap();
        let rows: Vec<(Option<String>, Option<String>)> = store::sqlx::query_as(
            "SELECT payload->>'from', payload->>'to' FROM audit_log WHERE wallet_id = $1 AND action = 'proposal_status' \
             AND (payload->>'proposal')::bigint = $2 ORDER BY id",
        )
        .bind(self.wallet)
        .bind(id)
        .fetch_all(&mut *conn)
        .await
        .unwrap();
        rows.into_iter().map(|(a, b)| (a.unwrap_or_default(), b.unwrap_or_default())).collect()
    }
}

/// A tx spending `op` to a stranger: "someone signed elsewhere".
fn foreign_spend(op: OutPoint) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: op, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::from_slice(&[vec![9u8; 72]]) }],
        output: vec![TxOut { value: Amount::from_sat(90_000), script_pubkey: recipient() }],
    }
}

#[tokio::test]
async fn broadcast_then_confirm_releases_reservation() {
    let env = setup(OrderingMode::Parallel, 2).await;
    let (id, built) = env.propose(30_000, None, None).await;
    assert_eq!(env.reserved().await, built.spec.inputs.len());
    assert!(env.sync().await.is_empty(), "nothing changes while unsigned");

    let tx = env.signed(&built);
    env.chain.broadcast(&tx).await.unwrap();
    assert_eq!(env.sync().await, vec![(id, Status::Broadcast)]);
    let p = env.status(id).await;
    assert_eq!(p.broadcast_txid.as_deref(), Some(tx.compute_txid().to_string().as_str()));
    assert_eq!(p.status_reason.as_deref(), Some("seen_in_mempool"));
    assert_eq!(env.reserved().await, built.spec.inputs.len(), "broadcast still reserves");

    // 1 confirmation: soft. Still holds its coins, still re-checked.
    let tip = env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id, Status::SoftConfirmed)]);
    let p = env.status(id).await;
    assert_eq!(p.confirmed_height, Some(tip as i32));
    assert_eq!(p.status_reason.as_deref(), Some("soft_confirmed"));
    assert_eq!(env.reserved().await, built.spec.inputs.len(), "soft confirmation still reserves");
    assert!(env.sync().await.is_empty(), "same depth: no change");

    // 2 confirmations: final, reservation released.
    env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id, Status::Confirmed)]);
    let p = env.status(id).await;
    assert_eq!(p.confirmed_height, Some(tip as i32), "height of the block it is in, not the tip");
    assert_eq!(p.status_reason.as_deref(), Some("final"));
    assert_eq!(env.reserved().await, 0);
    assert!(env.sync().await.is_empty(), "terminal states are left alone");
    let trail = env.audit_trail(id).await;
    assert_eq!(
        trail,
        vec![("pending".into(), "broadcast".into()), ("broadcast".into(), "soft_confirmed".into()), ("soft_confirmed".into(), "confirmed".into())]
    );
}

/// Broadcast, mined, and the block reorged out with the tx going back to the mempool.
#[tokio::test]
async fn soft_reorged_back_to_mempool_then_reconfirmed() {
    let env = setup(OrderingMode::Parallel, 2).await;
    let (id, built) = env.propose(30_000, None, None).await;
    let tx = env.signed(&built);
    env.chain.broadcast(&tx).await.unwrap();
    env.sync().await;
    env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id, Status::SoftConfirmed)]);
    let held = env.reserved_set().await;

    assert_eq!(env.chain.reorg(1, true), vec![tx.compute_txid()]);
    assert_eq!(env.sync().await, vec![(id, Status::Broadcast)]);
    let p = env.status(id).await;
    assert_eq!(p.status_reason.as_deref(), Some("reorged_back_to_mempool"));
    assert_eq!(p.confirmed_height, None, "no longer in a block");
    assert_eq!(env.reserved_set().await, held, "coins stay reserved through the rollback");

    // The replacement chain includes it again, at a new height.
    let h = env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id, Status::SoftConfirmed)]);
    assert_eq!(env.status(id).await.confirmed_height, Some(h as i32));
    env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id, Status::Confirmed)]);
    assert_eq!(env.reserved().await, 0);
    let trail = env.audit_trail(id).await;
    assert_eq!(&trail[1..], &[
        ("broadcast".into(), "soft_confirmed".into()),
        ("soft_confirmed".into(), "broadcast".into()),
        ("broadcast".into(), "soft_confirmed".into()),
        ("soft_confirmed".into(), "confirmed".into()),
    ]);
}

/// Reorged out and gone from the mempool too: soft → broadcast → ready (re-sendable), then
/// re-sent and confirmed again. Reservations never lapse on the way.
#[tokio::test]
async fn soft_reorged_out_and_gone_back_to_pending_then_reconfirmed() {
    let env = setup(OrderingMode::Parallel, 2).await;
    let (id, built) = env.propose(30_000, None, None).await;
    let tx = env.signed(&built);
    env.chain.broadcast(&tx).await.unwrap();
    env.sync().await;
    env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id, Status::SoftConfirmed)]);
    let held = env.reserved_set().await;

    env.chain.reorg(1, false);
    env.chain.mine(1); // the winning chain, without our tx
    assert_eq!(env.sync().await, vec![(id, Status::Broadcast)]);
    assert_eq!(env.status(id).await.status_reason.as_deref(), Some("reorged_out"));
    assert_eq!(env.reserved_set().await, held);
    assert_eq!(env.sync().await, vec![(id, Status::Ready)], "still gone: back to the queue as ready");
    assert_eq!(env.reserved_set().await, held, "a ready proposal keeps its coins");

    env.chain.broadcast(&tx).await.unwrap();
    assert_eq!(env.sync().await, vec![(id, Status::Broadcast)]);
    env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id, Status::SoftConfirmed)]);
    env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id, Status::Confirmed)]);
    assert_eq!(env.reserved().await, 0);
}

/// A double spend by someone else wins the reorg: the soft proposal fails, its coins are
/// released, and an unrelated proposal keeps its own.
#[tokio::test]
async fn soft_conflicting_tx_wins_invalidates_and_releases() {
    let env = setup(OrderingMode::Parallel, 2).await;
    let (a, built_a) = env.propose(30_000, None, None).await;
    let (b, built_b) = env.propose(30_000, None, None).await;
    let tx = env.signed(&built_a);
    env.chain.broadcast(&tx).await.unwrap();
    env.sync().await;
    env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(a, Status::SoftConfirmed)]);

    let a_in = built_a.spec.inputs[0].outpoint;
    let thief = foreign_spend(a_in);
    env.chain.reorg(1, true);
    env.chain.mine_with(vec![thief.clone()]);
    assert_eq!(env.sync().await, vec![(a, Status::Invalidated)]);
    let p = env.status(a).await;
    assert_eq!(p.invalidated_by_txid.as_deref(), Some(thief.compute_txid().to_string().as_str()));
    assert_eq!(p.status_reason.as_deref(), Some("input_spent_elsewhere"));
    assert_eq!(p.confirmed_height, None);
    let held = env.reserved_set().await;
    assert!(built_a.spec.inputs.iter().all(|i| !held.contains(&i.outpoint)), "A's coins are released");
    assert_eq!(held, built_b.spec.inputs.iter().map(|i| i.outpoint).collect(), "B keeps exactly its own");
    assert_eq!(env.status(b).await.status(), Status::Pending);
    assert_eq!(env.audit_trail(a).await.last().unwrap(), &("soft_confirmed".to_string(), "invalidated".to_string()));
}

/// Our own fee bump wins the reorg: the original is CONFLICTED, the bump confirms, and the
/// group's shared coins stay reserved by the bump until it is final.
#[tokio::test]
async fn soft_replacement_wins_conflicts_original() {
    let env = setup(OrderingMode::Parallel, 1).await;
    let (a, built_a) = env.propose(30_000, None, None).await;
    let prev = std::collections::BTreeMap::from([(built_a.spec.inputs[0].outpoint.txid, built_a.psbt.inputs[0].non_witness_utxo.clone().unwrap())]);
    let bumped = btc_safe_wallet::bump_fee(&env.policy, &built_a.spec, &prev, FeeRate::from_sat_per_vb(5).unwrap()).unwrap();
    let a2 = env.insert(&bumped, Some(a), None).await;

    env.chain.broadcast(&env.signed(&built_a)).await.unwrap();
    env.sync().await;
    env.chain.mine(1);
    assert!(env.sync().await.contains(&(a, Status::SoftConfirmed)));

    assert_eq!(env.status(a2).await.status(), Status::Pending, "a soft sibling doesn't kill the bump");

    env.chain.reorg(1, false);
    env.chain.mine_with(vec![env.signed(&bumped)]);
    // The bump is now the one in a block (soft); the original is out, back to broadcast.
    let changes = env.sync().await;
    assert!(changes.contains(&(a, Status::Broadcast)) && changes.contains(&(a2, Status::SoftConfirmed)), "{changes:?}");
    assert_eq!(env.reserved().await, bumped.spec.inputs.len(), "the group still holds the shared coin");
    // Once the bump is final, the original is CONFLICTED and everything is released.
    env.chain.mine(1);
    let changes = env.sync().await;
    assert!(changes.contains(&(a, Status::Conflicted)) && changes.contains(&(a2, Status::Confirmed)), "{changes:?}");
    assert_eq!(env.status(a).await.status_reason.as_deref(), Some("replacement_confirmed"));
    assert_eq!(env.reserved().await, 0);
    assert_eq!(
        env.audit_trail(a).await[1..],
        [
            ("broadcast".to_string(), "soft_confirmed".to_string()),
            ("soft_confirmed".to_string(), "broadcast".to_string()),
            ("broadcast".to_string(), "conflicted".to_string())
        ]
    );
}

/// Strict order: a soft predecessor loses its input in a reorg; its soft child (spending the
/// predecessor's change) can't exist either and is invalidated by the cascade.
#[tokio::test]
async fn soft_strict_order_cascade() {
    let env = setup(OrderingMode::Strict, 1).await;
    let (a, built_a) = env.propose(20_000, None, None).await;
    let pa = env.status(a).await;
    let (op, amount, index) = pa.change_output().unwrap();
    let ci = ChainInput { outpoint: op, amount, index, prev_tx: built_a.spec.unsigned_tx.clone() };
    let (b, built_b) = env.propose(10_000, Some(ci), Some(a)).await;
    env.chain.broadcast(&env.signed(&built_a)).await.unwrap();
    env.chain.broadcast(&env.signed(&built_b)).await.unwrap();
    env.sync().await;
    env.chain.mine(1);
    let ch = env.sync().await;
    assert!(ch.contains(&(a, Status::SoftConfirmed)) && ch.contains(&(b, Status::SoftConfirmed)), "{ch:?}");

    env.chain.reorg(1, false);
    env.chain.mine_with(vec![foreign_spend(built_a.spec.inputs[0].outpoint)]);
    env.sync().await;
    assert_eq!(env.status(a).await.status(), Status::Invalidated);
    let pb = env.status(b).await;
    assert_eq!(pb.status(), Status::Invalidated);
    assert_eq!(pb.status_reason.as_deref(), Some("predecessor_replaced"));
    assert_eq!(env.reserved().await, 0);
    assert_eq!(env.audit_trail(b).await.last().unwrap(), &("soft_confirmed".to_string(), "invalidated".to_string()));
}

/// Final means final: once CONFIRMED, the watcher never looks the tx up again, even if a
/// deep reorg (beyond the configured depth) removes it.
#[tokio::test]
async fn hard_confirmed_is_never_rechecked() {
    let env = setup(OrderingMode::Parallel, 1).await;
    let (id, built) = env.propose(30_000, None, None).await;
    let tx = env.signed(&built);
    let txid = tx.compute_txid();
    env.chain.broadcast(&tx).await.unwrap();
    env.sync().await;
    env.chain.mine(2);
    assert_eq!(env.sync().await, vec![(id, Status::Confirmed)], "first seen 2 deep: straight to final");
    let seen = env.chain.lookups().len();

    env.chain.reorg(3, false);
    env.chain.mine_with(vec![foreign_spend(built.spec.inputs[0].outpoint)]);
    env.chain.mine(3);
    assert!(env.sync().await.is_empty());
    assert!(env.sync().await.is_empty());
    assert_eq!(env.status(id).await.status(), Status::Confirmed);
    assert!(!env.chain.lookups()[seen..].contains(&txid), "a final proposal was re-checked");
}

#[test]
fn confirmations_final_parse() {
    assert_eq!(DEFAULT_CONFIRMATIONS_FINAL, 2);
    assert_eq!(parse_confirmations_final(None), Ok(2));
    assert_eq!(parse_confirmations_final(Some("  ")), Ok(2));
    assert_eq!(parse_confirmations_final(Some("1")), Ok(1));
    assert_eq!(parse_confirmations_final(Some(" 6 ")), Ok(6));
    assert!(parse_confirmations_final(Some("0")).is_err());
    assert!(parse_confirmations_final(Some("-1")).is_err());
    assert!(parse_confirmations_final(Some("two")).is_err());
}

/// The configured depth is what decides finality: 3 needs a third block; 1 is final at once.
#[tokio::test]
async fn threshold_is_honored() {
    let mut env = setup(OrderingMode::Parallel, 2).await;
    env.confs = parse_confirmations_final(Some("3")).unwrap();
    let (id, built) = env.propose(30_000, None, None).await;
    env.chain.broadcast(&env.signed(&built)).await.unwrap();
    env.sync().await;
    env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id, Status::SoftConfirmed)]);
    env.chain.mine(1);
    assert!(env.sync().await.is_empty(), "2 of 3: still soft");
    assert_eq!(env.status(id).await.status(), Status::SoftConfirmed);
    env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id, Status::Confirmed)]);

    env.confs = parse_confirmations_final(Some("1")).unwrap();
    let (id2, built2) = env.propose(20_000, None, None).await;
    env.chain.broadcast(&env.signed(&built2)).await.unwrap();
    env.sync().await;
    env.chain.mine(1);
    assert_eq!(env.sync().await, vec![(id2, Status::Confirmed)], "CONFIRMATIONS_FINAL=1: final at one");
}

#[tokio::test]
async fn input_spent_elsewhere_invalidates() {
    let env = setup(OrderingMode::Parallel, 2).await;
    let (a, built_a) = env.propose(30_000, None, None).await;
    let (b, built_b) = env.propose(30_000, None, None).await;
    let a_in = built_a.spec.inputs[0].outpoint;
    assert!(built_b.spec.inputs.iter().all(|i| i.outpoint != a_in), "parallel proposals are disjoint");

    let thief = foreign_spend(a_in);
    env.chain.inject(thief.clone());
    // Mempool spend by a non-sibling is enough: invalidate now, B is untouched.
    assert_eq!(env.sync().await, vec![(a, Status::Invalidated)]);
    let p = env.status(a).await;
    assert_eq!(p.invalidated_by_txid.as_deref(), Some(thief.compute_txid().to_string().as_str()));
    assert_eq!(p.status_reason.as_deref(), Some("input_spent_elsewhere"));
    assert_eq!(env.status(b).await.status(), Status::Pending);
    assert_eq!(env.reserved().await, built_b.spec.inputs.len(), "A's coins are released");
}

#[tokio::test]
async fn strict_order_cascades_to_descendants() {
    let env = setup(OrderingMode::Strict, 1).await;
    let (a, built_a) = env.propose(20_000, None, None).await;
    let pa = env.status(a).await;
    let (op, amount, index) = pa.change_output().unwrap();
    let ci = ChainInput { outpoint: op, amount, index, prev_tx: built_a.spec.unsigned_tx.clone() };
    let (b, built_b) = env.propose(10_000, Some(ci), Some(a)).await;
    assert!(built_b.spec.inputs.iter().any(|i| i.outpoint == op), "B spends A's change");

    // B's prevout doesn't exist on chain yet; the watcher must not trip over that.
    assert!(env.sync().await.is_empty());

    env.chain.inject(foreign_spend(built_a.spec.inputs[0].outpoint));
    let changes = env.sync().await;
    assert!(changes.contains(&(a, Status::Invalidated)), "{changes:?}");
    let pb = env.status(b).await;
    assert_eq!(pb.status(), Status::Invalidated);
    assert_eq!(pb.status_reason.as_deref(), Some("predecessor_replaced"));
    assert_eq!(env.reserved().await, 0);
}

#[tokio::test]
async fn confirmed_replacement_conflicts_original() {
    let env = setup(OrderingMode::Parallel, 1).await;
    let (a, built_a) = env.propose(30_000, None, None).await;
    let prev = std::collections::BTreeMap::from([(
        built_a.spec.inputs[0].outpoint.txid,
        built_a.psbt.inputs[0].non_witness_utxo.clone().unwrap(),
    )]);
    let bumped = btc_safe_wallet::bump_fee(&env.policy, &built_a.spec, &prev, FeeRate::from_sat_per_vb(5).unwrap()).unwrap();
    let a2 = env.insert(&bumped, Some(a), None).await;

    env.chain.broadcast(&env.signed(&bumped)).await.unwrap();
    // Replacement in the mempool: the original waits (the replacement can still be evicted).
    assert_eq!(env.sync().await, vec![(a2, Status::Broadcast)]);
    assert_eq!(env.status(a).await.status(), Status::Pending);

    env.chain.mine(1);
    // Replacement soft-confirmed: the original waits, a reorg could still undo the replacement.
    assert_eq!(env.sync().await, vec![(a2, Status::SoftConfirmed)]);
    assert_eq!(env.status(a).await.status(), Status::Pending);
    env.chain.mine(1);
    let changes = env.sync().await;
    assert!(changes.contains(&(a, Status::Conflicted)) && changes.contains(&(a2, Status::Confirmed)), "{changes:?}");
    assert_eq!(env.status(a).await.status_reason.as_deref(), Some("replacement_confirmed"));
}

#[tokio::test]
async fn dropped_from_mempool_returns_to_ready() {
    let env = setup(OrderingMode::Parallel, 1).await;
    let (id, built) = env.propose(30_000, None, None).await;
    let tx = env.signed(&built);
    env.chain.broadcast(&tx).await.unwrap();
    assert_eq!(env.sync().await, vec![(id, Status::Broadcast)]);
    env.chain.evict(tx.compute_txid());
    assert_eq!(env.sync().await, vec![(id, Status::Ready)]);
    assert_eq!(env.status(id).await.status_reason.as_deref(), Some("dropped_from_mempool"));
    assert_eq!(env.reserved().await, 1);
}
