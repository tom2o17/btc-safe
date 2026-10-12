//! Chain-facing side of the coordinator: the wallet cache (BDK state persisted in Postgres),
//! sync, proposal lifecycle transitions (incl. strict-order cascades), and the background
//! loop that reconciles proposals with what the chain says.
//!
//! Transitions out of BROADCAST/READY driven by chain state happen here, never on a client's
//! say-so (DESIGN.md §5.4).
//!
//! Lock order (everywhere, API included): wallet row lock (`store::lock_wallet`, inside a DB
//! transaction) → wallet mutex (`WalletCache`). The wallet row is only ever written inside
//! the transaction that holds its row lock; `Loaded::persist` takes that transaction. Never
//! touch the DB while holding the mutex without holding the row lock first.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bdk_wallet::chain::Merge;
use bdk_wallet::ChangeSet;
use bitcoin::{OutPoint, Txid};
use btc_safe_chain::{ChainSource, ScanRequest, TxState};
use btc_safe_core::state::{transition, Event, Status};
use btc_safe_core::Keychain;
use btc_safe_store::{self as store, sqlx, ProposalRow, StatusUpdate, StoreError};
use btc_safe_wallet::SafeWallet;
use sqlx::{PgConnection, PgPool};
use tokio::sync::Mutex;
use uuid::Uuid;

pub const STOP_GAP: usize = 20;
/// Run a full scan (finds funds sent to addresses we never handed out) every N syncs.
pub const FULL_SCAN_EVERY: u32 = 10;

/// Confirmations at which a proposal becomes final (CONFIRMED) when `CONFIRMATIONS_FINAL` is
/// unset. Below it, a proposal in a block is SOFT_CONFIRMED and re-checked every tick. This is
/// the only place the default lives; everything else takes the configured value.
/// 2 is thin for mainnet (this build is signet-only).
pub const DEFAULT_CONFIRMATIONS_FINAL: u32 = 2;

/// Parse `CONFIRMATIONS_FINAL`. Unset → the default; anything that isn't an integer ≥ 1 is an
/// error (the server refuses to start rather than guess).
pub fn parse_confirmations_final(v: Option<&str>) -> std::result::Result<u32, String> {
    match v.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(DEFAULT_CONFIRMATIONS_FINAL),
        Some(v) => match v.parse::<u32>() {
            Ok(n) if n >= 1 => Ok(n),
            _ => Err(format!("CONFIRMATIONS_FINAL={v} refused: needs an integer >= 1")),
        },
    }
}

/// Confirmations of a tx mined at `height` when the chain tip is `tip` (1 = in the tip block).
/// A tip read before a new block arrived can be below `height`; that counts as 1.
pub fn confirmations(tip: u32, height: u32) -> u32 {
    tip.saturating_sub(height).saturating_add(1)
}

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Wallet(#[from] btc_safe_wallet::WalletError),
    #[error(transparent)]
    Chain(#[from] btc_safe_chain::ChainError),
    #[error("state: {0}")]
    State(String),
}

pub type Result<T> = std::result::Result<T, WatchError>;

pub struct Loaded {
    pub wallet: SafeWallet,
    /// Full persisted BDK state (initial + every staged change since).
    pub changeset: ChangeSet,
    pub syncs: u32,
}

impl Loaded {
    /// Merge staged BDK changes and write them to the DB. `conn` must be the transaction that
    /// holds this wallet's row lock. Returns whether anything changed.
    pub async fn persist(&mut self, conn: &mut PgConnection, wallet_id: Uuid) -> Result<bool> {
        let Some(staged) = self.wallet.take_staged() else { return Ok(false) };
        self.changeset.merge(staged);
        let json = serde_json::to_value(&self.changeset).map_err(|e| WatchError::State(e.to_string()))?;
        store::save_changeset(conn, wallet_id, &json, self.wallet.tip_height()).await?;
        Ok(true)
    }
}

/// One loaded BDK wallet per coordinator wallet, guarded by an async mutex.
#[derive(Default)]
pub struct WalletCache {
    map: std::sync::Mutex<HashMap<Uuid, Arc<Mutex<Loaded>>>>,
}

impl WalletCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get(&self, pool: &PgPool, id: Uuid) -> Result<Arc<Mutex<Loaded>>> {
        if let Some(l) = self.map.lock().expect("cache").get(&id) {
            return Ok(l.clone());
        }
        let mut conn = pool.acquire().await.map_err(StoreError::from)?;
        let row = store::get_wallet(&mut conn, id).await?;
        let policy = row.policy()?;
        let (mut wallet, changeset) = match store::load_changeset(&mut conn, id).await? {
            Some(json) => {
                let cs: ChangeSet = serde_json::from_value(json).map_err(|e| WatchError::State(e.to_string()))?;
                (SafeWallet::load(policy, cs.clone())?, cs)
            }
            None => {
                let mut w = SafeWallet::new(policy)?;
                let cs = w.take_staged().unwrap_or_default();
                (w, cs)
            }
        };
        if row.next_receive_idx > 0 {
            wallet.reveal_to(Keychain::External, row.next_receive_idx as u32 - 1);
        }
        if row.next_change_idx > 0 {
            wallet.reveal_to(Keychain::Internal, row.next_change_idx as u32 - 1);
        }
        // No DB writes here: callers may hold this wallet's row lock in another transaction.
        // Staged changes (reveals) are persisted by the next locked `persist`.
        let arc = Arc::new(Mutex::new(Loaded { wallet, changeset, syncs: 0 }));
        // Another task may have raced us; keep the first.
        Ok(self.map.lock().expect("cache").entry(id).or_insert(arc).clone())
    }

    pub fn evict(&self, id: Uuid) {
        self.map.lock().expect("cache").remove(&id);
    }
}

/// Lock a wallet's mutex, giving up instead of hanging forever if something upstream wedged.
pub async fn lock_loaded(lw: &Arc<Mutex<Loaded>>) -> Result<tokio::sync::MutexGuard<'_, Loaded>> {
    tokio::time::timeout(Duration::from_secs(15), lw.lock())
        .await
        .map_err(|_| WatchError::State("wallet busy; try again".into()))
}

/// Pull chain state into the wallet. Network I/O happens without holding any lock; applying
/// the update follows the global lock order (row lock, then mutex).
pub async fn sync_wallet(pool: &PgPool, cache: &WalletCache, chain: &dyn ChainSource, id: Uuid) -> Result<u32> {
    let lw = cache.get(pool, id).await?;
    let req = {
        let g = lock_loaded(&lw).await?;
        if g.syncs % FULL_SCAN_EVERY == 0 {
            ScanRequest::Full { req: g.wallet.bdk().start_full_scan().build(), stop_gap: STOP_GAP }
        } else {
            ScanRequest::Sync(g.wallet.bdk().start_sync_with_revealed_spks().build())
        }
    };
    let update = chain.scan(req).await?;
    let mut tx = pool.begin().await.map_err(StoreError::from)?;
    store::lock_wallet(&mut tx, id).await?;
    let mut g = lock_loaded(&lw).await?;
    g.wallet.apply_update(update)?;
    g.syncs = g.syncs.wrapping_add(1);
    g.persist(&mut tx, id).await?;
    tx.commit().await.map_err(StoreError::from)?;
    Ok(g.wallet.tip_height())
}

fn reason_for(status: Status) -> &'static str {
    match status {
        Status::Deleted => "predecessor_deleted",
        Status::Conflicted => "predecessor_conflicted",
        _ => "predecessor_replaced",
    }
}

/// Apply one lifecycle event (CAS on the current status). If the proposal leaves the queue
/// without confirming, every strict-order descendant is invalidated too.
/// Returns the new status (unchanged if the event is a no-op for this state).
pub async fn apply_event(
    conn: &mut PgConnection,
    p: &ProposalRow,
    event: Event,
    update: StatusUpdate<'_>,
    actor: &str,
) -> Result<Status> {
    let from = p.status();
    let to = transition(from, event).map_err(|e| WatchError::State(e.to_string()))?;
    if to == from {
        return Ok(to);
    }
    let reason = update.reason.map(str::to_string);
    store::set_status(conn, p.id, from, to, update).await?;
    store::audit(
        conn,
        Some(p.wallet_id),
        actor,
        "proposal_status",
        serde_json::json!({ "proposal": p.id, "from": from.as_str(), "to": to.as_str(), "event": event, "reason": reason }),
    )
    .await?;
    if matches!(to, Status::Deleted | Status::Invalidated | Status::Conflicted) {
        cascade(conn, p.id, to, actor).await?;
    }
    Ok(to)
}

/// Invalidate every active strict-order descendant of `id`.
pub async fn cascade(conn: &mut PgConnection, id: i64, why: Status, actor: &str) -> Result<Vec<i64>> {
    let ids = store::active_descendants(conn, id).await?;
    for d in &ids {
        let row = store::get_proposal(conn, *d).await?;
        let from = row.status();
        if !from.is_active() {
            continue;
        }
        let to = transition(from, Event::PredecessorGone).map_err(|e| WatchError::State(e.to_string()))?;
        store::set_status(conn, *d, from, to, StatusUpdate { reason: Some(reason_for(why)), ..Default::default() }).await?;
        store::audit(
            conn,
            Some(row.wallet_id),
            actor,
            "proposal_status",
            serde_json::json!({ "proposal": d, "from": from.as_str(), "to": to.as_str(), "event": "predecessor_gone", "predecessor": id }),
        )
        .await?;
    }
    Ok(ids)
}

/// Strict-order: once any member of a replacement group is broadcast, the group's other
/// members will never confirm with their txids, so everything chained on them is dead.
pub async fn on_group_broadcast(conn: &mut PgConnection, id: i64, actor: &str) -> Result<Vec<i64>> {
    let mut out = vec![];
    for s in store::group_siblings(conn, id).await? {
        out.extend(cascade(conn, s.id, Status::Invalidated, actor).await?);
    }
    Ok(out)
}

/// Compare every active proposal of a wallet (incl. SOFT_CONFIRMED) with the chain and apply
/// transitions. Final (CONFIRMED) proposals are never looked at again.
/// `confirmations_final` = depth at which a confirmation becomes final (≥ 1).
/// Returns (proposal id, new status) for each change.
pub async fn reconcile(pool: &PgPool, chain: &dyn ChainSource, wallet_id: Uuid, confirmations_final: u32) -> Result<Vec<(i64, Status)>> {
    let confirmations_final = confirmations_final.max(1);
    let mut changes = vec![];
    let ids: Vec<i64> = {
        let mut conn = pool.acquire().await.map_err(StoreError::from)?;
        store::list_proposals(&mut conn, wallet_id, true).await?.into_iter().map(|p| p.id).collect()
    };
    if ids.is_empty() {
        return Ok(changes);
    }
    // Read before any tx_state: a tip from before a later block can only understate depth, so
    // a race here delays finality, never grants it early.
    let tip = chain.tip().await?;
    for id in ids {
        // Gather chain facts first, without holding locks.
        let snapshot = {
            let mut conn = pool.acquire().await.map_err(StoreError::from)?;
            store::get_proposal(&mut conn, id).await?
        };
        if !snapshot.status().is_active() {
            continue;
        }
        let txid = snapshot.txid()?;
        let own = chain.tx_state(txid).await?;
        let mut spends: Vec<(OutPoint, btc_safe_chain::Spend)> = vec![];
        let mut unspent_inputs: Vec<OutPoint> = vec![];
        let spec = snapshot.spec()?;
        for i in &spec.inputs {
            match chain.outspend(i.outpoint).await {
                Ok(Some(s)) if s.txid != txid => spends.push((i.outpoint, s)),
                Ok(Some(_)) => {}
                Ok(None) => unspent_inputs.push(i.outpoint),
                // e.g. the prevout belongs to a strict-order predecessor not yet on chain.
                Err(e) => tracing::debug!(proposal = id, outpoint = %i.outpoint, "outspend lookup failed: {e}"),
            }
        }
        // Inputs whose parent is one of our proposals that died (replaced/deleted/invalidated)
        // and never reached the chain: the coin will never exist (parallel-mode children of a
        // replaced parent; strict-order is also covered by `cascade`).
        let mut dead_parent: Option<Txid> = None;
        if own == TxState::NotFound {
            let mut conn = pool.acquire().await.map_err(StoreError::from)?;
            for op in &unspent_inputs {
                if let Some(st) = store::proposal_status_by_txid(&mut conn, wallet_id, op.txid).await? {
                    if matches!(st, Status::Deleted | Status::Invalidated | Status::Conflicted)
                        && chain.tx_state(op.txid).await? == TxState::NotFound
                    {
                        dead_parent = Some(op.txid);
                        break;
                    }
                }
            }
        }

        let mut tx = pool.begin().await.map_err(StoreError::from)?;
        store::lock_wallet(&mut tx, wallet_id).await?;
        let wrow = store::get_wallet(&mut tx, wallet_id).await?;
        let p = store::lock_proposal(&mut tx, id).await?;
        // The chain facts above were read against `snapshot`. If the proposal moved since
        // (e.g. it was executed meanwhile), they're stale: skip it this round.
        if !p.status().is_active() || p.status() != snapshot.status() {
            tx.commit().await.map_err(StoreError::from)?;
            continue;
        }
        let siblings: Vec<Txid> = store::group_siblings(&mut tx, id).await?.iter().filter_map(|s| s.txid().ok()).collect();
        let new = match own {
            TxState::Confirmed { height } => {
                let hard = confirmations(tip, height) >= confirmations_final;
                let reason = if hard { "final" } else { "soft_confirmed" };
                let update = StatusUpdate { confirmed_height: Some(height), broadcast_txid: Some(txid), reason: Some(reason), ..Default::default() };
                if p.status() == Status::SoftConfirmed && !hard {
                    // Still soft. If a reorg moved it to another block, record the new height.
                    if p.confirmed_height != Some(height as i32) {
                        store::set_status(&mut tx, p.id, Status::SoftConfirmed, Status::SoftConfirmed, update).await?;
                        store::audit(
                            &mut tx,
                            Some(wallet_id),
                            "watcher",
                            "proposal_status",
                            serde_json::json!({ "proposal": id, "from": "soft_confirmed", "to": "soft_confirmed", "event": "confirmation_moved", "old_height": p.confirmed_height, "height": height }),
                        )
                        .await?;
                    }
                    None
                } else {
                    Some(apply_event(&mut tx, &p, Event::Confirmed { hard }, update, "watcher").await?)
                }
            }
            // Was in a block, now back in the mempool: the block was reorged out.
            TxState::Mempool if p.status() == Status::SoftConfirmed => Some(
                apply_event(&mut tx, &p, Event::Reorged, StatusUpdate { reason: Some("reorged_back_to_mempool"), ..Default::default() }, "watcher").await?,
            ),
            TxState::Mempool if p.status() != Status::Broadcast => {
                let st = apply_event(&mut tx, &p, Event::Broadcast, StatusUpdate { broadcast_txid: Some(txid), reason: Some("seen_in_mempool"), ..Default::default() }, "watcher")
                    .await?;
                if wrow.ordering() == store::OrderingMode::Strict {
                    on_group_broadcast(&mut tx, id, "watcher").await?;
                }
                Some(st)
            }
            _ => {
                let mut out = None;
                // Conflicting spends: a sibling replacement (wait for it to confirm) or
                // someone else's tx (invalidate now). For a soft-confirmed proposal this is
                // "a conflicting tx won the reorg".
                for (_, s) in &spends {
                    let sibling = siblings.contains(&s.txid);
                    // A sibling only wins for good once it is final: a soft-confirmed sibling
                    // can still be reorged out, and then this proposal may confirm instead.
                    let won = s.confirmed_height.is_some_and(|h| confirmations(tip, h) >= confirmations_final);
                    let ev = Event::InputSpentElsewhere { by_sibling_replacement: sibling, confirmed: won };
                    let reason = if sibling { "replacement_confirmed" } else { "input_spent_elsewhere" };
                    let st = apply_event(&mut tx, &p, ev, StatusUpdate { invalidated_by: Some(s.txid), reason: Some(reason), ..Default::default() }, "watcher").await?;
                    if st != p.status() {
                        out = Some(st);
                        break;
                    }
                }
                if out.is_none() {
                    if let Some(parent) = dead_parent {
                        let ev = Event::InputSpentElsewhere { by_sibling_replacement: false, confirmed: false };
                        out = Some(apply_event(&mut tx, &p, ev, StatusUpdate { invalidated_by: Some(parent), reason: Some("parent_replaced"), ..Default::default() }, "watcher").await?);
                    }
                }
                // Soft-confirmed, but the tx is in neither a block nor the mempool, and nothing
                // conflicting won: reorged out. Back to BROADCAST; if it stays gone, the
                // next tick's "dropped" rule returns it to READY so it can be re-sent.
                if out.is_none() && p.status() == Status::SoftConfirmed {
                    out = Some(apply_event(&mut tx, &p, Event::Reorged, StatusUpdate { reason: Some("reorged_out"), ..Default::default() }, "watcher").await?);
                }
                if out.is_none() && p.status() == Status::Broadcast && own == TxState::NotFound && spends.is_empty() {
                    out = Some(apply_event(&mut tx, &p, Event::Dropped, StatusUpdate { reason: Some("dropped_from_mempool"), ..Default::default() }, "watcher").await?);
                }
                out
            }
        };
        tx.commit().await.map_err(StoreError::from)?;
        if let Some(st) = new {
            if st != snapshot.status() {
                changes.push((id, st));
            }
        }
    }
    Ok(changes)
}

/// Sync + reconcile every wallet once.
pub async fn tick(pool: &PgPool, cache: &WalletCache, chain: &dyn ChainSource, confirmations_final: u32) -> Result<()> {
    let wallets = {
        let mut conn = pool.acquire().await.map_err(StoreError::from)?;
        store::list_wallets(&mut conn).await?
    };
    for w in wallets {
        if let Err(e) = sync_wallet(pool, cache, chain, w.id).await {
            tracing::warn!(wallet = %w.id, "sync failed: {e}");
            continue;
        }
        match reconcile(pool, chain, w.id, confirmations_final).await {
            Ok(ch) if !ch.is_empty() => tracing::info!(wallet = %w.id, ?ch, "proposal transitions"),
            Ok(_) => {}
            Err(e) => tracing::warn!(wallet = %w.id, "reconcile failed: {e}"),
        }
    }
    Ok(())
}

/// Background loop. Runs until the task is dropped.
pub async fn run(pool: PgPool, cache: Arc<WalletCache>, chain: Arc<dyn ChainSource>, every: Duration, confirmations_final: u32) {
    let mut iv = tokio::time::interval(every);
    loop {
        iv.tick().await;
        if let Err(e) = tick(&pool, &cache, chain.as_ref(), confirmations_final).await {
            tracing::warn!("watcher tick failed: {e}");
        }
    }
}
