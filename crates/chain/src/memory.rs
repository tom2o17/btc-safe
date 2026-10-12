//! In-process chain simulator. Blocks and a mempool, no script validation (the coordinator
//! validates signatures itself; this only models UTXO spending, RBF, confirmations and reorgs).

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::Update;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::transaction::Version;
use bitcoin::{Amount, BlockHash, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::{ChainError, ChainSource, FeeEstimates, Result, ScanRequest, Spend, TxState};

struct Block {
    height: u32,
    hash: BlockHash,
    time: u64,
    txs: Vec<Transaction>,
}

struct State {
    blocks: Vec<Block>,
    mempool: Vec<(Transaction, u64)>,
    evicted: Vec<(Txid, u64)>,
    clock: u64,
    fees: FeeEstimates,
    nonce: u32,
    broadcasts: Vec<Txid>,
    /// Bumped on every reorg so replacement blocks get new hashes.
    forks: u32,
    /// Every `tx_state` lookup, in order (lets tests prove a txid was never re-checked).
    lookups: Vec<Txid>,
}

#[derive(Clone)]
pub struct MemoryChain {
    st: Arc<Mutex<State>>,
}

fn block_hash(height: u32, fork: u32) -> BlockHash {
    let mut data = b"btc-safe-memory-chain".to_vec();
    data.extend_from_slice(&height.to_le_bytes());
    if fork > 0 {
        data.extend_from_slice(&fork.to_le_bytes());
    }
    BlockHash::from_raw_hash(sha256d::Hash::hash(&data))
}

impl MemoryChain {
    pub fn new(network: Network) -> Self {
        let genesis = bitcoin::constants::genesis_block(network);
        let st = State {
            blocks: vec![Block { height: 0, hash: genesis.block_hash(), time: 1_600_000_000, txs: vec![] }],
            mempool: vec![],
            evicted: vec![],
            clock: 1_700_000_000,
            fees: FeeEstimates {
                fast: FeeRate::from_sat_per_vb(5).unwrap(),
                normal: FeeRate::from_sat_per_vb(2).unwrap(),
                slow: FeeRate::from_sat_per_vb(1).unwrap(),
            },
            nonce: 0,
            broadcasts: vec![],
            forks: 0,
            lookups: vec![],
        };
        MemoryChain { st: Arc::new(Mutex::new(st)) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().expect("memory chain lock")
    }

    pub fn set_fees(&self, fees: FeeEstimates) {
        self.lock().fees = fees;
    }

    /// Pay `amount` to `spk` from a fresh coinbase-like tx (goes to the mempool).
    pub fn fund(&self, spk: ScriptBuf, amount: Amount) -> OutPoint {
        let mut st = self.lock();
        st.nonce += 1;
        st.clock += 1;
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_raw_hash(sha256d::Hash::hash(&st.nonce.to_le_bytes())), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![0u8; 71], vec![2u8; 33]]),
            }],
            output: vec![TxOut { value: amount, script_pubkey: spk }],
        };
        let op = OutPoint { txid: tx.compute_txid(), vout: 0 };
        let t = st.clock;
        st.mempool.push((tx, t));
        op
    }

    /// Mine `n` blocks; the first includes the whole mempool. Returns the new tip height.
    pub fn mine(&self, n: u32) -> u32 {
        let mut st = self.lock();
        for i in 0..n {
            let height = st.blocks.len() as u32;
            st.clock += 600;
            let txs = if i == 0 { std::mem::take(&mut st.mempool).into_iter().map(|(t, _)| t).collect() } else { vec![] };
            let time = st.clock;
            let hash = block_hash(height, st.forks);
            st.blocks.push(Block { height, hash, time, txs });
        }
        st.blocks.len() as u32 - 1
    }

    /// Reorg: disconnect the top `depth` blocks (never genesis). With `back_to_mempool`, their
    /// txs return to the mempool, as a node does; otherwise they vanish (e.g. a competing miner's
    /// chain plus a mempool that never saw them). The new blocks that `mine` adds afterwards get
    /// different hashes. Returns the txids that were disconnected.
    pub fn reorg(&self, depth: u32, back_to_mempool: bool) -> Vec<Txid> {
        let mut st = self.lock();
        let depth = depth.min(st.blocks.len() as u32 - 1);
        st.forks += 1;
        st.clock += 1;
        let t = st.clock;
        let keep = st.blocks.len() - depth as usize;
        let gone: Vec<Block> = st.blocks.drain(keep..).collect();
        let mut out = vec![];
        for b in gone {
            for tx in b.txs {
                out.push(tx.compute_txid());
                if back_to_mempool {
                    st.mempool.push((tx, t));
                } else {
                    st.evicted.push((tx.compute_txid(), t));
                }
            }
        }
        out
    }

    /// Mine one block containing exactly `txs` (none of the mempool, except that mempool txs
    /// conflicting with `txs` are evicted). For "a conflicting tx won the reorg".
    pub fn mine_with(&self, txs: Vec<Transaction>) -> u32 {
        let mut st = self.lock();
        let spends: HashSet<OutPoint> = txs.iter().flat_map(|t| t.input.iter().map(|i| i.previous_output)).collect();
        let ids: HashSet<Txid> = txs.iter().map(|t| t.compute_txid()).collect();
        st.clock += 600;
        let t = st.clock;
        let (keep, gone): (Vec<_>, Vec<_>) = std::mem::take(&mut st.mempool)
            .into_iter()
            .partition(|(m, _)| !ids.contains(&m.compute_txid()) && !m.input.iter().any(|i| spends.contains(&i.previous_output)));
        st.mempool = keep;
        for (g, _) in gone {
            if !ids.contains(&g.compute_txid()) {
                st.evicted.push((g.compute_txid(), t));
            }
        }
        let height = st.blocks.len() as u32;
        let hash = block_hash(height, st.forks);
        st.blocks.push(Block { height, hash, time: t, txs });
        height
    }

    /// Txids passed to `tx_state`, in call order.
    pub fn lookups(&self) -> Vec<Txid> {
        self.lock().lookups.clone()
    }

    /// Put a transaction in the mempool without the usual checks (someone spending our coins
    /// with another tool). Evicts any mempool tx it conflicts with.
    pub fn inject(&self, tx: Transaction) {
        let mut st = self.lock();
        st.clock += 1;
        let spends: HashSet<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
        let t = st.clock;
        let (keep, gone): (Vec<_>, Vec<_>) =
            std::mem::take(&mut st.mempool).into_iter().partition(|(m, _)| !m.input.iter().any(|i| spends.contains(&i.previous_output)));
        st.mempool = keep;
        for (g, _) in gone {
            st.evicted.push((g.compute_txid(), t));
        }
        st.mempool.push((tx, t));
    }

    /// Drop a tx from the mempool (expiry / eviction).
    pub fn evict(&self, txid: Txid) {
        let mut st = self.lock();
        st.clock += 1;
        let t = st.clock;
        st.mempool.retain(|(m, _)| m.compute_txid() != txid);
        st.evicted.push((txid, t));
    }

    pub fn broadcasts(&self) -> Vec<Txid> {
        self.lock().broadcasts.clone()
    }

    fn find_output(st: &State, op: OutPoint) -> Option<TxOut> {
        st.blocks
            .iter()
            .flat_map(|b| b.txs.iter())
            .chain(st.mempool.iter().map(|(t, _)| t))
            .find(|t| t.compute_txid() == op.txid)
            .and_then(|t| t.output.get(op.vout as usize).cloned())
    }

    fn spender(st: &State, op: OutPoint) -> Option<Spend> {
        for b in &st.blocks {
            for t in &b.txs {
                if t.input.iter().any(|i| i.previous_output == op) {
                    return Some(Spend { txid: t.compute_txid(), confirmed_height: Some(b.height) });
                }
            }
        }
        st.mempool
            .iter()
            .find(|(t, _)| t.input.iter().any(|i| i.previous_output == op))
            .map(|(t, _)| Spend { txid: t.compute_txid(), confirmed_height: None })
    }
}

#[async_trait]
impl ChainSource for MemoryChain {
    fn describe(&self) -> String {
        "memory chain (simulator)".into()
    }

    async fn tip(&self) -> Result<u32> {
        Ok(self.lock().blocks.len() as u32 - 1)
    }

    async fn fee_estimates(&self) -> Result<FeeEstimates> {
        Ok(self.lock().fees)
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<()> {
        let mut st = self.lock();
        let txid = tx.compute_txid();
        if st.mempool.iter().any(|(t, _)| t.compute_txid() == txid) || st.blocks.iter().any(|b| b.txs.iter().any(|t| t.compute_txid() == txid)) {
            return Ok(());
        }
        let mut in_value = Amount::ZERO;
        let mut replaces = vec![];
        for i in &tx.input {
            let out = Self::find_output(&st, i.previous_output)
                .ok_or_else(|| ChainError::BroadcastRejected(format!("missing input {}", i.previous_output)))?;
            in_value += out.value;
            if let Some(s) = Self::spender(&st, i.previous_output) {
                if s.confirmed_height.is_some() {
                    return Err(ChainError::BroadcastRejected("bad-txns-inputs-missingorspent".into()));
                }
                let (old, _) = st.mempool.iter().find(|(t, _)| t.compute_txid() == s.txid).unwrap();
                if !old.input.iter().any(|i| i.sequence.is_rbf()) {
                    return Err(ChainError::BroadcastRejected("txn-mempool-conflict".into()));
                }
                replaces.push(s.txid);
            }
        }
        let out_value: Amount = tx.output.iter().map(|o| o.value).sum();
        if out_value > in_value {
            return Err(ChainError::BroadcastRejected("bad-txns-in-belowout".into()));
        }
        st.clock += 1;
        let t = st.clock;
        // Replacements evict the originals and everything that spends them.
        let mut gone: HashSet<Txid> = replaces.into_iter().collect();
        loop {
            let before = gone.len();
            for (m, _) in &st.mempool {
                if m.input.iter().any(|i| gone.contains(&i.previous_output.txid)) {
                    gone.insert(m.compute_txid());
                }
            }
            if gone.len() == before {
                break;
            }
        }
        st.mempool.retain(|(m, _)| !gone.contains(&m.compute_txid()));
        for g in gone {
            st.evicted.push((g, t));
        }
        st.mempool.push((tx.clone(), t));
        st.broadcasts.push(txid);
        Ok(())
    }

    async fn tx_state(&self, txid: Txid) -> Result<TxState> {
        let mut st = self.lock();
        st.lookups.push(txid);
        for b in &st.blocks {
            if b.txs.iter().any(|t| t.compute_txid() == txid) {
                return Ok(TxState::Confirmed { height: b.height });
            }
        }
        if st.mempool.iter().any(|(t, _)| t.compute_txid() == txid) {
            return Ok(TxState::Mempool);
        }
        Ok(TxState::NotFound)
    }

    async fn outspend(&self, op: OutPoint) -> Result<Option<Spend>> {
        Ok(Self::spender(&self.lock(), op))
    }

    async fn get_tx(&self, txid: Txid) -> Result<Option<Transaction>> {
        let st = self.lock();
        Ok(st
            .blocks
            .iter()
            .flat_map(|b| b.txs.iter())
            .chain(st.mempool.iter().map(|(t, _)| t))
            .find(|t| t.compute_txid() == txid)
            .cloned())
    }

    /// Returns everything; BDK keeps only what touches the wallet's scripts for balances.
    async fn scan(&self, _req: ScanRequest) -> Result<Update> {
        let st = self.lock();
        let mut tu = TxUpdate::<ConfirmationBlockTime>::default();
        let mut seen = BTreeMap::new();
        for b in &st.blocks {
            for t in &b.txs {
                let txid = t.compute_txid();
                tu.txs.push(Arc::new(t.clone()));
                tu.anchors.insert((
                    ConfirmationBlockTime { block_id: BlockId { height: b.height, hash: b.hash }, confirmation_time: b.time },
                    txid,
                ));
            }
        }
        for (t, at) in &st.mempool {
            tu.txs.push(Arc::new(t.clone()));
            seen.insert(t.compute_txid(), *at);
        }
        tu.seen_ats = seen.into_iter().collect();
        tu.evicted_ats = st.evicted.iter().copied().collect();
        let cp = CheckPoint::from_block_ids(st.blocks.iter().map(|b| BlockId { height: b.height, hash: b.hash }))
            .map_err(|_| ChainError::Backend("bad checkpoint".into()))?;
        Ok(Update { last_active_indices: Default::default(), tx_update: tu, chain: Some(cp) })
    }
}
