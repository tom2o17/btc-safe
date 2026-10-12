//! Chain sources. `ChainSource` is what the watcher and API need from the chain; `Esplora`
//! is the real backend (signet), `MemoryChain` an in-process simulator for tests and dev.

use std::collections::HashMap;

use async_trait::async_trait;
use bdk_wallet::chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_wallet::{KeychainKind, Update};
use bitcoin::{FeeRate, OutPoint, Transaction, Txid};
use serde::{Deserialize, Serialize};

pub mod esplora;
pub mod memory;

pub use esplora::Esplora;
pub use memory::MemoryChain;

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("chain source: {0}")]
    Backend(String),
    #[error("broadcast rejected: {0}")]
    BroadcastRejected(String),
}

pub type Result<T> = std::result::Result<T, ChainError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TxState {
    NotFound,
    Mempool,
    Confirmed { height: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spend {
    pub txid: Txid,
    pub confirmed_height: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeEstimates {
    pub fast: FeeRate,
    pub normal: FeeRate,
    pub slow: FeeRate,
}

pub enum ScanRequest {
    Full { req: FullScanRequest<KeychainKind>, stop_gap: usize },
    Sync(SyncRequest<(KeychainKind, u32)>),
}

#[async_trait]
pub trait ChainSource: Send + Sync {
    fn describe(&self) -> String;
    async fn tip(&self) -> Result<u32>;
    async fn fee_estimates(&self) -> Result<FeeEstimates>;
    async fn broadcast(&self, tx: &Transaction) -> Result<()>;
    async fn tx_state(&self, txid: Txid) -> Result<TxState>;
    /// Who spends `op`, if anyone (mempool or confirmed).
    async fn outspend(&self, op: OutPoint) -> Result<Option<Spend>>;
    async fn get_tx(&self, txid: Txid) -> Result<Option<Transaction>>;
    async fn scan(&self, req: ScanRequest) -> Result<Update>;
}

/// sat/vB (float, as Esplora reports) → FeeRate, rounded up.
pub fn fee_rate_from_sat_vb(x: f64) -> FeeRate {
    FeeRate::from_sat_per_kwu((x.max(0.0) * 250.0).ceil() as u64)
}

/// Pick fast/normal/slow from Esplora's target→rate map (targets 1..1008 blocks).
pub fn pick_estimates(m: &HashMap<u16, f64>) -> Option<FeeEstimates> {
    let at = |target: u16| -> Option<f64> {
        // Closest target at or above the wanted one, else the largest available.
        let mut keys: Vec<u16> = m.keys().copied().collect();
        keys.sort_unstable();
        keys.iter().find(|k| **k >= target).or(keys.last()).and_then(|k| m.get(k)).copied()
    };
    Some(FeeEstimates {
        fast: fee_rate_from_sat_vb(at(1)?),
        normal: fee_rate_from_sat_vb(at(6)?),
        slow: fee_rate_from_sat_vb(at(144)?),
    })
}
