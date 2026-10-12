//! Simulator controls, mounted only when the API runs on `MemoryChain` (CHAIN=memory).

use axum::extract::State;
use axum::Json;
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{Amount, Transaction};
use btc_safe_chain::ChainSource;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{ApiError, ApiResult, AppState};

#[derive(Deserialize)]
pub struct FundIn {
    address: String,
    amount_sats: u64,
}

pub async fn fund(State(st): State<AppState>, Json(b): Json<FundIn>) -> ApiResult<Json<Value>> {
    let mem = st.memory.as_ref().ok_or_else(ApiError::not_found)?;
    let addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        b.address.parse().map_err(|_| ApiError::bad_request("bad address"))?;
    let spk = addr.assume_checked().script_pubkey();
    let op = mem.fund(spk, Amount::from_sat(b.amount_sats));
    Ok(Json(json!({ "outpoint": op.to_string(), "note": "in mempool; POST /dev/mine to confirm" })))
}

#[derive(Deserialize)]
pub struct MineIn {
    blocks: Option<u32>,
}

pub async fn mine(State(st): State<AppState>, Json(b): Json<MineIn>) -> ApiResult<Json<Value>> {
    let mem = st.memory.as_ref().ok_or_else(ApiError::not_found)?;
    let tip = mem.mine(b.blocks.unwrap_or(1).clamp(1, 100));
    Ok(Json(json!({ "tip": tip })))
}

#[derive(Deserialize)]
pub struct InjectIn {
    tx_hex: String,
}

/// Put an arbitrary tx in the simulated mempool (e.g. someone spending our coins with
/// another tool), to exercise invalidation.
pub async fn inject(State(st): State<AppState>, Json(b): Json<InjectIn>) -> ApiResult<Json<Value>> {
    let mem = st.memory.as_ref().ok_or_else(ApiError::not_found)?;
    let tx: Transaction = deserialize_hex(&b.tx_hex).map_err(|_| ApiError::bad_request("bad tx hex"))?;
    let txid = tx.compute_txid();
    mem.inject(tx);
    Ok(Json(json!({ "txid": txid.to_string(), "tip": mem.tip().await.ok() })))
}

#[derive(Deserialize)]
pub struct ReorgIn {
    depth: Option<u32>,
    /// true: the disconnected txs go back to the mempool (what a node does); false: they vanish.
    back_to_mempool: Option<bool>,
}

/// Disconnect the top `depth` blocks (default 1), to exercise soft-confirmation rollback.
pub async fn reorg(State(st): State<AppState>, Json(b): Json<ReorgIn>) -> ApiResult<Json<Value>> {
    let mem = st.memory.as_ref().ok_or_else(ApiError::not_found)?;
    let gone = mem.reorg(b.depth.unwrap_or(1).clamp(1, 100), b.back_to_mempool.unwrap_or(true));
    Ok(Json(json!({ "disconnected": gone.iter().map(|t| t.to_string()).collect::<Vec<_>>(), "tip": mem.tip().await.ok() })))
}
