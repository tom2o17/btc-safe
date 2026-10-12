use async_trait::async_trait;
use bdk_esplora::esplora_client::{self, AsyncClient};
use bdk_esplora::EsploraAsyncExt;
use bitcoin::{OutPoint, Transaction, Txid};

use crate::{pick_estimates, ChainError, ChainSource, FeeEstimates, Result, ScanRequest, Spend, TxState};

const PARALLEL_REQUESTS: usize = 4;

pub struct Esplora {
    url: String,
    client: AsyncClient,
}

impl Esplora {
    pub fn new(url: &str) -> Result<Self> {
        let client = esplora_client::Builder::new(url.trim_end_matches('/'))
            .timeout(30)
            .build_async()
            .map_err(|e| ChainError::Backend(e.to_string()))?;
        Ok(Esplora { url: url.to_string(), client })
    }
}

fn be<E: std::fmt::Display>(e: E) -> ChainError {
    ChainError::Backend(e.to_string())
}

#[async_trait]
impl ChainSource for Esplora {
    fn describe(&self) -> String {
        format!("esplora {}", self.url)
    }

    async fn tip(&self) -> Result<u32> {
        self.client.get_height().await.map_err(be)
    }

    async fn fee_estimates(&self) -> Result<FeeEstimates> {
        let m = self.client.get_fee_estimates().await.map_err(be)?;
        pick_estimates(&m).ok_or_else(|| ChainError::Backend("no fee estimates".into()))
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<()> {
        self.client.broadcast(tx).await.map_err(|e| ChainError::BroadcastRejected(e.to_string()))
    }

    async fn tx_state(&self, txid: Txid) -> Result<TxState> {
        if self.client.get_tx(&txid).await.map_err(be)?.is_none() {
            return Ok(TxState::NotFound);
        }
        let st = self.client.get_tx_status(&txid).await.map_err(be)?;
        Ok(match (st.confirmed, st.block_height) {
            (true, Some(h)) => TxState::Confirmed { height: h },
            _ => TxState::Mempool,
        })
    }

    async fn outspend(&self, op: OutPoint) -> Result<Option<Spend>> {
        let st = self.client.get_output_status(&op.txid, op.vout as u64).await.map_err(be)?;
        Ok(st.and_then(|s| {
            if !s.spent {
                return None;
            }
            let txid = s.txid?;
            let confirmed_height = s.status.and_then(|t| if t.confirmed { t.block_height } else { None });
            Some(Spend { txid, confirmed_height })
        }))
    }

    async fn get_tx(&self, txid: Txid) -> Result<Option<Transaction>> {
        self.client.get_tx(&txid).await.map_err(be)
    }

    async fn scan(&self, req: ScanRequest) -> Result<bdk_wallet::Update> {
        match req {
            ScanRequest::Full { req, stop_gap } => {
                Ok(self.client.full_scan(req, stop_gap, PARALLEL_REQUESTS).await.map_err(be)?.into())
            }
            ScanRequest::Sync(req) => Ok(self.client.sync(req, PARALLEL_REQUESTS).await.map_err(be)?.into()),
        }
    }
}
