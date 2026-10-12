//! Network smoke test against public signet Esplora. Ignored by default:
//!   cargo test -p btc-safe-chain --test signet_smoke -- --ignored
//! ESPLORA_URL overrides the default (mempool.space signet).

use bitcoin::Network;
use btc_safe_chain::{ChainSource, Esplora, ScanRequest};
use btc_safe_core::policy::{OwnerKey, WalletPolicy};
use btc_safe_wallet::SafeWallet;

#[tokio::test]
#[ignore = "network"]
async fn sync_fresh_wallet_against_signet() {
    let url = std::env::var("ESPLORA_URL").unwrap_or_else(|_| "https://mempool.space/signet/api".into());
    let chain = Esplora::new(&url).unwrap();
    let tip = chain.tip().await.unwrap();
    assert!(tip > 200_000, "signet tip {tip}");
    let fees = chain.fee_estimates().await.unwrap();
    assert!(fees.fast >= fees.slow);

    let owners = btc_safe_testkit::three_owners();
    let policy = WalletPolicy::new(
        Network::Signet,
        2,
        owners.iter().map(|o| OwnerKey { name: o.name.clone(), fingerprint: o.fingerprint, path: o.path.clone(), xpub: o.xpub }).collect(),
    )
    .unwrap();
    let mut w = SafeWallet::new(policy).unwrap();
    let req = ScanRequest::Full { req: w.bdk().start_full_scan().build(), stop_gap: 5 };
    let update = chain.scan(req).await.unwrap();
    w.apply_update(update).unwrap();
    assert!(w.tip_height() >= tip, "wallet tip {} chain tip {tip}", w.tip_height());
    println!("signet tip {tip}, wallet tip {}, utxos {}, fees fast {:?}", w.tip_height(), w.utxos().len(), fees.fast);

    // Unknown txid → NotFound; a spent coinbase-era outpoint lookup works.
    let missing: bitcoin::Txid = "0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap();
    assert_eq!(chain.tx_state(missing).await.unwrap(), btc_safe_chain::TxState::NotFound);
}
