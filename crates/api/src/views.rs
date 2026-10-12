//! Response shapes.

use btc_safe_core::policy::WalletPolicy;
use btc_safe_core::state::Status;
use btc_safe_core::validate::{self, SigStatus};
use btc_safe_core::Keychain;
use btc_safe_store::{ProposalRow, WalletRow};
use btc_safe_wallet::Balance;
use serde_json::{json, Value};

use crate::ApiResult;

pub fn sat_vb(kwu: i64) -> f64 {
    (kwu as f64 / 250.0 * 100.0).round() / 100.0
}

pub fn balance(b: &Balance) -> Value {
    json!({
        "confirmed_sats": b.confirmed.to_sat(),
        "unconfirmed_sats": b.unconfirmed.to_sat(),
        "reserved_sats": b.reserved.to_sat(),
        "available_sats": b.available.to_sat(),
    })
}

pub fn wallet(w: &WalletRow, policy: &WalletPolicy, bal: Option<&Balance>, queue: usize, tip: Option<u32>) -> ApiResult<Value> {
    let owners: Vec<Value> = w
        .owners
        .iter()
        .map(|o| json!({ "id": o.id, "name": o.name, "fingerprint": o.fingerprint, "path": o.path, "xpub": o.xpub, "kind": o.kind, "position": o.position }))
        .collect();
    Ok(json!({
        "id": w.id,
        "name": w.name,
        "network": w.network,
        "threshold": w.threshold,
        "owners_count": w.owners.len(),
        "owners": owners,
        "policy": format!("P2WSH sortedmulti {}-of-{}", w.threshold, w.owners.len()),
        "descriptor": {
            "external": w.descriptor_ext,
            "internal": w.descriptor_int,
            "multipath": policy.multipath_descriptor_string()?,
        },
        "ordering_mode": w.ordering_mode,
        "balance": bal.map(balance),
        "queue_count": queue,
        "tip_height": tip.or(w.tip_height.map(|h| h as u32)),
        "last_synced_at": w.last_synced_at,
        "next_receive_index": w.next_receive_idx,
        "warnings": policy.warnings(),
        "created_at": w.created_at,
    }))
}

pub fn first_addresses(policy: &WalletPolicy, n: u32) -> ApiResult<Vec<String>> {
    (0..n).map(|i| Ok(policy.address(Keychain::External, i)?.to_string())).collect()
}

fn confirmations(w: &WalletRow, policy: &WalletPolicy, st: &SigStatus) -> Value {
    let owners: Vec<Value> = st
        .owners
        .iter()
        .map(|o| {
            let row = w.owners.iter().find(|r| r.position as usize == o.owner);
            json!({
                "owner_id": row.map(|r| r.id),
                "name": row.map(|r| r.name.clone()),
                "fingerprint": policy.owners()[o.owner].fingerprint.to_string(),
                "signed": o.complete,
                "inputs_signed": o.inputs_signed,
            })
        })
        .collect();
    json!({ "threshold": st.threshold, "count": st.confirmations, "ready": st.ready, "owners": owners })
}

/// Block depth of a confirmed proposal against the wallet's last synced tip. `final` is the
/// stored status (the watcher decides it), not recomputed here.
fn chain_depth(w: &WalletRow, p: &ProposalRow, confirmations_final: u32) -> Value {
    let count = match (p.confirmed_height, w.tip_height) {
        (Some(h), Some(tip)) if h >= 0 && tip >= 0 => Some(btc_safe_watcher::confirmations(tip as u32, h as u32)),
        (Some(_), _) => Some(1),
        _ => None,
    };
    json!({ "count": count, "final_at": confirmations_final, "final": p.status() == Status::Confirmed })
}

/// Full proposal view. Signature status is recomputed from the stored PSBT on every read.
pub fn proposal(w: &WalletRow, policy: &WalletPolicy, p: &ProposalRow, include_psbt: bool, confirmations_final: u32) -> ApiResult<Value> {
    let spec = p.spec()?;
    let psbt = p.psbt()?;
    let st = validate::signature_status(policy, &spec, &psbt)?;
    let mut v = json!({
        "id": p.id,
        "wallet_id": p.wallet_id,
        "status": p.status,
        "status_reason": p.status_reason,
        "created_by": p.created_by,
        "unsigned_txid": p.unsigned_txid,
        "fee_sats": p.fee_sats,
        "fee_rate_sat_vb": sat_vb(p.fee_rate_sat_kwu),
        "est_vsize": p.est_vsize,
        "sent_sats": p.sent_sats,
        "rbf": p.rbf,
        "fee_override": p.fee_override,
        "replaces": p.replaces_proposal_id,
        "replacement_group": p.group_id,
        "predecessor": p.predecessor_proposal_id,
        "broadcast_txid": p.broadcast_txid,
        "invalidated_by_txid": p.invalidated_by_txid,
        "confirmed_height": p.confirmed_height,
        "inputs": p.inputs.iter().map(|i| json!({ "outpoint": i.outpoint, "amount_sats": i.amount_sats, "keychain": i.keychain, "index": i.deriv_index })).collect::<Vec<_>>(),
        "outputs": p.outputs.iter().map(|o| json!({ "vout": o.vout, "address": o.address, "amount_sats": o.amount_sats, "is_change": o.is_change, "change_index": o.change_index })).collect::<Vec<_>>(),
        "confirmations": confirmations(w, policy, &st),
        "block_confirmations": chain_depth(w, p, confirmations_final),
        "created_at": p.created_at,
        "updated_at": p.updated_at,
        "note": "Proposal ids are display order only; Bitcoin has no nonce. In parallel mode queued proposals are independent; in strict-order mode each spends its predecessor's change.",
    });
    if include_psbt {
        v["psbt"] = json!(psbt.to_string());
    }
    Ok(v)
}
