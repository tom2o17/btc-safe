use std::collections::BTreeMap;
use std::str::FromStr;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use btc_safe_core::fees;
use btc_safe_core::state::{Event, Status};
use btc_safe_core::validate;
use btc_safe_store::{self as store, OrderingMode, ProposalRow, SigRecord, StatusUpdate};
use btc_safe_wallet::{BuildRequest, BuiltProposal, ChainInput};
use btc_safe_watcher::apply_event;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::{views, ApiError, ApiResult, AppState};

#[derive(Deserialize)]
pub struct OutputIn {
    address: String,
    #[serde(default)]
    amount_sats: u64,
}

#[derive(Deserialize, Default)]
pub struct CreateProposal {
    #[serde(default)]
    outputs: Vec<OutputIn>,
    fee_rate_sat_vb: Option<f64>,
    /// Coin control: outpoints "txid:vout".
    utxos: Option<Vec<String>>,
    manual_only: Option<bool>,
    rbf: Option<bool>,
    replaces: Option<i64>,
    /// For replacements: "rebuild" (new outputs, same coins), "bump" (RBF fee bump),
    /// "cancel" (send the coins back to ourselves).
    replace_mode: Option<String>,
    send_max: Option<bool>,
    fee_override: Option<bool>,
    /// Legacy field. The proposer is always the logged-in user; a value naming anyone else is
    /// refused (400) so a spoof attempt is visible rather than silently rewritten.
    created_by: Option<String>,
}

fn prev_txs_of(psbt: &Psbt) -> BTreeMap<Txid, Transaction> {
    psbt.inputs.iter().filter_map(|i| i.non_witness_utxo.clone()).map(|t| (t.compute_txid(), t)).collect()
}

fn chain_input_from(pred: &ProposalRow) -> ApiResult<ChainInput> {
    let (outpoint, amount, index) = pred.change_output().ok_or_else(|| {
        ApiError::conflict(
            "no_change_to_chain",
            format!("strict-order: queue tail #{} has no change output to chain on; replace it with one that has change, or switch the wallet to parallel mode", pred.id),
        )
    })?;
    Ok(ChainInput { outpoint, amount, index, prev_tx: pred.spec()?.unsigned_tx })
}

pub async fn create(State(st): State<AppState>, Extension(user): Extension<CurrentUser>, Path(wid): Path<Uuid>, Json(b): Json<CreateProposal>) -> ApiResult<(StatusCode, Json<Value>)> {
    let estimates = st.chain.fee_estimates().await.ok();
    let fee_rate = match b.fee_rate_sat_vb {
        Some(x) if x.is_finite() && x > 0.0 && x <= 10_000.0 => btc_safe_chain::fee_rate_from_sat_vb(x),
        Some(_) => return Err(ApiError::bad_request("fee_rate_sat_vb must be in (0, 10000]")),
        None => estimates.map(|e| e.normal).ok_or_else(|| ApiError::bad_request("no fee estimate available; pass fee_rate_sat_vb"))?,
    };
    let send_max = b.send_max.unwrap_or(false);
    let rbf = b.rbf.unwrap_or(true);
    let fee_override = b.fee_override.unwrap_or(false);
    if b.created_by.as_deref().is_some_and(|c| !c.trim().eq_ignore_ascii_case(&user.email)) {
        return Err(ApiError::bad_request("created_by is set by the server to the logged-in user; omit it"));
    }
    let created_by = user.email.clone();

    // Lock order: load the cache entry first (may read the DB), then row lock, then mutex.
    let lw = st.cache.get(&st.pool, wid).await?;
    let mut tx = st.pool.begin().await?;
    let row = store::lock_wallet(&mut tx, wid).await?;
    let policy = row.policy()?;
    let network = policy.network();

    let mut recipients = vec![];
    for (i, o) in b.outputs.iter().enumerate() {
        let spk = store::parse_script_address(&o.address, network)
            .ok_or_else(|| ApiError::bad_request(format!("output {i}: not a valid {} address", row.network)))?;
        if !send_max && o.amount_sats == 0 {
            return Err(ApiError::bad_request(format!("output {i}: amount_sats must be > 0")));
        }
        if o.amount_sats > Amount::MAX_MONEY.to_sat() {
            return Err(ApiError::bad_request(format!("output {i}: amount_sats exceeds 21M BTC")));
        }
        recipients.push((spk, Amount::from_sat(o.amount_sats)));
    }
    let total: u64 = recipients.iter().map(|(_, a)| a.to_sat()).sum(); // each ≤ MAX_MONEY, n small
    if total > Amount::MAX_MONEY.to_sat() || b.outputs.len() > 1000 {
        return Err(ApiError::bad_request("outputs exceed 21M BTC in total (or too many outputs)"));
    }

    let replaced = match b.replaces {
        Some(r) => {
            let p = store::lock_proposal(&mut tx, r).await?;
            if p.wallet_id != wid {
                return Err(ApiError::not_found());
            }
            if !p.status().is_active() {
                return Err(ApiError::conflict("not_active", format!("#{r} is {}, nothing to replace", p.status)));
            }
            if p.status() == Status::SoftConfirmed {
                return Err(ApiError::conflict("already_confirmed", format!("#{r} is already in a block; it can't be replaced unless a reorg undoes that")));
            }
            Some(p)
        }
        None => None,
    };
    let mode = match (&replaced, b.replace_mode.as_deref()) {
        (None, None) => "new",
        (None, Some(_)) => return Err(ApiError::bad_request("replace_mode needs replaces")),
        (Some(p), None) => {
            if p.status() == Status::Broadcast {
                "bump"
            } else {
                "rebuild"
            }
        }
        (Some(_), Some(m @ ("rebuild" | "bump" | "cancel"))) => m,
        (Some(_), Some(m)) => return Err(ApiError::bad_request(format!("unknown replace_mode {m}"))),
    };
    if matches!(mode, "new" | "rebuild") && recipients.is_empty() {
        return Err(ApiError::bad_request("at least one output is required"));
    }
    if matches!(mode, "bump" | "cancel") && !recipients.is_empty() {
        return Err(ApiError::bad_request("bump/cancel keep or drop the original outputs; don't pass outputs"));
    }
    if mode == "rebuild" && replaced.as_ref().is_some_and(|p| p.status() == Status::Broadcast) {
        return Err(ApiError::conflict("already_broadcast", "the original is broadcast; use replace_mode bump or cancel"));
    }

    // Strict-order chaining.
    let strict = row.ordering() == OrderingMode::Strict;
    let mut predecessor = None;
    let mut chain_input = None;
    let mut warnings: Vec<Value> = vec![];
    if strict {
        match &replaced {
            None => {
                if let Some(tail) = store::queue_tail(&mut tx, wid).await? {
                    chain_input = Some(chain_input_from(&tail)?);
                    predecessor = Some(tail.id);
                }
            }
            Some(r) => {
                predecessor = r.predecessor_proposal_id;
                if mode == "rebuild" {
                    if let Some(pid) = predecessor {
                        let pred = store::get_proposal(&mut tx, pid).await?;
                        if pred.status().is_active() && !pred.status().is_in_flight() {
                            chain_input = Some(chain_input_from(&pred)?);
                        }
                    }
                }
                let desc = store::active_descendants(&mut tx, r.id).await?;
                if !desc.is_empty() {
                    warnings.push(json!({
                        "kind": "strict_order_descendants",
                        "message": format!("executing this replacement invalidates queued proposals {desc:?}; they must be rebuilt and re-signed"),
                        "proposals": desc,
                    }));
                }
            }
        }
    }

    let except_group = replaced.as_ref().and_then(|p| p.group_id);
    let reserved = store::reserved_outpoints(&mut tx, wid, except_group).await?;
    let mut must_spend: Vec<OutPoint> = match &b.utxos {
        Some(list) => list
            .iter()
            .map(|s| OutPoint::from_str(s).map_err(|_| ApiError::bad_request(format!("bad outpoint {s}"))))
            .collect::<ApiResult<_>>()?,
        None => vec![],
    };
    if let (Some(r), "rebuild") = (&replaced, mode) {
        for i in r.spec()?.inputs {
            if chain_input.as_ref().is_none_or(|c| c.outpoint != i.outpoint) && !must_spend.contains(&i.outpoint) {
                must_spend.push(i.outpoint);
            }
        }
    }
    let change_index = store::alloc_index(&mut tx, wid, btc_safe_core::Keychain::Internal).await?;

    let mut g = btc_safe_watcher::lock_loaded(&lw).await?;
    let built: BuiltProposal = match (mode, &replaced) {
        ("bump", Some(r)) => btc_safe_wallet::bump_fee(&policy, &r.spec()?, &prev_txs_of(&r.psbt()?), fee_rate)?,
        ("cancel", Some(r)) => btc_safe_wallet::build_cancel(&policy, &r.spec()?, &prev_txs_of(&r.psbt()?), change_index, fee_rate)?,
        _ => g.wallet.build_proposal(&BuildRequest {
            recipients,
            fee_rate: Some(fee_rate),
            reserved,
            must_spend,
            manual_only: b.manual_only.unwrap_or(false) || mode == "rebuild",
            chain_input,
            change_index,
            rbf,
            send_max,
        })?,
    };
    if let Some(r) = &replaced {
        let old: Vec<OutPoint> = r.spec()?.inputs.iter().map(|i| i.outpoint).collect();
        if !built.spec.inputs.iter().any(|i| old.contains(&i.outpoint)) {
            return Err(ApiError::internal("replacement doesn't conflict with the original"));
        }
        // BIP-125 rules 3/4: pay more than everything the broadcast evicts (any broadcast
        // member of the group, plus strict-order descendants already broadcast), plus 1 sat/vB.
        let mut evicted: u64 = 0;
        let mut group = store::group_siblings(&mut tx, r.id).await?;
        group.push(r.clone());
        for m in group.iter().filter(|m| m.status() == Status::Broadcast) {
            let mut fee = m.fee_sats as u64;
            for d in store::active_descendants(&mut tx, m.id).await? {
                let d = store::get_proposal(&mut tx, d).await?;
                if d.status() == Status::Broadcast {
                    fee += d.fee_sats as u64;
                }
            }
            evicted = evicted.max(fee);
        }
        if evicted > 0 && built.summary.fee.to_sat() < evicted + built.summary.est_vsize {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "fee_too_low",
                format!("replacement must pay more than the {evicted} sats it evicts plus 1 sat/vB (BIP-125); raise fee_rate_sat_vb"),
            ));
        }
    }
    let s = &built.summary;
    let fee_warnings = fees::check_fee(s.fee, s.est_weight, s.sent, &st.fee_policy, estimates.map(|e| e.fast), fee_override)?;
    let id = store::insert_proposal(
        &mut tx,
        store::NewProposal {
            wallet_id: wid,
            created_by: &created_by,
            spec: &built.spec,
            psbt: &built.psbt,
            summary: s,
            fee_override,
            replaces: replaced.as_ref().map(|r| r.id),
            predecessor,
        },
    )
    .await?;
    store::audit(
        &mut tx,
        Some(wid),
        &created_by,
        "proposal_created",
        json!({ "proposal": id, "txid": s.unsigned_txid.to_string(), "fee": s.fee.to_sat(), "sent": s.sent.to_sat(), "mode": mode, "replaces": b.replaces, "predecessor": predecessor }),
    )
    .await?;
    let p = store::get_proposal(&mut tx, id).await?;
    g.persist(&mut tx, wid).await?;
    tx.commit().await?;
    drop(g);

    let mut v = views::proposal(&row, &policy, &p, true, st.confirmations_final)?;
    for w in fee_warnings {
        warnings.push(json!(w));
    }
    v["warnings"] = json!(warnings);
    Ok((StatusCode::CREATED, Json(v)))
}

#[derive(Deserialize)]
pub struct ListQuery {
    status: Option<String>,
}

pub async fn list(State(st): State<AppState>, Path(wid): Path<Uuid>, Query(q): Query<ListQuery>) -> ApiResult<Json<Value>> {
    let active = match q.status.as_deref().unwrap_or("queue") {
        "queue" => true,
        "history" => false,
        s => return Err(ApiError::bad_request(format!("status must be queue or history, got {s}"))),
    };
    let mut conn = st.pool.acquire().await?;
    let row = store::get_wallet(&mut conn, wid).await?;
    let policy = row.policy()?;
    let rows = store::list_proposals(&mut conn, wid, active).await?;
    let out = rows.iter().map(|p| views::proposal(&row, &policy, p, false, st.confirmations_final)).collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(json!(out)))
}

pub async fn get(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let mut conn = st.pool.acquire().await?;
    let p = store::get_proposal(&mut conn, id).await?;
    let row = store::get_wallet(&mut conn, p.wallet_id).await?;
    let policy = row.policy()?;
    let sigs = store::list_signatures(&mut conn, id).await?;
    let mut v = views::proposal(&row, &policy, &p, true, st.confirmations_final)?;
    v["signature_log"] = json!(sigs);
    if let Some(t) = store::final_tx(&mut conn, id).await? {
        v["final_tx_hex"] = json!(serialize_hex(&t));
    }
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct SigIn {
    /// Base64 PSBT from a signer.
    psbt: String,
}

pub async fn add_signatures(State(st): State<AppState>, Extension(user): Extension<CurrentUser>, Path(id): Path<i64>, Json(b): Json<SigIn>) -> ApiResult<Json<Value>> {
    let submitted = Psbt::from_str(b.psbt.trim()).map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_psbt", format!("can't decode PSBT: {e}")))?;
    // Cheap checks before taking any lock (this endpoint is unauthenticated). Unknown ids and
    // mismatching PSBTs get the same answer, so ids can't be enumerated.
    let mismatch = || ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_psbt", "PSBT does not match this proposal");
    let has_sigs = submitted.inputs.iter().any(|i| !i.partial_sigs.is_empty() || i.final_script_witness.is_some());
    let wid = {
        let mut conn = st.pool.acquire().await?;
        let p = match store::get_proposal(&mut conn, id).await {
            Ok(p) => p,
            Err(store::StoreError::NotFound) => return Err(mismatch()),
            Err(e) => return Err(e.into()),
        };
        if bitcoin::consensus::encode::serialize(&submitted.unsigned_tx) != p.unsigned_tx {
            return Err(mismatch());
        }
        if !has_sigs {
            return Err(validate::ValidationError::NoSignatures.into());
        }
        p.wallet_id
    };
    let mut tx = st.pool.begin().await?;
    let row = store::lock_wallet(&mut tx, wid).await?;
    let p = store::lock_proposal(&mut tx, id).await?;
    if !matches!(p.status(), Status::Pending | Status::Signing | Status::Ready) {
        return Err(ApiError::conflict("not_signable", format!("proposal is {}", p.status)));
    }
    let policy = row.policy()?;
    let spec = p.spec()?;
    let mut stored = p.psbt()?;
    let sub = validate::validate_submission(&policy, &spec, &stored, &submitted)?;
    validate::apply_signatures(&mut stored, &sub);
    let status = validate::signature_status(&policy, &spec, &stored)?;
    let records: Vec<SigRecord> = sub
        .new_sigs
        .iter()
        .map(|s| {
            Ok(SigRecord {
                owner_id: row.owner_id_at(s.owner).ok_or_else(|| ApiError::internal("owner row missing"))?,
                input_idx: s.input as u32,
                pubkey: s.pubkey.to_bytes(),
                sig: s.sig.to_vec(),
            })
        })
        .collect::<ApiResult<_>>()?;
    let mut new_status = p.status();
    if !sub.new_sigs.is_empty() {
        store::update_psbt(&mut tx, id, &stored).await?;
        store::insert_signatures(&mut tx, id, &records).await?;
        new_status = apply_event(&mut tx, &p, Event::SignaturesAdded { ready: status.ready }, StatusUpdate::default(), &user.email).await?;
        let owners: Vec<String> = sub.owners().iter().map(|o| policy.owners()[*o].name.clone()).collect();
        store::audit(&mut tx, Some(wid), &user.email, "signatures_added", json!({ "proposal": id, "owners": owners, "count": sub.new_sigs.len() })).await?;
    }
    let fresh = store::get_proposal(&mut tx, id).await?;
    tx.commit().await?;
    let mut v = views::proposal(&row, &policy, &fresh, false, st.confirmations_final)?;
    v["accepted"] = json!({ "new_signatures": sub.new_sigs.len(), "already_present": sub.already_present, "status": new_status });
    Ok(Json(v))
}

#[derive(Deserialize, Default)]
pub struct ExecQuery {
    /// Skip the fee re-check at execute time (e.g. estimates dropped since signing).
    fee_override: Option<bool>,
}

pub async fn execute(State(st): State<AppState>, Extension(user): Extension<CurrentUser>, Path(id): Path<i64>, Query(q): Query<ExecQuery>) -> ApiResult<Json<Value>> {
    let estimates = st.chain.fee_estimates().await.ok();
    let wid = {
        let mut conn = st.pool.acquire().await?;
        store::get_proposal(&mut conn, id).await?.wallet_id
    };
    let mut tx = st.pool.begin().await?;
    let row = store::lock_wallet(&mut tx, wid).await?;
    let p = store::lock_proposal(&mut tx, id).await?;
    match p.status() {
        Status::Ready | Status::Broadcast => {}
        Status::SoftConfirmed | Status::Confirmed => return Err(ApiError::conflict("already_confirmed", "this transaction is already in a block")),
        s => return Err(ApiError::conflict("not_ready", format!("proposal is {}; needs {} signatures on every input", s.as_str(), row.threshold))),
    }
    if let Some(pid) = p.predecessor_proposal_id {
        let pred = store::get_proposal(&mut tx, pid).await?;
        if !matches!(pred.status(), Status::Broadcast | Status::SoftConfirmed | Status::Confirmed) {
            return Err(ApiError::conflict(
                "predecessor_not_broadcast",
                format!("strict-order: execute #{} first (it is {})", pid, pred.status),
            ));
        }
    }
    let policy = row.policy()?;
    let spec = p.spec()?;
    // Finalize re-validates every signature against the stored proposal, and checks the
    // result with our CHECKMULTISIG verifier and miniscript's interpreter.
    let final_tx = validate::finalize(&policy, &spec, &p.psbt()?)?;
    if !p.fee_override && !q.fee_override.unwrap_or(false) {
        let s = validate::check_spec(&policy, &spec)?;
        fees::check_fee(s.fee, s.est_weight, s.sent, &st.fee_policy, estimates.map(|e| e.fast), false)?;
    }
    st.chain.broadcast(&final_tx).await?;
    let txid = final_tx.compute_txid();
    let status = apply_event(&mut tx, &p, Event::Broadcast, StatusUpdate { broadcast_txid: Some(txid), final_tx: Some(&final_tx), ..Default::default() }, &user.email).await?;
    let mut invalidated = vec![];
    if row.ordering() == OrderingMode::Strict {
        // A replacement changes the txid of its group, so anything chained on a sibling
        // spends an output that will never exist.
        invalidated = btc_safe_watcher::on_group_broadcast(&mut tx, id, &user.email).await?;
    }
    store::audit(&mut tx, Some(wid), &user.email, "proposal_broadcast", json!({ "proposal": id, "txid": txid.to_string(), "invalidated": invalidated })).await?;
    tx.commit().await?;
    Ok(Json(json!({
        "id": id,
        "status": status,
        "txid": txid.to_string(),
        "vsize": final_tx.vsize(),
        "tx_hex": serialize_hex(&final_tx),
        "invalidated_descendants": invalidated,
    })))
}

pub async fn delete(
    State(st): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Extension(access): Extension<crate::roles::WalletAccess>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let wid = {
        let mut conn = st.pool.acquire().await?;
        store::get_proposal(&mut conn, id).await?.wallet_id
    };
    let mut tx = st.pool.begin().await?;
    store::lock_wallet(&mut tx, wid).await?;
    let p = store::lock_proposal(&mut tx, id).await?;
    if access.role < crate::roles::Role::Admin && p.created_by != user.email {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "proposers can only delete their own proposals"));
    }
    if p.status() == Status::Broadcast {
        return Err(ApiError::conflict("already_broadcast", "a broadcast tx can't be deleted; create a replacement with replace_mode=cancel"));
    }
    if p.status() == Status::SoftConfirmed {
        return Err(ApiError::conflict("already_confirmed", "this transaction is already in a block; it can't be deleted"));
    }
    let desc = store::active_descendants(&mut tx, id).await?;
    let had_sigs = !p.psbt()?.inputs.iter().all(|i| i.partial_sigs.is_empty());
    apply_event(&mut tx, &p, Event::Delete, StatusUpdate { reason: Some("deleted_by_user"), ..Default::default() }, &user.email).await?;
    tx.commit().await?;
    Ok(Json(json!({
        "id": id,
        "status": "deleted",
        "invalidated_descendants": desc,
        "warning": if had_sigs {
            "Deleting does not revoke signatures already given. Anyone holding enough of them can still finalize and broadcast this exact transaction. To kill it for certain, spend one of its inputs (create a new proposal using that coin)."
        } else {
            "Deleted. No signatures had been collected."
        },
        "inputs": p.inputs.iter().map(|i| i.outpoint.clone()).collect::<Vec<_>>(),
    })))
}
