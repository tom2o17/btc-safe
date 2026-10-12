//! Ledger wallet-policy registrations (crates/core/src/ledger.rs).
//!
//! `GET` returns the policy the device must register for this wallet plus every stored
//! registration. `PUT .../owners/{owner}` stores the HMAC the device returned. The server
//! can't verify the HMAC (it's keyed by the device's seed), but it does require the submitted
//! policy to be exactly this wallet's and the id to hash correctly, so a confused or
//! malicious client can't attach an HMAC for some other policy to this wallet.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use bitcoin::hex::{DisplayHex, FromHex};
use btc_safe_core::ledger::LedgerPolicy;
use btc_safe_store as store;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::{ApiError, ApiResult, AppState};

fn expected(row: &store::WalletRow) -> ApiResult<LedgerPolicy> {
    Ok(LedgerPolicy::for_wallet(&row.name, &row.policy()?))
}

pub async fn get(State(st): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let mut conn = st.pool.acquire().await?;
    let row = store::get_wallet(&mut conn, id).await?;
    let policy = expected(&row)?;
    let regs = store::ledger_policies(&mut conn, id).await?;
    let registrations: Vec<Value> = regs
        .iter()
        .map(|r| {
            let fp = row.owners.iter().find(|o| o.id == r.owner_id).map(|o| o.fingerprint.clone());
            json!({
                "owner_id": r.owner_id,
                "fingerprint": fp,
                "policy": r.policy,
                "policy_id": r.policy_id.to_lower_hex_string(),
                "hmac": r.hmac.to_lower_hex_string(),
                "matches_wallet": r.policy == policy,
                "registered_at": r.registered_at,
            })
        })
        .collect();
    Ok(Json(json!({
        "policy": policy,
        "policy_id": policy.id().to_lower_hex_string(),
        "registrations": registrations,
    })))
}

#[derive(Deserialize)]
pub struct RegisterIn {
    pub policy: LedgerPolicy,
    pub policy_id: String,
    pub hmac: String,
}

pub async fn register(
    State(st): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path((id, owner)): Path<(Uuid, Uuid)>,
    Json(b): Json<RegisterIn>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let mut tx = st.pool.begin().await?;
    let row = store::lock_wallet(&mut tx, id).await?;
    if !row.owners.iter().any(|o| o.id == owner) {
        return Err(ApiError::not_found());
    }
    let want = expected(&row)?;
    if b.policy != want {
        return Err(ApiError::bad_request("policy is not this wallet's Ledger policy (name, template and keys must match GET exactly)")
            .with_details(json!({ "expected": want })));
    }
    let policy_id = <[u8; 32]>::from_hex(&b.policy_id).map_err(|_| ApiError::bad_request("policy_id must be 32 bytes hex"))?;
    if policy_id != want.id() {
        return Err(ApiError::bad_request("policy_id doesn't match the policy"));
    }
    let hmac = <[u8; 32]>::from_hex(&b.hmac).map_err(|_| ApiError::bad_request("hmac must be 32 bytes hex"))?;
    store::upsert_ledger_policy(&mut tx, id, owner, &want, &policy_id, &hmac).await?;
    // Log that it happened, never the HMAC itself.
    store::audit(&mut tx, Some(id), &user.email, "ledger_policy_registered", json!({ "owner_id": owner, "policy_id": b.policy_id })).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "owner_id": owner, "policy_id": b.policy_id }))))
}

pub async fn unregister(State(st): State<AppState>, Extension(user): Extension<CurrentUser>, Path((id, owner)): Path<(Uuid, Uuid)>) -> ApiResult<StatusCode> {
    let mut tx = st.pool.begin().await?;
    store::delete_ledger_policy(&mut tx, id, owner).await?;
    store::audit(&mut tx, Some(id), &user.email, "ledger_policy_removed", json!({ "owner_id": owner })).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
