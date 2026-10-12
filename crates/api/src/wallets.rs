use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::Network;
use btc_safe_core::import::{self, normalize_xpub};
use btc_safe_core::policy::{OwnerKey, WalletPolicy};
use btc_safe_core::Keychain;
use btc_safe_store::{self as store, OrderingMode};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::roles::{Role, WalletAccess};
use crate::{views, ApiError, ApiResult, AppState};

fn parse_net(s: &str) -> ApiResult<Network> {
    match store::parse_network(s) {
        Some(n) => Ok(n),
        None if s == "bitcoin" || s == "mainnet" => Err(ApiError::bad_request("mainnet is disabled in v1 (signet only)")),
        None => Err(ApiError::bad_request(format!("unknown network {s}"))),
    }
}

fn parse_ordering(s: Option<&str>) -> ApiResult<OrderingMode> {
    match s {
        None => Ok(OrderingMode::Parallel),
        Some(s) => OrderingMode::parse(s).ok_or_else(|| ApiError::bad_request("ordering_mode must be parallel or strict")),
    }
}

#[derive(Deserialize)]
pub struct OwnerIn {
    name: String,
    xpub: String,
    fingerprint: String,
    path: String,
}

#[derive(Deserialize)]
pub struct CreateWallet {
    name: String,
    network: String,
    threshold: usize,
    owners: Vec<OwnerIn>,
    ordering_mode: Option<String>,
}

fn check_pin(st: &AppState, network: Network) -> ApiResult<Network> {
    match st.pinned_network {
        Some(p) if p != network => Err(ApiError::bad_request(format!("this server only accepts {} wallets", store::network_str(p)))),
        _ => Ok(network),
    }
}

async fn store_new_wallet(st: &AppState, user: &CurrentUser, name: &str, policy: &WalletPolicy, ordering: OrderingMode, extra: Value) -> ApiResult<Value> {
    let actor = user.email.as_str();
    if name.trim().is_empty() || name.len() > 100 {
        return Err(ApiError::bad_request("name must be 1-100 chars"));
    }
    let mut tx = st.pool.begin().await?;
    if !user.is_admin && st.auth.max_wallets_per_user > 0 && store::users::lock_user_count_created(&mut tx, user.id).await? >= st.auth.max_wallets_per_user {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "wallet_cap",
            format!("this server allows {} wallets per account; delete one first", st.auth.max_wallets_per_user),
        ));
    }
    let id = store::insert_wallet(&mut tx, name.trim(), policy, ordering).await.map_err(|e| match e {
        store::StoreError::Db(ref d) if d.as_database_error().is_some_and(|d| d.is_unique_violation()) => ApiError::conflict("duplicate", "duplicate owner"),
        e => e.into(),
    })?;
    store::users::set_wallet_creator(&mut tx, id, user.id).await?;
    store::users::add_member(&mut tx, id, user.id, Role::Admin.as_str()).await?;
    store::audit(&mut tx, Some(id), actor, "wallet_created", extra).await?;
    let row = store::get_wallet(&mut tx, id).await?;
    tx.commit().await?;
    let mut v = views::wallet(&row, policy, None, 0, None)?;
    v["my_role"] = json!(Role::Admin.as_str());
    v["first_addresses"] = json!(views::first_addresses(policy, 3)?);
    v["backup"] = json!({
        "bsms": import::export_bsms(policy)?,
        "descriptor": policy.multipath_descriptor_string()?,
        "notice": "Store this backup. Recovering a multisig needs every cosigner's xpub; losing the descriptor is worse than on single-sig.",
    });
    v["verify"] = json!("Register the descriptor (BSMS) on each signing device and check that address #0 matches before funding.");
    Ok(v)
}

pub async fn create(State(st): State<AppState>, Extension(user): Extension<CurrentUser>, Json(b): Json<CreateWallet>) -> ApiResult<(StatusCode, Json<Value>)> {
    let network = check_pin(&st, parse_net(&b.network)?)?;
    let owners = b
        .owners
        .iter()
        .enumerate()
        .map(|(i, o)| {
            Ok(OwnerKey {
                name: if o.name.trim().is_empty() { format!("Owner {}", i + 1) } else { o.name.trim().to_string() },
                fingerprint: Fingerprint::from_str(&o.fingerprint).map_err(|_| ApiError::bad_request(format!("owner {i}: bad fingerprint")))?,
                path: DerivationPath::from_str(&o.path).map_err(|_| ApiError::bad_request(format!("owner {i}: bad path")))?,
                xpub: normalize_xpub(&o.xpub)?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let policy = WalletPolicy::new(network, b.threshold, owners)?;
    let v = store_new_wallet(&st, &user, &b.name, &policy, parse_ordering(b.ordering_mode.as_deref())?, json!({ "via": "create" })).await?;
    Ok((StatusCode::CREATED, Json(v)))
}

#[derive(Deserialize)]
pub struct ImportWallet {
    name: Option<String>,
    network: String,
    /// Descriptor(s), a BSMS 1.0 record, or Caravan/Sparrow JSON.
    data: String,
    ordering_mode: Option<String>,
}

pub async fn import(State(st): State<AppState>, Extension(user): Extension<CurrentUser>, Json(b): Json<ImportWallet>) -> ApiResult<(StatusCode, Json<Value>)> {
    let network = check_pin(&st, parse_net(&b.network)?)?;
    let imp = import::import_any(&b.data, network)?;
    let name = b.name.or(imp.name.clone()).unwrap_or_else(|| "Imported wallet".into());
    let mut v = store_new_wallet(&st, &user, &name, &imp.policy, parse_ordering(b.ordering_mode.as_deref())?, json!({ "via": "import", "format": imp.format })).await?;
    v["import"] = json!({ "format": imp.format, "warnings": imp.warnings });
    Ok((StatusCode::CREATED, Json(v)))
}

pub async fn list(State(st): State<AppState>, Extension(user): Extension<CurrentUser>) -> ApiResult<Json<Value>> {
    let mut conn = st.pool.acquire().await?;
    let rows = store::users::list_wallets_for_user(&mut conn, user.id).await?;
    Ok(Json(json!(rows
        .iter()
        .map(|(w, role)| json!({ "id": w.id, "name": w.name, "network": w.network, "threshold": w.threshold, "owners_count": w.owners.len(), "ordering_mode": w.ordering_mode, "role": role }))
        .collect::<Vec<_>>())))
}

pub async fn summary(State(st): State<AppState>, Extension(access): Extension<WalletAccess>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let mut conn = st.pool.acquire().await?;
    let row = store::get_wallet(&mut conn, id).await?;
    let policy = row.policy()?;
    let reserved: BTreeSet<_> = store::reserved_outpoints(&mut conn, id, None).await?;
    let queue = store::list_proposals(&mut conn, id, true).await?.len();
    drop(conn);
    let lw = st.cache.get(&st.pool, id).await?;
    let g = btc_safe_watcher::lock_loaded(&lw).await?;
    let bal = g.wallet.balance(&reserved);
    let mut v = views::wallet(&row, &policy, Some(&bal), queue, Some(g.wallet.tip_height()))?;
    v["confirmations_final"] = json!(st.confirmations_final);
    v["my_role"] = json!(access.role.as_str());
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct UpdateWallet {
    ordering_mode: Option<String>,
}

pub async fn update(
    State(st): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Extension(access): Extension<WalletAccess>,
    Path(id): Path<Uuid>,
    Json(b): Json<UpdateWallet>,
) -> ApiResult<Json<Value>> {
    let mut tx = st.pool.begin().await?;
    let row = store::lock_wallet(&mut tx, id).await?;
    if let Some(m) = b.ordering_mode.as_deref() {
        let mode = parse_ordering(Some(m))?;
        if mode != row.ordering() && !store::list_proposals(&mut tx, id, true).await?.is_empty() {
            return Err(ApiError::conflict("queue_not_empty", "change ordering mode only with an empty queue"));
        }
        store::set_ordering_mode(&mut tx, id, mode).await?;
        store::audit(&mut tx, Some(id), &user.email, "ordering_mode", json!({ "mode": m })).await?;
    }
    tx.commit().await?;
    summary(State(st), Extension(access), Path(id)).await
}

/// Delete a wallet's coordination state (owners, queue, labels). Funds are unaffected: they
/// stay spendable with the descriptor backup. Refused while proposals are queued.
pub async fn delete(State(st): State<AppState>, Extension(user): Extension<CurrentUser>, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    let mut tx = st.pool.begin().await?;
    store::lock_wallet(&mut tx, id).await?;
    if !store::list_proposals(&mut tx, id, true).await?.is_empty() {
        return Err(ApiError::conflict("queue_not_empty", "delete or finish the queued proposals first"));
    }
    store::audit(&mut tx, None, &user.email, "wallet_deleted", json!({ "wallet_id": id })).await?;
    store::delete_wallet(&mut tx, id).await?;
    tx.commit().await?;
    st.cache.evict(id);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn backup(State(st): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let mut conn = st.pool.acquire().await?;
    let row = store::get_wallet(&mut conn, id).await?;
    let policy = row.policy()?;
    Ok(Json(json!({
        "name": row.name,
        "network": row.network,
        "descriptor": policy.multipath_descriptor_string()?,
        "external": row.descriptor_ext,
        "internal": row.descriptor_int,
        "bsms": import::export_bsms(&policy)?,
        "first_addresses": views::first_addresses(&policy, 3)?,
    })))
}

#[derive(Deserialize)]
pub struct AddrQuery {
    kind: Option<String>,
    next: Option<bool>,
}

pub async fn address(State(st): State<AppState>, Extension(access): Extension<WalletAccess>, Path(id): Path<Uuid>, Query(q): Query<AddrQuery>) -> ApiResult<Json<Value>> {
    // Allocating a fresh address moves the wallet's index (a write); viewers only read.
    if q.next.unwrap_or(false) && access.role < Role::Proposer {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "viewers can't allocate new addresses; ask a proposer or admin"));
    }
    let keychain = match q.kind.as_deref().unwrap_or("receive") {
        "receive" | "external" => Keychain::External,
        "change" | "internal" => Keychain::Internal,
        k => return Err(ApiError::bad_request(format!("unknown kind {k}"))),
    };
    let lw = st.cache.get(&st.pool, id).await?;
    let mut tx = st.pool.begin().await?;
    let row = store::lock_wallet(&mut tx, id).await?;
    let policy = row.policy()?;
    let current = match keychain {
        Keychain::External => row.next_receive_idx,
        Keychain::Internal => row.next_change_idx,
    };
    let index = if q.next.unwrap_or(false) || (current == 0 && keychain == Keychain::External) {
        if keychain == Keychain::Internal {
            return Err(ApiError::bad_request("change addresses are allocated by proposals"));
        }
        store::alloc_index(&mut tx, id, keychain).await?
    } else if current == 0 {
        return Err(ApiError::not_found());
    } else {
        current as u32 - 1
    };
    let labels = store::address_labels(&mut tx, id).await?;
    {
        let mut g = btc_safe_watcher::lock_loaded(&lw).await?;
        g.wallet.reveal_to(keychain, index);
        g.persist(&mut tx, id).await?;
    }
    tx.commit().await?;
    let d = policy.derive(keychain, index)?;
    let label = labels.iter().find(|(k, i, _)| *k == keychain && *i == index).map(|(_, _, l)| l.clone());
    Ok(Json(json!({
        "keychain": keychain,
        "index": index,
        "path": format!("m/{}/{}", keychain.child(), index),
        "address": policy.address(keychain, index)?.to_string(),
        "witness_script": d.witness_script.to_hex_string(),
        "label": label,
        "verify": "Before sending large amounts, verify this address on a signing device that has the wallet registered.",
    })))
}

#[derive(Deserialize)]
pub struct LabelIn {
    label: String,
    kind: Option<String>,
}

pub async fn label_address(State(st): State<AppState>, Path((id, idx)): Path<(Uuid, u32)>, Json(b): Json<LabelIn>) -> ApiResult<Json<Value>> {
    let keychain = match b.kind.as_deref().unwrap_or("receive") {
        "receive" | "external" => Keychain::External,
        "change" | "internal" => Keychain::Internal,
        _ => return Err(ApiError::bad_request("kind must be receive or change")),
    };
    if b.label.len() > 200 {
        return Err(ApiError::bad_request("label too long"));
    }
    let mut conn = st.pool.acquire().await?;
    store::get_wallet(&mut conn, id).await?;
    if idx > btc_safe_core::MAX_INDEX {
        return Err(ApiError::bad_request("index out of range"));
    }
    store::set_address_label(&mut conn, id, keychain, idx, &b.label).await?;
    Ok(Json(json!({ "keychain": keychain, "index": idx, "label": b.label })))
}

pub async fn utxos(State(st): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let mut conn = st.pool.acquire().await?;
    let row = store::get_wallet(&mut conn, id).await?;
    let policy = row.policy()?;
    let res: BTreeMap<_, _> = store::reservations(&mut conn, id).await?.into_iter().collect();
    let labels = store::address_labels(&mut conn, id).await?;
    drop(conn);
    let lw = st.cache.get(&st.pool, id).await?;
    let g = btc_safe_watcher::lock_loaded(&lw).await?;
    let tip = g.wallet.tip_height();
    let out: Vec<Value> = g
        .wallet
        .utxos()
        .iter()
        .map(|u| {
            let label = labels.iter().find(|(k, i, _)| *k == u.keychain && *i == u.index).map(|(_, _, l)| l.clone());
            json!({
                "outpoint": u.outpoint.to_string(),
                "amount_sats": u.amount.to_sat(),
                "address": policy.address(u.keychain, u.index).map(|a| a.to_string()).ok(),
                "keychain": u.keychain,
                "index": u.index,
                "confirmations": u.height.map(|h| tip.saturating_sub(h) + 1).unwrap_or(0),
                "status": if res.contains_key(&u.outpoint) { "reserved" } else if u.height.is_none() { "unconfirmed" } else { "available" },
                "reserved_by": res.get(&u.outpoint),
                "label": label,
            })
        })
        .collect();
    Ok(Json(json!(out)))
}

pub async fn history(State(st): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let mut conn = st.pool.acquire().await?;
    let row = store::get_wallet(&mut conn, id).await?;
    let policy = row.policy()?;
    let mut ours: BTreeMap<String, i64> = BTreeMap::new();
    let mut done = vec![];
    for p in store::list_proposals(&mut conn, id, false).await? {
        ours.insert(p.unsigned_txid.clone(), p.id);
        done.push(views::proposal(&row, &policy, &p, false, st.confirmations_final)?);
    }
    for p in store::list_proposals(&mut conn, id, true).await? {
        ours.insert(p.unsigned_txid.clone(), p.id);
    }
    drop(conn);
    let lw = st.cache.get(&st.pool, id).await?;
    let g = btc_safe_watcher::lock_loaded(&lw).await?;
    let chain: Vec<Value> = g
        .wallet
        .history()
        .iter()
        .map(|h| {
            let pid = ours.get(&h.txid.to_string());
            json!({
                "txid": h.txid.to_string(),
                "height": h.height,
                "received_sats": h.received.to_sat(),
                "sent_sats": h.sent.to_sat(),
                "fee_sats": h.fee.map(|f| f.to_sat()),
                "proposal_id": pid,
                "origin": if pid.is_some() { "proposal" } else if h.sent.to_sat() > 0 { "external" } else { "incoming" },
            })
        })
        .collect();
    Ok(Json(json!({ "transactions": chain, "proposals": done })))
}

pub async fn fees(State(st): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let mut conn = st.pool.acquire().await?;
    store::get_wallet(&mut conn, id).await?;
    let f = st.chain.fee_estimates().await?;
    let v = |r: bitcoin::FeeRate| (r.to_sat_per_kwu() as f64 / 250.0 * 100.0).round() / 100.0;
    Ok(Json(json!({ "fast_sat_vb": v(f.fast), "normal_sat_vb": v(f.normal), "slow_sat_vb": v(f.slow), "source": st.chain.describe() })))
}

pub async fn sync(State(st): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let tip = btc_safe_watcher::sync_wallet(&st.pool, &st.cache, st.chain.as_ref(), id).await?;
    let changes = btc_safe_watcher::reconcile(&st.pool, st.chain.as_ref(), id, st.confirmations_final).await?;
    Ok(Json(json!({
        "tip_height": tip,
        "transitions": changes.iter().map(|(p, s)| json!({ "proposal": p, "status": s })).collect::<Vec<_>>(),
    })))
}

pub async fn address_book_list(State(st): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let mut conn = st.pool.acquire().await?;
    store::get_wallet(&mut conn, id).await?;
    Ok(Json(json!(store::address_book(&mut conn, id).await?)))
}

#[derive(Deserialize)]
pub struct BookIn {
    label: String,
    address: String,
}

pub async fn address_book_add(State(st): State<AppState>, Path(id): Path<Uuid>, Json(b): Json<BookIn>) -> ApiResult<(StatusCode, Json<Value>)> {
    let mut conn = st.pool.acquire().await?;
    let row = store::get_wallet(&mut conn, id).await?;
    let network = parse_net(&row.network)?;
    if store::parse_script_address(&b.address, network).is_none() {
        return Err(ApiError::bad_request(format!("not a {} address", row.network)));
    }
    if b.label.trim().is_empty() || b.label.len() > 100 {
        return Err(ApiError::bad_request("label must be 1-100 chars"));
    }
    let eid = store::upsert_address_book(&mut conn, id, b.label.trim(), &b.address, &row.network).await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": eid, "label": b.label.trim(), "address": b.address }))))
}

pub async fn address_book_delete(State(st): State<AppState>, Path((id, entry)): Path<(Uuid, Uuid)>) -> ApiResult<StatusCode> {
    let mut conn = st.pool.acquire().await?;
    store::delete_address_book(&mut conn, id, entry).await?;
    Ok(StatusCode::NO_CONTENT)
}
