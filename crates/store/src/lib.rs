//! Postgres persistence (sqlx). Maps rows to core domain types. Every mutation of a wallet's
//! queue runs in a transaction that first locks the wallet row (`lock_wallet`), so proposal
//! creation and signature merging are serialized per wallet.

use std::collections::BTreeSet;
use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, Txid};
use btc_safe_core::policy::{OwnerKey, WalletPolicy};
use btc_safe_core::state::Status;
use btc_safe_core::validate::{ChangeSpec, InputSpec, ProposalSpec, Summary};
use btc_safe_core::Keychain;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub use sqlx;

pub mod limits;
pub mod users;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("coin already reserved by another queued proposal")]
    ReservationConflict,
    #[error("proposal status changed concurrently (expected {expected})")]
    StaleStatus { expected: String },
    #[error("stored data is corrupt: {0}")]
    Corrupt(String),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

pub type Result<T> = std::result::Result<T, StoreError>;

fn corrupt<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Corrupt(e.to_string())
}

pub async fn connect(url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new().max_connections(10).connect(url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

pub fn network_str(n: Network) -> &'static str {
    match n {
        Network::Signet => "signet",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Regtest => "regtest",
        _ => "bitcoin",
    }
}

pub fn parse_network(s: &str) -> Option<Network> {
    Some(match s {
        "signet" => Network::Signet,
        "testnet" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingMode {
    Parallel,
    Strict,
}

impl OrderingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            OrderingMode::Parallel => "parallel",
            OrderingMode::Strict => "strict",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "parallel" => Some(OrderingMode::Parallel),
            "strict" => Some(OrderingMode::Strict),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------- wallets

#[derive(Clone, Debug, Serialize)]
pub struct OwnerRow {
    pub id: Uuid,
    pub name: String,
    pub xpub: String,
    pub fingerprint: String,
    pub path: String,
    pub kind: String,
    pub position: i32,
}

#[derive(Clone, Debug, Serialize)]
pub struct WalletRow {
    pub id: Uuid,
    pub name: String,
    pub network: String,
    pub descriptor_ext: String,
    pub descriptor_int: String,
    pub threshold: i32,
    pub policy_kind: String,
    pub ordering_mode: String,
    pub next_receive_idx: i32,
    pub next_change_idx: i32,
    pub tip_height: Option<i32>,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub owners: Vec<OwnerRow>,
}

impl WalletRow {
    pub fn ordering(&self) -> OrderingMode {
        OrderingMode::parse(&self.ordering_mode).unwrap_or(OrderingMode::Parallel)
    }

    /// Rebuild the policy from owner rows and require it to reproduce the stored descriptors.
    pub fn policy(&self) -> Result<WalletPolicy> {
        let network = parse_network(&self.network).ok_or_else(|| corrupt("network"))?;
        let mut owners = self.owners.clone();
        owners.sort_by_key(|o| o.position);
        let keys = owners
            .iter()
            .map(|o| {
                Ok(OwnerKey {
                    name: o.name.clone(),
                    fingerprint: Fingerprint::from_str(&o.fingerprint).map_err(corrupt)?,
                    path: DerivationPath::from_str(&o.path).map_err(corrupt)?,
                    xpub: Xpub::from_str(&o.xpub).map_err(corrupt)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let p = WalletPolicy::new(network, self.threshold as usize, keys).map_err(corrupt)?;
        if p.descriptor_string(Keychain::External).map_err(corrupt)? != self.descriptor_ext
            || p.descriptor_string(Keychain::Internal).map_err(corrupt)? != self.descriptor_int
        {
            return Err(corrupt("owners don't reproduce the stored descriptor"));
        }
        Ok(p)
    }

    pub fn owner_id_at(&self, position: usize) -> Option<Uuid> {
        self.owners.iter().find(|o| o.position as usize == position).map(|o| o.id)
    }
}

fn wallet_from_row(r: &PgRow) -> Result<WalletRow> {
    Ok(WalletRow {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        network: r.try_get("network")?,
        descriptor_ext: r.try_get("descriptor_ext")?,
        descriptor_int: r.try_get("descriptor_int")?,
        threshold: r.try_get("threshold")?,
        policy_kind: r.try_get("policy_kind")?,
        ordering_mode: r.try_get("ordering_mode")?,
        next_receive_idx: r.try_get("next_receive_idx")?,
        next_change_idx: r.try_get("next_change_idx")?,
        tip_height: r.try_get("tip_height")?,
        last_synced_at: r.try_get("last_synced_at")?,
        created_at: r.try_get("created_at")?,
        owners: vec![],
    })
}

const WALLET_COLS: &str = "id, name, network, descriptor_ext, descriptor_int, threshold, policy_kind, ordering_mode, \
     next_receive_idx, next_change_idx, tip_height, last_synced_at, created_at";

pub async fn insert_wallet(
    conn: &mut PgConnection,
    name: &str,
    policy: &WalletPolicy,
    ordering: OrderingMode,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO wallets (id, name, network, descriptor_ext, descriptor_int, threshold, ordering_mode) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(name)
    .bind(network_str(policy.network()))
    .bind(policy.descriptor_string(Keychain::External).map_err(corrupt)?)
    .bind(policy.descriptor_string(Keychain::Internal).map_err(corrupt)?)
    .bind(policy.threshold() as i32)
    .bind(ordering.as_str())
    .execute(&mut *conn)
    .await?;
    for (pos, o) in policy.owners().iter().enumerate() {
        sqlx::query(
            "INSERT INTO owners (id, wallet_id, name, xpub, fingerprint, path, position) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(&o.name)
        .bind(o.xpub.to_string())
        .bind(o.fingerprint.to_string())
        .bind(o.path.to_string())
        .bind(pos as i32)
        .execute(&mut *conn)
        .await?;
    }
    Ok(id)
}

async fn owners_of(conn: &mut PgConnection, wallet_id: Uuid) -> Result<Vec<OwnerRow>> {
    let rows = sqlx::query("SELECT id, name, xpub, fingerprint, path, kind, position FROM owners WHERE wallet_id = $1 ORDER BY position")
        .bind(wallet_id)
        .fetch_all(&mut *conn)
        .await?;
    rows.iter()
        .map(|r| {
            Ok(OwnerRow {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                xpub: r.try_get("xpub")?,
                fingerprint: r.try_get("fingerprint")?,
                path: r.try_get("path")?,
                kind: r.try_get("kind")?,
                position: r.try_get("position")?,
            })
        })
        .collect()
}

pub async fn get_wallet(conn: &mut PgConnection, id: Uuid) -> Result<WalletRow> {
    let r = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {WALLET_COLS} FROM wallets WHERE id = $1")))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(StoreError::NotFound)?;
    let mut w = wallet_from_row(&r)?;
    w.owners = owners_of(conn, id).await?;
    Ok(w)
}

/// Lock the wallet row for the rest of the transaction and return it. Must be called inside
/// a transaction; lock waits are bounded (`lock_timeout`) so nothing can hang forever.
pub async fn lock_wallet(conn: &mut PgConnection, id: Uuid) -> Result<WalletRow> {
    sqlx::query("SET LOCAL lock_timeout = '10s'").execute(&mut *conn).await?;
    sqlx::query("SELECT id FROM wallets WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(StoreError::NotFound)?;
    get_wallet(conn, id).await
}

/// Remove a wallet and (by cascade) its owners, proposals, reservations, labels and members.
pub async fn delete_wallet(conn: &mut PgConnection, id: Uuid) -> Result<()> {
    let n = sqlx::query("DELETE FROM wallets WHERE id = $1").bind(id).execute(&mut *conn).await?.rows_affected();
    if n == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

pub async fn list_wallets(conn: &mut PgConnection) -> Result<Vec<WalletRow>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {WALLET_COLS} FROM wallets ORDER BY created_at")))
        .fetch_all(&mut *conn)
        .await?;
    let mut out = vec![];
    for r in &rows {
        let mut w = wallet_from_row(r)?;
        w.owners = owners_of(conn, w.id).await?;
        out.push(w);
    }
    Ok(out)
}

pub async fn set_ordering_mode(conn: &mut PgConnection, id: Uuid, mode: OrderingMode) -> Result<()> {
    sqlx::query("UPDATE wallets SET ordering_mode = $2 WHERE id = $1").bind(id).bind(mode.as_str()).execute(&mut *conn).await?;
    Ok(())
}

/// Allocate the next index on a keychain (never handed out twice).
pub async fn alloc_index(conn: &mut PgConnection, id: Uuid, keychain: Keychain) -> Result<u32> {
    let sql = match keychain {
        Keychain::External => "UPDATE wallets SET next_receive_idx = next_receive_idx + 1 WHERE id = $1 RETURNING next_receive_idx - 1 AS idx",
        Keychain::Internal => "UPDATE wallets SET next_change_idx = next_change_idx + 1 WHERE id = $1 RETURNING next_change_idx - 1 AS idx",
    };
    let r = sqlx::query(sql).bind(id).fetch_optional(&mut *conn).await?.ok_or(StoreError::NotFound)?;
    Ok(r.try_get::<i32, _>("idx")? as u32)
}

pub async fn load_changeset(conn: &mut PgConnection, id: Uuid) -> Result<Option<serde_json::Value>> {
    let r = sqlx::query("SELECT bdk_changeset FROM wallets WHERE id = $1").bind(id).fetch_optional(&mut *conn).await?.ok_or(StoreError::NotFound)?;
    Ok(r.try_get("bdk_changeset")?)
}

pub async fn save_changeset(conn: &mut PgConnection, id: Uuid, cs: &serde_json::Value, tip: u32) -> Result<()> {
    sqlx::query("UPDATE wallets SET bdk_changeset = $2, tip_height = $3, last_synced_at = now() WHERE id = $1")
        .bind(id)
        .bind(cs)
        .bind(tip as i32)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------- proposals

#[derive(Clone, Debug, Serialize)]
pub struct InputRow {
    pub idx: i32,
    pub outpoint: String,
    pub amount_sats: i64,
    pub keychain: String,
    pub deriv_index: i32,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputRow {
    pub vout: i32,
    pub address: String,
    pub amount_sats: i64,
    pub is_change: bool,
    pub change_index: Option<i32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProposalRow {
    pub id: i64,
    pub wallet_id: Uuid,
    pub created_by: String,
    pub status: String,
    pub status_reason: Option<String>,
    #[serde(skip)]
    pub psbt: Vec<u8>,
    #[serde(skip)]
    pub unsigned_tx: Vec<u8>,
    pub unsigned_txid: String,
    pub fee_sats: i64,
    pub fee_rate_sat_kwu: i64,
    pub est_vsize: i32,
    pub sent_sats: i64,
    pub rbf: bool,
    pub fee_override: bool,
    pub group_id: Option<i64>,
    pub replaces_proposal_id: Option<i64>,
    pub predecessor_proposal_id: Option<i64>,
    pub broadcast_txid: Option<String>,
    pub invalidated_by_txid: Option<String>,
    pub confirmed_height: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub inputs: Vec<InputRow>,
    pub outputs: Vec<OutputRow>,
}

impl ProposalRow {
    pub fn status(&self) -> Status {
        Status::parse(&self.status).unwrap_or(Status::Invalidated)
    }

    pub fn psbt(&self) -> Result<Psbt> {
        Psbt::deserialize(&self.psbt).map_err(corrupt)
    }

    pub fn txid(&self) -> Result<Txid> {
        Txid::from_str(&self.unsigned_txid).map_err(corrupt)
    }

    /// Rebuild the proposal record that `core::validate` checks against.
    pub fn spec(&self) -> Result<ProposalSpec> {
        let unsigned_tx: Transaction = deserialize(&self.unsigned_tx).map_err(corrupt)?;
        if unsigned_tx.compute_txid().to_string() != self.unsigned_txid {
            return Err(corrupt("unsigned_tx doesn't hash to unsigned_txid"));
        }
        let inputs = self
            .inputs
            .iter()
            .map(|i| {
                Ok(InputSpec {
                    outpoint: OutPoint::from_str(&i.outpoint).map_err(corrupt)?,
                    amount: Amount::from_sat(u64::try_from(i.amount_sats).map_err(corrupt)?),
                    keychain: Keychain::parse(&i.keychain).ok_or_else(|| corrupt("keychain"))?,
                    index: u32::try_from(i.deriv_index).map_err(corrupt)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let change = self
            .outputs
            .iter()
            .filter(|o| o.is_change)
            .map(|o| {
                Ok(ChangeSpec {
                    vout: o.vout as u32,
                    index: u32::try_from(o.change_index.ok_or_else(|| corrupt("change index"))?).map_err(corrupt)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ProposalSpec { unsigned_tx, inputs, change })
    }

    /// The change output (outpoint, amount, internal index), if any.
    pub fn change_output(&self) -> Option<(OutPoint, Amount, u32)> {
        let txid = Txid::from_str(&self.unsigned_txid).ok()?;
        let o = self.outputs.iter().find(|o| o.is_change)?;
        Some((OutPoint { txid, vout: o.vout as u32 }, Amount::from_sat(o.amount_sats as u64), o.change_index? as u32))
    }
}

const PROPOSAL_COLS: &str = "id, wallet_id, created_by, status, status_reason, psbt, unsigned_tx, unsigned_txid, fee_sats, \
     fee_rate_sat_kwu, est_vsize, sent_sats, rbf, fee_override, group_id, replaces_proposal_id, predecessor_proposal_id, \
     broadcast_txid, invalidated_by_txid, confirmed_height, created_at, updated_at";

fn proposal_from_row(r: &PgRow) -> Result<ProposalRow> {
    Ok(ProposalRow {
        id: r.try_get("id")?,
        wallet_id: r.try_get("wallet_id")?,
        created_by: r.try_get("created_by")?,
        status: r.try_get("status")?,
        status_reason: r.try_get("status_reason")?,
        psbt: r.try_get("psbt")?,
        unsigned_tx: r.try_get("unsigned_tx")?,
        unsigned_txid: r.try_get("unsigned_txid")?,
        fee_sats: r.try_get("fee_sats")?,
        fee_rate_sat_kwu: r.try_get("fee_rate_sat_kwu")?,
        est_vsize: r.try_get("est_vsize")?,
        sent_sats: r.try_get("sent_sats")?,
        rbf: r.try_get("rbf")?,
        fee_override: r.try_get("fee_override")?,
        group_id: r.try_get("group_id")?,
        replaces_proposal_id: r.try_get("replaces_proposal_id")?,
        predecessor_proposal_id: r.try_get("predecessor_proposal_id")?,
        broadcast_txid: r.try_get("broadcast_txid")?,
        invalidated_by_txid: r.try_get("invalidated_by_txid")?,
        confirmed_height: r.try_get("confirmed_height")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
        inputs: vec![],
        outputs: vec![],
    })
}

async fn fill_io(conn: &mut PgConnection, p: &mut ProposalRow) -> Result<()> {
    let rows = sqlx::query("SELECT idx, outpoint, amount_sats, keychain, deriv_index FROM proposal_inputs WHERE proposal_id = $1 ORDER BY idx")
        .bind(p.id)
        .fetch_all(&mut *conn)
        .await?;
    p.inputs = rows
        .iter()
        .map(|r| {
            Ok(InputRow {
                idx: r.try_get("idx")?,
                outpoint: r.try_get("outpoint")?,
                amount_sats: r.try_get("amount_sats")?,
                keychain: r.try_get("keychain")?,
                deriv_index: r.try_get("deriv_index")?,
            })
        })
        .collect::<Result<_>>()?;
    let rows = sqlx::query("SELECT vout, address, amount_sats, is_change, change_index FROM proposal_outputs WHERE proposal_id = $1 ORDER BY vout")
        .bind(p.id)
        .fetch_all(&mut *conn)
        .await?;
    p.outputs = rows
        .iter()
        .map(|r| {
            Ok(OutputRow {
                vout: r.try_get("vout")?,
                address: r.try_get("address")?,
                amount_sats: r.try_get("amount_sats")?,
                is_change: r.try_get("is_change")?,
                change_index: r.try_get("change_index")?,
            })
        })
        .collect::<Result<_>>()?;
    Ok(())
}

pub struct NewProposal<'a> {
    pub wallet_id: Uuid,
    pub created_by: &'a str,
    pub spec: &'a ProposalSpec,
    pub psbt: &'a Psbt,
    pub summary: &'a Summary,
    pub fee_override: bool,
    pub replaces: Option<i64>,
    pub predecessor: Option<i64>,
}

fn is_exclusion_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some("23P01"))
}

/// Insert a proposal with its inputs (reserving them) and outputs. Fails with
/// `ReservationConflict` if any input is held by an active proposal outside the
/// replacement group.
pub async fn insert_proposal(conn: &mut PgConnection, np: NewProposal<'_>) -> Result<i64> {
    let s = np.summary;
    let r = sqlx::query(
        "INSERT INTO proposals (wallet_id, created_by, status, psbt, unsigned_tx, unsigned_txid, fee_sats, fee_rate_sat_kwu, \
         est_vsize, sent_sats, rbf, fee_override, replaces_proposal_id, predecessor_proposal_id) \
         VALUES ($1,$2,'pending',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id",
    )
    .bind(np.wallet_id)
    .bind(np.created_by)
    .bind(np.psbt.serialize())
    .bind(serialize(&np.spec.unsigned_tx))
    .bind(s.unsigned_txid.to_string())
    .bind(s.fee.to_sat() as i64)
    .bind(s.fee_rate_sat_kwu as i64)
    .bind(s.est_vsize as i32)
    .bind(s.sent.to_sat() as i64)
    .bind(s.rbf)
    .bind(np.fee_override)
    .bind(np.replaces)
    .bind(np.predecessor)
    .fetch_one(&mut *conn)
    .await?;
    let id: i64 = r.try_get("id")?;
    let group: i64 = match np.replaces {
        Some(rep) => sqlx::query("SELECT COALESCE(group_id, id) AS g FROM proposals WHERE id = $1")
            .bind(rep)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or(StoreError::NotFound)?
            .try_get("g")?,
        None => id,
    };
    sqlx::query("UPDATE proposals SET group_id = $2 WHERE id = $1").bind(id).bind(group).execute(&mut *conn).await?;
    for (i, inp) in np.spec.inputs.iter().enumerate() {
        let res = sqlx::query(
            "INSERT INTO proposal_inputs (proposal_id, wallet_id, idx, outpoint, amount_sats, keychain, deriv_index, group_id) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(id)
        .bind(np.wallet_id)
        .bind(i as i32)
        .bind(inp.outpoint.to_string())
        .bind(inp.amount.to_sat() as i64)
        .bind(inp.keychain.as_str())
        .bind(inp.index as i32)
        .bind(group)
        .execute(&mut *conn)
        .await;
        match res {
            Err(e) if is_exclusion_violation(&e) => return Err(StoreError::ReservationConflict),
            r => {
                r?;
            }
        }
    }
    for o in &s.outputs {
        sqlx::query(
            "INSERT INTO proposal_outputs (proposal_id, vout, script_pubkey, address, amount_sats, is_change, change_index) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(id)
        .bind(o.vout as i32)
        .bind(o.script_pubkey.as_bytes())
        .bind(&o.address)
        .bind(o.amount.to_sat() as i64)
        .bind(o.change_index.is_some())
        .bind(o.change_index.map(|i| i as i32))
        .execute(&mut *conn)
        .await?;
    }
    Ok(id)
}

pub async fn get_proposal(conn: &mut PgConnection, id: i64) -> Result<ProposalRow> {
    let r = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {PROPOSAL_COLS} FROM proposals WHERE id = $1")))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(StoreError::NotFound)?;
    let mut p = proposal_from_row(&r)?;
    fill_io(conn, &mut p).await?;
    Ok(p)
}

/// Lock one proposal row (inside a transaction that already holds the wallet lock).
pub async fn lock_proposal(conn: &mut PgConnection, id: i64) -> Result<ProposalRow> {
    sqlx::query("SELECT id FROM proposals WHERE id = $1 FOR UPDATE").bind(id).fetch_optional(&mut *conn).await?.ok_or(StoreError::NotFound)?;
    get_proposal(conn, id).await
}

pub async fn list_proposals(conn: &mut PgConnection, wallet_id: Uuid, active: bool) -> Result<Vec<ProposalRow>> {
    let sql = if active {
        format!("SELECT {PROPOSAL_COLS} FROM proposals WHERE wallet_id = $1 AND status IN {} ORDER BY id", Status::ACTIVE_SQL)
    } else {
        format!("SELECT {PROPOSAL_COLS} FROM proposals WHERE wallet_id = $1 AND status NOT IN {} ORDER BY id DESC", Status::ACTIVE_SQL)
    };
    // Only constant fragments are interpolated.
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(wallet_id).fetch_all(&mut *conn).await?;
    let mut out = vec![];
    for r in &rows {
        let mut p = proposal_from_row(r)?;
        fill_io(conn, &mut p).await?;
        out.push(p);
    }
    Ok(out)
}

/// Outpoints reserved by active proposals, optionally ignoring one replacement group.
pub async fn reserved_outpoints(conn: &mut PgConnection, wallet_id: Uuid, except_group: Option<i64>) -> Result<BTreeSet<OutPoint>> {
    let rows = sqlx::query("SELECT outpoint FROM proposal_inputs WHERE wallet_id = $1 AND active AND ($2::bigint IS NULL OR group_id <> $2)")
        .bind(wallet_id)
        .bind(except_group)
        .fetch_all(&mut *conn)
        .await?;
    rows.iter()
        .map(|r| OutPoint::from_str(&r.try_get::<String, _>("outpoint")?).map_err(corrupt))
        .collect()
}

/// Active reservations of a wallet: outpoint → proposal id.
pub async fn reservations(conn: &mut PgConnection, wallet_id: Uuid) -> Result<Vec<(OutPoint, i64)>> {
    let rows = sqlx::query("SELECT outpoint, proposal_id FROM proposal_inputs WHERE wallet_id = $1 AND active ORDER BY proposal_id")
        .bind(wallet_id)
        .fetch_all(&mut *conn)
        .await?;
    rows.iter()
        .map(|r| Ok((OutPoint::from_str(&r.try_get::<String, _>("outpoint")?).map_err(corrupt)?, r.try_get("proposal_id")?)))
        .collect()
}

/// Status of this wallet's newest proposal with the given unsigned txid, if any.
pub async fn proposal_status_by_txid(conn: &mut PgConnection, wallet_id: Uuid, txid: Txid) -> Result<Option<Status>> {
    let r = sqlx::query("SELECT status FROM proposals WHERE wallet_id = $1 AND unsigned_txid = $2 ORDER BY id DESC LIMIT 1")
        .bind(wallet_id)
        .bind(txid.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    Ok(match r {
        Some(r) => Some(Status::parse(&r.try_get::<String, _>("status")?).ok_or_else(|| corrupt("status"))?),
        None => None,
    })
}

/// Strict-order queue tail: the newest active proposal of the wallet.
pub async fn queue_tail(conn: &mut PgConnection, wallet_id: Uuid) -> Result<Option<ProposalRow>> {
    let sql = format!("SELECT id FROM proposals WHERE wallet_id = $1 AND status IN {} ORDER BY id DESC LIMIT 1", Status::ACTIVE_SQL);
    let r = sqlx::query(sqlx::AssertSqlSafe(sql)) // constant fragments only
        .bind(wallet_id)
        .fetch_optional(&mut *conn)
        .await?;
    match r {
        Some(r) => Ok(Some(get_proposal(conn, r.try_get("id")?).await?)),
        None => Ok(None),
    }
}

/// Active proposals that (transitively) chain on `id` in strict-order mode.
pub async fn active_descendants(conn: &mut PgConnection, id: i64) -> Result<Vec<i64>> {
    let sql = format!(
        "WITH RECURSIVE d(id) AS ( \
             SELECT id FROM proposals WHERE predecessor_proposal_id = $1 \
             UNION SELECT p.id FROM proposals p JOIN d ON p.predecessor_proposal_id = d.id ) \
         SELECT p.id FROM proposals p JOIN d ON p.id = d.id \
         WHERE p.status IN {} ORDER BY p.id",
        Status::ACTIVE_SQL
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql)) // constant fragments only
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter().map(|r| Ok(r.try_get("id")?)).collect()
}

/// Other active members of the replacement group of `id`.
pub async fn group_siblings(conn: &mut PgConnection, id: i64) -> Result<Vec<ProposalRow>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {PROPOSAL_COLS} FROM proposals WHERE group_id = (SELECT group_id FROM proposals WHERE id = $1) AND id <> $1 ORDER BY id"
    )))
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    let mut out = vec![];
    for r in &rows {
        let mut p = proposal_from_row(r)?;
        fill_io(conn, &mut p).await?;
        out.push(p);
    }
    Ok(out)
}

#[derive(Default)]
pub struct StatusUpdate<'a> {
    pub reason: Option<&'a str>,
    pub broadcast_txid: Option<Txid>,
    pub invalidated_by: Option<Txid>,
    pub confirmed_height: Option<u32>,
    pub final_tx: Option<&'a Transaction>,
}

/// Compare-and-swap status. Terminal statuses release the input reservations; active ones
/// (incl. SOFT_CONFIRMED) hold them. `confirmed_height` is cleared when the proposal leaves the
/// confirmed states (a reorg rolled it back, or a conflicting tx won).
pub async fn set_status(conn: &mut PgConnection, id: i64, from: Status, to: Status, u: StatusUpdate<'_>) -> Result<()> {
    let res = sqlx::query(
        "UPDATE proposals SET status = $3, status_reason = COALESCE($4, status_reason), \
         broadcast_txid = COALESCE($5, broadcast_txid), invalidated_by_txid = COALESCE($6, invalidated_by_txid), \
         confirmed_height = CASE WHEN $3 IN ('soft_confirmed', 'confirmed') THEN COALESCE($7, confirmed_height) END, final_tx = COALESCE($8, final_tx), updated_at = now() \
         WHERE id = $1 AND status = $2",
    )
    .bind(id)
    .bind(from.as_str())
    .bind(to.as_str())
    .bind(u.reason)
    .bind(u.broadcast_txid.map(|t| t.to_string()))
    .bind(u.invalidated_by.map(|t| t.to_string()))
    .bind(u.confirmed_height.map(|h| h as i32))
    .bind(u.final_tx.map(serialize))
    .execute(&mut *conn)
    .await?;
    if res.rows_affected() != 1 {
        return Err(StoreError::StaleStatus { expected: from.as_str().into() });
    }
    sqlx::query("UPDATE proposal_inputs SET active = $2 WHERE proposal_id = $1")
        .bind(id)
        .bind(to.is_active())
        .execute(&mut *conn)
        .await
        .map_err(|e| if is_exclusion_violation(&e) { StoreError::ReservationConflict } else { e.into() })?;
    Ok(())
}

pub async fn update_psbt(conn: &mut PgConnection, id: i64, psbt: &Psbt) -> Result<()> {
    sqlx::query("UPDATE proposals SET psbt = $2, updated_at = now() WHERE id = $1").bind(id).bind(psbt.serialize()).execute(&mut *conn).await?;
    Ok(())
}

pub struct SigRecord {
    pub owner_id: Uuid,
    pub input_idx: u32,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

pub async fn insert_signatures(conn: &mut PgConnection, proposal_id: i64, sigs: &[SigRecord]) -> Result<()> {
    for s in sigs {
        sqlx::query(
            "INSERT INTO signatures (proposal_id, owner_id, input_idx, pubkey, sig) VALUES ($1,$2,$3,$4,$5) \
             ON CONFLICT (proposal_id, owner_id, input_idx) DO NOTHING",
        )
        .bind(proposal_id)
        .bind(s.owner_id)
        .bind(s.input_idx as i32)
        .bind(&s.pubkey)
        .bind(&s.sig)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
pub struct SignatureRow {
    pub owner_id: Uuid,
    pub input_idx: i32,
    pub added_at: DateTime<Utc>,
}

pub async fn list_signatures(conn: &mut PgConnection, proposal_id: i64) -> Result<Vec<SignatureRow>> {
    let rows = sqlx::query("SELECT owner_id, input_idx, added_at FROM signatures WHERE proposal_id = $1 ORDER BY added_at, input_idx")
        .bind(proposal_id)
        .fetch_all(&mut *conn)
        .await?;
    rows.iter()
        .map(|r| Ok(SignatureRow { owner_id: r.try_get("owner_id")?, input_idx: r.try_get("input_idx")?, added_at: r.try_get("added_at")? }))
        .collect()
}

pub async fn final_tx(conn: &mut PgConnection, id: i64) -> Result<Option<Transaction>> {
    let r = sqlx::query("SELECT final_tx FROM proposals WHERE id = $1").bind(id).fetch_optional(&mut *conn).await?.ok_or(StoreError::NotFound)?;
    let b: Option<Vec<u8>> = r.try_get("final_tx")?;
    b.map(|b| deserialize(&b).map_err(corrupt)).transpose()
}

// ---------------------------------------------------------------- labels, address book, audit

pub async fn set_address_label(conn: &mut PgConnection, wallet_id: Uuid, keychain: Keychain, idx: u32, label: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO address_labels (wallet_id, keychain, deriv_index, label) VALUES ($1,$2,$3,$4) \
         ON CONFLICT (wallet_id, keychain, deriv_index) DO UPDATE SET label = EXCLUDED.label",
    )
    .bind(wallet_id)
    .bind(keychain.as_str())
    .bind(idx as i32)
    .bind(label)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn address_labels(conn: &mut PgConnection, wallet_id: Uuid) -> Result<Vec<(Keychain, u32, String)>> {
    let rows = sqlx::query("SELECT keychain, deriv_index, label FROM address_labels WHERE wallet_id = $1")
        .bind(wallet_id)
        .fetch_all(&mut *conn)
        .await?;
    rows.iter()
        .map(|r| {
            Ok((
                Keychain::parse(&r.try_get::<String, _>("keychain")?).ok_or_else(|| corrupt("keychain"))?,
                r.try_get::<i32, _>("deriv_index")? as u32,
                r.try_get("label")?,
            ))
        })
        .collect()
}

#[derive(Clone, Debug, Serialize)]
pub struct AddressBookEntry {
    pub id: Uuid,
    pub label: String,
    pub address: String,
    pub network: String,
    pub created_at: DateTime<Utc>,
}

pub async fn address_book(conn: &mut PgConnection, wallet_id: Uuid) -> Result<Vec<AddressBookEntry>> {
    let rows = sqlx::query("SELECT id, label, address, network, created_at FROM address_book WHERE wallet_id = $1 ORDER BY label")
        .bind(wallet_id)
        .fetch_all(&mut *conn)
        .await?;
    rows.iter()
        .map(|r| {
            Ok(AddressBookEntry {
                id: r.try_get("id")?,
                label: r.try_get("label")?,
                address: r.try_get("address")?,
                network: r.try_get("network")?,
                created_at: r.try_get("created_at")?,
            })
        })
        .collect()
}

pub async fn upsert_address_book(conn: &mut PgConnection, wallet_id: Uuid, label: &str, address: &str, network: &str) -> Result<Uuid> {
    let r = sqlx::query(
        "INSERT INTO address_book (id, wallet_id, label, address, network) VALUES ($1,$2,$3,$4,$5) \
         ON CONFLICT (wallet_id, address) DO UPDATE SET label = EXCLUDED.label RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(wallet_id)
    .bind(label)
    .bind(address)
    .bind(network)
    .fetch_one(&mut *conn)
    .await?;
    Ok(r.try_get("id")?)
}

pub async fn delete_address_book(conn: &mut PgConnection, wallet_id: Uuid, id: Uuid) -> Result<()> {
    let res = sqlx::query("DELETE FROM address_book WHERE wallet_id = $1 AND id = $2").bind(wallet_id).bind(id).execute(&mut *conn).await?;
    if res.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

// ---------------------------------------------------------------- ledger policies

#[derive(Clone, Debug, Serialize)]
pub struct LedgerRegistration {
    pub owner_id: Uuid,
    pub policy: btc_safe_core::ledger::LedgerPolicy,
    pub policy_id: Vec<u8>,
    pub hmac: Vec<u8>,
    pub registered_at: DateTime<Utc>,
}

pub async fn upsert_ledger_policy(
    conn: &mut PgConnection,
    wallet_id: Uuid,
    owner_id: Uuid,
    policy: &btc_safe_core::ledger::LedgerPolicy,
    policy_id: &[u8; 32],
    hmac: &[u8; 32],
) -> Result<()> {
    sqlx::query(
        "INSERT INTO ledger_policies (wallet_id, owner_id, name, descriptor_template, keys, policy_id, hmac) \
         SELECT $1, $2, $3, $4, $5, $6, $7 FROM owners WHERE id = $2 AND wallet_id = $1 \
         ON CONFLICT (wallet_id, owner_id) DO UPDATE SET name = EXCLUDED.name, \
           descriptor_template = EXCLUDED.descriptor_template, keys = EXCLUDED.keys, \
           policy_id = EXCLUDED.policy_id, hmac = EXCLUDED.hmac, registered_at = now()",
    )
    .bind(wallet_id)
    .bind(owner_id)
    .bind(&policy.name)
    .bind(&policy.descriptor_template)
    .bind(serde_json::to_value(&policy.keys).map_err(corrupt)?)
    .bind(&policy_id[..])
    .bind(&hmac[..])
    .execute(&mut *conn)
    .await
    .and_then(|r| if r.rows_affected() == 0 { Err(sqlx::Error::RowNotFound) } else { Ok(()) })
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => StoreError::NotFound,
        e => e.into(),
    })
}

pub async fn ledger_policies(conn: &mut PgConnection, wallet_id: Uuid) -> Result<Vec<LedgerRegistration>> {
    let rows = sqlx::query(
        "SELECT owner_id, name, descriptor_template, keys, policy_id, hmac, registered_at \
         FROM ledger_policies WHERE wallet_id = $1 ORDER BY registered_at",
    )
    .bind(wallet_id)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(LedgerRegistration {
                owner_id: r.try_get("owner_id")?,
                policy: btc_safe_core::ledger::LedgerPolicy {
                    name: r.try_get("name")?,
                    descriptor_template: r.try_get("descriptor_template")?,
                    keys: serde_json::from_value(r.try_get("keys")?).map_err(corrupt)?,
                },
                policy_id: r.try_get("policy_id")?,
                hmac: r.try_get("hmac")?,
                registered_at: r.try_get("registered_at")?,
            })
        })
        .collect()
}

pub async fn delete_ledger_policy(conn: &mut PgConnection, wallet_id: Uuid, owner_id: Uuid) -> Result<()> {
    let res = sqlx::query("DELETE FROM ledger_policies WHERE wallet_id = $1 AND owner_id = $2")
        .bind(wallet_id)
        .bind(owner_id)
        .execute(&mut *conn)
        .await?;
    if res.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

pub async fn audit(conn: &mut PgConnection, wallet_id: Option<Uuid>, actor: &str, action: &str, payload: serde_json::Value) -> Result<()> {
    sqlx::query("INSERT INTO audit_log (wallet_id, actor, action, payload) VALUES ($1,$2,$3,$4)")
        .bind(wallet_id)
        .bind(actor)
        .bind(action)
        .bind(payload)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Lookup helper for API inputs.
pub fn parse_script_address(addr: &str, network: Network) -> Option<ScriptBuf> {
    bitcoin::Address::from_str(addr).ok()?.require_network(network).ok().map(|a| a.script_pubkey())
}
