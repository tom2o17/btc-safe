//! Watch-only wallet over bdk_wallet, plus proposal building with coin reservation and
//! strict-order chaining.
//!
//! BDK does chain tracking and coin selection. It never holds keys (public descriptors only)
//! and its PSBT is discarded: we take the unsigned tx it selected and rebuild the PSBT with
//! `core::validate::build_canonical_psbt` from our own derivations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bdk_wallet::chain::{ChainPosition, ConfirmationBlockTime};
use bdk_wallet::error::CreateTxError;
use bdk_wallet::{ChangeSet, KeychainKind, LocalOutput, Update, Wallet};
use bitcoin::psbt::{Input as PsbtInput, Psbt};
use bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Txid};
use btc_safe_core::policy::WalletPolicy;
use btc_safe_core::validate::{self, ChangeSpec, InputSpec, ProposalSpec, Summary, ValidationError};
use btc_safe_core::Keychain;
use serde::{Deserialize, Serialize};

pub use bdk_wallet;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("descriptor: {0}")]
    Descriptor(String),
    #[error("loading wallet state: {0}")]
    Load(String),
    #[error("stored wallet state is for a different descriptor or network")]
    StateMismatch,
    #[error("coin selection: {0}")]
    Build(String),
    #[error("insufficient unreserved funds: need {needed}, available {available} (reserved by queued proposals: {reserved})")]
    InsufficientFunds { needed: Amount, available: Amount, reserved: Amount },
    #[error("coin {0} is not an unspent output of this wallet")]
    UnknownUtxo(OutPoint),
    #[error("coin {0} is reserved by another queued proposal")]
    Reserved(OutPoint),
    #[error("previous transaction {0} unknown")]
    MissingPrevTx(Txid),
    #[error("chain input {0} must be on the internal keychain at the claimed index")]
    BadChainInput(OutPoint),
    #[error("update: {0}")]
    Update(String),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

/// Belt and braces for the watch-only invariant: BDK would happily build signers from a
/// descriptor with private keys. Ours are built from xpubs, but check anyway.
fn public_only(desc: &str) -> Result<(), WalletError> {
    if desc.contains("prv") {
        return Err(WalletError::Descriptor("private key material in descriptor".into()));
    }
    Ok(())
}

pub fn to_bdk(k: Keychain) -> KeychainKind {
    match k {
        Keychain::External => KeychainKind::External,
        Keychain::Internal => KeychainKind::Internal,
    }
}

pub fn from_bdk(k: KeychainKind) -> Keychain {
    match k {
        KeychainKind::External => Keychain::External,
        KeychainKind::Internal => Keychain::Internal,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub keychain: Keychain,
    pub index: u32,
    pub script_pubkey: ScriptBuf,
    /// Confirmation height, `None` if unconfirmed.
    pub height: Option<u32>,
}

impl From<LocalOutput> for Utxo {
    fn from(o: LocalOutput) -> Self {
        Utxo {
            outpoint: o.outpoint,
            amount: o.txout.value,
            keychain: from_bdk(o.keychain),
            index: o.derivation_index,
            script_pubkey: o.txout.script_pubkey,
            height: match o.chain_position {
                ChainPosition::Confirmed { anchor, .. } => Some(anchor.block_id.height),
                ChainPosition::Unconfirmed { .. } => None,
            },
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    pub confirmed: Amount,
    pub unconfirmed: Amount,
    pub reserved: Amount,
    pub available: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub txid: Txid,
    pub height: Option<u32>,
    pub received: Amount,
    pub sent: Amount,
    pub fee: Option<Amount>,
}

/// The predecessor's change output a strict-order proposal must spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainInput {
    pub outpoint: OutPoint,
    pub amount: Amount,
    /// Internal-keychain index of the change output.
    pub index: u32,
    /// The predecessor's unsigned tx (its txid is final: segwit txids don't change on signing).
    pub prev_tx: Transaction,
}

#[derive(Clone, Debug, Default)]
pub struct BuildRequest {
    pub recipients: Vec<(ScriptBuf, Amount)>,
    pub fee_rate: Option<FeeRate>,
    /// Coins locked by other queued proposals.
    pub reserved: BTreeSet<OutPoint>,
    /// Coin control: spend these (and only these if `manual_only`).
    pub must_spend: Vec<OutPoint>,
    pub manual_only: bool,
    /// Strict-order: must spend this output of the queue tail.
    pub chain_input: Option<ChainInput>,
    /// Internal index to send change to (allocated by the store, never reused).
    pub change_index: u32,
    pub rbf: bool,
    /// Send everything selected (all unreserved coins, or `must_spend`) to the single recipient.
    pub send_max: bool,
}

#[derive(Clone, Debug)]
pub struct BuiltProposal {
    pub spec: ProposalSpec,
    pub psbt: Psbt,
    pub summary: Summary,
    pub change_used: bool,
}

pub struct SafeWallet {
    policy: WalletPolicy,
    inner: Wallet,
}

impl SafeWallet {
    /// Fresh watch-only wallet with no chain state.
    pub fn new(policy: WalletPolicy) -> Result<Self, WalletError> {
        let ext = policy.descriptor_string(Keychain::External).map_err(|e| WalletError::Descriptor(e.to_string()))?;
        let int = policy.descriptor_string(Keychain::Internal).map_err(|e| WalletError::Descriptor(e.to_string()))?;
        public_only(&ext)?;
        public_only(&int)?;
        let inner = Wallet::create(ext, int)
            .network(policy.network())
            .create_wallet_no_persist()
            .map_err(|e| WalletError::Descriptor(e.to_string()))?;
        Ok(SafeWallet { policy, inner })
    }

    /// Restore from a persisted BDK changeset. Descriptors and network are checked against
    /// the policy so a swapped DB row can't load someone else's state.
    pub fn load(policy: WalletPolicy, changeset: ChangeSet) -> Result<Self, WalletError> {
        let ext = policy.descriptor_string(Keychain::External).map_err(|e| WalletError::Descriptor(e.to_string()))?;
        let int = policy.descriptor_string(Keychain::Internal).map_err(|e| WalletError::Descriptor(e.to_string()))?;
        let inner = Wallet::load()
            .descriptor(KeychainKind::External, Some(ext))
            .descriptor(KeychainKind::Internal, Some(int))
            .check_network(policy.network())
            .load_wallet_no_persist(changeset)
            .map_err(|e| WalletError::Load(e.to_string()))?
            .ok_or(WalletError::StateMismatch)?;
        Ok(SafeWallet { policy, inner })
    }

    pub fn policy(&self) -> &WalletPolicy {
        &self.policy
    }

    pub fn bdk(&self) -> &Wallet {
        &self.inner
    }

    pub fn bdk_mut(&mut self) -> &mut Wallet {
        &mut self.inner
    }

    /// Changes since the last call, to be merged into the persisted changeset.
    pub fn take_staged(&mut self) -> Option<ChangeSet> {
        self.inner.take_staged()
    }

    /// Make sure BDK watches addresses up to `index` (inclusive) on `keychain`.
    pub fn reveal_to(&mut self, keychain: Keychain, index: u32) {
        let _ = self.inner.reveal_addresses_to(to_bdk(keychain), index).count();
    }

    pub fn apply_update(&mut self, update: impl Into<Update>) -> Result<(), WalletError> {
        self.inner.apply_update(update).map_err(|e| WalletError::Update(e.to_string()))
    }

    pub fn tip_height(&self) -> u32 {
        self.inner.latest_checkpoint().height()
    }

    pub fn utxos(&self) -> Vec<Utxo> {
        let mut v: Vec<Utxo> = self.inner.list_unspent().map(Utxo::from).collect();
        v.sort_by_key(|u| (u.height.is_none(), u.height, u.outpoint));
        v
    }

    pub fn balance(&self, reserved: &BTreeSet<OutPoint>) -> Balance {
        let mut b = Balance::default();
        for u in self.utxos() {
            if u.height.is_some() {
                b.confirmed += u.amount;
            } else {
                b.unconfirmed += u.amount;
            }
            if reserved.contains(&u.outpoint) {
                b.reserved += u.amount;
            } else {
                b.available += u.amount;
            }
        }
        b
    }

    pub fn history(&self) -> Vec<HistoryEntry> {
        let mut out: Vec<HistoryEntry> = self
            .inner
            .transactions()
            .map(|wtx| {
                let tx = &wtx.tx_node.tx;
                let (sent, received) = self.inner.sent_and_received(tx);
                HistoryEntry {
                    txid: wtx.tx_node.txid,
                    height: match wtx.chain_position {
                        ChainPosition::Confirmed { anchor, .. } => Some(anchor.block_id.height),
                        ChainPosition::Unconfirmed { .. } => None,
                    },
                    received,
                    sent,
                    fee: self.inner.calculate_fee(tx).ok(),
                }
            })
            .collect();
        out.sort_by_key(|h| (std::cmp::Reverse(h.height.unwrap_or(u32::MAX)), h.txid));
        out
    }

    pub fn get_tx(&self, txid: Txid) -> Option<Arc<Transaction>> {
        self.inner.tx_graph().get_tx(txid)
    }

    /// Build a proposal: BDK selects coins (excluding reserved ones), then we rebuild and
    /// validate the PSBT from our own derivations.
    pub fn build_proposal(&mut self, req: &BuildRequest) -> Result<BuiltProposal, WalletError> {
        let change_spk = self
            .policy
            .derive(Keychain::Internal, req.change_index)
            .map_err(|e| WalletError::Descriptor(e.to_string()))?
            .script_pubkey;
        self.reveal_to(Keychain::Internal, req.change_index);

        let unspent: BTreeMap<OutPoint, LocalOutput> = self.inner.list_unspent().map(|o| (o.outpoint, o)).collect();
        for op in &req.must_spend {
            if req.reserved.contains(op) {
                return Err(WalletError::Reserved(*op));
            }
            if !unspent.contains_key(op) {
                return Err(WalletError::UnknownUtxo(*op));
            }
        }
        let mut chain_local = false;
        if let Some(ci) = &req.chain_input {
            let d = self
                .policy
                .derive(Keychain::Internal, ci.index)
                .map_err(|e| WalletError::Descriptor(e.to_string()))?;
            let out = ci.prev_tx.output.get(ci.outpoint.vout as usize);
            if ci.prev_tx.compute_txid() != ci.outpoint.txid
                || out != Some(&TxOut { value: ci.amount, script_pubkey: d.script_pubkey })
            {
                return Err(WalletError::BadChainInput(ci.outpoint));
            }
            chain_local = unspent.contains_key(&ci.outpoint);
            self.reveal_to(Keychain::Internal, ci.index);
        }

        let mut b = self.inner.build_tx();
        if req.send_max {
            if req.recipients.len() != 1 {
                return Err(WalletError::Build("send max needs exactly one recipient".into()));
            }
            b.drain_to(req.recipients[0].0.clone());
            if req.must_spend.is_empty() && req.chain_input.is_none() {
                b.drain_wallet();
            }
        } else {
            for (spk, amt) in &req.recipients {
                b.add_recipient(spk.clone(), *amt);
            }
            b.drain_to(change_spk.clone());
        }
        if let Some(fr) = req.fee_rate {
            b.fee_rate(fr);
        }
        b.unspendable(req.reserved.iter().copied().collect());
        if !req.must_spend.is_empty() {
            b.add_utxos(&req.must_spend).map_err(|e| WalletError::Build(e.to_string()))?;
        }
        if let Some(ci) = &req.chain_input {
            if chain_local {
                b.add_utxo(ci.outpoint).map_err(|e| WalletError::Build(e.to_string()))?;
            } else {
                // Not on chain yet (the predecessor hasn't been broadcast): BDK treats it as
                // foreign. Value and script were checked above against the predecessor tx.
                let input = PsbtInput {
                    non_witness_utxo: Some(ci.prev_tx.clone()),
                    witness_utxo: Some(TxOut {
                        value: ci.amount,
                        script_pubkey: ci.prev_tx.output[ci.outpoint.vout as usize].script_pubkey.clone(),
                    }),
                    ..Default::default()
                };
                let seq = if req.rbf { Sequence::ENABLE_RBF_NO_LOCKTIME } else { Sequence::ENABLE_LOCKTIME_NO_RBF };
                b.add_foreign_utxo_with_sequence(ci.outpoint, input, self.policy.max_satisfaction_weight(), seq)
                    .map_err(|e| WalletError::Build(e.to_string()))?;
            }
        }
        if req.manual_only || (req.send_max && (!req.must_spend.is_empty() || req.chain_input.is_some())) {
            b.manually_selected_only();
        }
        if !req.rbf {
            b.set_exact_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF);
        }
        let bdk_psbt = match b.finish() {
            Ok(p) => p,
            Err(CreateTxError::CoinSelection(e)) => {
                let reserved: Amount = unspent.values().filter(|o| req.reserved.contains(&o.outpoint)).map(|o| o.txout.value).sum();
                let available: Amount = unspent.values().filter(|o| !req.reserved.contains(&o.outpoint)).map(|o| o.txout.value).sum();
                return Err(WalletError::InsufficientFunds { needed: e.needed, available, reserved });
            }
            Err(e) => return Err(WalletError::Build(e.to_string())),
        };
        let tx = bdk_psbt.unsigned_tx;

        let mut inputs = Vec::with_capacity(tx.input.len());
        let mut prev_txs = BTreeMap::new();
        for txin in &tx.input {
            let op = txin.previous_output;
            if req.reserved.contains(&op) {
                // Belt and braces: BDK honoured `unspendable`, but never trust it blindly.
                return Err(WalletError::Reserved(op));
            }
            let spec = match (unspent.get(&op), &req.chain_input) {
                (Some(o), _) => InputSpec { outpoint: op, amount: o.txout.value, keychain: from_bdk(o.keychain), index: o.derivation_index },
                (None, Some(ci)) if ci.outpoint == op => {
                    prev_txs.insert(op.txid, ci.prev_tx.clone());
                    InputSpec { outpoint: op, amount: ci.amount, keychain: Keychain::Internal, index: ci.index }
                }
                _ => return Err(WalletError::UnknownUtxo(op)),
            };
            if let std::collections::btree_map::Entry::Vacant(e) = prev_txs.entry(op.txid) {
                let prev = self.get_tx(op.txid).ok_or(WalletError::MissingPrevTx(op.txid))?;
                e.insert(prev.as_ref().clone());
            }
            inputs.push(spec);
        }
        let change: Vec<ChangeSpec> = tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, o)| !req.send_max && o.script_pubkey == change_spk)
            .map(|(v, _)| ChangeSpec { vout: v as u32, index: req.change_index })
            .collect();
        let change_used = !change.is_empty();
        let spec = ProposalSpec { unsigned_tx: tx, inputs, change };
        let psbt = validate::build_canonical_psbt(&self.policy, &spec, &prev_txs)?;
        let summary = validate::check_spec(&self.policy, &spec)?;
        Ok(BuiltProposal { spec, psbt, summary, change_used })
    }
}

/// RBF fee bump of an existing proposal: same inputs, same outputs, the change output pays
/// the extra fee. The new fee must exceed the old one by at least the incremental relay fee
/// (BIP-125 rule 4, 1 sat/vB). Pure: no wallet state needed.
pub fn bump_fee(
    policy: &WalletPolicy,
    original: &ProposalSpec,
    prev_txs: &BTreeMap<Txid, Transaction>,
    new_rate: FeeRate,
) -> Result<BuiltProposal, WalletError> {
    let old = validate::check_spec(policy, original)?;
    if !old.rbf {
        return Err(WalletError::Build("original doesn't signal RBF".into()));
    }
    let change = original.change.first().ok_or_else(|| WalletError::Build("no change output to take the fee from".into()))?;
    let vsize = old.est_vsize;
    let wanted = new_rate.to_sat_per_vb_ceil().saturating_mul(vsize);
    let min = old.fee.to_sat() + vsize; // + 1 sat/vB incremental relay fee
    let new_fee = wanted.max(min);
    let delta = new_fee - old.fee.to_sat();
    let mut tx = original.unsigned_tx.clone();
    let out = &mut tx.output[change.vout as usize];
    let left = out.value.to_sat().checked_sub(delta).ok_or(WalletError::InsufficientFunds {
        needed: Amount::from_sat(delta),
        available: out.value,
        reserved: Amount::ZERO,
    })?;
    if Amount::from_sat(left) < out.script_pubkey.minimal_non_dust() {
        return Err(WalletError::Build("bump would make change dust; cancel instead".into()));
    }
    out.value = Amount::from_sat(left);
    let spec = ProposalSpec { unsigned_tx: tx, inputs: original.inputs.clone(), change: original.change.clone() };
    let psbt = validate::build_canonical_psbt(policy, &spec, prev_txs)?;
    let summary = validate::check_spec(policy, &spec)?;
    Ok(BuiltProposal { spec, psbt, summary, change_used: true })
}

/// RBF cancel: spend the same inputs back to a fresh change address of ours, paying more
/// than the original fee.
pub fn build_cancel(
    policy: &WalletPolicy,
    original: &ProposalSpec,
    prev_txs: &BTreeMap<Txid, Transaction>,
    change_index: u32,
    new_rate: FeeRate,
) -> Result<BuiltProposal, WalletError> {
    let old = validate::check_spec(policy, original)?;
    let spk = policy.derive(Keychain::Internal, change_index).map_err(|e| WalletError::Descriptor(e.to_string()))?.script_pubkey;
    let mut tx = original.unsigned_tx.clone();
    tx.output = vec![TxOut { value: old.total_in, script_pubkey: spk }];
    for i in &mut tx.input {
        i.sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    }
    let vsize = btc_safe_core::fees::estimate_vsize(policy, &tx);
    let fee = new_rate.to_sat_per_vb_ceil().saturating_mul(vsize).max(old.fee.to_sat() + vsize);
    let left = old.total_in.to_sat().checked_sub(fee).ok_or(WalletError::InsufficientFunds {
        needed: Amount::from_sat(fee),
        available: old.total_in,
        reserved: Amount::ZERO,
    })?;
    tx.output[0].value = Amount::from_sat(left);
    let spec = ProposalSpec { unsigned_tx: tx, inputs: original.inputs.clone(), change: vec![ChangeSpec { vout: 0, index: change_index }] };
    let psbt = validate::build_canonical_psbt(policy, &spec, prev_txs)?;
    let summary = validate::check_spec(policy, &spec)?;
    Ok(BuiltProposal { spec, psbt, summary, change_used: true })
}

/// Helpers for building chain updates by hand (tests, and the in-memory chain source).
pub mod update {
    use super::*;
    use bdk_wallet::chain::{BlockId, CheckPoint, TxUpdate};

    pub fn confirmed(txs: &[Transaction], height: u32, block: bitcoin::BlockHash, time: u64, tip: CheckPoint) -> Update {
        let mut tu = TxUpdate::<ConfirmationBlockTime>::default();
        for tx in txs {
            tu.txs.push(Arc::new(tx.clone()));
            tu.anchors.insert((
                ConfirmationBlockTime { block_id: BlockId { height, hash: block }, confirmation_time: time },
                tx.compute_txid(),
            ));
        }
        Update { last_active_indices: Default::default(), tx_update: tu, chain: Some(tip) }
    }

    pub fn mempool(txs: &[Transaction], seen_at: u64) -> Update {
        let mut tu = TxUpdate::<ConfirmationBlockTime>::default();
        for tx in txs {
            tu.txs.push(Arc::new(tx.clone()));
            tu.seen_ats.insert((tx.compute_txid(), seen_at));
        }
        Update { last_active_indices: Default::default(), tx_update: tu, chain: None }
    }
}
