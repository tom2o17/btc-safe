//! PSBT validation (DESIGN.md §6.2).
//!
//! Design rule: the server never stores a client-supplied PSBT. A proposal's PSBT is built
//! here from data we derived ourselves (`build_canonical_psbt`). A signer's PSBT is only a
//! carrier for signatures: `validate_submission` checks it against the stored proposal and
//! returns the individually verified signatures, which the caller merges into the stored PSBT.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::consensus::encode::serialize;
use bitcoin::ecdsa;
use bitcoin::psbt::{Input as PsbtInput, Output as PsbtOutput, Psbt};
use bitcoin::secp256k1::{Message, Secp256k1, Verification};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Address, Amount, OutPoint, PublicKey, ScriptBuf, Transaction, TxOut, Txid, Weight, Witness};
use serde::{Deserialize, Serialize};

use crate::fees;
use crate::policy::{DerivedScript, PolicyError, WalletPolicy};
use crate::Keychain;

/// What we know about one input of a proposal, from our own records (never from a PSBT).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSpec {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub keychain: Keychain,
    pub index: u32,
}

/// An output we claim is change: it must re-derive from the internal keychain at `index`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSpec {
    pub vout: u32,
    pub index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalSpec {
    pub unsigned_tx: Transaction,
    /// One entry per tx input, in tx input order.
    pub inputs: Vec<InputSpec>,
    pub change: Vec<ChangeSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputSummary {
    pub vout: u32,
    pub script_pubkey: ScriptBuf,
    pub address: String,
    pub amount: Amount,
    /// `Some(index)` if this output is verified change at m/1/index.
    pub change_index: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub unsigned_txid: Txid,
    pub total_in: Amount,
    pub total_out: Amount,
    pub fee: Amount,
    /// Sum of non-change outputs.
    pub sent: Amount,
    pub outputs: Vec<OutputSummary>,
    pub est_weight: Weight,
    pub est_vsize: u64,
    pub fee_rate_sat_kwu: u64,
    pub rbf: bool,
    pub lock_time: u32,
    pub version: i32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("transaction has no inputs")]
    NoInputs,
    #[error("transaction has no outputs")]
    NoOutputs,
    #[error("unsupported tx version {0}")]
    BadVersion(i32),
    #[error("tx has {tx} inputs but the proposal records {spec}")]
    InputCountMismatch { tx: usize, spec: usize },
    #[error("input {0} outpoint doesn't match the proposal record")]
    InputMismatch(usize),
    #[error("outpoint {0} spent twice")]
    DuplicateInput(OutPoint),
    #[error("unsigned tx input {0} carries a scriptSig or witness")]
    NotUnsigned(usize),
    #[error("change vout {0} out of range")]
    ChangeVoutOutOfRange(u32),
    #[error("change vout {0} listed twice")]
    DuplicateChange(u32),
    #[error("output {vout} claimed as change at m/1/{index} but the script doesn't match our descriptor")]
    ChangeScriptMismatch { vout: u32, index: u32 },
    #[error("output {0} is dust")]
    DustOutput(u32),
    #[error("output {0} has a non-standard script")]
    NonStandardOutput(u32),
    #[error("amount overflow")]
    ValueOverflow,
    #[error("outputs exceed inputs")]
    OutputsExceedInputs,
    #[error("submitted PSBT's unsigned transaction differs from the stored proposal")]
    UnsignedTxMismatch,
    #[error("previous transaction {0} not available")]
    PrevTxMissing(Txid),
    #[error("input {0}: previous transaction doesn't match the outpoint/amount/script we hold")]
    PrevTxMismatch(usize),
    #[error("input {0}: witness_utxo doesn't match our record of the coin")]
    WitnessUtxoMismatch(usize),
    #[error("input {0}: non_witness_utxo doesn't match the outpoint or our record")]
    NonWitnessUtxoMismatch(usize),
    #[error("input {0}: witness_script doesn't match our descriptor")]
    WitnessScriptMismatch(usize),
    #[error("input {0}: only SIGHASH_ALL is accepted")]
    BadSighashType(usize),
    #[error("input {0}: has a final scriptSig (P2WSH inputs never do)")]
    FinalScriptSig(usize),
    #[error("input {0}: malformed final witness")]
    MalformedFinalWitness(usize),
    #[error("input {input}: signature from {pubkey}, which is not an owner key for this input")]
    UnknownSigner { input: usize, pubkey: String },
    #[error("input {input}: signature from owner #{owner} does not verify")]
    BadSignature { input: usize, owner: usize },
    #[error("submitted PSBT contains no signatures")]
    NoSignatures,
    #[error("input {input}: {have} valid signatures, need {need}")]
    NotEnoughSignatures { input: usize, have: usize, need: usize },
    #[error("final transaction failed re-validation: {0}")]
    FinalCheck(String),
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("sighash: {0}")]
    Sighash(String),
}

type Result<T> = std::result::Result<T, ValidationError>;

fn derive_inputs(policy: &WalletPolicy, spec: &ProposalSpec) -> Result<Vec<DerivedScript>> {
    let secp = Secp256k1::verification_only();
    spec.inputs
        .iter()
        .map(|i| policy.derive_with(&secp, i.keychain, i.index).map_err(Into::into))
        .collect()
}

/// Structural checks on a proposal record. Returns the review summary.
pub fn check_spec(policy: &WalletPolicy, spec: &ProposalSpec) -> Result<Summary> {
    let tx = &spec.unsigned_tx;
    if tx.input.is_empty() {
        return Err(ValidationError::NoInputs);
    }
    if tx.output.is_empty() {
        return Err(ValidationError::NoOutputs);
    }
    if !(tx.version.0 == 1 || tx.version.0 == 2) {
        return Err(ValidationError::BadVersion(tx.version.0));
    }
    if tx.input.len() != spec.inputs.len() {
        return Err(ValidationError::InputCountMismatch { tx: tx.input.len(), spec: spec.inputs.len() });
    }
    let mut seen = BTreeSet::new();
    let mut total_in = Amount::ZERO;
    for (i, (txin, rec)) in tx.input.iter().zip(&spec.inputs).enumerate() {
        if txin.previous_output != rec.outpoint {
            return Err(ValidationError::InputMismatch(i));
        }
        if !seen.insert(txin.previous_output) {
            return Err(ValidationError::DuplicateInput(txin.previous_output));
        }
        if !txin.script_sig.is_empty() || !txin.witness.is_empty() {
            return Err(ValidationError::NotUnsigned(i));
        }
        total_in = total_in.checked_add(rec.amount).ok_or(ValidationError::ValueOverflow)?;
    }

    let mut change_at: BTreeMap<u32, u32> = BTreeMap::new();
    for c in &spec.change {
        if c.vout as usize >= tx.output.len() {
            return Err(ValidationError::ChangeVoutOutOfRange(c.vout));
        }
        if change_at.insert(c.vout, c.index).is_some() {
            return Err(ValidationError::DuplicateChange(c.vout));
        }
        let d = policy.derive(Keychain::Internal, c.index)?;
        if tx.output[c.vout as usize].script_pubkey != d.script_pubkey {
            return Err(ValidationError::ChangeScriptMismatch { vout: c.vout, index: c.index });
        }
    }

    let mut total_out = Amount::ZERO;
    let mut sent = Amount::ZERO;
    let mut outputs = Vec::with_capacity(tx.output.len());
    for (vout, out) in tx.output.iter().enumerate() {
        let vout = vout as u32;
        let address = Address::from_script(&out.script_pubkey, policy.network())
            .map_err(|_| ValidationError::NonStandardOutput(vout))?;
        if out.value < out.script_pubkey.minimal_non_dust() {
            return Err(ValidationError::DustOutput(vout));
        }
        total_out = total_out.checked_add(out.value).ok_or(ValidationError::ValueOverflow)?;
        let change_index = change_at.get(&vout).copied();
        if change_index.is_none() {
            sent = sent.checked_add(out.value).ok_or(ValidationError::ValueOverflow)?;
        }
        outputs.push(OutputSummary {
            vout,
            script_pubkey: out.script_pubkey.clone(),
            address: address.to_string(),
            amount: out.value,
            change_index,
        });
    }
    let fee = total_in.checked_sub(total_out).ok_or(ValidationError::OutputsExceedInputs)?;
    let est_weight = fees::estimate_weight(policy, tx);
    Ok(Summary {
        unsigned_txid: tx.compute_txid(),
        total_in,
        total_out,
        fee,
        sent,
        outputs,
        est_weight,
        est_vsize: est_weight.to_vbytes_ceil(),
        fee_rate_sat_kwu: fees::fee_rate(fee, est_weight).to_sat_per_kwu(),
        rbf: tx.input.iter().any(|i| i.sequence.is_rbf()),
        lock_time: tx.lock_time.to_consensus_u32(),
        version: tx.version.0,
    })
}

/// Build the PSBT we store for a proposal, entirely from our own derivations.
/// `prev_txs` must contain the full previous transaction of every input (hardware
/// wallets need `non_witness_utxo` for segwit v0 inputs).
pub fn build_canonical_psbt(
    policy: &WalletPolicy,
    spec: &ProposalSpec,
    prev_txs: &BTreeMap<Txid, Transaction>,
) -> Result<Psbt> {
    check_spec(policy, spec)?;
    let derived = derive_inputs(policy, spec)?;
    let mut psbt = Psbt::from_unsigned_tx(spec.unsigned_tx.clone()).map_err(|_| ValidationError::NotUnsigned(0))?;
    // BIP-174 global xpubs: lets multisig signers recognise the wallet's cosigner set.
    for o in policy.owners() {
        psbt.xpub.insert(o.xpub, (o.fingerprint, o.path.clone()));
    }
    for (i, (rec, d)) in spec.inputs.iter().zip(&derived).enumerate() {
        let txout = TxOut { value: rec.amount, script_pubkey: d.script_pubkey.clone() };
        let prev = prev_txs.get(&rec.outpoint.txid).ok_or(ValidationError::PrevTxMissing(rec.outpoint.txid))?;
        if prev.compute_txid() != rec.outpoint.txid || prev.output.get(rec.outpoint.vout as usize) != Some(&txout) {
            return Err(ValidationError::PrevTxMismatch(i));
        }
        let mut prev = prev.clone();
        // Witness data doesn't affect the txid; strip it to keep the PSBT small.
        for inp in &mut prev.input {
            inp.witness = Witness::new();
        }
        psbt.inputs[i] = PsbtInput {
            witness_utxo: Some(txout),
            non_witness_utxo: Some(prev),
            witness_script: Some(d.witness_script.clone()),
            bip32_derivation: d.bip32_derivation(),
            sighash_type: None,
            ..Default::default()
        };
    }
    for c in &spec.change {
        let d = policy.derive(Keychain::Internal, c.index)?;
        psbt.outputs[c.vout as usize] = PsbtOutput {
            witness_script: Some(d.witness_script.clone()),
            bip32_derivation: d.bip32_derivation(),
            ..Default::default()
        };
    }
    Ok(psbt)
}

fn sighash_msg(tx: &Transaction, input: usize, ws: &ScriptBuf, amount: Amount) -> Result<Message> {
    let h = SighashCache::new(tx)
        .p2wsh_signature_hash(input, ws, amount, EcdsaSighashType::All)
        .map_err(|e| ValidationError::Sighash(e.to_string()))?;
    Ok(Message::from(h))
}

fn verify_sig<C: Verification>(secp: &Secp256k1<C>, msg: &Message, pk: &PublicKey, sig: &ecdsa::Signature) -> bool {
    sig.sighash_type == EcdsaSighashType::All && secp.verify_ecdsa(msg, &sig.signature, &pk.inner).is_ok()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSig {
    pub input: usize,
    pub owner: usize,
    pub pubkey: PublicKey,
    pub sig: ecdsa::Signature,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Submission {
    /// Signatures not already present in the stored PSBT, each verified.
    pub new_sigs: Vec<VerifiedSig>,
    /// Valid signatures we already had (resubmission is idempotent).
    pub already_present: usize,
}

impl Submission {
    pub fn owners(&self) -> BTreeSet<usize> {
        self.new_sigs.iter().map(|s| s.owner).collect()
    }
}

fn input_matches_stored(i: usize, sub: &PsbtInput, rec: &InputSpec, d: &DerivedScript) -> Result<()> {
    let expected = TxOut { value: rec.amount, script_pubkey: d.script_pubkey.clone() };
    if let Some(wu) = &sub.witness_utxo {
        if *wu != expected {
            return Err(ValidationError::WitnessUtxoMismatch(i));
        }
    }
    if let Some(prev) = &sub.non_witness_utxo {
        if prev.compute_txid() != rec.outpoint.txid || prev.output.get(rec.outpoint.vout as usize) != Some(&expected) {
            return Err(ValidationError::NonWitnessUtxoMismatch(i));
        }
    }
    if let Some(ws) = &sub.witness_script {
        if *ws != d.witness_script {
            return Err(ValidationError::WitnessScriptMismatch(i));
        }
    }
    if let Some(t) = sub.sighash_type {
        if t.ecdsa_hash_ty() != Ok(EcdsaSighashType::All) {
            return Err(ValidationError::BadSighashType(i));
        }
    }
    if sub.final_script_sig.as_ref().is_some_and(|s| !s.is_empty()) {
        return Err(ValidationError::FinalScriptSig(i));
    }
    Ok(())
}

/// Pull signatures out of a finalized P2WSH multisig witness: `[<> sig1 .. sigk <ws>]`.
fn sigs_from_final_witness<C: Verification>(
    secp: &Secp256k1<C>,
    i: usize,
    w: &Witness,
    d: &DerivedScript,
    msg: &Message,
) -> Result<Vec<(PublicKey, ecdsa::Signature)>> {
    // At most one signature per owner: [<>, sig.., ws] has ≤ n + 2 items. Checked before any
    // signature work so an oversized witness can't buy n verifications per item.
    if w.len() < 3 || w.len() > d.owner_keys.len() + 2 {
        return Err(ValidationError::MalformedFinalWitness(i));
    }
    let items: Vec<&[u8]> = w.iter().collect();
    if !items[0].is_empty() || items[items.len() - 1] != d.witness_script.as_bytes() {
        return Err(ValidationError::MalformedFinalWitness(i));
    }
    let mut out = vec![];
    for raw in &items[1..items.len() - 1] {
        let sig = ecdsa::Signature::from_slice(raw).map_err(|_| ValidationError::MalformedFinalWitness(i))?;
        let pk = d
            .owner_keys
            .iter()
            .map(|(_, k, _)| *k)
            .find(|k| verify_sig(secp, msg, k, &sig))
            .ok_or(ValidationError::MalformedFinalWitness(i))?;
        out.push((pk, sig));
    }
    Ok(out)
}

/// Validate a signer's PSBT against the stored proposal. Any defect rejects the whole
/// submission; nothing from it is stored unless everything checks out.
pub fn validate_submission(
    policy: &WalletPolicy,
    spec: &ProposalSpec,
    stored: &Psbt,
    submitted: &Psbt,
) -> Result<Submission> {
    check_spec(policy, spec)?;
    let canonical = serialize(&spec.unsigned_tx);
    if serialize(&stored.unsigned_tx) != canonical {
        return Err(ValidationError::FinalCheck("stored PSBT diverged from proposal record".into()));
    }
    if submitted.version != 0 || serialize(&submitted.unsigned_tx) != canonical {
        return Err(ValidationError::UnsignedTxMismatch);
    }
    if submitted.inputs.len() != spec.inputs.len() || submitted.outputs.len() != spec.unsigned_tx.output.len() {
        return Err(ValidationError::UnsignedTxMismatch);
    }
    let secp = Secp256k1::verification_only();
    let derived = derive_inputs(policy, spec)?;
    let mut sub = Submission::default();
    let mut found_any = false;
    for (i, ((pin, rec), d)) in submitted.inputs.iter().zip(&spec.inputs).zip(&derived).enumerate() {
        input_matches_stored(i, pin, rec, d)?;
        let msg = sighash_msg(&spec.unsigned_tx, i, &d.witness_script, rec.amount)?;
        let mut candidates: Vec<(PublicKey, ecdsa::Signature)> =
            pin.partial_sigs.iter().map(|(k, s)| (*k, *s)).collect();
        if let Some(w) = &pin.final_script_witness {
            candidates.extend(sigs_from_final_witness(&secp, i, w, d, &msg)?);
        }
        let mut seen_owner = BTreeSet::new();
        for (pk, sig) in candidates {
            found_any = true;
            let owner = d
                .owner_of(&pk)
                .ok_or_else(|| ValidationError::UnknownSigner { input: i, pubkey: pk.to_string() })?;
            if !verify_sig(&secp, &msg, &pk, &sig) {
                return Err(ValidationError::BadSignature { input: i, owner });
            }
            if !seen_owner.insert(owner) {
                continue; // same key in partial_sigs and final witness
            }
            if stored.inputs[i].partial_sigs.contains_key(&pk) {
                sub.already_present += 1;
            } else {
                sub.new_sigs.push(VerifiedSig { input: i, owner, pubkey: pk, sig });
            }
        }
    }
    if !found_any {
        return Err(ValidationError::NoSignatures);
    }
    Ok(sub)
}

pub fn apply_signatures(stored: &mut Psbt, sub: &Submission) {
    for s in &sub.new_sigs {
        stored.inputs[s.input].partial_sigs.insert(s.pubkey, s.sig);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerSigStatus {
    pub owner: usize,
    pub inputs_signed: Vec<bool>,
    /// Signed every input.
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigStatus {
    pub threshold: usize,
    pub owners: Vec<OwnerSigStatus>,
    /// Owners who have signed every input (the "N of M confirmations" figure).
    pub confirmations: usize,
    /// Every input has at least `threshold` valid signatures.
    pub ready: bool,
}

/// Re-verify every signature in the stored PSBT and report who has signed what.
pub fn signature_status(policy: &WalletPolicy, spec: &ProposalSpec, psbt: &Psbt) -> Result<SigStatus> {
    check_spec(policy, spec)?;
    if serialize(&psbt.unsigned_tx) != serialize(&spec.unsigned_tx) {
        return Err(ValidationError::UnsignedTxMismatch);
    }
    let secp = Secp256k1::verification_only();
    let derived = derive_inputs(policy, spec)?;
    let n = policy.owners().len();
    let mut signed = vec![vec![false; spec.inputs.len()]; n];
    let mut ready = true;
    for (i, (rec, d)) in spec.inputs.iter().zip(&derived).enumerate() {
        let msg = sighash_msg(&spec.unsigned_tx, i, &d.witness_script, rec.amount)?;
        let mut count = 0;
        for (pk, sig) in &psbt.inputs[i].partial_sigs {
            let owner = d
                .owner_of(pk)
                .ok_or_else(|| ValidationError::UnknownSigner { input: i, pubkey: pk.to_string() })?;
            if !verify_sig(&secp, &msg, pk, sig) {
                return Err(ValidationError::BadSignature { input: i, owner });
            }
            signed[owner][i] = true;
            count += 1;
        }
        if count < policy.threshold() {
            ready = false;
        }
    }
    let owners: Vec<OwnerSigStatus> = signed
        .into_iter()
        .enumerate()
        .map(|(owner, inputs_signed)| OwnerSigStatus { owner, complete: inputs_signed.iter().all(|b| *b), inputs_signed })
        .collect();
    let confirmations = owners.iter().filter(|o| o.complete).count();
    Ok(SigStatus { threshold: policy.threshold(), owners, confirmations, ready })
}

/// Build the final signed transaction and re-validate it two independent ways:
/// our own CHECKMULTISIG-order verifier and miniscript's interpreter.
pub fn finalize(policy: &WalletPolicy, spec: &ProposalSpec, psbt: &Psbt) -> Result<Transaction> {
    let status = signature_status(policy, spec, psbt)?;
    let derived = derive_inputs(policy, spec)?;
    let m = policy.threshold();
    let mut tx = spec.unsigned_tx.clone();
    for (i, d) in derived.iter().enumerate() {
        let sigs = &psbt.inputs[i].partial_sigs;
        if sigs.len() < m {
            return Err(ValidationError::NotEnoughSignatures { input: i, have: sigs.len(), need: m });
        }
        // Script key order is sorted by serialized pubkey (sortedmulti); CHECKMULTISIG
        // needs the signatures in the same order as their keys.
        let mut keys: Vec<PublicKey> = d.owner_keys.iter().map(|(_, k, _)| *k).collect();
        keys.sort_by_key(|k| k.to_bytes());
        let mut w = Witness::new();
        w.push([]);
        let mut used = 0;
        for k in &keys {
            if used == m {
                break;
            }
            if let Some(s) = sigs.get(k) {
                w.push(s.to_vec());
                used += 1;
            }
        }
        w.push(d.witness_script.as_bytes());
        tx.input[i].witness = w;
    }
    debug_assert!(status.ready);
    verify_final_tx(policy, spec, &tx)?;

    // Second, independent check: miniscript's interpreter over the finalized PSBT.
    let mut fin = psbt.clone();
    for (i, inp) in fin.inputs.iter_mut().enumerate() {
        inp.final_script_witness = Some(tx.input[i].witness.clone());
        inp.partial_sigs.clear();
        inp.bip32_derivation.clear();
        inp.witness_script = None;
        inp.sighash_type = None;
    }
    let secp = Secp256k1::verification_only();
    miniscript::psbt::interpreter_check(&fin, &secp).map_err(|e| ValidationError::FinalCheck(e.to_string()))?;
    Ok(tx)
}

/// Verify a fully signed transaction against the proposal: same unsigned tx, and every
/// input carries exactly `threshold` valid owner signatures in CHECKMULTISIG key order.
pub fn verify_final_tx(policy: &WalletPolicy, spec: &ProposalSpec, tx: &Transaction) -> Result<()> {
    let mut stripped = tx.clone();
    for i in &mut stripped.input {
        i.witness = Witness::new();
    }
    if serialize(&stripped) != serialize(&spec.unsigned_tx) {
        return Err(ValidationError::UnsignedTxMismatch);
    }
    let secp = Secp256k1::verification_only();
    let derived = derive_inputs(policy, spec)?;
    let m = policy.threshold();
    for (i, (rec, d)) in spec.inputs.iter().zip(&derived).enumerate() {
        let items: Vec<&[u8]> = tx.input[i].witness.iter().collect();
        let fail = |why: &str| ValidationError::FinalCheck(format!("input {i}: {why}"));
        if items.len() != m + 2 {
            return Err(fail("wrong witness item count"));
        }
        if !items[0].is_empty() {
            return Err(fail("CHECKMULTISIG dummy element must be empty"));
        }
        if items[m + 1] != d.witness_script.as_bytes() {
            return Err(fail("witness script mismatch"));
        }
        let msg = sighash_msg(&spec.unsigned_tx, i, &d.witness_script, rec.amount)?;
        let mut keys: Vec<PublicKey> = d.owner_keys.iter().map(|(_, k, _)| *k).collect();
        keys.sort_by_key(|k| k.to_bytes());
        let mut ki = 0;
        for raw in &items[1..=m] {
            let sig = ecdsa::Signature::from_slice(raw).map_err(|_| fail("undecodable signature"))?;
            loop {
                if ki == keys.len() {
                    return Err(fail("signatures don't verify in key order"));
                }
                let ok = verify_sig(&secp, &msg, &keys[ki], &sig);
                ki += 1;
                if ok {
                    break;
                }
            }
        }
    }
    Ok(())
}
