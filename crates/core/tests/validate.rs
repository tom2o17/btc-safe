//! Adversarial tests for `core::validate`. Each test tries to get a bad PSBT accepted.

mod common;

use btc_safe_core::bitcoin::absolute::LockTime;
use btc_safe_core::bitcoin::psbt::PsbtSighashType;
use btc_safe_core::bitcoin::sighash::EcdsaSighashType;
use btc_safe_core::bitcoin::{Amount, Psbt, ScriptBuf, Sequence, TxOut, Witness};
use btc_safe_core::fees::{self, FeeError, FeePolicy, FeeWarning};
use btc_safe_core::validate::{self, ChangeSpec, ValidationError as E};
use btc_safe_core::Keychain;
use btc_safe_testkit::{sign_p2wsh, stranger};
use common::*;

fn signed_by(f: &Fixture, who: &[usize]) -> Psbt {
    let mut p = f.psbt();
    for &i in who {
        assert_eq!(f.owners[i].sign(&mut p), 2, "owner {i} signs both inputs");
    }
    p
}

#[test]
fn happy_path_two_of_three() {
    let f = fixture();
    let mut stored = f.psbt();
    let s0 = validate::signature_status(&f.policy, &f.spec, &stored).unwrap();
    assert_eq!((s0.confirmations, s0.ready), (0, false));

    // Alice signs offline and submits.
    let sub = validate::validate_submission(&f.policy, &f.spec, &stored, &signed_by(&f, &[0])).unwrap();
    assert_eq!(sub.new_sigs.len(), 2);
    validate::apply_signatures(&mut stored, &sub);
    let s1 = validate::signature_status(&f.policy, &f.spec, &stored).unwrap();
    assert_eq!((s1.confirmations, s1.ready), (1, false));
    assert!(matches!(validate::finalize(&f.policy, &f.spec, &stored), Err(E::NotEnoughSignatures { .. })));

    // Resubmitting the same signatures is idempotent.
    let again = validate::validate_submission(&f.policy, &f.spec, &stored, &signed_by(&f, &[0])).unwrap();
    assert_eq!((again.new_sigs.len(), again.already_present), (0, 2));

    // Carol signs on a fresh copy of the unsigned PSBT (independent device).
    let sub = validate::validate_submission(&f.policy, &f.spec, &stored, &signed_by(&f, &[2])).unwrap();
    validate::apply_signatures(&mut stored, &sub);
    let s2 = validate::signature_status(&f.policy, &f.spec, &stored).unwrap();
    assert_eq!((s2.confirmations, s2.ready), (2, true));

    let tx = validate::finalize(&f.policy, &f.spec, &stored).unwrap();
    assert_eq!(tx.compute_txid(), f.spec.unsigned_tx.compute_txid());
    validate::verify_final_tx(&f.policy, &f.spec, &tx).unwrap();
    // Size estimate is an upper bound and within a few vbytes.
    let est = fees::estimate_vsize(&f.policy, &f.spec.unsigned_tx);
    let actual = tx.vsize() as u64;
    assert!(est >= actual && est - actual <= 4, "est {est} actual {actual}");
}

#[test]
fn all_three_sign_finalize_uses_two() {
    let f = fixture();
    let mut stored = f.psbt();
    let sub = validate::validate_submission(&f.policy, &f.spec, &stored, &signed_by(&f, &[0, 1, 2])).unwrap();
    assert_eq!(sub.new_sigs.len(), 6);
    validate::apply_signatures(&mut stored, &sub);
    let tx = validate::finalize(&f.policy, &f.spec, &stored).unwrap();
    assert_eq!(tx.input[0].witness.len(), 4);
}

#[test]
fn summary_and_change() {
    let f = fixture();
    let s = validate::check_spec(&f.policy, &f.spec).unwrap();
    assert_eq!(s.fee, Amount::from_sat(1000));
    assert_eq!(s.sent, Amount::from_sat(120_000));
    assert_eq!(s.outputs[1].change_index, Some(0));
    assert_eq!(s.outputs[0].change_index, None);
    assert!(s.rbf);
    // Change output carries derivation info so hardware wallets can verify it.
    let p = f.psbt();
    assert_eq!(p.outputs[1].bip32_derivation.len(), 3);
    assert_eq!(p.xpub.len(), 3);
    assert!(f.owners.iter().all(|o| p.xpub.get(&o.xpub) == Some(&(o.fingerprint, o.path.clone()))));
    assert!(p.outputs[0].bip32_derivation.is_empty());
}

#[test]
fn swapped_change_output_rejected() {
    // Attacker-controlled output claimed as change.
    let mut f = fixture();
    f.spec.change = vec![ChangeSpec { vout: 0, index: 0 }];
    assert_eq!(validate::check_spec(&f.policy, &f.spec).unwrap_err(), E::ChangeScriptMismatch { vout: 0, index: 0 });
    // Right output, wrong claimed index.
    let mut f = fixture();
    f.spec.change = vec![ChangeSpec { vout: 1, index: 1 }];
    assert!(matches!(validate::check_spec(&f.policy, &f.spec), Err(E::ChangeScriptMismatch { .. })));
    // A receive-keychain script is not change.
    let mut f = fixture();
    f.spec.unsigned_tx.output[1].script_pubkey = f.policy.derive(Keychain::External, 0).unwrap().script_pubkey;
    assert!(matches!(validate::check_spec(&f.policy, &f.spec), Err(E::ChangeScriptMismatch { .. })));
}

#[test]
fn submitted_tx_must_be_byte_equal() {
    let f = fixture();
    let stored = f.psbt();
    type Mutation = Box<dyn Fn(&mut Psbt)>;
    let mutations: Vec<(&str, Mutation)> = vec![
        ("swap recipient", Box::new(|p: &mut Psbt| p.unsigned_tx.output[0].script_pubkey = ScriptBuf::new_op_return([1u8; 4]))),
        ("swap change and recipient amounts", Box::new(|p: &mut Psbt| {
            let a = p.unsigned_tx.output[0].value;
            p.unsigned_tx.output[0].value = p.unsigned_tx.output[1].value;
            p.unsigned_tx.output[1].value = a;
        })),
        ("nSequence", Box::new(|p: &mut Psbt| p.unsigned_tx.input[0].sequence = Sequence::MAX)),
        ("nSequence one off", Box::new(|p: &mut Psbt| p.unsigned_tx.input[1].sequence = Sequence(0xffff_fffc))),
        ("locktime", Box::new(|p: &mut Psbt| p.unsigned_tx.lock_time = LockTime::from_height(200_001).unwrap())),
        ("locktime zero", Box::new(|p: &mut Psbt| p.unsigned_tx.lock_time = LockTime::ZERO)),
        ("version", Box::new(|p: &mut Psbt| p.unsigned_tx.version = btc_safe_core::bitcoin::transaction::Version::ONE)),
        ("input order", Box::new(|p: &mut Psbt| p.unsigned_tx.input.swap(0, 1))),
        ("extra output", Box::new(|p: &mut Psbt| {
            p.unsigned_tx.output.push(TxOut { value: Amount::from_sat(500), script_pubkey: recipient() });
            p.outputs.push(Default::default());
        })),
    ];
    for (name, m) in mutations {
        let mut sub = f.psbt();
        m(&mut sub);
        // Owners sign the mutated tx (they were tricked); signatures are valid for *that* tx.
        f.owners[0].sign(&mut sub);
        f.owners[1].sign(&mut sub);
        assert_eq!(
            validate::validate_submission(&f.policy, &f.spec, &stored, &sub).unwrap_err(),
            E::UnsignedTxMismatch,
            "{name}"
        );
    }
}

#[test]
fn signature_from_unknown_key_rejected() {
    let f = fixture();
    let stored = f.psbt();
    let mut sub = f.psbt();
    let m = stranger();
    let sk = m.secret_for(&(m.fingerprint, "m/48'/1'/0'/2'/0/0".parse().unwrap())).unwrap();
    let ws = sub.inputs[0].witness_script.clone().unwrap();
    let (pk, sig) = sign_p2wsh(&sk, &sub.unsigned_tx, 0, &ws, Amount::from_sat(100_000), EcdsaSighashType::All);
    sub.inputs[0].partial_sigs.insert(pk, sig);
    assert!(matches!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub), Err(E::UnknownSigner { input: 0, .. })));

    // A valid owner signature alongside the stranger's doesn't smuggle it in.
    f.owners[0].sign(&mut sub);
    assert!(matches!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub), Err(E::UnknownSigner { .. })));
}

#[test]
fn owner_key_from_other_derivation_rejected() {
    // Alice's key, but derived at an index that isn't this input's.
    let f = fixture();
    let stored = f.psbt();
    let mut sub = f.psbt();
    let a = &f.owners[0];
    let sk = a.secret_for(&(a.fingerprint, "m/48'/1'/0'/2'/0/9".parse().unwrap())).unwrap();
    let ws = sub.inputs[0].witness_script.clone().unwrap();
    let (pk, sig) = sign_p2wsh(&sk, &sub.unsigned_tx, 0, &ws, Amount::from_sat(100_000), EcdsaSighashType::All);
    sub.inputs[0].partial_sigs.insert(pk, sig);
    assert!(matches!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub), Err(E::UnknownSigner { .. })));
}

#[test]
fn wrong_sighash_types_rejected() {
    let f = fixture();
    let stored = f.psbt();
    let a = &f.owners[0];
    let ks = stored.inputs[0].bip32_derivation.values().find(|k| k.0 == a.fingerprint).unwrap().clone();
    let sk = a.secret_for(&ks).unwrap();
    let ws = stored.inputs[0].witness_script.clone().unwrap();
    for ty in [
        EcdsaSighashType::None,
        EcdsaSighashType::Single,
        EcdsaSighashType::AllPlusAnyoneCanPay,
        EcdsaSighashType::NonePlusAnyoneCanPay,
        EcdsaSighashType::SinglePlusAnyoneCanPay,
    ] {
        let mut sub = f.psbt();
        let (pk, sig) = sign_p2wsh(&sk, &sub.unsigned_tx, 0, &ws, Amount::from_sat(100_000), ty);
        sub.inputs[0].partial_sigs.insert(pk, sig);
        assert!(matches!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub), Err(E::BadSignature { .. })), "{ty:?}");
    }
    // PSBT input asking for a non-ALL sighash.
    let mut sub = signed_by(&f, &[0]);
    sub.inputs[1].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::Single));
    assert_eq!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub).unwrap_err(), E::BadSighashType(1));
}

#[test]
fn fee_lie_rejected() {
    // Signer's PSBT claims a different input amount (segwit v0 fee attack).
    let f = fixture();
    let stored = f.psbt();
    let mut sub = f.psbt();
    sub.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(90_000);
    f.owners[0].sign(&mut sub);
    assert_eq!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub).unwrap_err(), E::WitnessUtxoMismatch(0));

    // Same lie, but the attacker strips witness_utxo afterwards: the signature itself
    // committed to the wrong amount and fails against our sighash.
    sub.inputs[0].witness_utxo = None;
    assert!(matches!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub), Err(E::BadSignature { input: 0, .. })));

    // Lying non_witness_utxo.
    let mut sub = signed_by(&f, &[0]);
    let mut prev = sub.inputs[1].non_witness_utxo.clone().unwrap();
    prev.output[1].value = Amount::from_sat(1);
    sub.inputs[1].non_witness_utxo = Some(prev);
    assert_eq!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub).unwrap_err(), E::NonWitnessUtxoMismatch(1));
}

#[test]
fn signature_moved_between_inputs_rejected() {
    let f = fixture();
    let stored = f.psbt();
    let mut sub = signed_by(&f, &[0]);
    // Take Alice's input-0 signature and put it on input 1 under her input-1 key.
    let (_, sig0) = sub.inputs[0].partial_sigs.iter().next().map(|(k, s)| (*k, *s)).unwrap();
    let pk1 = *sub.inputs[1].partial_sigs.keys().next().unwrap();
    sub.inputs[1].partial_sigs.insert(pk1, sig0);
    assert!(matches!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub), Err(E::BadSignature { input: 1, .. })));
}

#[test]
fn witness_script_swap_rejected() {
    let f = fixture();
    let stored = f.psbt();
    let mut sub = signed_by(&f, &[0]);
    sub.inputs[0].witness_script = Some(f.policy.derive(Keychain::External, 1).unwrap().witness_script);
    assert_eq!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub).unwrap_err(), E::WitnessScriptMismatch(0));
}

#[test]
fn high_s_and_corrupt_signatures_rejected() {
    use btc_safe_core::bitcoin::secp256k1::ecdsa::Signature;
    let f = fixture();
    let stored = f.psbt();
    let mut sub = signed_by(&f, &[0]);
    let (pk, sig) = sub.inputs[0].partial_sigs.iter().next().map(|(k, s)| (*k, *s)).unwrap();
    // Flip to high-S: s' = n - s. Same signature mathematically, non-standard on the network.
    let compact = sig.signature.serialize_compact();
    let n = hex_to_bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let mut s = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let v = n[i] as i16 - compact[32 + i] as i16 - borrow;
        s[i] = (v.rem_euclid(256)) as u8;
        borrow = if v < 0 { 1 } else { 0 };
    }
    let mut hi = compact;
    hi[32..].copy_from_slice(&s);
    let high = Signature::from_compact(&hi).unwrap();
    // Prove the construction: normalizing it gives back the original low-S signature.
    let mut norm = high;
    norm.normalize_s();
    assert_eq!(norm, sig.signature);
    assert_ne!(high, sig.signature);
    let mut bad = sig;
    bad.signature = high;
    sub.inputs[0].partial_sigs.insert(pk, bad);
    assert!(matches!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub), Err(E::BadSignature { .. })));
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn empty_submission_rejected() {
    let f = fixture();
    let stored = f.psbt();
    assert_eq!(validate::validate_submission(&f.policy, &f.spec, &stored, &f.psbt()).unwrap_err(), E::NoSignatures);
}

#[test]
fn final_witness_submission() {
    // Some signers finalize when they think they're done. We accept the signatures inside,
    // after checking the witness shape and each signature.
    let f = fixture();
    let mut stored = f.psbt();
    let full = signed_by(&f, &[0, 1]);
    let mut tmp = stored.clone();
    validate::apply_signatures(&mut tmp, &validate::validate_submission(&f.policy, &f.spec, &stored, &full).unwrap());
    let tx = validate::finalize(&f.policy, &f.spec, &tmp).unwrap();
    let mut finalized = f.psbt();
    for i in 0..2 {
        finalized.inputs[i].final_script_witness = Some(tx.input[i].witness.clone());
    }
    let sub = validate::validate_submission(&f.policy, &f.spec, &stored, &finalized).unwrap();
    assert_eq!(sub.new_sigs.len(), 4);
    validate::apply_signatures(&mut stored, &sub);
    assert!(validate::signature_status(&f.policy, &f.spec, &stored).unwrap().ready);

    // Final witness with the wrong script.
    let mut bad = f.psbt();
    let mut w: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|x| x.to_vec()).collect();
    *w.last_mut().unwrap() = f.policy.derive(Keychain::External, 1).unwrap().witness_script.to_bytes();
    bad.inputs[0].final_script_witness = Some(Witness::from_slice(&w));
    assert_eq!(validate::validate_submission(&f.policy, &f.spec, &f.psbt(), &bad).unwrap_err(), E::MalformedFinalWitness(0));
    // Final witness with a garbage signature.
    let mut bad = f.psbt();
    let mut w: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|x| x.to_vec()).collect();
    w[1][10] ^= 1;
    bad.inputs[0].final_script_witness = Some(Witness::from_slice(&w));
    assert!(validate::validate_submission(&f.policy, &f.spec, &f.psbt(), &bad).is_err());
    // Oversized witness (DoS shape) is refused before any signature work.
    let mut bad = f.psbt();
    let mut w: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|x| x.to_vec()).collect();
    let sig = w[1].clone();
    for _ in 0..5000 {
        w.insert(1, sig.clone());
    }
    bad.inputs[0].final_script_witness = Some(Witness::from_slice(&w));
    let t = std::time::Instant::now();
    assert_eq!(validate::validate_submission(&f.policy, &f.spec, &f.psbt(), &bad).unwrap_err(), E::MalformedFinalWitness(0));
    assert!(t.elapsed() < std::time::Duration::from_millis(200), "{:?}", t.elapsed());
    // final_script_sig is never valid for P2WSH.
    let mut bad = signed_by(&f, &[0]);
    bad.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x00]));
    assert_eq!(validate::validate_submission(&f.policy, &f.spec, &f.psbt(), &bad).unwrap_err(), E::FinalScriptSig(0));
}

#[test]
fn tampered_stored_psbt_detected() {
    // Defense in depth: if the DB copy were tampered with, status/finalize notice.
    let f = fixture();
    let mut stored = signed_by(&f, &[0, 1]);
    let m = stranger();
    let sk = m.secret_for(&(m.fingerprint, "m/48'/1'/0'/2'/0/0".parse().unwrap())).unwrap();
    let ws = stored.inputs[0].witness_script.clone().unwrap();
    let (pk, sig) = sign_p2wsh(&sk, &stored.unsigned_tx, 0, &ws, Amount::from_sat(100_000), EcdsaSighashType::All);
    stored.inputs[0].partial_sigs.insert(pk, sig);
    assert!(matches!(validate::signature_status(&f.policy, &f.spec, &stored), Err(E::UnknownSigner { .. })));
    assert!(validate::finalize(&f.policy, &f.spec, &stored).is_err());

    let mut stored = signed_by(&f, &[0, 1]);
    stored.unsigned_tx.output[0].value = Amount::from_sat(1);
    assert!(validate::finalize(&f.policy, &f.spec, &stored).is_err());
}

#[test]
fn verify_final_tx_rejects_bad_witnesses() {
    let f = fixture();
    let mut stored = f.psbt();
    let sub = validate::validate_submission(&f.policy, &f.spec, &stored, &signed_by(&f, &[0, 2])).unwrap();
    validate::apply_signatures(&mut stored, &sub);
    let tx = validate::finalize(&f.policy, &f.spec, &stored).unwrap();

    let mut swapped = tx.clone();
    let mut w: Vec<Vec<u8>> = swapped.input[0].witness.iter().map(|x| x.to_vec()).collect();
    w.swap(1, 2);
    swapped.input[0].witness = Witness::from_slice(&w);
    assert!(validate::verify_final_tx(&f.policy, &f.spec, &swapped).is_err(), "sig order matters for CHECKMULTISIG");

    let mut dummy = tx.clone();
    let mut w: Vec<Vec<u8>> = dummy.input[0].witness.iter().map(|x| x.to_vec()).collect();
    w[0] = vec![1];
    dummy.input[0].witness = Witness::from_slice(&w);
    assert!(validate::verify_final_tx(&f.policy, &f.spec, &dummy).is_err(), "NULLDUMMY");

    let mut dup = tx.clone();
    let mut w: Vec<Vec<u8>> = dup.input[0].witness.iter().map(|x| x.to_vec()).collect();
    w[2] = w[1].clone();
    dup.input[0].witness = Witness::from_slice(&w);
    assert!(validate::verify_final_tx(&f.policy, &f.spec, &dup).is_err(), "same sig twice");

    let mut other = tx.clone();
    other.lock_time = LockTime::ZERO;
    assert_eq!(validate::verify_final_tx(&f.policy, &f.spec, &other).unwrap_err(), E::UnsignedTxMismatch);
}

#[test]
fn spec_structural_rejections() {
    let mut f = fixture();
    f.spec.unsigned_tx.output[0].value = Amount::from_sat(200_000);
    assert_eq!(validate::check_spec(&f.policy, &f.spec).unwrap_err(), E::OutputsExceedInputs);

    let mut f = fixture();
    f.spec.unsigned_tx.output[0].value = Amount::from_sat(100);
    assert_eq!(validate::check_spec(&f.policy, &f.spec).unwrap_err(), E::DustOutput(0));

    let mut f = fixture();
    f.spec.unsigned_tx.output[0].script_pubkey = ScriptBuf::new_op_return([0u8; 8]);
    assert_eq!(validate::check_spec(&f.policy, &f.spec).unwrap_err(), E::NonStandardOutput(0));

    let mut f = fixture();
    let dup = f.spec.unsigned_tx.input[0].clone();
    f.spec.unsigned_tx.input[1] = dup;
    f.spec.inputs[1] = f.spec.inputs[0].clone();
    assert!(matches!(validate::check_spec(&f.policy, &f.spec), Err(E::DuplicateInput(_))));

    // Our record of the coin's amount is what counts; a wrong record shows up as a
    // signature failure, never as a silently different fee.
    let mut f = fixture();
    f.spec.inputs[0].amount = Amount::from_sat(100_001);
    assert!(matches!(validate::build_canonical_psbt(&f.policy, &f.spec, &f.prev), Err(E::PrevTxMismatch(0))));

    let mut f = fixture();
    f.prev.clear();
    assert!(matches!(validate::build_canonical_psbt(&f.policy, &f.spec, &f.prev), Err(E::PrevTxMissing(_))));

    let mut f = fixture();
    f.spec.unsigned_tx.version = btc_safe_core::bitcoin::transaction::Version(3);
    assert_eq!(validate::check_spec(&f.policy, &f.spec).unwrap_err(), E::BadVersion(3));
}

#[test]
fn fee_caps() {
    let f = fixture();
    let s = validate::check_spec(&f.policy, &f.spec).unwrap();
    let pol = FeePolicy::default();
    let fast = btc_safe_core::bitcoin::FeeRate::from_sat_per_vb(2).unwrap();
    // 1000 sat over ~ 300 vB ~= 3.3 sat/vB: fine.
    assert!(fees::check_fee(s.fee, s.est_weight, s.sent, &pol, Some(fast), false).unwrap().is_empty());
    // Overpay: absolute cap.
    let big = Amount::from_sat(1_500_000);
    assert!(matches!(fees::check_fee(big, s.est_weight, Amount::from_sat(50_000_000), &pol, None, false), Err(FeeError::AbsoluteCap { .. })));
    // Rate cap: 10x fast.
    let over = Amount::from_sat(s.est_vsize * 21);
    assert!(matches!(fees::check_fee(over, s.est_weight, Amount::from_sat(50_000_000), &pol, Some(fast), false), Err(FeeError::RateCap { .. })));
    // Override turns both into warnings.
    let w = fees::check_fee(big, s.est_weight, Amount::from_sat(1_000_000), &pol, Some(fast), true).unwrap();
    assert_eq!(w.iter().filter(|w| matches!(w, FeeWarning::CapOverridden { .. })).count(), 2);
    assert!(w.iter().any(|w| matches!(w, FeeWarning::HighShareOfSent { .. })));
    // Share-of-sent warning.
    let w = fees::check_fee(Amount::from_sat(6_000), s.est_weight, Amount::from_sat(100_000), &pol, None, false).unwrap();
    assert!(w.contains(&FeeWarning::NoFastEstimate));
    assert!(w.iter().any(|w| matches!(w, FeeWarning::HighShareOfSent { bps: 600, .. })));
}
