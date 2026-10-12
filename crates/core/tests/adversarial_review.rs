//! Adversarial review (2026-10-07). Attacks on `core::validate` beyond validate.rs.
//! Every test here asserts the attack is REJECTED (or that nothing attacker-supplied is
//! stored); a failure would mean the attack worked.

mod common;


use btc_safe_core::bitcoin::bip32::{DerivationPath, Fingerprint};
use btc_safe_core::bitcoin::psbt::raw::ProprietaryKey;
use btc_safe_core::bitcoin::secp256k1::{Message, Secp256k1};
use btc_safe_core::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use btc_safe_core::bitcoin::{ecdsa, Amount, PublicKey, ScriptBuf, Witness};
use btc_safe_core::validate::{self, ValidationError as E};
use btc_safe_testkit::sign_p2wsh;
use common::*;


#[test]
fn uncompressed_form_of_owner_key_rejected() {
    // Same secret, same curve point, but keyed under the 65-byte uncompressed encoding.
    let f = fixture();
    let stored = f.psbt();
    let mut sub = f.psbt();
    let sk = f.owners[0].input_secret(&f.psbt(), 0).unwrap();
    let ws = sub.inputs[0].witness_script.clone().unwrap();
    let (pk, sig) = sign_p2wsh(&sk, &sub.unsigned_tx, 0, &ws, Amount::from_sat(100_000), EcdsaSighashType::All);
    let unc = PublicKey { compressed: false, inner: pk.inner };
    sub.inputs[0].partial_sigs.insert(unc, sig);
    assert!(matches!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub), Err(E::UnknownSigner { input: 0, .. })));
}

#[test]
fn valid_owner_sig_for_a_different_tx_over_same_coins_rejected() {
    // Alice signed a sibling proposal (same inputs, 100 sats moved recipient -> change).
    // Her signatures are perfectly valid for that tx; replaying them here must fail.
    let f = fixture();
    let stored = f.psbt();
    let mut other = fixture();
    other.spec.unsigned_tx.output[0].value = Amount::from_sat(119_900);
    other.spec.unsigned_tx.output[1].value = Amount::from_sat(29_100);
    let mut op = other.psbt();
    assert_eq!(other.owners[0].sign(&mut op), 2);
    let mut sub = f.psbt();
    for i in 0..2 {
        sub.inputs[i].partial_sigs = op.inputs[i].partial_sigs.clone();
    }
    assert!(matches!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub), Err(E::BadSignature { input: 0, .. })));
}

#[test]
fn legacy_sighash_signature_rejected() {
    // Owner key, SIGHASH_ALL byte, but signed over the pre-segwit (legacy) sighash.
    let f = fixture();
    let stored = f.psbt();
    let mut sub = f.psbt();
    let sk = f.owners[0].input_secret(&f.psbt(), 0).unwrap();
    let ws = sub.inputs[0].witness_script.clone().unwrap();
    let h = SighashCache::new(&sub.unsigned_tx).legacy_signature_hash(0, &ws, EcdsaSighashType::All.to_u32()).unwrap();
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa(&Message::from(h), &sk);
    let pk = PublicKey::new(sk.public_key(&secp));
    sub.inputs[0].partial_sigs.insert(pk, ecdsa::Signature { signature: sig, sighash_type: EcdsaSighashType::All });
    assert!(matches!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub), Err(E::BadSignature { input: 0, .. })));
}

#[test]
fn stranger_sig_in_final_witness_rejected() {
    // Witness shape is right ([<> sigA sigM ws]) but sigM is from a non-owner.
    let f = fixture();
    let stored = f.psbt();
    let ws = stored.inputs[0].witness_script.clone().unwrap();
    let (_, sa) = sign_p2wsh(&f.owners[0].input_secret(&f.psbt(), 0).unwrap(), &stored.unsigned_tx, 0, &ws, Amount::from_sat(100_000), EcdsaSighashType::All);
    let m = btc_safe_testkit::stranger();
    let skm = m.secret_for(&(m.fingerprint, "m/48'/1'/0'/2'/0/0".parse().unwrap())).unwrap();
    let (_, sm) = sign_p2wsh(&skm, &stored.unsigned_tx, 0, &ws, Amount::from_sat(100_000), EcdsaSighashType::All);
    let mut sub = f.psbt();
    sub.inputs[0].final_script_witness = Some(Witness::from_slice(&[vec![], sa.to_vec(), sm.to_vec(), ws.to_bytes()]));
    assert_eq!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub).unwrap_err(), E::MalformedFinalWitness(0));
}

#[test]
fn nothing_but_verified_sigs_is_stored() {
    // Load every non-signature PSBT field we can with attacker data, plus one real
    // signature in partial_sigs and another in a final witness. After apply_signatures the
    // stored PSBT must equal canonical + exactly those verified signatures.
    let f = fixture();
    let canonical = f.psbt();
    let mut stored = canonical.clone();
    let mut sub = f.psbt();
    f.owners[0].sign(&mut sub); // partial sigs for Alice on both inputs
    // Bob's input-1 sig only inside a final witness.
    let ws1 = sub.inputs[1].witness_script.clone().unwrap();
    let bob = &f.owners[1];
    let ksb = canonical.inputs[1].bip32_derivation.values().find(|k| k.0 == bob.fingerprint).unwrap().clone();
    let (_, sb) = sign_p2wsh(&bob.secret_for(&ksb).unwrap(), &sub.unsigned_tx, 1, &ws1, Amount::from_sat(50_000), EcdsaSighashType::All);
    sub.inputs[1].final_script_witness = Some(Witness::from_slice(&[vec![], sb.to_vec(), ws1.to_bytes()]));
    // Junk everywhere else.
    let evil_xpub = btc_safe_testkit::stranger().xpub;
    sub.xpub.insert(evil_xpub, (Fingerprint::from([1, 2, 3, 4]), DerivationPath::master()));
    sub.proprietary.insert(ProprietaryKey { prefix: b"evil".to_vec(), subtype: 1, key: vec![1] }, vec![0xde, 0xad]);
    sub.inputs[0].redeem_script = Some(ScriptBuf::from_bytes(vec![0x51]));
    sub.inputs[0].bip32_derivation.clear();
    sub.inputs[0].bip32_derivation.insert(evil_xpub.public_key, (Fingerprint::from([9, 9, 9, 9]), DerivationPath::master()));
    sub.inputs[0].sha256_preimages.insert(btc_safe_core::bitcoin::hashes::Hash::hash(b"x"), b"x".to_vec());
    sub.outputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x51])); // "make the recipient look like change"
    sub.outputs[0].bip32_derivation = canonical.outputs[1].bip32_derivation.clone();
    sub.outputs[1].bip32_derivation.clear();
    sub.outputs[1].proprietary.insert(ProprietaryKey { prefix: b"evil".to_vec(), subtype: 2, key: vec![] }, vec![1]);

    let s = validate::validate_submission(&f.policy, &f.spec, &stored, &sub).unwrap();
    assert_eq!(s.new_sigs.len(), 3);
    validate::apply_signatures(&mut stored, &s);
    let mut expected = canonical.clone();
    for v in &s.new_sigs {
        expected.inputs[v.input].partial_sigs.insert(v.pubkey, v.sig);
    }
    assert_eq!(stored, expected);
    // Global xpubs are exactly the wallet's cosigners (we add them); the smuggled one isn't there.
    assert!(!stored.xpub.contains_key(&evil_xpub));
    assert_eq!(stored.xpub.len(), 3);
    assert!(f.owners.iter().all(|o| stored.xpub.get(&o.xpub) == Some(&(o.fingerprint, o.path.clone()))));
    assert!(stored.proprietary.is_empty());
    assert!(stored.inputs.iter().all(|i| i.final_script_witness.is_none() && i.redeem_script.is_none()));
    assert_eq!(stored.outputs, canonical.outputs);
    // And the final tx is exactly the stored unsigned tx plus witnesses (Carol completes input 0).
    let mut carol = f.psbt();
    f.owners[2].sign(&mut carol);
    let s = validate::validate_submission(&f.policy, &f.spec, &stored, &carol).unwrap();
    validate::apply_signatures(&mut stored, &s);
    let tx = validate::finalize(&f.policy, &f.spec, &stored).unwrap();
    let mut stripped = tx.clone();
    stripped.input.iter_mut().for_each(|i| i.witness = Witness::new());
    assert_eq!(stripped, f.spec.unsigned_tx);
}

#[test]
fn one_owner_cannot_count_twice() {
    // Same owner, two distinct valid signatures (fresh nonces) on one input: one in
    // partial_sigs, one in the final witness. Must not reach threshold 2.
    let f = fixture();
    let mut stored = f.psbt();
    let ws = stored.inputs[0].witness_script.clone().unwrap();
    let sk = f.owners[0].input_secret(&f.psbt(), 0).unwrap();
    let (pk, s1) = sign_p2wsh(&sk, &stored.unsigned_tx, 0, &ws, Amount::from_sat(100_000), EcdsaSighashType::All);
    // A second, different valid signature by the same key (low-R grinding gives a new nonce).
    let secp = Secp256k1::new();
    let h = SighashCache::new(&stored.unsigned_tx).p2wsh_signature_hash(0, &ws, Amount::from_sat(100_000), EcdsaSighashType::All).unwrap();
    let s2 = ecdsa::Signature { signature: secp.sign_ecdsa_with_noncedata(&Message::from(h), &sk, &[7u8; 32]), sighash_type: EcdsaSighashType::All };
    assert_ne!(s1, s2);
    let mut sub = f.psbt();
    sub.inputs[0].partial_sigs.insert(pk, s1);
    sub.inputs[0].final_script_witness = Some(Witness::from_slice(&[vec![], s2.to_vec(), s2.to_vec(), ws.to_bytes()]));
    let s = validate::validate_submission(&f.policy, &f.spec, &stored, &sub).unwrap();
    assert_eq!(s.new_sigs.len(), 1);
    validate::apply_signatures(&mut stored, &s);
    let st = validate::signature_status(&f.policy, &f.spec, &stored).unwrap();
    assert!(!st.ready);
    assert!(validate::finalize(&f.policy, &f.spec, &stored).is_err());
    // verify_final_tx: the same signature twice can't satisfy 2-of-3 either.
    let mut tx = f.spec.unsigned_tx.clone();
    tx.input[0].witness = Witness::from_slice(&[vec![], s1.to_vec(), s1.to_vec(), ws.to_bytes()]);
    assert!(validate::verify_final_tx(&f.policy, &f.spec, &tx).is_err());
}
