//! Property tests for core validation.

mod common;

use btc_safe_core::bitcoin::consensus::encode::{deserialize, serialize};
use btc_safe_core::bitcoin::{ecdsa, Amount, FeeRate, Network, Transaction, Weight};
use btc_safe_core::fees::{self, FeePolicy};
use btc_safe_core::import;
use btc_safe_core::validate::{self, ChangeSpec, ValidationError as E};
use btc_safe_core::Keychain;
use btc_safe_testkit::TestOwner;
use common::*;
use proptest::prelude::*;

fn owners_from(seed: u8, n: usize) -> Vec<TestOwner> {
    (0..n).map(|i| TestOwner::new(&format!("o{i}"), seed.wrapping_mul(7).wrapping_add(i as u8 * 31), Network::Signet)).collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, .. ProptestConfig::default() })]

    /// Descriptor export → import is the identity, for any M-of-N, at any index.
    #[test]
    fn descriptor_roundtrip(seed in any::<u8>(), n in 2usize..=5, m_raw in 1usize..=5, idx in 0u32..10_000) {
        let m = m_raw.min(n);
        let owners = owners_from(seed, n);
        let p = policy_m_of(m, &owners);
        let imp = import::import_any(&p.multipath_descriptor_string().unwrap(), Network::Signet).unwrap();
        prop_assert_eq!(imp.policy.address(Keychain::External, idx).unwrap(), p.address(Keychain::External, idx).unwrap());
        prop_assert_eq!(imp.policy.address(Keychain::Internal, idx).unwrap(), p.address(Keychain::Internal, idx).unwrap());
        let bsms = import::import_any(&import::export_bsms(&p).unwrap(), Network::Signet).unwrap();
        prop_assert_eq!(bsms.policy.descriptor_string(Keychain::Internal).unwrap(), p.descriptor_string(Keychain::Internal).unwrap());
    }

    /// Any change to the unsigned tx bytes is rejected, even when owners signed the changed tx.
    #[test]
    fn any_unsigned_tx_mutation_rejected(pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let f = fixture();
        let stored = f.psbt();
        let mut bytes = serialize(&f.spec.unsigned_tx);
        let i = pos.index(bytes.len());
        bytes[i] ^= 1 << bit;
        let Ok(mutated) = deserialize::<Transaction>(&bytes) else { return Ok(()) };
        if mutated.input.len() != 2 || mutated.output.len() != 2 || serialize(&mutated) == serialize(&f.spec.unsigned_tx) {
            return Ok(());
        }
        let mut sub = f.psbt();
        sub.unsigned_tx = mutated;
        f.owners[0].sign(&mut sub);
        f.owners[1].sign(&mut sub);
        prop_assert_eq!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub).unwrap_err(), E::UnsignedTxMismatch);
    }

    /// Readiness is exactly "at least M distinct owners signed every input", for any M-of-N
    /// and any order of submissions; finalize succeeds iff ready.
    #[test]
    fn readiness_matches_threshold(seed in any::<u8>(), n in 2usize..=4, m_raw in 1usize..=4, mask in any::<u8>(), order_rev in any::<bool>()) {
        let m = m_raw.min(n);
        let owners = owners_from(seed, n);
        let f = fixture_for(policy_m_of(m, &owners), owners);
        let mut stored = f.psbt();
        let mut who: Vec<usize> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
        if order_rev { who.reverse(); }
        for &w in &who {
            let mut p = f.psbt();
            f.owners[w].sign(&mut p);
            let sub = validate::validate_submission(&f.policy, &f.spec, &stored, &p).unwrap();
            validate::apply_signatures(&mut stored, &sub);
        }
        let st = validate::signature_status(&f.policy, &f.spec, &stored).unwrap();
        prop_assert_eq!(st.confirmations, who.len());
        prop_assert_eq!(st.ready, who.len() >= m);
        match validate::finalize(&f.policy, &f.spec, &stored) {
            Ok(tx) => {
                prop_assert!(who.len() >= m);
                validate::verify_final_tx(&f.policy, &f.spec, &tx).unwrap();
            }
            Err(e) => {
                prop_assert!(who.len() < m);
                let is_not_enough = matches!(e, E::NotEnoughSignatures { .. });
                prop_assert!(is_not_enough);
            }
        }
    }

    /// A signature with any single bit flipped is never accepted.
    #[test]
    fn corrupted_signature_never_accepted(pos in any::<prop::sample::Index>(), bit in 0u8..8, input in 0usize..2) {
        let f = fixture();
        let stored = f.psbt();
        let mut sub = f.psbt();
        f.owners[1].sign(&mut sub);
        let (pk, sig) = sub.inputs[input].partial_sigs.iter().next().map(|(k, s)| (*k, *s)).unwrap();
        let mut raw = sig.to_vec();
        let i = pos.index(raw.len());
        raw[i] ^= 1 << bit;
        let Ok(bad) = ecdsa::Signature::from_slice(&raw) else { return Ok(()) };
        if bad == sig { return Ok(()); }
        sub.inputs[input].partial_sigs.insert(pk, bad);
        prop_assert!(validate::validate_submission(&f.policy, &f.spec, &stored, &sub).is_err());
    }

    /// A change claim is accepted iff the output really derives from m/1/index.
    #[test]
    fn change_claims(vout in 0u32..3, index in 0u32..4) {
        let mut f = fixture();
        f.spec.change = vec![ChangeSpec { vout, index }];
        let truth = vout == 1 && index == 0;
        prop_assert_eq!(validate::check_spec(&f.policy, &f.spec).is_ok(), truth);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, .. ProptestConfig::default() })]

    /// check_fee errs exactly when a hard cap is exceeded and no override was given.
    #[test]
    fn fee_cap_exact(fee in 0u64..3_000_000, wu in 400u64..400_000, sent in 0u64..100_000_000, fast_kwu in prop::option::of(250u64..100_000), ovr in any::<bool>()) {
        let pol = FeePolicy::default();
        let fast = fast_kwu.map(FeeRate::from_sat_per_kwu);
        let r = fees::check_fee(Amount::from_sat(fee), Weight::from_wu(wu), Amount::from_sat(sent), &pol, fast, ovr);
        let rate_kwu = fee * 1000 / wu;
        let over = fee > pol.max_fee.to_sat() || fast_kwu.is_some_and(|f| rate_kwu > f * 10);
        prop_assert_eq!(r.is_err(), over && !ovr);
    }
}
