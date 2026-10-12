#![allow(clippy::disallowed_types, clippy::disallowed_methods)]
//! TEST-ONLY. Generates throwaway owner keys and signs PSBTs offline, playing the part of
//! the owners' hardware wallets. This crate must only ever appear as a dev-dependency; it is
//! the one place in the workspace allowed to hold private keys (`clippy.toml` bans the types
//! everywhere else, and this crate doesn't opt into the workspace lints).

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Fingerprint, KeySource, Xpriv, Xpub};
use bitcoin::ecdsa;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, Network, PublicKey, Script, Transaction};

pub const BIP48_TEST_PATH: &str = "m/48'/1'/0'/2'";

#[derive(Clone, Debug)]
pub struct TestOwner {
    pub name: String,
    pub master: Xpriv,
    pub fingerprint: Fingerprint,
    pub path: DerivationPath,
    pub xpub: Xpub,
}

impl TestOwner {
    /// Deterministic owner from a one-byte seed tag.
    pub fn new(name: &str, seed_tag: u8, network: Network) -> Self {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(network, &[seed_tag; 32]).expect("seed");
        let path = DerivationPath::from_str(BIP48_TEST_PATH).unwrap();
        let account = master.derive_priv(&secp, &path).unwrap();
        TestOwner {
            name: name.into(),
            fingerprint: master.fingerprint(&secp),
            xpub: Xpub::from_priv(&secp, &account),
            master,
            path,
        }
    }

    pub fn xpub_at(&self, path: &DerivationPath) -> Xpub {
        let secp = Secp256k1::new();
        Xpub::from_priv(&secp, &self.master.derive_priv(&secp, path).unwrap())
    }

    /// This owner's key for input `input` of a PSBT built by the coordinator.
    pub fn input_secret(&self, psbt: &Psbt, input: usize) -> Option<SecretKey> {
        let ks = psbt.inputs[input].bip32_derivation.values().find(|k| k.0 == self.fingerprint)?.clone();
        self.secret_for(&ks)
    }

    pub fn secret_for(&self, ks: &KeySource) -> Option<SecretKey> {
        if ks.0 != self.fingerprint {
            return None;
        }
        let secp = Secp256k1::new();
        Some(self.master.derive_priv(&secp, &ks.1).ok()?.private_key)
    }

    /// Sign every input whose bip32_derivation names this owner (what a hardware wallet does).
    /// Returns the number of signatures added.
    pub fn sign(&self, psbt: &mut Psbt) -> usize {
        let tx = psbt.unsigned_tx.clone();
        let mut n = 0;
        for i in 0..psbt.inputs.len() {
            let inp = &psbt.inputs[i];
            let (Some(ws), Some(wu)) = (inp.witness_script.clone(), inp.witness_utxo.clone()) else { continue };
            let keys: Vec<_> = inp.bip32_derivation.values().cloned().collect();
            for ks in keys {
                if let Some(sk) = self.secret_for(&ks) {
                    let (pk, sig) = sign_p2wsh(&sk, &tx, i, &ws, wu.value, EcdsaSighashType::All);
                    psbt.inputs[i].partial_sigs.insert(pk, sig);
                    n += 1;
                }
            }
        }
        n
    }
}

/// Raw P2WSH signing primitive, for building adversarial cases.
pub fn sign_p2wsh(
    sk: &SecretKey,
    tx: &Transaction,
    input: usize,
    witness_script: &Script,
    amount: Amount,
    ty: EcdsaSighashType,
) -> (PublicKey, ecdsa::Signature) {
    let secp = Secp256k1::new();
    let h = SighashCache::new(tx).p2wsh_signature_hash(input, witness_script, amount, ty).unwrap();
    let sig = secp.sign_ecdsa(&Message::from(h), sk);
    (PublicKey::new(sk.public_key(&secp)), ecdsa::Signature { signature: sig, sighash_type: ty })
}

/// Three deterministic signet owners.
pub fn three_owners() -> Vec<TestOwner> {
    vec![
        TestOwner::new("Alice", 1, Network::Signet),
        TestOwner::new("Bob", 2, Network::Signet),
        TestOwner::new("Carol", 3, Network::Signet),
    ]
}

/// A key that is not an owner.
pub fn stranger() -> TestOwner {
    TestOwner::new("Mallory", 66, Network::Signet)
}
