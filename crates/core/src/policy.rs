//! Wallet policy: M-of-N P2WSH `sortedmulti` over owner xpubs with key origin.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub};
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::{Address, Network, NetworkKind, PublicKey, ScriptBuf, Weight};
use miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard};
use miniscript::Descriptor;
use serde::{Deserialize, Serialize};

use crate::{Keychain, MAX_INDEX};

/// Hardware wallets (Coldcard, Jade) cap multisig at 15 cosigners; so do we.
pub const MAX_OWNERS: usize = 15;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerKey {
    pub name: String,
    pub fingerprint: Fingerprint,
    /// Origin path from the owner's master key to `xpub`, e.g. m/48'/1'/0'/2'.
    pub path: DerivationPath,
    pub xpub: Xpub,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("need at least 2 owners, got {0}")]
    TooFewOwners(usize),
    #[error("at most {MAX_OWNERS} owners supported, got {0}")]
    TooManyOwners(usize),
    #[error("threshold {threshold} out of range 1..={n}")]
    BadThreshold { threshold: usize, n: usize },
    #[error("duplicate owner fingerprint {0}")]
    DuplicateFingerprint(Fingerprint),
    #[error("duplicate owner xpub {0}")]
    DuplicateXpub(Xpub),
    #[error("owner {owner}: xpub is for {xpub_network:?} but wallet network is {network}")]
    WrongNetwork { owner: String, xpub_network: NetworkKind, network: Network },
    #[error("owner {owner}: xpub depth {depth} doesn't match origin path length {path_len}")]
    DepthMismatch { owner: String, depth: u8, path_len: usize },
    #[error("owner {owner}: xpub child number doesn't match the last element of its origin path")]
    ChildMismatch { owner: String },
    #[error("owner {owner}: xpub is a master key (depth 0) but fingerprint doesn't match it")]
    MasterFingerprintMismatch { owner: String },
    #[error("derivation index {0} is hardened or out of range")]
    BadIndex(u32),
    #[error("descriptor error: {0}")]
    Descriptor(String),
    #[error("key derivation error: {0}")]
    Derivation(String),
}

/// Non-fatal observations about a policy (shown in the create/import review screen).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyWarning {
    /// Path looks like a single-sig account (44'/49'/84'/86') being used for multisig.
    SingleSigPath { owner: String, path: String },
    /// Path isn't the BIP-48 P2WSH path m/48'/coin'/account'/2'.
    NonStandardPath { owner: String, path: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPolicy {
    network: Network,
    threshold: usize,
    owners: Vec<OwnerKey>,
}

/// One derived address of the wallet with everything needed to validate spends from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedScript {
    pub keychain: Keychain,
    pub index: u32,
    pub witness_script: ScriptBuf,
    pub script_pubkey: ScriptBuf,
    /// (owner position, derived pubkey, key source) for every owner, in owner order.
    pub owner_keys: Vec<(usize, PublicKey, KeySource)>,
}

impl DerivedScript {
    pub fn owner_of(&self, pk: &PublicKey) -> Option<usize> {
        self.owner_keys.iter().find(|(_, k, _)| k == pk).map(|(i, _, _)| *i)
    }

    pub fn bip32_derivation(&self) -> BTreeMap<bitcoin::secp256k1::PublicKey, KeySource> {
        self.owner_keys.iter().map(|(_, pk, ks)| (pk.inner, ks.clone())).collect()
    }
}

impl WalletPolicy {
    pub fn new(network: Network, threshold: usize, owners: Vec<OwnerKey>) -> Result<Self, PolicyError> {
        let n = owners.len();
        if n < 2 {
            return Err(PolicyError::TooFewOwners(n));
        }
        if n > MAX_OWNERS {
            return Err(PolicyError::TooManyOwners(n));
        }
        if threshold == 0 || threshold > n {
            return Err(PolicyError::BadThreshold { threshold, n });
        }
        let want = NetworkKind::from(network);
        for (i, o) in owners.iter().enumerate() {
            for p in &owners[..i] {
                if p.fingerprint == o.fingerprint {
                    return Err(PolicyError::DuplicateFingerprint(o.fingerprint));
                }
                if p.xpub.public_key == o.xpub.public_key {
                    return Err(PolicyError::DuplicateXpub(o.xpub));
                }
            }
            if o.xpub.network != want {
                return Err(PolicyError::WrongNetwork {
                    owner: o.name.clone(),
                    xpub_network: o.xpub.network,
                    network,
                });
            }
            let path: &[ChildNumber] = o.path.as_ref();
            if o.xpub.depth as usize != path.len() {
                return Err(PolicyError::DepthMismatch {
                    owner: o.name.clone(),
                    depth: o.xpub.depth,
                    path_len: path.len(),
                });
            }
            match path.last() {
                Some(last) if *last != o.xpub.child_number => {
                    return Err(PolicyError::ChildMismatch { owner: o.name.clone() })
                }
                None if o.xpub.fingerprint() != o.fingerprint => {
                    return Err(PolicyError::MasterFingerprintMismatch { owner: o.name.clone() })
                }
                _ => {}
            }
        }
        let policy = WalletPolicy { network, threshold, owners };
        // Make sure miniscript accepts it (script size limits etc.).
        policy.descriptor(Keychain::External)?;
        Ok(policy)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn owners(&self) -> &[OwnerKey] {
        &self.owners
    }

    pub fn owner_by_fingerprint(&self, fp: Fingerprint) -> Option<usize> {
        self.owners.iter().position(|o| o.fingerprint == fp)
    }

    pub fn warnings(&self) -> Vec<PolicyWarning> {
        let mut out = vec![];
        for o in &self.owners {
            let p: &[ChildNumber] = o.path.as_ref();
            let purpose = p.first().copied();
            let single_sig = [44u32, 49, 84, 86]
                .iter()
                .any(|n| purpose == Some(ChildNumber::Hardened { index: *n }));
            if single_sig {
                out.push(PolicyWarning::SingleSigPath { owner: o.name.clone(), path: o.path.to_string() });
                continue;
            }
            let bip48 = p.len() == 4
                && p[0] == ChildNumber::Hardened { index: 48 }
                && p.iter().all(|c| c.is_hardened())
                && p[3] == ChildNumber::Hardened { index: 2 };
            if !bip48 {
                out.push(PolicyWarning::NonStandardPath { owner: o.name.clone(), path: o.path.to_string() });
            }
        }
        out
    }

    fn keys(&self, child: DerivationPath) -> Vec<DescriptorPublicKey> {
        self.owners
            .iter()
            .map(|o| {
                DescriptorPublicKey::XPub(DescriptorXKey {
                    origin: Some((o.fingerprint, o.path.clone())),
                    xkey: o.xpub,
                    derivation_path: child.clone(),
                    wildcard: Wildcard::Unhardened,
                })
            })
            .collect()
    }

    /// Single-path public descriptor for one keychain: `wsh(sortedmulti(M,[fp/path]xpub/<k>/*,...))`.
    pub fn descriptor(&self, keychain: Keychain) -> Result<Descriptor<DescriptorPublicKey>, PolicyError> {
        let child = DerivationPath::from(vec![ChildNumber::Normal { index: keychain.child() }]);
        Descriptor::new_wsh_sortedmulti(self.threshold, self.keys(child))
            .map_err(|e| PolicyError::Descriptor(e.to_string()))
    }

    /// Descriptor string with checksum.
    pub fn descriptor_string(&self, keychain: Keychain) -> Result<String, PolicyError> {
        Ok(self.descriptor(keychain)?.to_string())
    }

    /// Two-path descriptor (`/<0;1>/*`) with checksum, for backups and BSMS export.
    pub fn multipath_descriptor_string(&self) -> Result<String, PolicyError> {
        let ext = self.descriptor(Keychain::External)?.to_string();
        let body = ext.split('#').next().unwrap_or_default().replace("/0/*", "/<0;1>/*");
        let d = Descriptor::<DescriptorPublicKey>::from_str(&body).map_err(|e| PolicyError::Descriptor(e.to_string()))?;
        Ok(d.to_string())
    }

    /// Upper bound on the witness weight added by satisfying one input of this wallet.
    pub fn max_satisfaction_weight(&self) -> Weight {
        self.descriptor(Keychain::External)
            .and_then(|d| d.max_weight_to_satisfy().map_err(|e| PolicyError::Descriptor(e.to_string())))
            .expect("sortedmulti descriptor is always satisfiable")
    }

    pub fn derive(&self, keychain: Keychain, index: u32) -> Result<DerivedScript, PolicyError> {
        let secp = Secp256k1::verification_only();
        self.derive_with(&secp, keychain, index)
    }

    pub fn derive_with<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        keychain: Keychain,
        index: u32,
    ) -> Result<DerivedScript, PolicyError> {
        if index > MAX_INDEX {
            return Err(PolicyError::BadIndex(index));
        }
        let tail = [ChildNumber::Normal { index: keychain.child() }, ChildNumber::Normal { index }];
        let mut owner_keys = Vec::with_capacity(self.owners.len());
        for (i, o) in self.owners.iter().enumerate() {
            let child = o.xpub.derive_pub(secp, &tail).map_err(|e| PolicyError::Derivation(e.to_string()))?;
            let full = o.path.extend(tail);
            owner_keys.push((i, PublicKey::new(child.public_key), (o.fingerprint, full)));
        }
        let derived = self
            .descriptor(keychain)?
            .at_derivation_index(index)
            .map_err(|e| PolicyError::Descriptor(e.to_string()))?;
        let witness_script = derived.explicit_script().map_err(|e| PolicyError::Descriptor(e.to_string()))?;
        let script_pubkey = derived.script_pubkey();
        // Independent cross-check: the script must be sortedmulti over exactly the keys we derived.
        let mut pks: Vec<PublicKey> = owner_keys.iter().map(|(_, k, _)| *k).collect();
        pks.sort_by_key(|k| k.to_bytes());
        let expected = multisig_script(self.threshold, &pks);
        if expected != witness_script || ScriptBuf::new_p2wsh(&expected.wscript_hash()) != script_pubkey {
            return Err(PolicyError::Descriptor("derived script mismatch".into()));
        }
        Ok(DerivedScript { keychain, index, witness_script, script_pubkey, owner_keys })
    }

    pub fn address(&self, keychain: Keychain, index: u32) -> Result<Address, PolicyError> {
        let d = self.derive(keychain, index)?;
        Address::from_script(&d.script_pubkey, self.network).map_err(|e| PolicyError::Descriptor(e.to_string()))
    }
}

/// `OP_k <pk1> ... <pkn> OP_n OP_CHECKMULTISIG`, keys in the order given.
pub fn multisig_script(k: usize, pks: &[PublicKey]) -> ScriptBuf {
    use bitcoin::opcodes::all::OP_CHECKMULTISIG;
    use bitcoin::script::Builder;
    let mut b = Builder::new().push_int(k as i64);
    for pk in pks {
        b = b.push_key(pk);
    }
    b.push_int(pks.len() as i64).push_opcode(OP_CHECKMULTISIG).into_script()
}
