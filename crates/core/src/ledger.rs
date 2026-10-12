//! Ledger Bitcoin app (app-bitcoin-new ≥ 2.1) wallet policies, BIP-388 style.
//!
//! A multisig has to be registered on the device before it will sign or show addresses. The
//! device answers a registration with an HMAC over the policy id, keyed by a secret derived
//! from its seed; the HMAC is presented back on every later sign/address call so the device
//! doesn't have to ask the user again. The HMAC is not key material, but it lets anyone who
//! holds it skip the on-device review of *this* policy, so we keep it server-side and scoped
//! to the wallet.
//!
//! The server can't check the HMAC (it needs the device secret). It can, and does, check
//! that the registered policy is exactly this wallet's policy: same template, same keys in
//! the same order, and an id that hashes to what the device would compute. The id
//! serialization mirrors `WalletPolicy.serialize()` in LedgerHQ's `ledger-bitcoin` JS client
//! (wallet policy version 2).

use bitcoin::hashes::{sha256, Hash};

use crate::policy::WalletPolicy;

/// `MAX_WALLET_NAME_LENGTH` in app-bitcoin-new's `src/constants.h`.
pub const MAX_NAME_LEN: usize = 64;
const WALLET_POLICY_V2: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LedgerPolicy {
    pub name: String,
    pub descriptor_template: String,
    /// Key information strings, `[fingerprint/path']xpub`, in owner-position order.
    pub keys: Vec<String>,
}

/// A name the device accepts: printable ASCII, no surrounding spaces, ≤ 64 bytes, non-empty.
pub fn device_name(wallet_name: &str) -> String {
    let s: String = wallet_name.chars().filter(|c| (' '..='~').contains(c)).collect();
    let s = s.trim();
    let s = if s.len() > MAX_NAME_LEN { s[..MAX_NAME_LEN].trim_end() } else { s };
    if s.is_empty() { "BTC Safe".to_string() } else { s.to_string() }
}

impl LedgerPolicy {
    /// The policy for a P2WSH sortedmulti wallet. `@i/**` is `/<0;1>/*` on key `i`, which is
    /// exactly our receive (`/0/*`) and change (`/1/*`) descriptors.
    pub fn for_wallet(wallet_name: &str, policy: &WalletPolicy) -> Self {
        let n = policy.owners().len();
        let placeholders: Vec<String> = (0..n).map(|i| format!("@{i}/**")).collect();
        let descriptor_template = format!("wsh(sortedmulti({},{}))", policy.threshold(), placeholders.join(","));
        let keys = policy
            .owners()
            .iter()
            .map(|o| {
                let path = o.path.to_string();
                let path = path.trim_start_matches("m/").trim_start_matches('m');
                let origin = if path.is_empty() { o.fingerprint.to_string() } else { format!("{}/{}", o.fingerprint, path) };
                // The device wants `'`, not `h`, on older app versions.
                format!("[{}]{}", origin.replace('h', "'"), o.xpub)
            })
            .collect();
        LedgerPolicy { name: device_name(wallet_name), descriptor_template, keys }
    }

    /// Serialized policy, as hashed by the device to get the policy id.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![WALLET_POLICY_V2];
        write_varint(&mut out, self.name.len() as u64);
        out.extend_from_slice(self.name.as_bytes());
        write_varint(&mut out, self.descriptor_template.len() as u64);
        out.extend_from_slice(sha256::Hash::hash(self.descriptor_template.as_bytes()).as_byte_array());
        write_varint(&mut out, self.keys.len() as u64);
        let leaves: Vec<[u8; 32]> = self.keys.iter().map(|k| hash_leaf(k.as_bytes())).collect();
        out.extend_from_slice(&merkle_root(&leaves));
        out
    }

    pub fn id(&self) -> [u8; 32] {
        sha256::Hash::hash(&self.serialize()).to_byte_array()
    }
}

fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut v = Vec::with_capacity(1 + data.len());
    v.push(0);
    v.extend_from_slice(data);
    sha256::Hash::hash(&v).to_byte_array()
}

/// The app's Merkle tree: the left subtree takes the largest power of two strictly below n.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => [0; 32],
        1 => leaves[0],
        n => {
            let mut left = 1;
            while left * 2 < n {
                left *= 2;
            }
            let mut v = Vec::with_capacity(65);
            v.push(1);
            v.extend_from_slice(&merkle_root(&leaves[..left]));
            v.extend_from_slice(&merkle_root(&leaves[left..]));
            sha256::Hash::hash(&v).to_byte_array()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_device_safe() {
        assert_eq!(device_name("  Treasury ✓ "), "Treasury");
        assert_eq!(device_name("✓✓"), "BTC Safe");
        assert_eq!(device_name(&"a".repeat(80)).len(), MAX_NAME_LEN);
    }

    #[test]
    fn merkle_shape_matches_the_app() {
        let l = |b: u8| [b; 32];
        let node = |a: [u8; 32], b: [u8; 32]| {
            let mut v = vec![1];
            v.extend_from_slice(&a);
            v.extend_from_slice(&b);
            sha256::Hash::hash(&v).to_byte_array()
        };
        assert_eq!(merkle_root(&[l(1), l(2), l(3)]), node(node(l(1), l(2)), l(3)));
        assert_eq!(merkle_root(&[l(1), l(2), l(3), l(4), l(5)]), node(node(node(l(1), l(2)), node(l(3), l(4))), l(5)));
    }

    /// Vectors produced by `new WalletPolicy(...).getId()` from npm `ledger-bitcoin@0.3.0`
    /// (web/e2e/ledger-policy-vector.mjs). Key strings are opaque to the id, so two are dummies.
    #[test]
    fn id_matches_ledger_bitcoin_js() {
        let keys = [
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']key-two",
            "[0badc0de/48'/1'/0'/2']key-three",
        ];
        let p = |name: &str, t: &str, n: usize| LedgerPolicy {
            name: name.into(),
            descriptor_template: t.into(),
            keys: keys[..n].iter().map(|k| k.to_string()).collect(),
        };
        assert_eq!(
            hex(&p("Cold storage", "wsh(sortedmulti(2,@0/**,@1/**))", 2).id()),
            "5c308562edcdbd164d1cedbfa80f75f0bca92d060551eb03bccd2df00d38bf0f"
        );
        assert_eq!(
            hex(&p("Treasury", "wsh(sortedmulti(2,@0/**,@1/**,@2/**))", 3).id()),
            "639f5e3a1cc2ffdef67a30ec387dacc25c6689b381df6ef5887e57bdd4ace631"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
