#![allow(dead_code)]

use std::collections::BTreeMap;
use std::str::FromStr;

use btc_safe_core::bitcoin::absolute::LockTime;
use btc_safe_core::bitcoin::transaction::Version;
use btc_safe_core::bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use btc_safe_core::policy::{OwnerKey, WalletPolicy};
use btc_safe_core::validate::{build_canonical_psbt, ChangeSpec, InputSpec, ProposalSpec};
use btc_safe_core::Keychain;
use btc_safe_testkit::TestOwner;

pub fn owner_key(o: &TestOwner) -> OwnerKey {
    OwnerKey { name: o.name.clone(), fingerprint: o.fingerprint, path: o.path.clone(), xpub: o.xpub }
}

pub fn owners_n(n: usize) -> Vec<TestOwner> {
    (0..n).map(|i| TestOwner::new(&format!("Owner{i}"), 10 + i as u8, Network::Signet)).collect()
}

pub fn policy_m_of(m: usize, owners: &[TestOwner]) -> WalletPolicy {
    WalletPolicy::new(Network::Signet, m, owners.iter().map(owner_key).collect()).unwrap()
}

pub fn two_of_three() -> (WalletPolicy, Vec<TestOwner>) {
    let owners = btc_safe_testkit::three_owners();
    (policy_m_of(2, &owners), owners)
}

/// External recipient on signet (a P2WPKH address not belonging to the wallet).
pub fn recipient() -> ScriptBuf {
    Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
        .unwrap()
        .require_network(Network::Signet)
        .unwrap()
        .script_pubkey()
}

/// A fake confirmed funding tx paying to wallet addresses.
pub fn funding_tx(policy: &WalletPolicy, outs: &[(Keychain, u32, u64)]) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_str(&"11".repeat(32)).unwrap(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1u8; 72], vec![2u8; 33]]),
        }],
        output: outs
            .iter()
            .map(|(k, i, v)| TxOut { value: Amount::from_sat(*v), script_pubkey: policy.derive(*k, *i).unwrap().script_pubkey })
            .collect(),
    }
}

pub struct Fixture {
    pub policy: WalletPolicy,
    pub owners: Vec<TestOwner>,
    pub funding: Transaction,
    pub spec: ProposalSpec,
    pub prev: BTreeMap<Txid, Transaction>,
}

/// 2-of-3, two funding coins (100k @ m/0/0, 50k @ m/0/3), spend both: 120k to recipient,
/// change 29k to m/1/0, fee 1000.
pub fn fixture() -> Fixture {
    let (policy, owners) = two_of_three();
    fixture_for(policy, owners)
}

pub fn fixture_for(policy: WalletPolicy, owners: Vec<TestOwner>) -> Fixture {
    let funding = funding_tx(&policy, &[(Keychain::External, 0, 100_000), (Keychain::External, 3, 50_000)]);
    let txid = funding.compute_txid();
    let change_spk = policy.derive(Keychain::Internal, 0).unwrap().script_pubkey;
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(200_000).unwrap(),
        input: [0u32, 1]
            .iter()
            .map(|v| TxIn {
                previous_output: OutPoint { txid, vout: *v },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![
            TxOut { value: Amount::from_sat(120_000), script_pubkey: recipient() },
            TxOut { value: Amount::from_sat(29_000), script_pubkey: change_spk },
        ],
    };
    let spec = ProposalSpec {
        unsigned_tx: tx,
        inputs: vec![
            InputSpec { outpoint: OutPoint { txid, vout: 0 }, amount: Amount::from_sat(100_000), keychain: Keychain::External, index: 0 },
            InputSpec { outpoint: OutPoint { txid, vout: 1 }, amount: Amount::from_sat(50_000), keychain: Keychain::External, index: 3 },
        ],
        change: vec![ChangeSpec { vout: 1, index: 0 }],
    };
    let prev = BTreeMap::from([(txid, funding.clone())]);
    Fixture { policy, owners, funding, spec, prev }
}

impl Fixture {
    pub fn psbt(&self) -> btc_safe_core::bitcoin::Psbt {
        build_canonical_psbt(&self.policy, &self.spec, &self.prev).unwrap()
    }
}
