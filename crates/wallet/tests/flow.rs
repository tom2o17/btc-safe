//! In-memory end-to-end flow: watch-only wallet from 3 xpubs, fund, propose, sign 2-of-3
//! offline (test keys only), combine, finalize. Plus reservation and strict-order chaining.

use std::collections::BTreeSet;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, BlockHash, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use btc_safe_core::policy::{OwnerKey, WalletPolicy};
use btc_safe_core::validate;
use btc_safe_core::Keychain;
use btc_safe_wallet::bdk_wallet::chain::BlockId;
use btc_safe_wallet::{update, BuildRequest, ChainInput, SafeWallet, WalletError};
use btc_safe_testkit::{three_owners, TestOwner};

fn policy(owners: &[TestOwner]) -> WalletPolicy {
    WalletPolicy::new(
        Network::Signet,
        2,
        owners.iter().map(|o| OwnerKey { name: o.name.clone(), fingerprint: o.fingerprint, path: o.path.clone(), xpub: o.xpub }).collect(),
    )
    .unwrap()
}

fn recipient() -> ScriptBuf {
    Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap().assume_checked().script_pubkey()
}

fn block(h: u32) -> BlockHash {
    BlockHash::from_byte_array([h as u8; 32])
}

fn fund(w: &mut SafeWallet, outs: &[(u32, u64)], height: u32) -> Transaction {
    let p = w.policy().clone();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([height as u8; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1u8; 71], vec![2u8; 33]]),
        }],
        output: outs
            .iter()
            .map(|(i, v)| TxOut { value: Amount::from_sat(*v), script_pubkey: p.derive(Keychain::External, *i).unwrap().script_pubkey })
            .collect(),
    };
    let max = outs.iter().map(|(i, _)| *i).max().unwrap();
    w.reveal_to(Keychain::External, max);
    let tip = w.bdk().latest_checkpoint().insert(BlockId { height, hash: block(height) });
    w.apply_update(update::confirmed(std::slice::from_ref(&tx), height, block(height), 1_700_000_000 + height as u64, tip)).unwrap();
    tx
}

fn sign_and_finalize(w: &SafeWallet, owners: &[TestOwner], built: &btc_safe_wallet::BuiltProposal, who: &[usize]) -> Transaction {
    let mut stored = built.psbt.clone();
    for &i in who {
        // Each owner gets a fresh copy, as if they downloaded the PSBT to their device.
        let mut theirs = built.psbt.clone();
        assert!(owners[i].sign(&mut theirs) > 0);
        let sub = validate::validate_submission(w.policy(), &built.spec, &stored, &theirs).unwrap();
        validate::apply_signatures(&mut stored, &sub);
    }
    validate::finalize(w.policy(), &built.spec, &stored).unwrap()
}

#[test]
fn full_flow_two_of_three() {
    let owners = three_owners();
    let mut w = SafeWallet::new(policy(&owners)).unwrap();
    fund(&mut w, &[(0, 100_000), (1, 60_000)], 100);
    assert_eq!(w.balance(&BTreeSet::new()).confirmed, Amount::from_sat(160_000));

    let req = BuildRequest {
        recipients: vec![(recipient(), Amount::from_sat(50_000))],
        fee_rate: Some(FeeRate::from_sat_per_vb(2).unwrap()),
        change_index: 0,
        rbf: true,
        ..Default::default()
    };
    let built = w.build_proposal(&req).unwrap();
    assert!(built.change_used);
    assert_eq!(built.spec.change.len(), 1);
    assert_eq!(built.summary.sent, Amount::from_sat(50_000));
    assert!(built.summary.rbf);
    // The PSBT we hand to signers carries full prev txs and derivations for change.
    assert!(built.psbt.inputs.iter().all(|i| i.non_witness_utxo.is_some() && i.bip32_derivation.len() == 3));
    let cv = built.spec.change[0].vout as usize;
    assert_eq!(built.psbt.outputs[cv].bip32_derivation.len(), 3);

    let tx = sign_and_finalize(&w, &owners, &built, &[0, 2]);
    let fee = built.summary.fee.to_sat();
    let rate = fee as f64 / tx.vsize() as f64;
    assert!((2.0..2.2).contains(&rate), "actual fee rate {rate}");

    // Broadcast + confirm: the wallet sees the spend and the change.
    w.apply_update(update::mempool(std::slice::from_ref(&tx), 1_700_000_500)).unwrap();
    let tip = w.bdk().latest_checkpoint().insert(BlockId { height: 101, hash: block(101) });
    w.apply_update(update::confirmed(std::slice::from_ref(&tx), 101, block(101), 1_700_000_600, tip)).unwrap();
    let bal = w.balance(&BTreeSet::new());
    assert_eq!(bal.confirmed, Amount::from_sat(160_000 - 50_000 - fee));
    assert_eq!(w.history().len(), 2);
}

#[test]
fn reservations_keep_proposals_disjoint() {
    let owners = three_owners();
    let mut w = SafeWallet::new(policy(&owners)).unwrap();
    fund(&mut w, &[(0, 100_000), (1, 100_000), (2, 100_000)], 100);
    let fr = Some(FeeRate::from_sat_per_vb(1).unwrap());

    let mut reserved = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for (k, change_index) in [(0, 0u32), (1, 1), (2, 2)] {
        let built = w
            .build_proposal(&BuildRequest {
                recipients: vec![(recipient(), Amount::from_sat(40_000 + k))],
                fee_rate: fr,
                reserved: reserved.clone(),
                change_index,
                rbf: true,
                ..Default::default()
            })
            .unwrap();
        for i in &built.spec.inputs {
            assert!(seen.insert(i.outpoint), "input reused across queued proposals");
            reserved.insert(i.outpoint);
        }
    }
    assert_eq!(reserved.len(), 3);
    let err = w
        .build_proposal(&BuildRequest {
            recipients: vec![(recipient(), Amount::from_sat(10_000))],
            fee_rate: fr,
            reserved: reserved.clone(),
            change_index: 3,
            ..Default::default()
        })
        .unwrap_err();
    match err {
        WalletError::InsufficientFunds { reserved: r, available, .. } => {
            assert_eq!(r, Amount::from_sat(300_000));
            assert_eq!(available, Amount::ZERO);
        }
        e => panic!("{e}"),
    }
    // Coin control can't pick a reserved coin either.
    let op = *reserved.iter().next().unwrap();
    let err = w
        .build_proposal(&BuildRequest {
            recipients: vec![(recipient(), Amount::from_sat(10_000))],
            fee_rate: fr,
            reserved: reserved.clone(),
            must_spend: vec![op],
            change_index: 3,
            ..Default::default()
        })
        .unwrap_err();
    assert!(matches!(err, WalletError::Reserved(o) if o == op));
}

#[test]
fn strict_order_chains_on_predecessor_change() {
    let owners = three_owners();
    let mut w = SafeWallet::new(policy(&owners)).unwrap();
    fund(&mut w, &[(0, 200_000), (1, 100_000)], 100);
    let fr = Some(FeeRate::from_sat_per_vb(1).unwrap());

    // #1: head of the queue spends confirmed coins.
    let a = w
        .build_proposal(&BuildRequest {
            recipients: vec![(recipient(), Amount::from_sat(30_000))],
            fee_rate: fr,
            change_index: 0,
            rbf: true,
            ..Default::default()
        })
        .unwrap();
    let a_change = &a.spec.change[0];
    let chain = ChainInput {
        outpoint: OutPoint { txid: a.spec.unsigned_tx.compute_txid(), vout: a_change.vout },
        amount: a.spec.unsigned_tx.output[a_change.vout as usize].value,
        index: a_change.index,
        prev_tx: a.spec.unsigned_tx.clone(),
    };
    let reserved: BTreeSet<OutPoint> = a.spec.inputs.iter().map(|i| i.outpoint).collect();

    // #2 must spend #1's change output, even though #1 isn't on chain yet.
    let b = w
        .build_proposal(&BuildRequest {
            recipients: vec![(recipient(), Amount::from_sat(20_000))],
            fee_rate: fr,
            reserved: reserved.clone(),
            chain_input: Some(chain.clone()),
            change_index: 1,
            rbf: true,
            ..Default::default()
        })
        .unwrap();
    assert!(b.spec.unsigned_tx.input.iter().any(|i| i.previous_output == chain.outpoint));

    // Both can be signed independently, before either is broadcast.
    let a_tx = sign_and_finalize(&w, &owners, &a, &[0, 1]);
    let b_tx = sign_and_finalize(&w, &owners, &b, &[1, 2]);
    // #2 can only exist after #1: its input is #1's output.
    assert_eq!(b_tx.input.iter().filter(|i| i.previous_output.txid == a_tx.compute_txid()).count(), 1);

    // Broadcast in order; the wallet tracks the chain.
    w.apply_update(update::mempool(std::slice::from_ref(&a_tx), 1)).unwrap();
    w.apply_update(update::mempool(std::slice::from_ref(&b_tx), 2)).unwrap();
    let total: u64 = w.utxos().iter().map(|u| u.amount.to_sat()).sum();
    assert_eq!(total, 300_000 - 30_000 - 20_000 - a.summary.fee.to_sat() - b.summary.fee.to_sat());

    // An RBF bump of #1 changes its txid, so #2's chain input no longer exists: #2 must be
    // rebuilt and re-signed (the store/API cascade marks it invalidated).
    let prev: std::collections::BTreeMap<_, _> = a.psbt.inputs.iter().map(|i| {
        let t = i.non_witness_utxo.clone().unwrap();
        (t.compute_txid(), t)
    }).collect();
    let bumped = btc_safe_wallet::bump_fee(w.policy(), &a.spec, &prev, FeeRate::from_sat_per_vb(5).unwrap()).unwrap();
    assert!(bumped.summary.fee > a.summary.fee);
    assert_eq!(bumped.spec.inputs, a.spec.inputs);
    let bumped_txid = bumped.spec.unsigned_tx.compute_txid();
    assert_ne!(bumped_txid, a_tx.compute_txid());
    assert!(b_tx.input.iter().all(|i| i.previous_output.txid != bumped_txid), "#2 can't spend the replacement");
    // The bump is signable on its own.
    sign_and_finalize(&w, &owners, &bumped, &[0, 2]);

    let cancel = btc_safe_wallet::build_cancel(w.policy(), &a.spec, &prev, 5, FeeRate::from_sat_per_vb(3).unwrap()).unwrap();
    assert_eq!(cancel.summary.sent, Amount::ZERO);
    assert!(cancel.summary.fee > a.summary.fee);
    sign_and_finalize(&w, &owners, &cancel, &[0, 1]);
}

#[test]
fn chain_input_must_be_our_change() {
    let owners = three_owners();
    let mut w = SafeWallet::new(policy(&owners)).unwrap();
    fund(&mut w, &[(0, 200_000)], 100);
    let a = w
        .build_proposal(&BuildRequest {
            recipients: vec![(recipient(), Amount::from_sat(30_000))],
            fee_rate: Some(FeeRate::from_sat_per_vb(1).unwrap()),
            change_index: 0,
            ..Default::default()
        })
        .unwrap();
    // Claim the *recipient* output as the chain input.
    let rv = a.spec.unsigned_tx.output.iter().position(|o| o.script_pubkey == recipient()).unwrap() as u32;
    let bad = ChainInput {
        outpoint: OutPoint { txid: a.spec.unsigned_tx.compute_txid(), vout: rv },
        amount: Amount::from_sat(30_000),
        index: 0,
        prev_tx: a.spec.unsigned_tx.clone(),
    };
    let err = w
        .build_proposal(&BuildRequest {
            recipients: vec![(recipient(), Amount::from_sat(10_000))],
            chain_input: Some(bad),
            change_index: 1,
            ..Default::default()
        })
        .unwrap_err();
    assert!(matches!(err, WalletError::BadChainInput(_)));
}

#[test]
fn state_persists_and_rejects_other_policy() {
    let owners = three_owners();
    let p = policy(&owners);
    let mut w = SafeWallet::new(p.clone()).unwrap();
    fund(&mut w, &[(0, 100_000), (4, 5_000)], 100);
    let cs = w.take_staged().unwrap();
    let json = serde_json::to_string(&cs).unwrap();
    let back: btc_safe_wallet::bdk_wallet::ChangeSet = serde_json::from_str(&json).unwrap();
    let w2 = SafeWallet::load(p, back.clone()).unwrap();
    assert_eq!(w2.utxos(), w.utxos());

    let other: Vec<TestOwner> = (0..3).map(|i| TestOwner::new("x", 40 + i, Network::Signet)).collect();
    assert!(SafeWallet::load(policy(&other), back).is_err());
}

#[test]
fn send_max_has_no_change() {
    let owners = three_owners();
    let mut w = SafeWallet::new(policy(&owners)).unwrap();
    fund(&mut w, &[(0, 100_000), (1, 50_000)], 100);
    let built = w
        .build_proposal(&BuildRequest {
            recipients: vec![(recipient(), Amount::ZERO)],
            fee_rate: Some(FeeRate::from_sat_per_vb(1).unwrap()),
            change_index: 0,
            send_max: true,
            ..Default::default()
        })
        .unwrap();
    assert!(!built.change_used);
    assert_eq!(built.spec.unsigned_tx.output.len(), 1);
    assert_eq!(built.summary.sent + built.summary.fee, Amount::from_sat(150_000));
    sign_and_finalize(&w, &owners, &built, &[1, 2]);
}
