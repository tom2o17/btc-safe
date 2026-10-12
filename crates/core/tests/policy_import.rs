mod common;

use std::str::FromStr;

use btc_safe_core::bitcoin::bip32::{DerivationPath, Xpub};
use btc_safe_core::bitcoin::{base58, Network};
use btc_safe_core::import::{self, ImportError, ImportFormat, ImportWarning};
use btc_safe_core::policy::{PolicyError, PolicyWarning, WalletPolicy};
use btc_safe_core::Keychain;
use btc_safe_testkit::TestOwner;
use common::*;

#[test]
fn descriptor_shape() {
    let (p, owners) = two_of_three();
    let ext = p.descriptor_string(Keychain::External).unwrap();
    assert!(ext.starts_with("wsh(sortedmulti(2,["), "{ext}");
    assert!(ext.contains(&format!("[{}/48'/1'/0'/2']{}/0/*", owners[0].fingerprint, owners[0].xpub)), "{ext}");
    let int = p.descriptor_string(Keychain::Internal).unwrap();
    assert!(int.contains("/1/*"));
    let mp = p.multipath_descriptor_string().unwrap();
    assert!(mp.contains("/<0;1>/*"), "{mp}");
    assert!(p.warnings().is_empty());
    let a = p.address(Keychain::External, 0).unwrap().to_string();
    assert!(a.starts_with("tb1q") && a.len() == 62, "{a}");
}

#[test]
fn derive_matches_owner_keys() {
    let (p, owners) = two_of_three();
    let d = p.derive(Keychain::Internal, 7).unwrap();
    assert_eq!(d.owner_keys.len(), 3);
    for (i, (pos, _pk, ks)) in d.owner_keys.iter().enumerate() {
        assert_eq!(*pos, i);
        assert_eq!(ks.0, owners[i].fingerprint);
        assert_eq!(ks.1, DerivationPath::from_str("m/48'/1'/0'/2'/1/7").unwrap());
    }
    assert!(p.derive(Keychain::External, 1 << 31).is_err());
}

#[test]
fn policy_rejections() {
    let owners = btc_safe_testkit::three_owners();
    let keys: Vec<_> = owners.iter().map(owner_key).collect();
    assert_eq!(WalletPolicy::new(Network::Signet, 0, keys.clone()), Err(PolicyError::BadThreshold { threshold: 0, n: 3 }));
    assert_eq!(WalletPolicy::new(Network::Signet, 4, keys.clone()), Err(PolicyError::BadThreshold { threshold: 4, n: 3 }));
    assert_eq!(WalletPolicy::new(Network::Signet, 1, keys[..1].to_vec()), Err(PolicyError::TooFewOwners(1)));

    let mut dup_fp = keys.clone();
    dup_fp[2].fingerprint = dup_fp[0].fingerprint;
    assert!(matches!(WalletPolicy::new(Network::Signet, 2, dup_fp), Err(PolicyError::DuplicateFingerprint(_))));

    let mut dup_x = keys.clone();
    dup_x[2].xpub = dup_x[0].xpub;
    assert!(matches!(WalletPolicy::new(Network::Signet, 2, dup_x), Err(PolicyError::DuplicateXpub(_))));

    assert!(matches!(WalletPolicy::new(Network::Bitcoin, 2, keys.clone()), Err(PolicyError::WrongNetwork { .. })));

    let mut bad_depth = keys.clone();
    bad_depth[1].path = DerivationPath::from_str("m/48'/1'/0'").unwrap();
    assert!(matches!(WalletPolicy::new(Network::Signet, 2, bad_depth), Err(PolicyError::DepthMismatch { .. })));

    let mut bad_child = keys.clone();
    bad_child[1].path = DerivationPath::from_str("m/48'/1'/0'/1'").unwrap();
    assert!(matches!(WalletPolicy::new(Network::Signet, 2, bad_child), Err(PolicyError::ChildMismatch { .. })));

    let many: Vec<_> = (0..16).map(|i| owner_key(&TestOwner::new("x", 100 + i, Network::Signet))).collect();
    assert_eq!(WalletPolicy::new(Network::Signet, 2, many), Err(PolicyError::TooManyOwners(16)));
}

#[test]
fn single_sig_path_warns() {
    let mut keys: Vec<_> = btc_safe_testkit::three_owners().iter().map(owner_key).collect();
    // Re-derive owner 0 at a BIP-84 path so depth/child are consistent.
    let o = &btc_safe_testkit::three_owners()[0];
    let path = DerivationPath::from_str("m/84'/1'/0'").unwrap();
    keys[0].xpub = o.xpub_at(&path);
    keys[0].path = path;
    let p = WalletPolicy::new(Network::Signet, 2, keys).unwrap();
    assert!(matches!(p.warnings()[0], PolicyWarning::SingleSigPath { .. }));
}

#[test]
fn import_descriptor_roundtrip_all_shapes() {
    let (p, _) = two_of_three();
    for text in [
        p.multipath_descriptor_string().unwrap(),
        format!("{}\n{}", p.descriptor_string(Keychain::External).unwrap(), p.descriptor_string(Keychain::Internal).unwrap()),
        // Sparrow-style export with comments, mixed forms.
        format!(
            "# Receive and change descriptor (BIP389):\n{}\n\n# Receive descriptor (Bitcoin Core):\n{}\n# Change descriptor (Bitcoin Core):\n{}\n",
            p.multipath_descriptor_string().unwrap(),
            p.descriptor_string(Keychain::External).unwrap(),
            p.descriptor_string(Keychain::Internal).unwrap()
        ),
    ] {
        let imp = import::import_any(&text, Network::Signet).unwrap();
        assert_eq!(imp.format, ImportFormat::Descriptor);
        assert!(imp.warnings.is_empty());
        assert_eq!(imp.policy.descriptor_string(Keychain::External).unwrap(), p.descriptor_string(Keychain::External).unwrap());
        assert_eq!(imp.policy.address(Keychain::Internal, 5).unwrap(), p.address(Keychain::Internal, 5).unwrap());
    }
    let only_ext = import::import_any(&p.descriptor_string(Keychain::External).unwrap(), Network::Signet).unwrap();
    assert_eq!(only_ext.warnings, vec![ImportWarning::ChangePathAssumed]);
}

#[test]
fn import_descriptor_rejections() {
    let (p, owners) = two_of_three();
    let mp = p.multipath_descriptor_string().unwrap();
    let body = mp.split('#').next().unwrap().to_string();

    // Bad checksum.
    let bad_cs = format!("{body}#qqqqqqqq");
    assert!(matches!(import::import_any(&bad_cs, Network::Signet), Err(ImportError::Descriptor(_))));
    // Unsorted multi is not supported.
    let multi = body.replace("sortedmulti", "multi");
    assert_eq!(import::import_any(&multi, Network::Signet).unwrap_err(), ImportError::UnsupportedPolicy);
    // sh(wsh(...)) not supported.
    let shwsh = format!("sh({body})");
    assert_eq!(import::import_any(&shwsh, Network::Signet).unwrap_err(), ImportError::UnsupportedPolicy);
    // Private key in a descriptor is refused by the public-key parser.
    let xprv = owners[0].master.to_string();
    let with_priv = body.replacen(&owners[0].xpub.to_string(), &xprv, 1);
    assert!(import::import_any(&with_priv, Network::Signet).is_err());
    // Missing key origin.
    let no_origin = body.replacen(&format!("[{}/48'/1'/0'/2']", owners[0].fingerprint), "", 1);
    assert_eq!(import::import_any(&no_origin, Network::Signet).unwrap_err(), ImportError::MissingOrigin(0));
    // Hardened wildcard.
    let hard = body.replace("/<0;1>/*", "/<0;1>/*'");
    assert!(import::import_any(&hard, Network::Signet).is_err());
    // Non-standard change path.
    let odd = body.replace("/<0;1>/*", "/<0;2>/*");
    assert!(matches!(import::import_any(&odd, Network::Signet), Err(ImportError::BadKeyDerivation(_))));
    // Two descriptors for different wallets.
    let other = policy_m_of(2, &owners_n(3));
    let mixed = format!("{}\n{}", p.descriptor_string(Keychain::External).unwrap(), other.descriptor_string(Keychain::Internal).unwrap());
    assert_eq!(import::import_any(&mixed, Network::Signet).unwrap_err(), ImportError::Inconsistent);
    // Mainnet network with testnet keys.
    assert!(matches!(import::import_any(&mp, Network::Bitcoin), Err(ImportError::Policy(PolicyError::WrongNetwork { .. }))));
}

#[test]
fn bsms_roundtrip_and_checks() {
    let (p, _) = two_of_three();
    let bsms = import::export_bsms(&p).unwrap();
    let lines: Vec<&str> = bsms.lines().collect();
    assert_eq!(lines[0], "BSMS 1.0");
    assert!(lines[1].contains("/**"), "{bsms}");
    let imp = import::import_any(&bsms, Network::Signet).unwrap();
    assert_eq!(imp.format, ImportFormat::Bsms);
    assert_eq!(imp.policy, WalletPolicy::new(Network::Signet, 2, imp.policy.owners().to_vec()).unwrap());
    assert_eq!(imp.policy.address(Keychain::External, 0).unwrap(), p.address(Keychain::External, 0).unwrap());

    // Wrong first address.
    let other_addr = p.address(Keychain::External, 1).unwrap().to_string();
    let tampered = bsms.replace(lines[3], &other_addr);
    assert!(matches!(import::import_any(&tampered, Network::Signet), Err(ImportError::Bsms(_))));
    // Checksum mismatch (change threshold, keep checksum).
    let tampered = bsms.replacen("sortedmulti(2,", "sortedmulti(1,", 1);
    assert!(matches!(import::import_any(&tampered, Network::Signet), Err(ImportError::Bsms(_))));
    // Wrong header.
    assert!(import::import_any(&bsms.replace("BSMS 1.0", "BSMS 2.0"), Network::Signet).is_err());
}

fn slip132(x: &Xpub, version: [u8; 4]) -> String {
    let mut data = x.encode();
    data[..4].copy_from_slice(&version);
    base58::encode_check(&data)
}

#[test]
fn caravan_json_import() {
    let (p, owners) = two_of_three();
    let keys: Vec<String> = owners
        .iter()
        .enumerate()
        .map(|(i, o)| {
            // Owner 1 uses the SLIP-132 Vpub encoding Sparrow/Coldcard sometimes emit.
            let x = if i == 1 { slip132(&o.xpub, [0x02, 0x57, 0x54, 0x83]) } else { o.xpub.to_string() };
            format!(r#"{{"name":"{}","bip32Path":"m/48'/1'/0'/2'","xpub":"{}","xfp":"{}","method":"text"}}"#, o.name, x, o.fingerprint)
        })
        .collect();
    let json = format!(
        r#"{{"name":"Treasury","addressType":"P2WSH","network":"testnet","client":{{"type":"public"}},"quorum":{{"requiredSigners":2,"totalSigners":3}},"extendedPublicKeys":[{}],"startingAddressIndex":0}}"#,
        keys.join(",")
    );
    let imp = import::import_any(&json, Network::Signet).unwrap();
    assert_eq!(imp.format, ImportFormat::CaravanJson);
    assert_eq!(imp.name.as_deref(), Some("Treasury"));
    assert_eq!(imp.policy.owners()[1].name, "Bob");
    assert_eq!(imp.policy.address(Keychain::External, 2).unwrap(), p.address(Keychain::External, 2).unwrap());

    let bad = json.replace("\"P2WSH\"", "\"P2SH\"");
    assert!(matches!(import::import_any(&bad, Network::Signet), Err(ImportError::Json(_))));
    let bad = json.replace("\"totalSigners\":3", "\"totalSigners\":4");
    assert!(matches!(import::import_any(&bad, Network::Signet), Err(ImportError::Json(_))));
    let bad = json.replacen(&owners[0].fingerprint.to_string(), "Unknown", 1);
    assert!(matches!(import::import_any(&bad, Network::Signet), Err(ImportError::Json(_))));
    let bad = json.replace("\"testnet\"", "\"mainnet\"");
    assert!(matches!(import::import_any(&bad, Network::Signet), Err(ImportError::Json(_))));
}

#[test]
fn normalize_xpub_rejects_xprv() {
    let o = &btc_safe_testkit::three_owners()[0];
    assert!(import::normalize_xpub(&o.master.to_string()).is_err());
    assert_eq!(import::normalize_xpub(&o.xpub.to_string()).unwrap(), o.xpub);
}
