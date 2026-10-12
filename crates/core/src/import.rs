//! Wallet import: output descriptors (incl. Sparrow's descriptor export), BSMS 1.0, and
//! Caravan-format JSON (which Sparrow also exports).
//!
//! Every import is round-tripped: we rebuild the descriptor from the parsed policy and require
//! it to equal what was imported, so an import can never silently mean something else.

use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::{base58, Network, NetworkKind};
use miniscript::descriptor::{DescriptorPublicKey, Wildcard, WshInner};
use miniscript::Descriptor;
use serde::{Deserialize, Serialize};

use crate::policy::{OwnerKey, PolicyError, WalletPolicy};
use crate::Keychain;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImportError {
    #[error("empty input")]
    Empty,
    #[error("descriptor parse error: {0}")]
    Descriptor(String),
    #[error("only wsh(sortedmulti(...)) descriptors are supported in v1")]
    UnsupportedPolicy,
    #[error("key {0}: must be an xpub with key origin [fingerprint/path]")]
    MissingOrigin(usize),
    #[error("key {0}: derivation after the xpub must be /0/*, /1/* or /<0;1>/* (unhardened)")]
    BadKeyDerivation(usize),
    #[error("descriptors in the file describe different wallets")]
    Inconsistent,
    #[error("round-trip mismatch: imported descriptor doesn't rebuild identically")]
    RoundTrip,
    #[error("BSMS: {0}")]
    Bsms(String),
    #[error("JSON: {0}")]
    Json(String),
    #[error("bad xpub {0}: {1}")]
    BadXpub(String, String),
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImportWarning {
    /// Only a receive descriptor was given; change was assumed to be /1/*.
    ChangePathAssumed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    pub name: Option<String>,
    pub policy: WalletPolicy,
    pub warnings: Vec<ImportWarning>,
    pub format: ImportFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    Descriptor,
    Bsms,
    CaravanJson,
}

/// Sniff the format and import.
pub fn import_any(text: &str, network: Network) -> Result<Imported, ImportError> {
    let t = text.trim_start_matches('\u{feff}').trim();
    if t.is_empty() {
        return Err(ImportError::Empty);
    }
    if t.starts_with("BSMS") {
        import_bsms(t, network)
    } else if t.starts_with('{') {
        import_caravan_json(t, network)
    } else {
        import_descriptor(t, network)
    }
}

/// Convert SLIP-132 encodings (Zpub/Vpub/ypub/...) to plain xpub/tpub. Version bytes only;
/// the key material is unchanged.
pub fn normalize_xpub(s: &str) -> Result<Xpub, ImportError> {
    let bad = |e: String| ImportError::BadXpub(s.to_string(), e);
    let mut data = base58::decode_check(s).map_err(|e| bad(e.to_string()))?;
    if data.len() != 78 {
        return Err(bad("wrong length".into()));
    }
    const MAIN: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
    const TEST: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
    let v = [data[0], data[1], data[2], data[3]];
    let target = match v {
        MAIN | [0x04, 0x9D, 0x7C, 0xB2] | [0x04, 0xB2, 0x47, 0x46] | [0x02, 0x95, 0xB4, 0x3F] | [0x02, 0xAA, 0x7E, 0xD3] => MAIN,
        TEST | [0x04, 0x4A, 0x52, 0x62] | [0x04, 0x5F, 0x1C, 0xF6] | [0x02, 0x42, 0x89, 0xEF] | [0x02, 0x57, 0x54, 0x83] => TEST,
        _ => return Err(bad("unknown version bytes (private key or unsupported encoding?)".into())),
    };
    data[..4].copy_from_slice(&target);
    Xpub::decode(&data).map_err(|e| bad(e.to_string()))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    Multipath,
    Single(Keychain),
}

fn policy_from_descriptor(
    d: &Descriptor<DescriptorPublicKey>,
    network: Network,
) -> Result<(WalletPolicy, Shape), ImportError> {
    let Descriptor::Wsh(wsh) = d else {
        return Err(ImportError::UnsupportedPolicy);
    };
    let WshInner::SortedMulti(smv) = wsh.as_inner() else {
        return Err(ImportError::UnsupportedPolicy);
    };
    let mut shape: Option<Shape> = None;
    let mut owners = vec![];
    for (i, k) in smv.pks().iter().enumerate() {
        let (origin, xkey, this_shape) = match k {
            DescriptorPublicKey::XPub(x) => {
                if x.wildcard != Wildcard::Unhardened {
                    return Err(ImportError::BadKeyDerivation(i));
                }
                let p: &[ChildNumber] = x.derivation_path.as_ref();
                let s = match p {
                    [ChildNumber::Normal { index: 0 }] => Shape::Single(Keychain::External),
                    [ChildNumber::Normal { index: 1 }] => Shape::Single(Keychain::Internal),
                    _ => return Err(ImportError::BadKeyDerivation(i)),
                };
                (&x.origin, x.xkey, s)
            }
            DescriptorPublicKey::MultiXPub(x) => {
                if x.wildcard != Wildcard::Unhardened {
                    return Err(ImportError::BadKeyDerivation(i));
                }
                let paths = x.derivation_paths.paths();
                let ok = paths.len() == 2
                    && paths[0].as_ref() == [ChildNumber::Normal { index: 0 }]
                    && paths[1].as_ref() == [ChildNumber::Normal { index: 1 }];
                if !ok {
                    return Err(ImportError::BadKeyDerivation(i));
                }
                (&x.origin, x.xkey, Shape::Multipath)
            }
            DescriptorPublicKey::Single(_) => return Err(ImportError::MissingOrigin(i)),
        };
        let (fp, path) = origin.clone().ok_or(ImportError::MissingOrigin(i))?;
        match shape {
            None => shape = Some(this_shape),
            Some(s) if s != this_shape => return Err(ImportError::BadKeyDerivation(i)),
            _ => {}
        }
        owners.push(OwnerKey { name: format!("Owner {}", i + 1), fingerprint: fp, path, xpub: xkey });
    }
    let policy = WalletPolicy::new(network, smv.k(), owners)?;
    Ok((policy, shape.ok_or(ImportError::UnsupportedPolicy)?))
}

fn round_trip(policy: &WalletPolicy, d: &Descriptor<DescriptorPublicKey>, shape: Shape) -> Result<(), ImportError> {
    let ours = match shape {
        Shape::Multipath => policy.multipath_descriptor_string()?,
        Shape::Single(k) => policy.descriptor_string(k)?,
    };
    if ours != d.to_string() {
        return Err(ImportError::RoundTrip);
    }
    Ok(())
}

/// Import one or more descriptors (one per line; `#` comment lines ignored, as in Sparrow's
/// export). All descriptors must describe the same wallet.
pub fn import_descriptor(text: &str, network: Network) -> Result<Imported, ImportError> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if lines.is_empty() {
        return Err(ImportError::Empty);
    }
    let mut policy: Option<WalletPolicy> = None;
    let mut have_internal = false;
    for line in lines {
        // `from_str` on DescriptorPublicKey rejects private keys outright, and validates the
        // checksum if one is present.
        let d = Descriptor::<DescriptorPublicKey>::from_str(line).map_err(|e| ImportError::Descriptor(e.to_string()))?;
        let (p, shape) = policy_from_descriptor(&d, network)?;
        round_trip(&p, &d, shape)?;
        if matches!(shape, Shape::Multipath | Shape::Single(Keychain::Internal)) {
            have_internal = true;
        }
        match &policy {
            None => policy = Some(p),
            Some(prev) if *prev != p => return Err(ImportError::Inconsistent),
            _ => {}
        }
    }
    let warnings = if have_internal { vec![] } else { vec![ImportWarning::ChangePathAssumed] };
    Ok(Imported { name: None, policy: policy.expect("non-empty"), warnings, format: ImportFormat::Descriptor })
}

/// BSMS 1.0 (BIP-129) descriptor record:
/// ```text
/// BSMS 1.0
/// wsh(sortedmulti(2,[fp/48'/1'/0'/2']tpub.../**,...))#checksum
/// /0/*,/1/*
/// tb1q...   (first receive address, verified)
/// ```
pub fn import_bsms(text: &str, network: Network) -> Result<Imported, ImportError> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.len() != 4 {
        return Err(ImportError::Bsms(format!("expected 4 lines, got {}", lines.len())));
    }
    if lines[0] != "BSMS 1.0" {
        return Err(ImportError::Bsms("first line must be 'BSMS 1.0'".into()));
    }
    let restrictions = lines[2].replace(' ', "");
    if restrictions != "/0/*,/1/*" && lines[2] != "No path restrictions" {
        return Err(ImportError::Bsms(format!("unsupported path restrictions '{}'", lines[2])));
    }
    let raw = lines[1];
    let body = match raw.split_once('#') {
        Some((body, cs)) => {
            let want = miniscript::descriptor::checksum::desc_checksum(body)
                .map_err(|e| ImportError::Descriptor(e.to_string()))?;
            if want != cs {
                return Err(ImportError::Bsms("descriptor checksum mismatch".into()));
            }
            body
        }
        None => raw,
    };
    let expanded = body.replace("/**", "/<0;1>/*");
    let d = Descriptor::<DescriptorPublicKey>::from_str(&expanded).map_err(|e| ImportError::Descriptor(e.to_string()))?;
    let (policy, shape) = policy_from_descriptor(&d, network)?;
    if shape != Shape::Multipath {
        return Err(ImportError::Bsms("descriptor must use /** (receive and change)".into()));
    }
    round_trip(&policy, &d, shape)?;
    let first = policy.address(Keychain::External, 0)?.to_string();
    if first != lines[3] {
        return Err(ImportError::Bsms(format!("first address mismatch: file says {}, descriptor derives {}", lines[3], first)));
    }
    Ok(Imported { name: None, policy, warnings: vec![], format: ImportFormat::Bsms })
}

/// Export a BSMS 1.0 record for device registration / backup.
pub fn export_bsms(policy: &WalletPolicy) -> Result<String, ImportError> {
    let mp = policy.multipath_descriptor_string()?;
    let body = mp.split('#').next().unwrap_or_default().replace("/<0;1>/*", "/**");
    let cs = miniscript::descriptor::checksum::desc_checksum(&body).map_err(|e| ImportError::Descriptor(e.to_string()))?;
    let addr = policy.address(Keychain::External, 0)?;
    Ok(format!("BSMS 1.0\n{body}#{cs}\n/0/*,/1/*\n{addr}\n"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaravanConfig {
    name: Option<String>,
    address_type: String,
    network: Option<String>,
    quorum: CaravanQuorum,
    extended_public_keys: Vec<CaravanKey>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaravanQuorum {
    required_signers: usize,
    total_signers: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaravanKey {
    name: Option<String>,
    bip32_path: String,
    xpub: String,
    xfp: String,
}

/// Caravan wallet config JSON (Sparrow: File → Export → Caravan).
pub fn import_caravan_json(text: &str, network: Network) -> Result<Imported, ImportError> {
    let c: CaravanConfig = serde_json::from_str(text).map_err(|e| ImportError::Json(e.to_string()))?;
    if !c.address_type.eq_ignore_ascii_case("P2WSH") {
        return Err(ImportError::Json(format!("addressType {} not supported (P2WSH only)", c.address_type)));
    }
    if let Some(n) = &c.network {
        let kind = match n.as_str() {
            "mainnet" | "bitcoin" => NetworkKind::Main,
            "testnet" | "testnet4" | "signet" | "regtest" => NetworkKind::Test,
            other => return Err(ImportError::Json(format!("unknown network {other}"))),
        };
        if kind != NetworkKind::from(network) {
            return Err(ImportError::Json(format!("config is for {n}, wallet network is {network}")));
        }
    }
    if c.quorum.total_signers != c.extended_public_keys.len() {
        return Err(ImportError::Json("totalSigners doesn't match the number of keys".into()));
    }
    let mut owners = vec![];
    for (i, k) in c.extended_public_keys.iter().enumerate() {
        let fp = Fingerprint::from_str(&k.xfp)
            .map_err(|_| ImportError::Json(format!("key {i}: xfp '{}' is not a fingerprint", k.xfp)))?;
        let path = DerivationPath::from_str(&k.bip32_path)
            .map_err(|_| ImportError::Json(format!("key {i}: bip32Path '{}' invalid", k.bip32_path)))?;
        let xpub = normalize_xpub(&k.xpub)?;
        let name = k.name.clone().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| format!("Owner {}", i + 1));
        owners.push(OwnerKey { name, fingerprint: fp, path, xpub });
    }
    let policy = WalletPolicy::new(network, c.quorum.required_signers, owners)?;
    Ok(Imported { name: c.name, policy, warnings: vec![], format: ImportFormat::CaravanJson })
}
