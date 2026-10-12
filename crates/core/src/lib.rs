//! btc-safe core: domain types, descriptor building and import, PSBT validation, fee checks.
//!
//! No I/O. Everything here is deterministic so it can be property-tested and fuzzed.
//! The crate is watch-only by construction: clippy's `disallowed_types` (see `clippy.toml`)
//! forbids private-key types across the workspace.

pub mod fees;
pub mod import;
pub mod ledger;
pub mod policy;
pub mod state;
pub mod validate;

pub use bitcoin;
pub use miniscript;

use serde::{Deserialize, Serialize};

/// Which branch of the wallet descriptor: `/0/*` (receive) or `/1/*` (change).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Keychain {
    External,
    Internal,
}

impl Keychain {
    pub fn child(self) -> u32 {
        match self {
            Keychain::External => 0,
            Keychain::Internal => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Keychain::External => "external",
            Keychain::Internal => "internal",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "external" | "receive" => Some(Keychain::External),
            "internal" | "change" => Some(Keychain::Internal),
            _ => None,
        }
    }
}

/// Largest non-hardened child index.
pub const MAX_INDEX: u32 = (1 << 31) - 1;
