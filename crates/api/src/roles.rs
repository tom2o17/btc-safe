//! Roles per wallet and the one table that says which role each wallet-scoped route needs.
//!
//! | Role | Can |
//! |---|---|
//! | viewer | read everything in the wallet (balances, history, addresses, proposals, members, backup), sync, leave |
//! | proposer | + create proposals, upload signatures, **execute** (broadcast a fully signed proposal), delete proposals *they* created, labels, address book, Ledger registrations |
//! | admin | + delete any proposal, wallet settings, delete the wallet, manage members and roles |
//!
//! Execute is proposer-level on purpose: a proposal only executes once it carries the wallet's
//! M owner signatures, which are the real authorization; broadcasting is just delivery. Viewers
//! can't, so a read-only share can't decide *when* a signed transaction goes out.
//!
//! [`required`] is deny-by-default: a wallet-scoped (method, path) that isn't listed gets 403.

use axum::http::Method;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Proposer,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Proposer => "proposer",
            Role::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "viewer" => Some(Role::Viewer),
            "proposer" => Some(Role::Proposer),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

/// The wallet a scoped request is about and the caller's role in it, put in request extensions
/// by `auth::require_membership`.
#[derive(Debug, Clone, Copy)]
pub struct WalletAccess {
    pub wallet_id: uuid::Uuid,
    pub role: Role,
}

/// Minimum role for a wallet-scoped request; None = not allowed for anyone (403).
/// `segs` is the path split on '/', starting at "wallets" or "proposals".
pub fn required(method: &Method, segs: &[&str]) -> Option<Role> {
    use Role::*;
    let read = matches!(*method, Method::GET | Method::HEAD);
    match (segs, method.as_str()) {
        // Wallet reads.
        (["wallets", _], _) if read => Some(Viewer),
        (["wallets", _, "backup" | "addresses" | "utxos" | "history" | "fees" | "proposals" | "address-book" | "ledger" | "members"], _) if read => Some(Viewer),
        (["wallets", _, "sync"], "POST") => Some(Viewer),
        // Wallet settings and lifecycle.
        (["wallets", _], "PATCH" | "DELETE") => Some(Admin),
        // Members: admins manage; anyone may remove themselves (checked in the handler).
        (["wallets", _, "members"], "POST") => Some(Admin),
        (["wallets", _, "members", _], "PATCH") => Some(Admin),
        (["wallets", _, "members", _], "DELETE") => Some(Viewer),
        // Spending workflow and wallet bookkeeping.
        (["wallets", _, "proposals"], "POST") => Some(Proposer),
        (["wallets", _, "addresses", _, "label"], "POST") => Some(Proposer),
        (["wallets", _, "address-book"], "POST") => Some(Proposer),
        (["wallets", _, "address-book", _], "DELETE") => Some(Proposer),
        (["wallets", _, "ledger", "owners", _], "PUT" | "DELETE") => Some(Proposer),
        (["proposals", _], _) if read => Some(Viewer),
        // Proposers may delete only their own proposals (checked in the handler).
        (["proposals", _], "DELETE") => Some(Proposer),
        (["proposals", _, "signatures" | "execute"], "POST") => Some(Proposer),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table() {
        let r = |m: &str, p: &str| required(&m.parse().unwrap(), &p.split('/').collect::<Vec<_>>());
        assert_eq!(r("GET", "wallets/x"), Some(Role::Viewer));
        assert_eq!(r("DELETE", "wallets/x"), Some(Role::Admin));
        assert_eq!(r("PATCH", "wallets/x"), Some(Role::Admin));
        assert_eq!(r("POST", "wallets/x/proposals"), Some(Role::Proposer));
        assert_eq!(r("POST", "proposals/1/execute"), Some(Role::Proposer));
        assert_eq!(r("POST", "proposals/1/signatures"), Some(Role::Proposer));
        assert_eq!(r("POST", "wallets/x/members"), Some(Role::Admin));
        // Unlisted: denied.
        assert_eq!(r("POST", "wallets/x/backup"), None);
        assert_eq!(r("PUT", "wallets/x"), None);
        assert_eq!(r("POST", "wallets/x/something-new"), None);
        assert!(Role::Admin > Role::Proposer && Role::Proposer > Role::Viewer);
    }
}
