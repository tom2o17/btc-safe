# Security policy

btc-safe is experimental and **signet-only**. It has not had an independent security audit.
Do not use it with real funds.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately through
GitHub's [private vulnerability reporting](../../security/advisories/new) for this repository.

Include what you can: affected component, steps to reproduce or a proof-of-concept, and the
impact you expect. We aim to acknowledge reports within a week. Please give us a reasonable
window to fix the issue before disclosing it publicly.

## Scope and threat model

The server is **watch-only**: it stores xpubs and descriptors, never private keys, and never
signs. Owners sign on their own devices. The most valuable findings are ones that break those
guarantees or the checks around them, for example:

- getting a PSBT accepted, stored or finalized that differs from the server-built proposal
  (`crates/core/src/validate.rs`);
- making an attacker-controlled output pass as change, or a wrong receive address pass the
  browser's independent re-derivation (`web/lib/bitcoin.ts`);
- getting a hardware signer to sign something the user wasn't shown;
- private-key material reaching any non-test crate (enforced by `clippy.toml` and
  `scripts/check-watch-only.sh`);
- auth issues: session, CSRF, cross-wallet access, role bypass, 2FA bypass.

A compromised server can deny service or show wrong balances; that is a known limit, described
in [docs/ARCHITECTURE.md §6](docs/ARCHITECTURE.md#6-auth-and-security). Reports that it can
move funds or get a tampered transaction signed are in scope.

Out of scope: findings that need mainnet (it is refused in code), denial of service by volume
against a self-hosted instance, and issues in third-party dependencies with no impact here
(report those upstream).

The public signet demo linked from the README is fine for manual testing with your own accounts.
Please don't run automated scanners or load tests against it, and don't touch other users'
accounts or wallets; run your own instance for that (see the README).
