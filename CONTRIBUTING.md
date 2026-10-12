# Contributing

Thanks for your interest. Issues and pull requests are welcome.

## Before you start

- Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The original rationale is in
  [DESIGN.md](DESIGN.md).
- For anything larger than a small fix, open an issue first so the approach can be agreed.
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Ground rules

- **Watch-only.** The backend never holds private keys. Private-key types are banned by
  `clippy.toml`; only `crates/testkit` (a dev-dependency) may opt out. Don't add opt-outs.
- **The server builds every PSBT itself.** A client PSBT only carries signatures. Changes to
  `crates/core/src/validate.rs` need tests for the attack they could open.
- **No mainnet** until the validation code has had an external review.
- Match the surrounding code style; run `cargo fmt`.

## Checks

```sh
createdb btc_safe_test
cargo test --workspace
./scripts/check-watch-only.sh        # clippy -D warnings + watch-only invariant

cd web && npm ci
npm test && npm run typecheck && npm run build
```

CI runs the same checks on every pull request. Browser and device e2e scripts in `web/e2e/`
are run by hand (see the README).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
