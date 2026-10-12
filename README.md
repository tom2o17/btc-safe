# btc-safe

A self-hosted Bitcoin multisig coordinator with a Safe{Wallet}-style UI: one owner proposes a
transaction, every owner sees it in a shared queue, each signs from their own device, and the
transaction is broadcast once M of N have signed. Rust backend (axum, bdk_wallet, Postgres),
Next.js frontend. **Watch-only:** the server holds xpubs and descriptors, never owner private
keys, and never signs. **Signet only** for now.

Working name. This is a clean-room build. It does not use Safe's code, name, or logo, and it is
not affiliated with Safe.

> [!WARNING]
> **Experimental, unaudited software. Do not use it with real funds.** Mainnet is refused in code
> (signet only). The PSBT validation, change verification and auth code have had internal
> adversarial review but no independent security audit, and Trezor, QR and file signing have not
> been verified on real devices. See [SECURITY.md](SECURITY.md) to report a vulnerability.

- How it works internally: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (summary below)
- Original design: [DESIGN.md](DESIGN.md)
- Development log (what's done, what isn't): [PROGRESS.md](PROGRESS.md)

## Status

Phase 1 (Rust backend, signet) is built: `core`, `wallet`, `chain`, `store`, `watcher`, `api`.
Phase 2 (Next.js frontend in `web/`) is built, and the core flow is verified in Chrome.
Accounts (invite or optional public signup), TOTP 2FA with recovery codes, per-wallet roles
(admin / proposer / viewer), Postgres-backed rate limits, login backoff and a strict CSP are in.
Ledger signing is verified against the Speculos emulator; Trezor, QR and file signing
are built but **not yet verified on real devices** (Phase 3).

## Layout

```
crates/core      domain types, descriptors + import (descriptor/BSMS/Caravan), PSBT validation, fees, state machine. No I/O.
crates/wallet    watch-only bdk_wallet wrapper: coin selection with reservations, strict-order chaining, RBF bump/cancel
crates/chain     ChainSource trait; Esplora (signet) and MemoryChain (in-process simulator)
crates/store     Postgres schema + sqlx repositories (reservations enforced by an EXCLUDE constraint)
crates/watcher   wallet cache, sync, lifecycle transitions, reconcile loop
crates/api       axum HTTP API, auth, rate limits, admin CLI
crates/testkit   TEST-ONLY throwaway keys + offline signer (dev-dependency only)
web/             Next.js frontend (App Router, TypeScript); web/e2e = browser + device e2e scripts
docs/            ARCHITECTURE.md
scripts/         check-watch-only.sh, Speculos (Ledger emulator) setup
```

## Under the hood (summary)

```
Browser ──/api/*──▶ Next.js (rewrite) ──▶ axum API ──▶ core · wallet · watcher · store · chain
  │                                          │                                  │
  └ decodes PSBTs, re-derives addresses      └ session + CSRF + membership      └ Esplora (signet)
    from xpubs, talks to Ledger/Trezor                                            or MemoryChain
```

- **Create.** BDK picks coins (skipping coins reserved by other queued proposals), a fresh change
  index is allocated, fee caps are checked, and the PSBT is rebuilt from our own derivations
  (`non_witness_utxo`, `witness_script`, `bip32_derivation`, global xpubs). BDK's PSBT is
  discarded.
- **Sign.** Any signer's PSBT is validated against the stored proposal: identical unsigned tx,
  matching UTXO data and scripts, SIGHASH_ALL only, every signature from an owner key and valid
  over our sighash. One defect rejects the whole upload; nothing partial is stored.
- **Execute.** At M signatures on every input, the tx is finalized, checked two independent ways
  (own CHECKMULTISIG verifier + miniscript interpreter), fee-checked again, and broadcast.
- **Watch.** A background loop syncs each wallet and moves proposals through
  `pending → signing → ready → broadcast → soft_confirmed → confirmed`, or to
  `invalidated`/`conflicted` when an input is spent elsewhere or a replacement is final.
  One block makes a proposal *soft confirmed* ("1 block confirmation, waiting for final");
  `CONFIRMATIONS_FINAL` blocks (default 2) make it *final*. Soft proposals keep their coins
  reserved and are re-checked every tick: a reorg rolls them back to `broadcast`, and a
  conflicting tx that wins the reorg fails them and frees their coins. Final is never
  re-checked. RBF bump/cancel and an optional
  strict-order mode (each proposal spends the previous one's change) are built in.
- **Reservations.** A Postgres `EXCLUDE` constraint guarantees an outpoint is held by at most one
  active replacement group, even under concurrent requests.
- **Trust.** The browser cross-checks every PSBT against the server's summary and re-derives
  change and receive addresses before any sign button is enabled. A compromised server can deny
  service or lie about balances, but it holds no keys and can't get a tampered PSBT past the
  cross-check, as long as the xpubs the browser derives from are the real ones (they come from
  the server too; see the threat model).

Full details, with file and line references: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

| Topic | Section |
|---|---|
| Request flow, crates, lock order | [1. Big picture](docs/ARCHITECTURE.md#1-big-picture) |
| Create, PSBT contents, validation rules, threshold, execute, state machine, watcher, RBF, strict order | [2. Lifecycle of a proposal](docs/ARCHITECTURE.md#2-lifecycle-of-a-proposal) |
| Descriptors, import formats, BDK, addresses | [3. Wallet model](docs/ARCHITECTURE.md#3-wallet-model) |
| Schema, reservation constraint, audit log | [4. Persistence](docs/ARCHITECTURE.md#4-persistence) |
| ChainSource, Esplora vs MemoryChain, signet pin | [5. Chain layer](docs/ARCHITECTURE.md#5-chain-layer) |
| argon2id, cookies, CSRF, membership, rate limits, browser cross-check, threat model | [6. Auth and security](docs/ARCHITECTURE.md#6-auth-and-security) |
| Ledger, Trezor, file/QR; verified vs unverified | [7. Hardware signing](docs/ARCHITECTURE.md#7-hardware-signing) |
| Routes and modules | [8. Frontend structure](docs/ARCHITECTURE.md#8-frontend-structure) |
| Dockerfiles, hosting | [9. Deployment](docs/ARCHITECTURE.md#9-deployment) |
| Test suites | [10. Testing](docs/ARCHITECTURE.md#10-testing) |
| Limits | [11. Known gaps](docs/ARCHITECTURE.md#11-known-gaps-and-limits) |

## Run locally

Prerequisites: Rust stable, Postgres 16, Node ≥ 23 for the frontend tests. Copy
[.env.example](.env.example) for a starting set of variables.

```sh
createdb btc_safe_dev
createdb btc_safe_test          # used by the test suite

cargo test --workspace          # needs btc_safe_test (or BTC_SAFE_TEST_DATABASE_URL)
./scripts/check-watch-only.sh   # clippy -D + watch-only invariant checks
cargo test -p btc-safe-chain --test signet_smoke -- --ignored   # hits public signet Esplora

# Real signet (mempool.space Esplora):
DATABASE_URL="postgres:///btc_safe_dev?host=/tmp&user=$USER" cargo run -p btc-safe-api
# In-process simulated chain with /dev/fund, /dev/mine, /dev/inject, /dev/reorg:
DATABASE_URL="postgres:///btc_safe_dev?host=/tmp&user=$USER" CHAIN=memory cargo run -p btc-safe-api
```

Migrations run automatically on startup.

### Environment (API)

| Var | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | — (required) | Postgres connection string |
| `CHAIN` | `esplora` | `esplora` or `memory` (in-process simulator, enables `/dev/*`) |
| `ESPLORA_URL` | mempool.space signet API | must serve signet: the genesis hash is checked at startup |
| `NETWORK` | `signet` | mainnet is refused; other test networks only with `CHAIN=memory` |
| `BIND` | `127.0.0.1:8080`, or `[::]:$PORT` if `PORT` is set | listen address |
| `SYNC_SECS` | `30` | watcher interval |
| `CONFIRMATIONS_FINAL` | `2` | block confirmations at which a sent proposal is final (integer ≥ 1; anything else refuses to start). Below it the proposal is "soft confirmed" and re-checked for reorgs. 2 is thin for mainnet (this build is signet-only); use 6 there |
| `COOKIE_SECURE` | `true` | `false` only for local http (drops `Secure` and the `__Host-` prefix) |
| `CLIENT_IP_HEADER` | TCP peer | header with the real client IP behind a proxy that overwrites it (e.g. `x-real-ip`) |
| `CORS_ORIGINS` | none | comma-separated origins; not needed when the web app proxies `/api/*` |
| `WEB_ORIGIN` | — | public web URL, used to print setup links |
| `RATE_IP` / `RATE_USER` / `RATE_LOGIN` | `300/120`, `600/200`, `10/5` | `<per minute>/<burst>`; stored in Postgres, shared by all API processes |
| `RATE_SIGNUP` / `RATE_SIGNUP_GLOBAL` | `5/3`, `60/20` | `<per hour>/<burst>`: signups per client IP (IPv6 per /64) and from everyone together |
| `OPEN_SIGNUP` | off | `1`: anyone can create an account at /signup. Off: invite-only |
| `MAX_USERS` | `1000` | signup refuses once this many accounts exist (invited ones count) |
| `MAX_WALLETS_PER_USER` | `20` | wallets a non-admin account may create or import (`0` = no limit) |
| `SIGNUP_POW_BITS` | `20` | signup proof-of-work difficulty (leading zero bits of SHA-256; 20 ≈ 1M hashes, about a second in a browser; max 28) |
| `SIGNUP_SECRET` | random per process | 64 hex chars; set it when running several API processes so they accept each other's signup challenges |
| `SESSION_HOURS` / `SESSION_IDLE_MINS` | `12` / `30` | absolute session lifetime / idle timeout |
| `LOGIN_BACKOFF` | `5/900` | `<free failures>/<max seconds>`: from the 5th failure in a row an account waits 1, 2, 4 … s (capped at 15 min) between password checks, except from browsers that have logged in to it before |
| `ADMIN_EMAIL` + `ADMIN_SETUP_TOKEN` | — | bootstrap an admin; the token works once, until a password is set |

### Accounts

Two ways in:

- **Invite** (always on): `btc-safe-api invite you@example.com --admin` prints a one-time setup
  link (72 h); open it and choose a password. On an existing account the link is a **reset**:
  when used it replaces the password, turns off 2FA and ends every session. So never run
  `invite` on someone else's existing email unless you mean to reset them.
- **Signup** (`OPEN_SIGNUP=1`): email + password at /signup. There is no email delivery, so the
  email is only a username and is never verified. Passwords need 12+ characters and are checked
  against a bundled list of ~47k common/breached passwords. A small proof-of-work and a hidden
  honeypot field slow bots down, plus per-IP and global signup limits and a user cap.

Account page (/account): change password (needs the current one; ends other sessions), log out
everywhere, optional TOTP 2FA with 10 one-time recovery codes. **Without email, recovery codes
are the only self-service way back in** if the authenticator is lost; otherwise an admin must
reset the account with `invite`. `btc-safe-api delete-user <email>` removes an account (refused
while it's the only admin of a wallet).

Roles per wallet: **viewer** (read, sync), **proposer** (+ propose, sign, execute, delete own
proposals, labels, address book, Ledger registrations), **admin** (+ settings, delete any
proposal, delete the wallet, manage members and roles). Creators are admins; members from
before roles existed became admins.

## Frontend

```sh
cd web && npm install
BTC_SAFE_API=http://127.0.0.1:8080 npm run dev     # http://localhost:3000; /api/* is proxied to the Rust API
npm test                                           # device-free unit tests
npm run typecheck
```

Log in at /login (local http needs the API started with `COOKIE_SECURE=false`).

Browser e2e (system Chrome, `CHAIN=memory`): `./web/e2e/reset-dev.sh` wipes `btc_safe_dev` and
creates a local dev admin (credentials are in `web/e2e/session.mjs`; API with `OPEN_SIGNUP=1`),
then run `npm run dev` and `node web/e2e/walkthrough.mjs`, `auth.mjs` (signup, 2FA, recovery
codes, password change, log out everywhere), `roles.mjs`, `csp.mjs` (CSP + headers on every page,
WebHID, Trezor Connect iframe, `/api/price`; run it against `npm run build && npm start` for the
production policy). `WEB` / `API` override the URLs. Screenshots: `web/screenshots/`.

Ledger (WebHID, Chrome/Edge): with the Speculos emulator up
([scripts/speculos/START.md](scripts/speculos/START.md)) and the API reset: `npm run e2e:ledger`
(node, same client calls) and, with `npm run dev` running, `npm run e2e:ledger-browser` (real UI
in Chrome).

## Deploying (signet)

Two images plus Postgres, all from the repo root as build context:

- `api`: root [`Dockerfile`](Dockerfile). Set `DATABASE_URL`, `COOKIE_SECURE=true`,
  `WEB_ORIGIN`, and `CLIENT_IP_HEADER` if it sits behind a proxy that overwrites that header.
- `web`: [`Dockerfile.web`](Dockerfile.web), with build arg `BTC_SAFE_API` set to the API's
  internal address (Next.js fixes the `/api/*` rewrite target at build time).
- Postgres: keep it off the public internet.

Create the first admin with `ADMIN_EMAIL` + `ADMIN_SETUP_TOKEN`, or run
`btc-safe-api invite <email> --admin` inside the api container. Details:
[docs/ARCHITECTURE.md §9](docs/ARCHITECTURE.md#9-deployment).

## Curl walk-through (CHAIN=memory)

Every call below except `/health` also needs the session cookie and, for writes,
`x-csrf-token` (from `POST /auth/login`); e.g. `curl -c jar -b jar` plus
`-H "x-csrf-token: $CSRF"`.

`testsigner` plays the owners' hardware wallets with deterministic TEST keys.

```sh
cargo build -p btc-safe-testkit --example testsigner
S=./target/debug/examples/testsigner; H=localhost:8080; CT='content-type: application/json'

WID=$(curl -s -H "$CT" $H/wallets -d "{\"name\":\"Treasury\",\"network\":\"signet\",\"threshold\":2,\"owners\":$($S owners)}" | jq -r .id)
ADDR=$(curl -s "$H/wallets/$WID/addresses?kind=receive&next=true" | jq -r .address)
curl -s -H "$CT" $H/dev/fund -d "{\"address\":\"$ADDR\",\"amount_sats\":250000}"
curl -s -H "$CT" $H/dev/mine -d '{}'; curl -s -X POST $H/wallets/$WID/sync

P=$(curl -s -H "$CT" $H/wallets/$WID/proposals -d '{"outputs":[{"address":"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx","amount_sats":100000}],"fee_rate_sat_vb":2}')
ID=$(echo "$P" | jq .id); PSBT=$(echo "$P" | jq -r .psbt)
for i in 0 2; do curl -s -H "$CT" $H/proposals/$ID/signatures -d "{\"psbt\":\"$($S sign $i "$PSBT")\"}" | jq '.status, .confirmations.count'; done
curl -s -X POST $H/proposals/$ID/execute | jq '.status, .txid'
curl -s -H "$CT" $H/dev/mine -d '{}'; curl -s -X POST $H/wallets/$WID/sync; curl -s $H/proposals/$ID | jq .status   # "soft_confirmed"
curl -s -H "$CT" $H/dev/reorg -d '{"depth":1}'; curl -s -X POST $H/wallets/$WID/sync; curl -s $H/proposals/$ID | jq .status_reason   # "reorged_back_to_mempool"
curl -s -H "$CT" $H/dev/mine -d '{"blocks":2}'; curl -s -X POST $H/wallets/$WID/sync; curl -s $H/proposals/$ID | jq .status   # "confirmed" (final)
```

## Endpoints (v1)

JSON in/out, amounts in satoshis, PSBTs base64. Everything except `/health` and the
login/signup/setup routes needs a session; wallet- and proposal-scoped routes also need
membership of that wallet (non-members get 404) and a role (too low: 403).

```
GET    /health
POST   /auth/login {email,password}         → session, or {mfa_required, mfa_token}
POST   /auth/login/mfa {mfa_token, code | recovery_code}
POST   /auth/logout · GET /auth/me (→ csrf_token, totp_enabled, recovery_codes_left, session expiry)
GET    /auth/signup (→ open, pow challenge) · POST /auth/signup {email,password,pow_challenge,pow_nonce,website:""}
GET    /auth/setup?token= · POST /auth/setup {token,password}      one-time setup/reset links
POST   /auth/logout-all · POST /auth/password {current_password,new_password}
POST   /auth/totp/setup {password} · /auth/totp/enable {code} · /auth/totp/disable {password, code|recovery_code}
POST   /auth/recovery-codes {password, code}   new set; old codes die
POST   /auth/invites {email, admin?} · GET /auth/users             admin only
GET    /price                               mainnet BTC/USD, display only
GET/POST /wallets/{id}/members {email, role?}, PATCH /wallets/{id}/members/{user} {role}, DELETE /wallets/{id}/members/{user}
DELETE /wallets/{id}                        coordination state only; refused while proposals are queued
POST   /wallets                             {name, network, threshold, owners[{name,xpub,fingerprint,path}], ordering_mode?}
POST   /wallets/import                      {name?, network, data: descriptor | BSMS | Caravan/Sparrow JSON}
GET    /wallets                             the caller's wallets
GET    /wallets/{id}                        summary: balance (incl. reserved), policy, owners, descriptors, tip
PATCH  /wallets/{id}                        {ordering_mode: parallel|strict} (empty queue only)
GET    /wallets/{id}/backup                 descriptor + BSMS + first addresses
GET    /wallets/{id}/addresses?kind=receive&next=true
POST   /wallets/{id}/addresses/{idx}/label  {label, kind?}
GET    /wallets/{id}/utxos                  coins with reserved_by / labels
GET    /wallets/{id}/history                chain txs (proposal / external / incoming) + finished proposals
GET    /wallets/{id}/fees
POST   /wallets/{id}/sync                   sync + reconcile now (the watcher does this every SYNC_SECS)
POST   /wallets/{id}/proposals              {outputs[], fee_rate_sat_vb?, utxos?, manual_only?, rbf?, send_max?,
                                             replaces?, replace_mode?: rebuild|bump|cancel, fee_override?}
GET    /wallets/{id}/proposals?status=queue|history
GET    /proposals/{id}                      PSBT (base64), decoded summary, confirmations by owner, signature log
POST   /proposals/{id}/signatures           {psbt}  (fully validated; nothing stored on any defect)
POST   /proposals/{id}/execute[?fee_override=true]
DELETE /proposals/{id}                      soft delete (warns that given signatures stay valid)
GET/POST /wallets/{id}/address-book, DELETE /wallets/{id}/address-book/{entry}
GET    /wallets/{id}/ledger                 Ledger wallet policy + stored registrations (HMACs)
PUT    /wallets/{id}/ledger/owners/{owner}  {policy, policy_id, hmac}: policy must be exactly GET's
DELETE /wallets/{id}/ledger/owners/{owner}  forget a registration
POST   /dev/fund | /dev/mine | /dev/inject | /dev/reorg  CHAIN=memory only
```

`created_by` is no longer accepted from clients for anyone but the caller: the proposer is always
the logged-in user.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), not in public issues.

## License

[MIT](LICENSE). `crates/api/data/common-passwords.txt` is derived from
[SecLists](https://github.com/danielmiessler/SecLists) (MIT); see [NOTICE](NOTICE).
