# BTC Safe: development log

Development log, newest sections at the bottom. Last updated 2026-10-08.

## Phase 1 (Rust backend, signet): done

| Area | State |
|---|---|
| Workspace (§5.1) | `core`, `wallet`, `chain`, `store`, `watcher`, `api`, plus `testkit` (test-only). No `cosigner` crate (v2). |
| Pinned deps | bdk_wallet =3.2.0 (verified latest on crates.io 2026-10-07), bdk_esplora =0.22.2, miniscript 12.3.7 and bitcoin 0.32.102 (the versions bdk_wallet 3.2 requires; miniscript 13 exists but would duplicate types), sqlx =0.9.0, axum =0.8.9. Rust 1.97.1. |
| Policy | M-of-N P2WSH `sortedmulti` (2..=15 owners). Import: descriptors (single, two-line, `<0;1>` multipath, Sparrow export with comments), BSMS 1.0 (first address verified), Caravan/Sparrow JSON, SLIP-132 xpubs. Every import round-trips. |
| Validation (§6.2) | The server never stores a client PSBT. Its PSBT is built from our own derivations. A signer's PSBT only carries signatures: the unsigned tx must be byte-equal; utxo/script/sighash fields are checked; each signature must come from a derived owner key and verify against our sighash. Change is re-derived from the internal descriptor. Fees: absolute cap, rate ≤ 10× fast, share-of-sent warning, override. Finalize is checked twice, by our CHECKMULTISIG-order verifier and by miniscript's interpreter. |
| State machine (§5.4) | `core::state`, a pure transition function with proptests. Store CAS. Watcher drives chain transitions (confirmed, seen in mempool, input spent elsewhere, sibling confirmed, dropped, parent gone). |
| Reservations (§2) | Postgres `EXCLUDE (wallet, outpoint, group <>) WHERE active`, plus a coin-selection filter. Replacements share coins by design. |
| Strict-order | Per-wallet setting. Each proposal spends the queue tail's change. Execute order is enforced. A cascade invalidates descendants on delete, invalidate, conflict, or a replacement broadcast (via the API or seen by the watcher). |
| Watch-only (§6.1) | `clippy.toml` bans private-key types and signing methods; `scripts/check-watch-only.sh` enforces it. Verified that it rejects injected `Xpriv`, `PrivateKey`, `Psbt::sign` and `Descriptor::parse_descriptor`. |
| API (§5.2 v1) | All v1 routes, plus `/backup`, `/sync`, `PATCH ordering_mode`, and `/dev/*` for CHAIN=memory. README lists them. |

Tests (Phase 1): 73 passing, 1 ignored (the network smoke test, which passes when run with `--ignored`). Postgres-backed suites use the `btc_safe_test` DB.

Adversarial review: a fresh-context reviewer found no way to get a bad PSBT accepted or stored. It found 3 deadlocks, a reconcile race, a pool-starvation DoS, 2 cascade gaps and an overflow panic. All are fixed, and the repros are kept as regression tests in `crates/api/tests/adversarial_review.rs`; every `fixed_*` test fails on the old code.

## Phase 2 (Next.js frontend): built, core flow verified in Chrome

`web/`: Next.js 16 (App Router) + TypeScript, npm only. Clean-room Safe-style layout (sidebar account card, Home, Assets, Transactions Queue/History, Send → Review → Sign, create wizard, Settings, Receive). Own name ("BTC Safe") and own mark; no Safe code, assets or CSS. `/api/*` is proxied to the Rust API by `next.config.ts`, so the API needs no CORS. The bearer token is entered on the start page and kept in localStorage.

Phase 1 re-verified before frontend work: `cargo test --workspace` = **73 passed, 0 failed, 1 ignored**; watch-only check OK.

**Independent browser checks** (`web/lib/bitcoin.ts`). The browser doesn't trust the server's summary:
- It decodes the PSBT with bitcoinjs-lib and compares the txid, inputs and amounts, outputs, and fee against the server's JSON.
- It re-derives every "change" output and every receive address from the owners' xpubs (bip32 + secp256k1, pure JS) and checks the server's first 3 addresses at wallet creation and import.
- It rejects a `non_witness_utxo` that doesn't hash to the outpoint's txid (a fake one could hide the fee).
- A mismatch shows a red banner, disables Download/QR, and blocks Execute.
- Checked against the server: browser-derived addresses and descriptor checksum equal the server's. Tampering with the change index, fee, recipient, or prev-tx is caught.

**Signing.** Download a `.psbt` (binary), or show an animated QR: BBQr via `bbqr` (Coinkite), or UR `crypto-psbt` via `@ngraveio/bc-ur` with a `buffer` polyfill. Signed PSBTs come back by file upload (binary, base64 or hex; several files at once) or by paste. In node, BBQr and UR frames round-trip back to the exact PSBT bytes.

**End-to-end in a real browser.** `web/e2e/walkthrough.mjs` drives system Chrome through `playwright-core` (no browser download) against `CHAIN=memory`. The testsigner example plays the devices. Flow: set token → create 2-of-3 (owners JSON) → review → backup (BSMS download, address match) → receive → fund via /dev → address-book entry → send to the book name → review (cross-check OK) → sign step (QR shown, PSBT downloaded, 2 signed binary files uploaded → 2 of 2) → second proposal at 1 of 2 → queue expand → execute → mine+sync → **confirmed** → history, assets, settings → tampered API response flagged → import the downloaded BSMS as a second account (addresses match). The run passes. Screenshots are in `web/screenshots/` (00–15). `next build` passes, and `node --version` still works after npm install (v25.4.0).

| Screen | State |
|---|---|
| Accounts list, API token | works (e2e) |
| Create wizard (4 steps + backup gate) | works (e2e); key-expression paste parser written, not e2e-tested |
| Import (descriptor / BSMS / JSON) | BSMS import works (e2e); descriptor/JSON paths not exercised in the browser |
| Home | works (e2e) |
| Receive | works (e2e): QR, browser re-derivation, device-verification notes. Label and "New address" built but not e2e-tested |
| Assets / coin control | list + reserved works (e2e); "Send selected" → `utxos` param built, not e2e-tested |
| Send → Review → Sign | single output + Normal fee works (e2e). Multi-output, Max, custom fee, the fee-cap override button and Back (discard) are built but not e2e-tested |
| Transactions Queue/History | works (e2e): expandable rows, signer list, execute, history. Delete is built but not e2e-tested |
| Address book | add works (e2e); remove not e2e-tested |
| Settings | renders (e2e): owners, descriptor, BSMS export, chain status; ordering switch not e2e-tested |

## Ledger signing over WebHID: done, verified on Speculos

Client: LedgerHQ's `ledger-bitcoin` 0.3.0 (published from the app-bitcoin-new repo) plus `@ledgerhq/hw-transport-webhid` 6.36.0; app-bitcoin-new ≥ 2.1, "Bitcoin Test" app on signet. Ledger's newer Device Management Kit (`@ledgerhq/device-signer-kit-bitcoin`) also exists; we didn't use it.

| Flow | Where | State |
|---|---|---|
| Add owner from Ledger (fp + xpub at m/48'/1'/0'/2') | Create wizard, "Connect Ledger" per owner | Speculos (browser) |
| Register `wsh(sortedmulti(M,@0/**,…))` and store the HMAC per (wallet, owner) | Settings → Ledger; also "Register, then sign" from a sign button | Speculos (browser + node) |
| Sign a proposal: signPsbt with the stored policy + HMAC, merge, upload to `/proposals/:id/signatures` (unchanged server validation) | Send step 3 "Ledger (USB)"; queue row "Sign with Ledger" | Speculos (browser + node) |
| Show a receive address on the device and compare | Receive, "Show on Ledger" | Speculos (browser) |
| Device states: not connected, locked, wrong/old app, not registered, rejected on device, bad HMAC, no WebHID | `<DeviceStatus>` | rejected, not registered, bad HMAC and no-WebHID were triggered on Speculos/Chrome. not connected, locked and wrong app are unit-tested only |

**Server.** Migration `20261007000002_ledger_policies.sql` adds the `ledger_policies` table, keyed (wallet_id, owner_id), cascading on delete. `core::ledger` builds the wallet's policy and computes the policy id; the id matches `ledger-bitcoin`'s on fixed vectors. `PUT` rejects any policy that isn't exactly this wallet's (name, template, keys in owner order), a policy_id that doesn't hash from it, a malformed HMAC, or an owner of another wallet. HMACs are readable only behind the API token, only for their own wallet, and are never written to the audit log. The server can't verify an HMAC (it's keyed by the device seed); the device does.

**Browser.** It rebuilds the policy from the owners and refuses a server policy, or a stored registration, whose template or keys differ. Before upload, `mergePartialSigs` requires each signature's pubkey to be in that input's `bip32_derivation` and the signature to verify against the input's sighash. The cross-check banner gates "Sign with Ledger" the same way it gates QR and download. A dev-only `__btcSafeLedgerBridge` hook lets the e2e relay APDUs to Speculos; it's compiled out of `next build` (checked: 0 occurrences in `.next/static`). The watch-only invariant is unchanged: keys stay on the device.

**Verified against Speculos** (app-bitcoin-new "Bitcoin Test" **2.5.1**, Nano S Plus, default Speculos seed, fp f5acc2fd). Speculos can't run natively on macOS, so it runs in a Lima VM; see `scripts/speculos/START.md`.
- `web/e2e/ledger-speculos.mjs` (node): app check → xpub → 2-of-3 wallet (Ledger + 2 test keys) → register rejected → register approved → server policy id == device id → device addresses (receive 0/1) == server → address shown on screen → sign rejected → bad HMAC (device answers 0xB008) → sign approved (2 inputs, recipient shown on device) → swapped and bit-flipped sigs refused by merge → server accepts → second signer → execute → **confirmed**.
- `web/e2e/ledger-browser.mjs` (real UI in system Chrome): wizard owner from Ledger → Settings register (reject, then approve) → Receive "Show on Ledger" (address seen on the device screen) → send flow sign (reject, then approve: 1 of 2) → execute → confirmed → Forget registration → queue row "Sign with Ledger" shows "not registered" → "Register, then sign" → signed → a context without WebHID shows "Browser not supported". Screenshots: `web/screenshots/ledger-*.png`.
- Unit: `cargo test` (+3 core, +2 api: policy/id/HMAC validation, scoping, auth, no HMAC in audit log); `npm test` (5: merge, re-merge no-op, bad device output, policy mirror, error/app classification).

**Not verified on real hardware.** Not tested: a physical Ledger, the WebHID picker and permission flow, Ledger Live holding the device, a locked device, and the dashboard or wrong-app status words (the codes come from Ledger's docs and app source, not observed). The Speculos ELF is a CI build of app-bitcoin-new `master` (da3c8c9, 2026-09-14), reporting 2.5.1, newer than the latest tagged release (2.4.2); Ledger Live ships whatever Ledger has released. Screen texts asserted in the e2e (e.g. "Register account") are Nano S Plus NBGL texts; Stax/Flex are touch UIs and weren't emulated. Only P2WSH sortedmulti; mainnet ("Bitcoin" app) is refused by the network check because the wallet is signet-only.

## Trezor signer: built, device flows UNVERIFIED

Added 2026-10-07. No Rust or API changes: Trezor signatures go through `POST /proposals/:id/signatures` and the same server validation as an uploaded PSBT.

**SDK.** `@trezor/connect-web` 10.0.1 (npm latest, 2026-09-25). Connect 10 dropped the self-hosted iframe/popup. Every call goes to **Trezor Suite**: Suite desktop over `ws://127.0.0.1:21335` when it's running, otherwise a Suite Web popup from `suite.trezor.io`. Suite shows the permission prompt, PIN and passphrase. `manifest.appName` is required. The host page must not send `COOP: same-origin`, and any CSP must allow framing suite.trezor.io. We set neither. Set `NEXT_PUBLIC_TREZOR_MANIFEST_EMAIL` for the manifest contact.

**Network.** Connect 10 coins are `btc`, `test`, `regtest`; there is **no signet coin**. Signet shares testnet's tb1 HRP, tpub version and SLIP-44 coin type 1, and we pass every previous tx (refTxs) ourselves. So signet signs as `coin: "test"`, path `m/48'/1'/0'/2'`. Suite's only testnet gate for third-party apps is in `selectAccount` (`Method_UnsupportedCoinForHost`, suite-common/connect-popup/src/methodHooks/selectAccount.ts:111-115), which we don't call; the `signTransaction` pre-call hook swallows its own errors (bitcoinSignTransaction.ts:91-94). So enabling "Bitcoin Testnet" in Suite shouldn't be needed. The UI still suggests it on a wrong-network error, which is harmless. Not observed on a real Suite.

**Firmware floor.** Sortedmulti is sent as `pubkeys_order = LEXICOGRAPHIC`, which needs core ≥ 2.8.7 (Model T, Safe 3/5/7) or legacy ≥ 1.13.0 (Model One), per the trezor-firmware changelogs. LEXICOGRAPHIC is required, not just convenient: the firmware's multisig fingerprint hashes the nodes in the order sent unless the order is lexicographic. Per-input pre-sorting would give each input a different fingerprint, and the device would then show change as a send (unit test `PRESERVED order would break…`).

| Piece | File | State |
|---|---|---|
| Shared adapter shape | `web/lib/signers/types.ts` | `SignerAdapter { getXpub, signPsbt }`, `SignerError` codes (not_connected, cancelled, wrong_network, wrong_device, busy, unsupported, failed). Other signers can add their own adapter next to it. |
| PSBT → Trezor request | `web/lib/signers/trezor-tx.ts` | Pure, no SDK. Per input: device `address_n` = origin + chain/index (from the PSBT's bip32_derivation, pubkey checked against the xpub), multisig = all owners' xpubs in wallet position order with `[chain, index]`, `m`, LEXICOGRAPHIC. It refuses any input whose prev-tx output isn't the owners' sortedmulti at that index, whose non_witness_utxo is missing or forged, or whose witness_script differs. Change: the PSBT derivation or the server's hint, re-derived. A match is sent with the same multisig (device hides it as change); a mismatch is sent as a plain address, so the device shows it. |
| Merge back | same | Connect's DER signatures (no sighash byte) → partial_sig with 0x01. Each is verified against the BIP-143 sighash before merging; idempotent. |
| Device wrapper | `web/lib/signers/trezor.ts` | `getXpub(path)` returns xpub + master fingerprint (`rootFingerprint`, else the descriptor's origin). `identify()` reads the xpub at each owner path (one Suite prompt) and matches fingerprint and key, which catches the wrong device or a wrong passphrase. `signAs()` builds, signs, merges. Errors are mapped from Connect codes. Connect 10 failures are `{success:false, error:{message, code}}`, not `payload.error`. |
| UI | `web/components/trezor.tsx` | Wizard: "Add from Trezor" on every owner fills fp/path/xpub. Send step 3 and the queue row: "Sign with Trezor", which identifies → signs → POSTs, with phase hints ("check the recipient on the Trezor; change is not shown"). Distinct messages for not connected, cancelled, wrong network, wrong Trezor/passphrase, busy and old firmware. |

**Verified (no device):**
- `npm test`: 10 unit tests. They run against `web/test/trezor-mock.mjs`, a model of the firmware's checks taken from trezor-firmware `core/src/apps/bitcoin` (multisig.py, addresses.py, change_detector.py). The model rebuilds the tx from the request (txid must equal ours), hashes the refTxs, checks input scripts against the prev txs and the device key against the multisig, computes the multisig fingerprint and wallet path, decides change, and signs BIP-143. Cases covered: each of the 3 owners as the device, change via derivation or hint, a lying hint, merge of 2 Trezors → finalize, a bad signature rejected, a wrong device, a missing/forged prev tx, a missing or tampered witness script, a lying derivation, a different owner set, OP_RETURN (single push only), and a change index past the firmware's 1,000,000 limit (sent as a shown output). Mutation checks: switching to PRESERVED order fails 4 tests; a wrong change `address_n` fails 4.
- `web/e2e/trezor-server.mjs` against the real API (CHAIN=memory):
  - Server: a 2-of-3 wallet with mock-device owners. The server's PSBT goes through builder → firmware model → merge → POST. The **server accepted the signatures** (2 of 2), and the device's rebuilt txid equals the server's unsigned txid. Execute → mine → **confirmed**.
  - Browser: "Add from Trezor" and "Sign with Trezor" with no Suite reachable show **"Trezor not connected"** (screenshots 16, 17). The test blocks `*.trezor.io`, because Connect falls back to Suite Web even when pinned to `suite-desktop`.
- `web/e2e/walkthrough.mjs` still passes, and so do `cargo test --workspace` (**73 passed, 0 failed, 1 ignored**), `check-watch-only.sh`, `tsc` and `next build`.

**Adversarial review** (fresh-context agent, checked against trezor-suite@develop `packages/connect-core` and trezor-firmware@main):
- Confirmed: xpub-string multisig nodes converted with the coin's network; `pubkeys_order` passed through (old firmware that ignores it fails safe with "Input does not match scriptPubKey"); `rootFingerprint` is the big-endian master fingerprint; failures are `{error:{message,code}}` on desktop and web; refTxs are used as given (no backend fetch); signatures are plain DER per input.
- No path found for a malicious server to get an unseen output signed, or a foreign address treated as change.
- Fixed in the follow-up commit:
  - The "check the device" hint was built from the server's JSON; it now comes from our own decode of the PSBT.
  - A missing witness script is now refused before signing (otherwise the user signs and the merge fails).
  - A multi-push OP_RETURN is now refused.
  - A change index above 1e6 is now sent as a shown output.
  - "Forbidden key path" is no longer labeled "wrong network".
  - A code-less Suite Web error no longer shows "undefined".
- Caveat: the reviewer read Suite/firmware `develop`/`main`, not the exact builds a user will run.

**Second source review** (2026-10-07, pinned: trezor-suite@875fc49, trezor-firmware@6ab39e9, plus the installed `@trezor/connect-web` 10.0.1):
- Request shape matches Trezor's own e2e fixture `packages/connect-core/e2e/__fixtures__/signTransactionMultisigPubkeysOrder.ts`: `coin: 'test'`, xpub-string `node`s with `address_n: [chain, index]`, `signatures: ['', …]`, numeric `pubkeys_order`, `refTxs`, result = DER hex without the sighash byte. Xpub strings → HDNodeType: connect-core/src/utils/hdnodeUtils.ts:99-113. `pubkeys_order` is in the protobuf schema (packages/protobuf/src/definitions/messages-bitcoin.ts:135), and bufbuild `fromJson` accepts the numeric enum. Signatures are indexed by input: api/bitcoin/signtx.ts:224-235. Firmware DER: core apps/bitcoin/common.py:127-133.
- Change: change_detector.py `output_is_change` needs a single-path multisig (common.py:287-295), the same fingerprint (multisig.py:15-48, nodes sorted when LEXICOGRAPHIC), the same wallet path (address_n minus 2), chain ≤ 1, index ≤ 1e6 and amount > 0. All inputs carry the same owner xpubs, so there's no per-input fingerprint mismatch.
- getPublicKey: `xpub` is re-encoded to the coin's network (tpub) and `xpubSegwit` holds the Vpub/vpub form; `rootFingerprint` = firmware `root_fingerprint` (connect-core/src/device/DeviceCommands.ts:100-118). Every mapped error code exists in connect-common 10.0.1 `constants/errors.js`, and the `Failure_*` codes in connect-core.
- **Fixed** (old firmware): the fixture's `legacyResults: ['<2.8.7']` shows old firmware *silently ignores* `pubkeys_order`. Our P2WSH inputs then fail on the device with "Input does not match scriptPubKey" (core sign_tx/bitcoin.py:277-278), or the signature fails our merge check. Both used to show a generic "Trezor error"; they now map to `unsupported`, so the UI shows the firmware ≥ 2.8.7 / 1.13.0 hint. Unit test: `firmware < 2.8.7 ignores pubkeys_order…`, with the mock modeling the dropped field.

**UNVERIFIED (needs a real Trezor):**
- End to end on a real device + Suite build. The request shape, `pubkeys_order` pass-through, refTxs-as-given and the signature shape are now confirmed from source (above), not by observation.
- That a production Suite build (not `develop`) lets a third-party origin sign with coin `test` without extra settings. The source shows no gate.
- That the device shows only the recipient + fee, with change hidden. The source logic agrees; the screen itself hasn't been observed.
- Legacy (Model One) behavior on old firmware: whether it fails the input check or signs over the unsorted script. Either way, the merge check refuses it.
- The "cancelled", "wrong network" and "wrong device" UI paths (mapped from Connect error codes, not observed).
- **Emulator:** timeboxed, not run. Trezor publishes only Linux ELF emulator builds (`data.trezor.io/dev/firmware/releases/emulators/`; newest core build is 2.7.0, which is older than the 2.8.7 we need). No VM tooling was available on the dev machine at the time. Also, Connect 10 needs Suite in the loop, so an emulator alone wouldn't exercise this path.

**Gaps:** "Show on Trezor" on Receive is built (2026-10-07, fix-8) but UNVERIFIED on a real device. The Trezor's xpub is not saved as an owner `kind` (the API has no field for it; the signer is identified by xpub at sign time). `package.json` gained a `test` script and `@trezor/connect-web`.

## Login, rate limits, hosted signet deploy (2026-10-07): done

**Auth** (`crates/api/src/auth.rs`, migration `20261007000003_auth.sql`, store `users.rs`). Replaces `API_TOKEN` (now ignored with a warning).
- Users: email + argon2id hash (RustCrypto defaults m=19 MiB, t=2, p=1; hashed on the blocking pool; unknown users still pay one argon2 verify).
- Invite-only: `POST /auth/invites` (admin), `btc-safe-api invite <email> [--admin]`, or the `ADMIN_EMAIL` + `ADMIN_SETUP_TOKEN` bootstrap. Each gives a one-time setup token (SHA-256 stored; single use; re-issuing revokes older ones; redeeming logs the user out everywhere). The bootstrap is idempotent across restarts and can't revive a redeemed token. No open registration.
- Sessions: 32 random bytes in `__Host-bsid` (HttpOnly, Secure, SameSite=Strict, Path=/, 12 h), SHA-256 stored server-side, hourly purge. CSRF: every non-GET needs `X-CSRF-Token` = the session's token (from login/setup/`/auth/me`), constant-time compare.
- Scope: `wallet_members`. Creator becomes a member; any member can add an existing user or remove one (never the last). `/wallets/{id}/…` and `/proposals/{id}/…` go through a deny-by-default middleware: non-members and unknown ids both get 404. **`POST /proposals/{id}/signatures` is now behind login + membership** (DESIGN.md §6.7 had it open; a public deployment shouldn't).
- `DELETE /wallets/{id}` (refused while proposals are queued) and `btc-safe-api delete-user <email>` (refused while sole member of a wallet).
- Signet pin: `CHAIN=esplora` refuses to start unless `NETWORK=signet` and the Esplora's block 0 is signet's genesis; mainnet `NETWORK` is refused in every mode; with a pinned network, wallets on any other network are 400.

**Rate limits** (`ratelimit.rs`): in-memory token buckets, per client IP on every route (300/min, burst 120), per user on logged-in routes (600/min, burst 200), login/setup per IP and per email (10/min, burst 5). 429 + `Retry-After`. The IP comes from `CLIENT_IP_HEADER` (last entry) when set, else the TCP peer. Per process (one API instance).

**Web**: `/login`, `/setup` (token read once, then removed from the URL; `Referrer-Policy: no-referrer`), `AuthGate` on every page (redirect to `/login?next=`, same-site `next` only), logout in the top bar, Settings → Advanced → Members, "Invite a user" on the start page for admins. The token/localStorage code is gone; the CSRF token is kept in memory only. Headers: X-Frame-Options DENY, nosniff, HSTS (prod), no `x-powered-by`.

**Tests**: `cargo test --workspace` = **89 passed, 0 failed, 1 ignored** (+11 in `crates/api/tests/auth.rs`: 401 on every route class, cross-wallet 404 on 14 routes incl. signatures/execute/delete, CSRF missing/wrong/other-session, argon2id format + salting + verify, invite → setup → login → logout → reset, admin-only invites + bootstrap one-shot, login 429 per IP and per email, per-IP and per-user 429, network pin + wallet delete, insecure-cookie dev mode, delete-user). Mutation check: disabling the membership check or the CSRF check makes the matching test fail. `npm test` 16 pass, `tsc` + `next build` clean. Browser (system Chrome, CHAIN=memory): `walkthrough.mjs` passes logged in; new `e2e/auth.mjs` passes (guard redirect, wrong password, admin invite → setup link → logged in with an HttpOnly+Strict cookie not visible to JS, link single-use, logout); `trezor-server.mjs` passes. **Not re-run:** `ledger-speculos.mjs` / `ledger-browser.mjs` (need the Speculos VM); they were updated to log in the same way.

**Hosted signet instance** (2026-10-07): three services (Postgres with no public access, `api` from the root `Dockerfile`, `web` from `Dockerfile.web` proxying `/api/*` over a private network). Verified live: health; unauthenticated `/api/wallets` 401; CORS allows only the web origin; setup → `__Host-bsid` with HttpOnly/Secure/SameSite=Strict; setup token single-use (404 on reuse); logout kills the session; login 200; write without CSRF 403; mainnet wallet 400; wallet from testkit xpubs created, synced against mempool.space signet, receive address #0 = first_addresses[0]; second user gets 404 on it; wallet deleted (204, then 404); bad logins → 429 + Retry-After; spoofed `X-Real-IP`/`X-Forwarded-For` → 429 after the burst (the platform's edge overwrites `X-Real-IP`); Chrome on the web URL: `isSecureContext` true, `navigator.hid` present, guard redirects to /login. Smoke accounts deleted with `delete-user`. Not verified live: a funded signet send end to end on the hosted instance, Ledger/Trezor against the hosted origin. Idle footprint: api 170 MB, web 62 MB, Postgres 130 MB.

## USD display (2026-10-07): done

- `GET /price` (session required) → `{usd, source, fetched_at, stale}`. Server-side fetch from mempool.space mainnet `/api/v1/prices` (`USD`), falling back to Coinbase spot (`data.amount`, checked `BTC`/`USD`). 60 s cache, at most one fetch per TTL; on failure the last good value comes back with `stale: true`, or 503 if there never was one. Display only: nothing in validation or fees reads it (`crates/api/src/price.rs`; 6 unit tests against a local mock HTTP server).
- Web: `components/price.tsx` (`PriceProvider`, `<Usd>`, `<UsdNote>`), `usd()` in `lib/format.ts`. `≈ $X.XX` on the sidebar and Home balances, Home queue rows, Assets (rows + selection total), Send amount (live), Review (amount, change, fee), transaction rows/details and the Execute modal; `< $0.01` for tiny amounts; hidden when no price. Note under the balance: "USD at mainnet BTC price · signet coins have no real value".
- Verified live 2026-10-07: `/price` 83051 (mempool.space) vs Coinbase 82995.33 (0.07%); demo wallet 10,000 sats shows ≈ $8.31.

## Real device test (not yet done)

Common setup: run the API against signet (`ESPLORA_URL` default; CHAIN=memory for a dry run), then `cd web && npm install && npm run dev`, and open http://localhost:3000 in **Chrome or Edge** (WebHID needs a secure context; localhost counts). Fund from a signet faucet.

**Ledger**
1. Ledger Live ("Ledger Wallet") → Settings → Experimental features → **Developer mode** ([docs](https://developers.ledger.com/docs/ledger-live/discover/references/developer-mode)). Install **Bitcoin Test** ≥ 2.1, update firmware if asked, then quit Live (it holds the USB interface).
2. Unlock the device, open Bitcoin Test. Create account → Owners → **Connect Ledger** on owner 1, pick it in Chrome's prompt, add the other owners, create, back up the BSMS.
3. Settings → Ledger → **Register on connected Ledger**. Check name, "2 of 3" and every key against the Owners table, approve.
4. Receive → **Show on Ledger**: the device address must match the page. Fund it.
5. New transaction → step 3 → **Ledger (USB)** → **Sign with Ledger**. Check recipient, amount, fee on the device; sign. Expect "1 of 2".
6. Note what differs from Speculos: the WebHID permission prompt, Live open, device locked, dashboard open instead of the app (these states are unverified).

**Trezor**
1. In Trezor Suite, update firmware (core ≥ 2.8.7 / Model One ≥ 1.13.0). Keep Suite desktop open, or let the Suite Web popup open in Chrome/Edge/Brave. You do **not** need to enable "Bitcoin Testnet" in Suite: the source review found no such gate for `signTransaction` (see the Trezor section). If a real Suite build disagrees, record it.
2. Create account → Owners → **Add from Trezor** on an owner, approve in Suite. The fp must match Suite's (or Sparrow's) for `m/48'/1'/0'/2'`.
3. Fund the first address, wait for a confirmation, create a send that has change.
4. Step 3 → **Trezor** → **Sign with Trezor** → approve. The device should show only recipient + fee. If it shows the change address as a send, stop: change detection failed. Note the screen.
5. Also try: cancel on the device (expect "Cancelled") and a Trezor that isn't an owner (expect "Wrong Trezor").

**Both:** a wallet with a Ledger owner and a Trezor owner is the best single test. Sign once with each → Execute → confirm on a signet explorer.

## Not done / stubbed

- **Frontend gaps:**
  - No UI for replacements (RBF bump/cancel/rebuild); the API supports them.
  - No camera QR *scanning*: signed PSBTs return by file or paste only, and the QR is display-only.
  - "Show on Trezor" (receive) is built but UNVERIFIED on a device (see "Fix-8"); Ledger and Trezor signing are done (see above). ETH approvals are hidden (v2).
  - Testnet4/mainnet radios are disabled; no fiat price; no Notifications/Appearance tabs; not responsive on mobile.
  - The browser cross-check doesn't verify signatures, doesn't check that inputs are ours, and doesn't compare per-owner signature counts with the server.
  - There are no web unit tests; coverage is the e2e script plus `tsc`.
    - The device menu paths on the Receive screen are unverified.
- **Real signers (Phase 3).** Not tested with Sparrow, Coldcard or Jade. The PSBT carries `non_witness_utxo`, `witness_script`, `bip32_derivation` and global xpubs, but device acceptance is **unverified**. MemoryChain doesn't run Script, so script validity is checked by our verifier plus miniscript's interpreter, never by a node, until a real signet spend happens.
- **Auth gaps** (after the 2026-10-08 public-auth work, below): no email delivery or verification (email is a username; setup links are handed over manually; self-registered accounts are flagged and sharing to them needs confirmation); no passkeys/WebAuthn; TOTP secrets stored raw in Postgres (no app-level encryption key); no admin UI to delete/promote users or list sessions (CLI only: `invite`, `promote`, `delete-user`); no per-wallet caps on members, proposals, labels or address-book entries (only per-user rate limits bound them); a determined attacker rotating IPs can use up the global signup bucket (60/h) and, over ~17 h, `MAX_USERS`; a brand-new browser waits out an account's login backoff (≤ 15 min at a time) while it's under attack; `next start` page responses that are Next prefetches skip the proxy (and so the CSP), as in Next's documented pattern.
- **Rate limits** are per process and in memory: a restart resets them, and >1 API replica would multiply them.
- **Electrum** chain source: not implemented (Esplora only). No OpenAPI document.
- **Reorg depth:** finality is depth-based (`CONFIRMATIONS_FINAL`, default 2). A reorg deeper than that, after a proposal went final, isn't noticed (by design: final is never re-checked). 2 is thin for mainnet; use 6 there.
- **Esplora load:** each watcher tick costs one `outspend` call per input of every active proposal, plus a full scan every 10th sync. Untested at scale against the public endpoint's rate limits.
- **BIP-329 labels**, fee-estimate caching, and audit-log read endpoints: not done.
- **Strict-order limits:** a send-max (changeless) tail can't be chained on (409). Switching ordering mode requires an empty queue.
- Change indices are allocated per proposal and burned if no change is produced (small gaps, within the stop gap).

## Environment notes

- Postgres DBs `btc_safe_dev` (manual runs) and `btc_safe_test` (tests). Socket at /tmp.

## How to resume

1. `cargo test --workspace && ./scripts/check-watch-only.sh`
2. Frontend: `cd web && npm install && npm run dev` (API on :8080). E2E: `cargo build -p btc-safe-testkit --example testsigner`, `web/e2e/reset-dev.sh` (**drops and recreates btc_safe_dev**, restarts the API with CHAIN=memory and COOKIE_SECURE=false, and creates the dev admin dev@btcsafe.local / devpassword-123), `npm run dev`, then `node e2e/walkthrough.mjs`. Next frontend work: an RBF/replace UI, QR scanning, and e2e coverage for the untested buttons above.
3. Phase 3: run the API against signet (default `ESPLORA_URL`). Import a 2-of-3 from Sparrow (BSMS or Caravan export), fund it from a signet faucet, sign in Sparrow plus one device, and execute. Then do the adversarial pass on the real-device PSBTs.
4. Before mainnet: external review of `core::validate`, rate limiting, real auth; raise `CONFIRMATIONS_FINAL` (6).

## Dark mode (2026-10-07): done
- Settings > Appearance (wallet settings tab) and Home > Settings > Appearance: System / Light / Dark. Per browser (localStorage `btcsafe.theme`; System = no key). No backend change.
- `THEME_INIT_SCRIPT` (web/lib/theme.ts) sets `<html data-theme>` in `<head>` before first paint; `ThemeSync` follows OS changes while on System.
- Palette is CSS tokens in globals.css; dark set under `:root[data-theme="dark"]`. `.qrbox` pins dark-on-white in both themes.
- web/test/theme.test.mjs: resolver + persistence, runs the init script for every case, and checks every text/surface token pair for WCAG AA in both palettes. To pass it, light `--muted`, `--faint`, `--warn`, `--ok` got slightly darker, `.linkbtn` uses a darker `--link`, and text on amber is now dark (white on amber was 2.7:1).
- Verified live (web/e2e/dark-live.mjs, read-only): first animation frame after reload is already dark (bg #121312), receive QR box is white.
- Not seen live in dark: the animated PSBT QR, Ledger/Trezor modals and the red mismatch banner (no active proposal on the demo wallet). They use the same tokens/classes the contrast test covers.

## Fix-8 (2026-10-07): 8 known bugs fixed, deployed, verified live

Live check: `web/e2e/fix8-live.mjs` (demo user, demo wallet only; creates one tiny proposal, never signs it, deletes it). 14/14 checks passed on the hosted signet instance.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | "Proposed by" was a client-chosen owner name | Server sets `created_by` = logged-in email; a `created_by` naming anyone else → 400. Signatures, execute, delete, ordering and Ledger (un)registration audit the user's email (were `"api"`/`"signer"`). Send page shows "Proposed by: <email>"; queue rows show the proposer. Test `auth.rs::proposer_and_audit_actor_are_the_logged_in_user`. | live-verified (API 400 on spoof, stored + shown proposer) |
| 2 | Fee warning rendered as raw JSON | `lib/warnings.ts`: a sentence for every kind (`high_share_of_sent`, `no_fast_estimate`, `cap_overridden`, `strict_order_descendants`, `change_path_assumed`, `single_sig_path`, `non_standard_path`), readable fallback for unknown kinds. Test parses the Rust enums so a new variant without a sentence fails. | live-verified ("Fee is 37.8% of the amount sent …") |
| 3 | Caravan/BSMS/descriptor pasted into "Paste all owners" errored | Detected (`lib/import-sniff.ts`) and moved to Import with a notice | live-verified |
| 4 | Import's Name defaulted to "Treasury" and overrode the file | Import has its own Name, prefilled from the file's `name` until edited; empty → server uses the file's | live-verified |
| 5 | Import was paste-only | "Wallet file" picker (.json/.txt/.bsms, 512 KB cap) | live-verified |
| 6 | No Receive link in the sidebar | Added | live-verified |
| 7 | Send-page Trezor button didn't wait for the PSBT cross-check | `TrezorSign disabled={!check?.ok}` on send + queue; handler also refuses. Source test pins the gate on all 4 hardware sign call sites. | live: queue buttons disabled on a tampered PSBT; send-step-3 enabled after a passing check. The send-page disabled state itself isn't reachable live (step 3 needs a passing check), so it rests on the source test. |
| 8 | "Show on Trezor" was a disabled placeholder | Connect `getAddress` with `showOnTrezor`, `SPENDWITNESS`, the device's full path, the signer's multisig (owners' xpubs at [chain, index], m, LEXICOGRAPHIC) and `address` (Connect fails on mismatch). Built only after this browser re-derives the address. Params checked against `@trezor/connect-common` 10.0.1 `getAddress.d.ts`. Test: the request's multisig derives our address and contains the device's own key. | **UNVERIFIED on a real Trezor.** Live: with no Trezor, the page shows "Trezor not connected" + "Not verified on a device", never a ✓. |

Tests after: `cargo test --workspace` 96 passed / 1 ignored; clippy clean; watch-only OK; `npm test` 38 passed; typecheck and `next build` clean.

## Reorgs: soft and final confirmations (2026-10-08): done

Decision: 1 confirmation = soft, 2 = final. The watcher used to mark `confirmed` at 1 confirmation and never look again.

**State machine** (`core::state`): new `soft_confirmed` (1..N-1 block confirmations) between `broadcast` and `confirmed`; `confirmed` now means final (≥ N). N = `CONFIRMATIONS_FINAL` (env, default 2, integer ≥ 1, else the API refuses to start; default only in `watcher::DEFAULT_CONFIRMATIONS_FINAL`). `soft_confirmed` is active: it keeps its reservations, stays in the queue, and is re-checked every tick. It can go to `confirmed`, back to `broadcast` (`Event::Reorged`), or to `invalidated`/`conflicted`; it can't be deleted, executed or replaced (409 `already_confirmed`). `confirmed` is never looked up again.

**Watcher** (`watcher::reconcile`): tip read once, before any tx lookup (a race can only understate depth). Own tx at depth ≥ N → `confirmed`; < N → `soft_confirmed` (a move to another block updates the height, audited `confirmation_moved`). Soft + tx back in mempool → `broadcast` (`reorged_back_to_mempool`); soft + tx gone and no conflicting spend → `broadcast` (`reorged_out`), then `ready` next tick if still gone (`dropped_from_mempool`), so it can be re-sent. Soft + input spent by someone else → `invalidated`, coins released, strict-order descendants cascaded. **Changed rule:** a sibling replacement now makes a proposal `conflicted` only when the sibling is *final*; before, a bump with 1 confirmation killed the original for good, and a reorg that let the original win left it `conflicted`. Reservations are never released and re-taken across a rollback, so a rollback can't fail on the exclusion constraint. Every transition writes a `proposal_status` audit row. Locking unchanged (chain reads lock-free; row lock → proposal lock; stale-snapshot skip).

**Migration** `20261008000001_soft_confirmed.sql`: status CHECK and the active-txid unique index gain `soft_confirmed`. Existing `confirmed` rows are demoted to `soft_confirmed` (their depth was never checked), their input reservations re-activated only where no other active group holds the coin (can't violate the EXCLUDE constraint), and an audit row is written (actor `migration`, reason `reverify_after_upgrade`). The next tick re-verifies each: deep → `confirmed` again, reorged → `broadcast`. Checked on a clone of the local dev DB (2 confirmed rows → soft, reservations active, 2 audit rows).

**API**: proposal JSON has `block_confirmations: {count, final_at, final}` (depth from the wallet's synced tip); wallet JSON has `confirmations_final`. `/dev/reorg {depth, back_to_mempool}` on CHAIN=memory.

**UI**: "1 block confirmation, waiting for final" (amber) in the queue row, Home queue and detail; "Final" (green) in history and detail; a reorged proposal reads "Reorged, waiting to be mined again" or "Reorged, not in a block", with a plain explanation under the status. Detail shows "Block N · k block confirmations · final at N" and signer-panel steps Executed → In a block → Final. The queue has a "Sent, waiting for final" group; the on-chain history table shows "Block N · 1 block confirmation, waiting for final" until final. Wording says "block confirmation" because the UI already uses "confirmations" for owner signatures.

**MemoryChain**: `reorg(depth, back_to_mempool)` (later blocks get new hashes), `mine_with(txs)`, `lookups()`.

**Tests** (before → after): `cargo test --workspace` 96 → **104 passed**, 1 ignored; `npm test` 38 → **42**. New in `crates/watcher/tests/reconcile.rs`: 1 conf → soft, 2 → final (with audit trail); soft → reorged back to mempool → reconfirmed; soft → reorged out and gone → broadcast → ready → re-sent → final, reservations held throughout; soft → foreign double spend wins → invalidated, only its coins released; soft → own bump wins → original back to broadcast, then conflicted when the bump is final; strict-order cascade from a soft predecessor; a final proposal is never looked up again (via `lookups()`), even after a 3-block reorg; `CONFIRMATIONS_FINAL` parsing and 3 / 1 honored. Updated: e2e (soft → `/dev/reorg` → broadcast → final over HTTP), adversarial review (delete/execute/sign/bump/cancel refused at soft *and* final). `web/test/chain-status.test.mjs` (labels; every Rust status has one, read from `state.rs`).
Mutation check (each reverted after): Reorged keeps soft → 3 tests fail; no rollback when gone → 2; no rollback when back in mempool → 1; sibling conflicts on a soft confirmation → 2; threshold hardcoded to 2 → 1; soft not active → 8.
Browser: `walkthrough.mjs` passes with a new step 8b (soft → `/dev/reorg` → "Reorged…" → 2 blocks → "Final"; screenshots `11b-soft-confirmed.png`, `11c-reorged.png`, `11d-final.png`); it needed two locator fixes for fix-8's UI changes (sidebar Receive link, import textarea label). `trezor-server.mjs` and `auth.mjs` pass. `ledger-*.mjs` updated (mine 2 blocks) but not re-run (Speculos VM).


**Deployed** 2026-10-08 to the hosted signet instance. Verified live, read-only: health OK (signet tip 325508); API log `final after 2 confirmation(s) confirmations_final=2`; the migration ran, and on its first tick the watcher re-verified the one previously-`confirmed` proposal (#3) back to `confirmed` (log `ch=[(3, Confirmed)]`). Demo user: wallet, queue, history and proposal detail render (200s, no page errors), proposals carry `block_confirmations`, the wallet carries `confirmations_final: 2`, on-chain rows deeper than 2 show plain "Block N". Unauthenticated `/api/wallets` is still 401.
Not seen live: the soft/"Reorged" chips (no proposal in flight on the hosted instance, and signet reorgs are rare); proposal #3's new status row (not visible to the demo user; only the log line). Possible edge on Esplora: tip and tx status may come from different backend nodes behind mempool.space, which could mis-state depth by a block during a node lag; not observed.

## Public signup + auth hardening (2026-10-08): done

Details: docs/ARCHITECTURE.md §6.1–6.3, README "Accounts" + env table.

- **Signup** behind `OPEN_SIGNUP` (default off): email as username (said in the UI: no verification, no email ever sent), 12+ chars, bundled list of 46,815 common/breached passwords of 12+ chars (SecLists, MIT; `crates/api/data/common-passwords.txt`), not one repeated char, not mostly the email. Bot speed bump: HMAC-signed proof-of-work challenge (`SIGNUP_POW_BITS`, default 20; spent once in `pow_spent`) + honeypot field. Caps: `MAX_USERS`, `MAX_WALLETS_PER_USER`, `RATE_SIGNUP` per IP (/64 for IPv6), `RATE_SIGNUP_GLOBAL`. Signup never touches an existing row (no takeover of invited-but-unused accounts). Invite flow and CLI unchanged; new `promote` CLI.
- **Rate limits in Postgres** (`rate_limits`, one atomic upsert per check), shared across processes; refusals spend nothing; fail closed on DB error. Same 429 + `Retry-After`.
- **Failed logins audited** (`login_failed` with ip + reason). Per-account exponential backoff (`LOGIN_BACKOFF`, 5 free, 1 s doubling to 15 min) with a known-device cookie (`__Host-bsdev`) that exempts browsers that logged in before, so an attacker can't lock the owner out. Applies to the 2FA step too.
- **Sessions:** new id on every login/signup/setup (incoming session dropped); all sessions replaced on password change and 2FA on/off; `SESSION_HOURS` (12) absolute + `SESSION_IDLE_MINS` (30) idle; `POST /auth/logout-all`; becoming server admin ends sessions.
- **Password change** (`/account`): current password required, other sessions revoked, pending reset links revoked. Wrong answers on account pages count per session (5 → session ends), not against the account.
- **TOTP 2FA** (optional) + 10 one-time recovery codes (SHA-256(user‖code)); replay-proof (last accepted step), one open login challenge per account (5 tries, 5 min). UI says recovery codes are the only self-service way back; admin reset = `invite` (clears 2FA).
- **Roles** admin/proposer/viewer (`crates/api/src/roles.rs`, deny-by-default). Execute = proposer+ (signatures are the authorization). Proposers delete only their own proposals; only admins change settings, delete the wallet, manage members. Existing members migrated to admin; new shares default to viewer; last admin protected. Sharing UI with roles in Settings → Sharing.
- **Headers:** API: `default-src 'none'` CSP, nosniff, DENY, no-referrer, Permissions-Policy all off, HSTS. Web: per-request nonce CSP via `web/proxy.ts` (`'strict-dynamic'`; `frame-src https://suite.trezor.io` and `connect-src ws://127.0.0.1:21335` for Trezor Connect 10; WebHID needs none), HSTS, `Permissions-Policy: hid=(self), usb=(self)`, COOP `same-origin-allow-popups`.

**Adversarial review** (fresh-context sub-agent, exploit tests run against the real router + Postgres). Found and fixed, each with a `fixed_*` regression test in `crates/api/tests/hardening.rs`:
1. HIGH: sign up under the email an admin is about to invite as admin → server admin → reset the real admin. Fix: invite/bootstrap never promote an existing account with a password or a self-signup; `promote` CLI for deliberate upgrades; bootstrap refusal is logged, not fatal.
2. MEDIUM: pre-registered (squatted) email gets wallet access when shared. Fix: `self_signup` flag; sharing to such an account needs `confirm_unverified` (UI confirm dialog), list shows "self-registered"; share calls rate-limited.
3. MEDIUM: TOTP guesses ignored the backoff and could be spread over stockpiled challenges. Fix: one open challenge per account, backoff + per-account bucket on the code step.
4. MEDIUM: an outsider's failed logins blocked the logged-in owner from changing password/2FA. Fix: reauth skips the account lock; per-session failure count ends a stolen session after 5 wrong answers.
5. LOW: device trust survived password change/reset/logout-all. Fix: revoked (this browser re-trusted).
6. LOW: viewers could move the receive index via `GET …/addresses?next=true`. Fix: proposer+ (UI hides "New address").
7. INFO: non-ASCII (look-alike) signup emails refused; password change revokes pending reset links.
Checked sound by the reviewer: fixation/rotation, CSRF on every write, cross-wallet IDOR incl. path tricks, SQL bucket under concurrency, TOTP/recovery races, PoW forgery/replay, dummy-hash timing.

**Tests:** `cargo test --workspace` 96 → **139 passed, 0 failed, 1 ignored** (the 96 was before this work; after rebasing onto the reorg work, 104 of the 139 are pre-existing/reorg tests and 35 are new: 27 in `tests/hardening.rs` + 8 unit tests incl. RFC 6238 vectors). Two existing tests in `tests/auth.rs` now pass `"role": "admin"` when sharing (they exercise admin actions; shares default to viewer now), and `delete_user_refused_while_sole_member` additionally checks that a viewer doesn't count as a second admin. Mutation check: 29 targeted mutations (each check disabled in turn: role gate, TOTP replay, recovery reuse, backoff, device bypass, login rotation, idle timeout, honeypot, PoW spend, last admin, signup takeover, own-proposal delete, bucket refusal, password-change revocation, wallet cap, MFA gate, user cap, CSP header, failed-login audit, challenge attempts, and the 9 review fixes) → every one makes a test fail. clippy + watch-only OK. Web: `npm test` **53 pass** (38 before; +11 here: CSP builder, PoW vs node:crypto, roles; +4 from the reorg work), `tsc` and `next build` clean. Browser (system Chrome, CHAIN=memory, `next start` production build): `walkthrough.mjs`, `auth.mjs` (signup w/ PoW, weak password refused, TOTP enrol → MFA login → recovery code once, log out everywhere, password change), new `roles.mjs` (viewer/proposer/admin UI + forced 403, self-registered share confirmation, last-admin 409), new `csp.mjs` (CSP + nonce on /signup, /account, /new, wallet, send, settings with zero violations; `navigator.hid`; Trezor Connect iframe from suite.trezor.io loads with no violation; `/api/price` 200), `trezor-server.mjs` all pass. Not re-run: `ledger-speculos.mjs` / `ledger-browser.mjs` (need the Speculos VM).

**Deployed** 2026-10-08 to the hosted signet instance with `OPEN_SIGNUP=1`, `MAX_USERS=500`, `MAX_WALLETS_PER_USER=10` and the other defaults; `SIGNUP_SECRET` set. Migration `20261008150000_auth_hardening` applied on start; existing members became admins.

**Live check** (system Chrome, throwaway accounts `live-a/live-b-…@example.test`, script kept outside the repo): 21/21 — signup with 20-bit PoW in the browser (~2 s) lands logged in; `__Host-bsid` HttpOnly+Secure+Strict and `__Host-bsdev` set; CSP with nonce + HSTS + `frame-ancestors 'none'` + Permissions-Policy on pages; `navigator.hid` present in a secure context; TOTP enrolled from /account with 10 recovery codes; password-only login now returns `mfa_required` with no session; TOTP login works; A's signet wallet (testkit xpubs) shared to B as viewer through the UI (self-registered confirmation shown); B as viewer gets 403 on propose, share, wallet delete and address allocation, and sees no send form; `/api/price` 200 under the CSP; zero CSP violations across 6 pages. Spoofed `X-Real-IP`/`X-Forwarded-For` don't escape the per-IP signup bucket (400 then 429s). Wallet deleted (204), both accounts removed with `btc-safe-api delete-user` (login → 401). API headers on `/health` checked.
