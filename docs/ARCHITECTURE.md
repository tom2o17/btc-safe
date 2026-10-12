# btc-safe: how it works

This is the deep dive. The [README](../README.md) has the quick start, env vars and endpoint list.
Everything here was read from the code at the time of writing; where the code and
[DESIGN.md](../DESIGN.md) or [PROGRESS.md](../PROGRESS.md) disagree, this file follows the code
and says so.

Contents:
1. [Big picture](#1-big-picture)
2. [Lifecycle of a proposal](#2-lifecycle-of-a-proposal)
3. [Wallet model](#3-wallet-model)
4. [Persistence](#4-persistence)
5. [Chain layer](#5-chain-layer)
6. [Auth and security](#6-auth-and-security)
7. [Hardware signing](#7-hardware-signing)
8. [Frontend structure](#8-frontend-structure)
9. [Deployment](#9-deployment)
10. [Testing](#10-testing)
11. [Known gaps and limits](#11-known-gaps-and-limits)

---

## 1. Big picture

btc-safe is a **watch-only coordinator**. The server knows each owner's xpub, fingerprint and
origin path, builds unsigned PSBTs, collects signatures, and broadcasts once a threshold is met.
It never holds or derives a private key, and it never signs. Owners sign on their own devices
(Ledger, Trezor, or anything that reads a PSBT file or animated QR).

The watch-only rule is enforced mechanically, not just by convention:

- [`clippy.toml`](../clippy.toml) disallows private-key types (`PrivateKey`, `Xpriv`, `SecretKey`,
  `Keypair`, `DescriptorSecretKey`, `KeyMap`, BDK's `SignersContainer`) and signing methods
  (`Psbt::sign`, `Wallet::sign`) across the workspace.
- [`scripts/check-watch-only.sh`](../scripts/check-watch-only.sh) runs clippy with `-D warnings`,
  fails if any crate other than `crates/testkit` opts out of the lint, and checks that `testkit`
  (throwaway test keys) is only ever a dev-dependency and isn't reachable from the API binary.
- [`crates/wallet/src/lib.rs`](../crates/wallet/src/lib.rs) `public_only()` rejects a descriptor
  string that contains private key material before handing it to BDK.

### Request flow

```
  Browser (Next.js app, web/)
  │  - decodes every PSBT itself, re-derives change/receive addresses from xpubs
  │  - talks to Ledger (WebHID) / Trezor (Connect → Suite) / file / QR
  │
  │  same-origin fetch /api/*  (cookie: session, header: X-CSRF-Token)
  ▼
  Next.js server  ── rewrite /api/:path* → $BTC_SAFE_API/:path*   (web/next.config.ts)
  │
  ▼
  axum API  (crates/api)
  │  per-IP rate limit → require_user (session + CSRF + per-user limit)
  │  → require_membership (wallet scope, deny by default) → handler
  │
  ├──► core     pure logic: policy/descriptors, import, PSBT build + validation,
  │             fee checks, state machine            (crates/core, no I/O)
  ├──► wallet   watch-only bdk_wallet: coin selection, change, RBF  (crates/wallet)
  ├──► watcher  wallet cache, sync, reconcile proposals with chain  (crates/watcher)
  │             also runs as a background loop every SYNC_SECS
  ├──► store    Postgres via sqlx: wallets, proposals, reservations, users  (crates/store)
  └──► chain    ChainSource trait: Esplora (signet) or MemoryChain (simulator)  (crates/chain)
```

The browser only ever talks to its own origin; the Next.js server proxies `/api/*` to the Rust
API ([`web/next.config.ts`](../web/next.config.ts)). That's why the API needs no CORS in the
hosted setup (`CORS_ORIGINS` exists for other setups).

### Crates

| Crate | Role | I/O |
|---|---|---|
| `crates/core` | `WalletPolicy`, descriptors, import/export, PSBT build + validation, fee policy, Ledger policy ids, state machine | none |
| `crates/wallet` | `SafeWallet`: BDK wallet from public descriptors, `build_proposal`, `bump_fee`, `build_cancel` | none (operates on in-memory BDK state) |
| `crates/chain` | `ChainSource` trait, `Esplora`, `MemoryChain` | network |
| `crates/store` | sqlx repositories, migrations | Postgres |
| `crates/watcher` | `WalletCache`, `sync_wallet`, `reconcile`, `apply_event`, strict-order cascades, background `run` | Postgres + chain |
| `crates/api` | axum router, auth, rate limits, handlers, CLI (`invite`, `delete-user`) | all of the above |
| `crates/testkit` | TEST-ONLY deterministic keys and the `testsigner` example | dev-dependency only |

### Locking

[`crates/watcher/src/lib.rs`](../crates/watcher/src/lib.rs) documents one lock order used
everywhere, API included: **wallet row lock** (`store::lock_wallet`, `SELECT … FOR UPDATE` inside a
DB transaction) **→ wallet mutex** (the in-memory BDK wallet in `WalletCache`). The persisted BDK
changeset is only written inside the transaction that holds the row lock. Every handler that
mutates a wallet or proposal opens a transaction, takes the row lock, then the proposal row lock
(`lock_proposal`), and commits at the end.

---

## 2. Lifecycle of a proposal

### 2.1 Create — `POST /wallets/{id}/proposals`

Handler: `create` in [`crates/api/src/proposals.rs`](../crates/api/src/proposals.rs) (line 64).

1. **Fee rate.** `fee_rate_sat_vb` must be in (0, 10000]; if absent, the chain source's "normal"
   estimate is used, and the request fails if there is none.
2. **Proposer.** `created_by` is always the logged-in user's email. A body that names anyone else
   gets a 400 rather than being silently rewritten.
3. **Outputs.** Each address must parse for the wallet's network; amounts must be > 0 (unless
   `send_max`) and ≤ 21M BTC, in total too; at most 1000 outputs.
4. **Mode.** `new`, or for a replacement (`replaces: <id>`) one of `rebuild` (new outputs, same
   coins), `bump` (RBF fee bump) or `cancel` (send the coins back to ourselves). Default for a
   replacement is `bump` if the original is broadcast, else `rebuild`. `rebuild` is refused once
   the original is broadcast.
5. **Strict-order chaining** (only when the wallet's `ordering_mode` is `strict`, see 2.8).
6. **Reservations.** `store::reserved_outpoints` returns every outpoint held by an *active*
   proposal of this wallet, except those of the replacement's own group. These are passed to BDK
   as `unspendable`, and checked again after BDK returns ("never trust it blindly").
7. **Change index.** A fresh internal index is allocated with
   `UPDATE wallets SET next_change_idx = next_change_idx + 1 … RETURNING` (`store::alloc_index`).
   Change indexes are never reused, even if the proposal is later deleted.
8. **Build.** `SafeWallet::build_proposal` ([`crates/wallet/src/lib.rs`](../crates/wallet/src/lib.rs)
   line 269) lets BDK select coins (`add_recipient` + `drain_to(change)`, or `drain_to(recipient)`
   + `drain_wallet` for send-max), honouring coin control (`utxos`, `manual_only`), `rbf`
   (default on: `ENABLE_RBF_NO_LOCKTIME`; off: `ENABLE_LOCKTIME_NO_RBF`), and the reservation
   set. **BDK's PSBT is thrown away**: only its unsigned tx is kept, and the PSBT is rebuilt from
   our own derivations (2.2).
9. **Replacement checks.** The new tx must share at least one input with the original. If any
   member of the replacement group is already broadcast, the new fee must exceed what the
   broadcast evicts (that member's fee plus any broadcast strict-order descendants) by at least
   1 sat/vB × vsize (BIP-125 rules 3/4), else 422 `fee_too_low`.
10. **Fee policy.** `core::fees::check_fee` ([`crates/core/src/fees.rs`](../crates/core/src/fees.rs)):

    | Check | Default | Result |
    |---|---|---|
    | Absolute fee cap | 0.01 BTC (1,000,000 sats) | error, or warning `cap_overridden` with `fee_override` |
    | Fee rate vs "fast" estimate | > 10× fast | error, or warning `cap_overridden` with `fee_override` |
    | No fast estimate available | — | warning `no_fast_estimate` |
    | Fee as a share of recipients' total | > 5% (500 bps) | warning `high_share_of_sent` |

    Weight is estimated assuming every input carries a full M-of-N witness with 73-byte
    signatures (`estimate_weight`), the same bound BDK uses.
11. **Insert.** `store::insert_proposal` writes the proposal, its inputs (which take the
    reservation, see 4.2), outputs and an audit row, then the BDK changeset is persisted and the
    transaction commits. Returns 201 with the decoded proposal and any warnings.

### 2.2 What's in the PSBT

`core::validate::build_canonical_psbt` ([`crates/core/src/validate.rs`](../crates/core/src/validate.rs)
line 235) builds the stored PSBT entirely from the wallet policy and the proposal record, never
from a PSBT someone sent:

| Field | Content |
|---|---|
| global `xpub` | every owner's xpub with (fingerprint, origin path), so multisig signers recognise the cosigner set (BIP-174) |
| input `witness_utxo` | amount + P2WSH script, re-derived at the input's keychain/index |
| input `non_witness_utxo` | the full previous tx (witnesses stripped; they don't affect the txid). Must hash to the outpoint's txid and contain the expected output, else `PrevTxMismatch` |
| input `witness_script` | `OP_M <keys sorted> OP_N OP_CHECKMULTISIG` |
| input `bip32_derivation` | each owner's derived pubkey → (fingerprint, origin path + `/chain/index`) |
| input `sighash_type` | unset (only `SIGHASH_ALL` is accepted on the way back) |
| change output `witness_script` + `bip32_derivation` | same as inputs, at `m/…/1/index`, so devices can recognise change |

Before building, `check_spec` (line 148) validates the record itself: at least one input and
output, tx version 1 or 2, inputs exactly match the recorded outpoints with no duplicates and no
scriptSig/witness, every claimed change output re-derives from the internal keychain at its index,
no dust and no non-standard outputs, no overflow, outputs ≤ inputs.

### 2.3 Signature upload and merge — `POST /proposals/{id}/signatures`

Handler: `add_signatures` (proposals.rs line 312). The body is a base64 PSBT from any signer.

1. Before taking locks: decode; an unknown id and a PSBT whose unsigned tx doesn't match give the
   **same** 422 (`PSBT does not match this proposal`) so ids can't be enumerated by content.
2. Lock wallet + proposal; the proposal must be `pending`, `signing` or `ready`.
3. `validate::validate_submission` (validate.rs line 372). **Any defect rejects the whole
   submission and nothing from it is stored.**
4. New verified signatures are merged into the stored PSBT (`apply_signatures`), written to the
   `signatures` table (one row per owner × input), and `signature_status` re-verifies **every**
   signature in the stored PSBT to decide whether each input has ≥ M.
5. Status moves via the state machine (`SignaturesAdded { ready }`), audited as
   `signatures_added`. Re-submitting signatures already held is accepted and counted as
   `already_present` (idempotent).

What `validate_submission` rejects, and why:

| Rejected | Why |
|---|---|
| Submitted unsigned tx not byte-identical to the stored one, PSBT version ≠ 0, or input/output counts differ | the signer must have signed *this* transaction (`UnsignedTxMismatch`) |
| Stored PSBT's unsigned tx diverged from the proposal record | internal integrity check (`FinalCheck`) |
| `witness_utxo` ≠ our record of the coin (amount + script) | a lying amount changes the sighash and hides the fee (`WitnessUtxoMismatch`) |
| `non_witness_utxo` doesn't hash to the outpoint's txid or doesn't contain our output | same, for devices that read the full prev tx (`NonWitnessUtxoMismatch`) |
| `witness_script` ≠ our derived script | someone else's script (`WitnessScriptMismatch`) |
| `sighash_type` other than `ALL`, or a signature whose sighash byte isn't `ALL` | `NONE`/`SINGLE`/`ANYONECANPAY` signatures let outputs or inputs be changed after signing (`BadSighashType`; `verify_sig` checks the byte too) |
| A non-empty `final_script_sig` | P2WSH inputs never have one (`FinalScriptSig`) |
| A `final_script_witness` that isn't `[<empty>, sig…, witness_script]` with ≤ N signatures, or contains a signature that verifies for no owner | malformed or foreign (`MalformedFinalWitness`). The size check runs before any signature work, so an oversized witness can't buy N verifications per item |
| A signature from a pubkey that isn't an owner key derived for that input | includes uncompressed forms of owner keys (`UnknownSigner`) |
| A signature that doesn't verify over the BIP-143 sighash of *our* tx, script and amount | `BadSignature` |
| No signatures at all | `NoSignatures` |

The same owner appearing twice (in `partial_sigs` and the final witness) counts once.
[`crates/core/tests/adversarial_review.rs`](../crates/core/tests/adversarial_review.rs) pins the
attack cases: uncompressed owner key, a valid owner signature over a *different* tx spending the
same coins, legacy-sighash signatures, a stranger's signature inside a final witness, "only
verified signatures are stored", "one owner can't count twice".

### 2.4 Threshold

`signature_status` (validate.rs line 451) reports, per input, which owners have a valid signature,
and two figures: owners who signed **every** input (the "N of M confirmations" shown in the UI)
and `ready` = every input has ≥ M valid signatures. `ready` drives `SIGNING → READY`.

### 2.5 Finalize and broadcast — `POST /proposals/{id}/execute`

Handler: `execute` (proposals.rs line 378).

1. Status must be `ready` (or `broadcast`, to re-broadcast). `soft_confirmed`/`confirmed` → 409
   `already_confirmed`.
2. Strict-order: the predecessor must already be `broadcast`, `soft_confirmed` or `confirmed`.
3. `validate::finalize` (validate.rs line 489) re-verifies every stored signature, then builds each
   witness as `[<empty>, M signatures in sorted-key order, witness_script]` (CHECKMULTISIG needs
   signatures in key order; `sortedmulti` sorts keys by serialized pubkey). The result is checked
   **two independent ways**: `verify_final_tx` (our own CHECKMULTISIG-order verifier: exactly M
   signatures, empty dummy, script match) and `miniscript::psbt::interpreter_check`.
4. The fee is re-checked against current estimates, unless the proposal was created with
   `fee_override` or the call passes `?fee_override=true`.
5. Broadcast via the chain source, then `Event::Broadcast` with the txid and final tx stored,
   audited as `proposal_broadcast`. In strict mode, siblings in the replacement group get their
   descendants invalidated (`on_group_broadcast`), because their txids will never confirm.

Execute is not restricted to the last signer or to owners; any wallet member can call it once the
proposal is ready.

### 2.6 State machine

Source: [`crates/core/src/state.rs`](../crates/core/src/state.rs) (`transition`, line 93). It's a
pure function; the store applies each transition as a compare-and-swap on the previous status
(`UPDATE … WHERE id = $1 AND status = $2`, `store::set_status`).

```
                 sig            sigs ≥ M          execute / seen in mempool       1..N-1 confs                 ≥ N confs
   PENDING ──────────▶ SIGNING ─────────▶ READY ─────────────────────────▶ BROADCAST ──────────▶ SOFT_CONFIRMED ──────────▶ CONFIRMED (final)
      │  ╲                │                 │  ▲                               │  ▲  │                    │
      │   ╲───────────────┼─────────────────┼──┼── seen in mempool ───────────▶│  │  └──── ≥ N confs ───┼─────────────────▶ CONFIRMED
      │                   │                 │  └──── dropped from mempool, ────┘  └── reorged out ──────┘
      │                   │                 │        inputs unspent again           (back in mempool, or gone)
      ├── delete ─────────┴─────────────────┴──────────────────▶ DELETED
      │
      └── (any active: PENDING / SIGNING / READY / BROADCAST / SOFT_CONFIRMED)
            ├─ input spent by a tx that isn't ours or a sibling's ─▶ INVALIDATED
            ├─ strict-order predecessor gone ──────────────────────▶ INVALIDATED
            ├─ sibling replacement FINAL (≥ N confs) ──────────────▶ CONFLICTED
            └─ seen confirmed directly ────────────────────────────▶ SOFT_CONFIRMED / CONFIRMED
```

N = `CONFIRMATIONS_FINAL` (env, default 2, minimum 1; the default lives only in
`watcher::DEFAULT_CONFIRMATIONS_FINAL`, everything else takes the configured value). Depth =
`tip − block height + 1`.

- Active = `pending | signing | ready | broadcast | soft_confirmed` (`Status::is_active`, and
  `Status::ACTIVE_SQL` for the store's SQL; a unit test keeps them equal). Active proposals hold
  reservations, show in the queue and are re-checked by the watcher; the rest are history.
- `soft_confirmed` is **not final**: it keeps its coin reservations and is re-checked on every
  tick. `confirmed` is final and is never looked up again, even if a deeper reorg than N happens
  (a deliberate choice: N is the trust boundary).
- `soft_confirmed` can only go to `confirmed`, back to `broadcast` (`Event::Reorged`), or to
  `invalidated`/`conflicted`. It can't be deleted, re-executed or replaced (409
  `already_confirmed`).
- A sibling replacement merely seen in the mempool, or only soft-confirmed, leaves a proposal
  where it is; only a *final* sibling makes it `conflicted`. (Before this rule, a bump that got
  one confirmation killed the original for good, and a reorg that let the original win left it
  `conflicted`; `soft_replacement_wins_conflicts_original` covers it.)
- `broadcast` can't be deleted (the API answers 409 and points at `replace_mode=cancel`).
- Deleting doesn't revoke signatures already given: anyone holding M of them can still finalize
  that exact tx. The delete response says so when signatures exist.
- Every transition writes a `proposal_status` audit row. Leaving the queue via `deleted`,
  `invalidated` or `conflicted` cascades `PredecessorGone` to every active strict-order
  descendant (`watcher::cascade`).

### 2.7 Watcher, reorgs, conflicts

[`crates/watcher/src/lib.rs`](../crates/watcher/src/lib.rs). `run` ticks every `SYNC_SECS`
(default 30); `POST /wallets/{id}/sync` does the same for one wallet on demand. Each tick, for
each wallet:

1. **Sync** (`sync_wallet`): a BDK sync over revealed scripts, or every 10th tick
   (`FULL_SCAN_EVERY`) a full scan with stop gap 20 (`STOP_GAP`), which finds funds sent to
   addresses the app never handed out. The BDK update is applied under the row lock and the
   changeset persisted.
2. **Reconcile** (`reconcile`), per active proposal. Chain facts are read first without locks:
   the proposal tx's state, and the spender of each input (`outspend`). Then the wallet and
   proposal rows are locked; if the proposal's status changed in the meantime, the facts are
   stale and it's skipped this round. Otherwise:
   - own tx in a block at depth ≥ N → `confirmed` (final, reason `final`); depth < N →
     `soft_confirmed` (reason `soft_confirmed`). A soft proposal whose tx moved to another
     block keeps `soft_confirmed` with the new height (audited as `confirmation_moved`);
   - `soft_confirmed`, own tx back in the mempool → `broadcast` (`reorged_back_to_mempool`);
   - `soft_confirmed`, own tx in neither a block nor the mempool, no conflicting spend →
     `broadcast` (`reorged_out`); if it stays gone, the next tick's "dropped" rule returns it to
     `ready`, so it can be executed again;
   - own tx in mempool and not yet `broadcast` → `Broadcast` (someone else broadcast it; in
     strict mode this also kills sibling descendants);
   - an input spent by a sibling replacement → stays put until that spend is final (≥ N), then
     `conflicted`; spent by anything else → `invalidated` (`input_spent_elsewhere`), with the
     spending txid recorded. For a `soft_confirmed` proposal this is "a conflicting tx won the
     reorg": it releases the coins (and cascades in strict order);
   - an input whose parent is one of our own proposals that died off-chain → `Invalidated`
     (`parent_replaced`);
   - `broadcast`, tx gone from the chain source, no input spent → `Dropped` → back to `READY`
     (it can be executed again).

**Reorgs.** BDK's checkpoint chain handles reorgs for balances and UTXOs. Proposal status uses
soft vs final confirmations: one block puts a proposal in `soft_confirmed`, N blocks make it
`confirmed`. The chain tip is read once per reconcile, *before* any `tx_state` call, so a block
arriving mid-reconcile can only understate depth (delay finality), never grant it early.

Reservations through a reorg: a soft proposal keeps `active = true` on its inputs, and so does
the `broadcast`/`ready` it rolls back to, so no other proposal can grab its coins while it is
being re-mined. Rolling back never re-acquires a reservation, so it can't fail on the exclusion
constraint. Only `confirmed` (final), `invalidated` and `conflicted` release them.
`confirmed_height` is cleared when a proposal leaves the confirmed states.

Locking is unchanged (see Locking above): chain facts, including the tip, are read without
locks; transitions are applied under the wallet row lock, then the proposal row lock, with the
same stale-snapshot check (`fixed_reconcile_race_keeps_broadcast`). The watcher never takes the
wallet mutex in reconcile.

**Upgrade (migration `20261008000001_soft_confirmed.sql`).** Rows that were `confirmed` before
this change were marked at one confirmation and never re-checked, so their depth is unknown. The
migration demotes them to `soft_confirmed`, re-activates their input reservations where no other
active group holds the coin (it can't violate the exclusion constraint), and writes a
`proposal_status` audit row (actor `migration`, reason `reverify_after_upgrade`). The next
watcher tick re-verifies each one: deep enough → `confirmed` again; reorged out → `broadcast`.

**Mainnet note.** 2 confirmations is thin for mainnet value. This build is signet-only; raise
`CONFIRMATIONS_FINAL` (6 is the usual figure) before any mainnet use.

### 2.8 RBF: bump and cancel

Both are pure functions in `crates/wallet/src/lib.rs` and go through the same create endpoint
with `replaces` + `replace_mode`. Replacements share the original's `group_id`, which is what lets
them hold the same coins (see the reservation constraint, 4.2).

- **Bump** (`bump_fee`, line 400): same inputs, same outputs; only the change output shrinks. The
  original must signal RBF and have a change output. New fee = max(rate × vsize, old fee + 1
  sat/vB × vsize). Refused if change would become dust ("cancel instead").
- **Cancel** (`build_cancel`, line 435): same inputs, a single output to a fresh internal address,
  all inputs set RBF, fee = max(rate × vsize, old fee + vsize).
- **Rebuild**: same coins (forced as `must_spend` with `manual_only`), new outputs. Only before
  broadcast.

Every replacement is a new proposal that needs its own M signatures.

### 2.9 Strict-order mode

`ordering_mode` is `parallel` (default) or `strict`; it can only be switched while the queue is
empty (`PATCH /wallets/{id}`).

In strict mode each new proposal **spends the change output of the queue tail**
(`store::queue_tail` → `ChainInput`), recorded as `predecessor_proposal_id`. If the tail isn't on
chain yet, BDK sees that coin as foreign; `build_proposal` checks the predecessor tx's output
(value and script, re-derived from the internal keychain) before adding it. Segwit txids don't
change when signed, so the child's input is final from the start. Consequences:

- If the tail has no change output, creation fails with 409 `no_change_to_chain`.
- Execute is refused until the predecessor is `broadcast` or `confirmed`.
- If a predecessor is deleted, invalidated or conflicted, or a sibling replacement of it is
  broadcast, every active descendant is invalidated (`cascade`, `on_group_broadcast`). Creating a
  replacement for a proposal with descendants returns a `strict_order_descendants` warning.

---

## 3. Wallet model

### 3.1 Policy and descriptors

[`crates/core/src/policy.rs`](../crates/core/src/policy.rs). A wallet is exactly one policy shape:
**M-of-N P2WSH `sortedmulti`** over owner xpubs with key origin:

```
wsh(sortedmulti(M,[fp/48'/1'/0'/2']tpub…/0/*,…))   receive  (External, /0/*)
wsh(sortedmulti(M,[fp/48'/1'/0'/2']tpub…/1/*,…))   change   (Internal, /1/*)
wsh(sortedmulti(M,[fp/…]tpub…/<0;1>/*,…))           multipath form, for backups/BSMS
```

`WalletPolicy::new` (line 94) enforces: 2 ≤ N ≤ 15 (`MAX_OWNERS`, the Coldcard/Jade cosigner
cap), 1 ≤ M ≤ N, no duplicate fingerprints or xpubs, every xpub on the wallet's network, xpub
depth equal to the origin path length, the path's last step equal to the xpub's child number (or,
for a depth-0 xpub, the fingerprint equal to the xpub's own), and miniscript accepting the
descriptor. Non-fatal warnings: a single-sig-looking path (44'/49'/84'/86') or a non-BIP-48 path.

### 3.2 Import formats

[`crates/core/src/import.rs`](../crates/core/src/import.rs). `import_any` sniffs the text:

| Starts with | Format | Function |
|---|---|---|
| `BSMS` | BSMS 1.0 (BIP-129): descriptor, path restrictions, first address (verified) | `import_bsms` |
| `{` | Caravan JSON (also Sparrow's Caravan export) | `import_caravan_json` |
| anything else | one or more output descriptors, one per line, `#` comments ignored (Sparrow's export) | `import_descriptor` |

SLIP-132 keys (`Zpub`, `Vpub`, …) are normalised to `xpub`/`tpub` (version bytes only). Every
import is **round-tripped**: the descriptor is rebuilt from the parsed policy and must equal what
was imported, so an import can't silently mean something else. A receive-only descriptor imports
with a `change_path_assumed` warning. Export: `export_bsms` and `GET /wallets/{id}/backup`.

### 3.3 BDK, watch-only

`SafeWallet` ([`crates/wallet/src/lib.rs`](../crates/wallet/src/lib.rs)) wraps a `bdk_wallet::Wallet`
created from the two public descriptors (`create_wallet_no_persist`). BDK tracks chain state and
does coin selection. Persistence is manual: the BDK `ChangeSet` is stored as JSON in
`wallets.bdk_changeset` and merged on every persist. `SafeWallet::load` checks the descriptors and
network against the policy, so a swapped row can't load another wallet's state. Loaded wallets
live in `WalletCache` (one `Mutex` per wallet).

### 3.4 Addresses, gap and stop limits

- Receive addresses: `GET /wallets/{id}/addresses?kind=receive&next=true` allocates the next
  index (`next_receive_idx`, atomic `UPDATE … RETURNING`) and reveals it in BDK. Without
  `next=true` it returns the current one (allocating #0 on a fresh wallet).
- Change addresses are only allocated by proposals; the API refuses `kind=change&next=true`.
- There is **no receive gap limit** on allocation: `next=true` always hands out a new index.
  Revealed addresses are always synced, so funds are found; the stop gap only matters for the
  periodic full scan (20).
- Indexes are non-hardened (`MAX_INDEX` = 2³¹ − 1).

---

## 4. Persistence

Postgres, migrations in [`crates/store/migrations/`](../crates/store/migrations/), applied by
`btc_safe_store::connect`. The schema holds **coordination state only**: losing it loses the queue,
labels and accounts, never funds (descriptors can be re-imported from a backup).

### 4.1 Tables

| Table | Holds |
|---|---|
| `wallets` | name, network (`signet`/`testnet`/`testnet4`/`regtest`; mainnet isn't even a legal value), both descriptors, threshold, `ordering_mode`, next receive/change index, the BDK changeset (jsonb), tip height, last sync |
| `owners` | per wallet: name, xpub, fingerprint, origin path, kind, position. Unique per wallet on fingerprint, xpub and position |
| `proposals` | status + reason, latest combined PSBT, consensus-serialized unsigned tx (the byte-equality reference), unsigned txid, fee/rate/vsize/sent, rbf, `fee_override`, `group_id`, `replaces_proposal_id`, `predecessor_proposal_id`, broadcast txid, invalidating txid, confirmed height, final tx. Partial unique index: one active proposal per (wallet, unsigned txid) |
| `proposal_inputs` | outpoint, amount, keychain, derivation index, `group_id`, `active` — the reservation table |
| `proposal_outputs` | script, address, amount, `is_change` ⇔ `change_index` set |
| `signatures` | one row per (proposal, owner, input): pubkey + signature |
| `address_labels`, `address_book` | labels per derived address; saved recipients |
| `audit_log` | wallet, actor, action, jsonb payload, time |
| `ledger_policies` | per (wallet, owner): Ledger policy name, template, keys, 32-byte policy id and 32-byte HMAC |
| `users` | email (lower-case), argon2id PHC hash (NULL until setup), `is_admin`, `failed_logins` + `locked_until` (backoff), TOTP secret / pending secret / last accepted step |
| `sessions` | SHA-256 of the session token, user, CSRF token, absolute expiry, `last_seen_at` (idle timeout) |
| `setup_tokens` | SHA-256 of one-time invite/reset tokens, expiry, `used_at` |
| `wallet_members` | which users can see which wallet, and their `role` (admin / proposer / viewer) |
| `recovery_codes` | SHA-256(user id ‖ code), `used_at` |
| `login_challenges` | SHA-256 of a password-ok-2FA-pending token, user, attempts, expiry (5 min, 5 tries) |
| `known_devices` | SHA-256 of a device cookie per browser that has logged in to an account (anti-lockout) |
| `rate_limits` | token buckets (key, tokens, time), shared by every API process |
| `pow_spent` | SHA-256 of signup challenges already used |

### 4.2 The reservation constraint

```sql
EXCLUDE USING gist (wallet_id WITH =, outpoint WITH =, group_id WITH <>) WHERE (active)
```

(`20261007000001_init.sql` line 81, needs `btree_gist`.) Among active rows, an outpoint can belong
to at most one **replacement group** per wallet. Replacements share their original's `group_id`,
so they may spend the same coins; unrelated proposals can't. `set_status` flips `active` to match
the new status, so terminal proposals release their coins. A violation (SQLSTATE `23P01`) maps to
`StoreError::ReservationConflict`. This is the backstop behind the application-level
`reserved_outpoints` check: two concurrent creates that both passed the app check can't both
commit (tested by `rejects_concurrent_double_reservation`).

### 4.3 What's audited

`store::audit` writes `audit_log` rows for: `wallet_created`, `wallet_deleted`, `ordering_mode`,
`proposal_created`, `signatures_added` (owner names + count), `proposal_broadcast` (txid +
invalidated descendants), `proposal_status` (every state transition with from/to/event/reason,
actor = user or `watcher`), `ledger_policy_registered` (policy id, **not** the HMAC),
`ledger_policy_removed`, `login` (ip, second factor used), `login_failed` (ip, reason:
`unknown_user` / `no_password` / `bad_password` / `backoff` / `bad_second_factor` /
`reauth_bad_password` / `reauth_bad_second_factor`, failure count, lock time; actor = the email
that was tried), `signup`, `signup_refused` (honeypot), `password_set`, `password_changed`,
`logout_all`, `totp_enabled`, `totp_disabled`, `recovery_codes_regenerated`, `invite`,
`member_added`, `member_role_changed`, `member_removed`, and `user_deleted` (CLI).

---

## 5. Chain layer

[`crates/chain/src/lib.rs`](../crates/chain/src/lib.rs):

```rust
trait ChainSource {
    fn describe(&self) -> String;
    async fn tip(&self) -> Result<u32>;
    async fn fee_estimates(&self) -> Result<FeeEstimates>;   // fast / normal / slow
    async fn broadcast(&self, tx: &Transaction) -> Result<()>;
    async fn tx_state(&self, txid: Txid) -> Result<TxState>; // NotFound | Mempool | Confirmed{height}
    async fn outspend(&self, op: OutPoint) -> Result<Option<Spend>>;
    async fn get_tx(&self, txid: Txid) -> Result<Option<Transaction>>;
    async fn scan(&self, req: ScanRequest) -> Result<Update>; // BDK full scan or sync
}
```

- **`Esplora`** ([`esplora.rs`](../crates/chain/src/esplora.rs)): `bdk_esplora` async client, 30 s
  timeout, 4 parallel requests. Fee estimates map Esplora's target→rate table to fast (1 block),
  normal (6) and slow (144), taking the closest target at or above each.
- **`MemoryChain`** ([`memory.rs`](../crates/chain/src/memory.rs)): an in-process simulator with
  blocks and a mempool. It models UTXO spending, RBF, confirmations and reorgs but **does no
  script validation** (the coordinator validates signatures itself). `reorg(depth,
  back_to_mempool)` disconnects the top blocks (later blocks get new hashes); `mine_with(txs)`
  mines a block with exactly those txs (a competing chain); `lookups()` records every `tx_state`
  call. `CHAIN=memory` enables `/dev/fund`, `/dev/mine`, `/dev/inject` and `/dev/reorg`
  (`{depth, back_to_mempool}`).

**Signet pin** ([`crates/api/src/main.rs`](../crates/api/src/main.rs)): `NETWORK` must parse to a
non-mainnet network (mainnet is refused outright), and `CHAIN=esplora` additionally requires
signet. At startup `check_signet_esplora` (line 59) fetches `/block-height/0` from `ESPLORA_URL`
and refuses to start unless it equals the signet genesis hash. `AppState.pinned_network` then
makes wallet create/import refuse any other network.

---

## 6. Auth and security

### 6.1 Accounts and sessions

[`crates/api/src/auth.rs`](../crates/api/src/auth.rs), [`signup.rs`](../crates/api/src/signup.rs),
[`mfa.rs`](../crates/api/src/mfa.rs):

- **Invites** (always available): a user row is created by an admin (`POST /auth/invites`), the
  `invite` CLI, or the `ADMIN_EMAIL` + `ADMIN_SETUP_TOKEN` bootstrap, with no password and a
  one-time setup token (72 h for invites). The invitee sets a password at `/setup`. On an
  existing account a setup link is the **admin reset**: redeeming it sets the password, turns 2FA
  off (secret and recovery codes deleted), clears the backoff and ends every session. Setup and
  session tokens are stored only as SHA-256 hashes.
- **Signup** (`OPEN_SIGNUP=1`, off by default): `POST /auth/signup` with email + password. No
  email is sent or verified: the email is a username. Signup never touches an existing row
  (`INSERT … ON CONFLICT DO NOTHING`), so it can't claim an invited-but-unused account. In order:
  honeypot field (`website` must be empty), per-IP (/64 for IPv6) and global signup buckets,
  email + password rules, proof-of-work, user cap (`MAX_USERS`, checked under an advisory lock so
  concurrent signups can't overshoot). Proof-of-work: `GET /auth/signup` returns
  `"<expiry>.<random>.<HMAC-SHA256(key)>"`; the browser finds a decimal nonce with
  SHA-256(challenge ":" nonce) starting with `SIGNUP_POW_BITS` zero bits; each challenge is spent
  once in `pow_spent`. No third-party service. Wallet cap: `MAX_WALLETS_PER_USER` wallets created
  per non-admin account (`wallets.created_by`, checked with the user row locked).
- **Passwords:** argon2id with RustCrypto defaults (m = 19 MiB, t = 2, p = 1), run on a blocking
  thread. 12–1024 characters; not in a bundled list of ~47k common/breached passwords of 12+
  characters (SecLists, MIT; [`crates/api/data/common-passwords.txt`](../crates/api/data/common-passwords.txt),
  case-insensitive); not one repeated character; not mostly the account's own email. The same
  rules apply at signup, setup and password change. Unknown or password-less accounts are
  verified against a dummy hash so they take as long as a wrong password.
- **Failed logins** are audit-logged (`login_failed`, 4.3) and per-account **backoff**: from the
  `LOGIN_BACKOFF` 5th consecutive failure, password checks for that account are refused (429,
  `Retry-After`) for 1, 2, 4 … seconds, capped at 15 min; a success resets it. Wrong 2FA codes and
  wrong current passwords on account pages count too. Anti-lockout: a successful login sets a
  long-lived `__Host-bsdev` device cookie (HttpOnly, Strict, 180 days, SHA-256 stored in
  `known_devices`). A login attempt carrying a device cookie *for that same account* skips the
  account's backoff and the per-email bucket and uses a bucket of its own, so an attacker hammering
  an account can't keep its owner out of a browser they've used before. A brand-new browser does
  wait out the backoff (at most 15 min at a time).
- **Session cookie:** 32 random bytes; `__Host-bsid` with `HttpOnly; SameSite=Strict; Path=/;
  Secure` (plain `bsid` without `Secure` only when `COOKIE_SECURE=false`). Absolute lifetime
  `SESSION_HOURS` (12 h) and idle timeout `SESSION_IDLE_MINS` (30 min, `last_seen_at` touched on
  every authenticated request); an hourly task deletes expired and idle sessions, stale
  challenges, old device rows, setup tokens a week after they expire, and day-old rate buckets.
- **Rotation:** every login, signup and setup deletes the session the request arrived with (if
  any, whoever's it is) before issuing a new id (no fixation). Password change, enabling and
  disabling 2FA replace *all* of the user's sessions with one new one (new CSRF token too).
  Becoming a server admin (`invite --admin` on an existing account) ends the user's sessions.
  Wallet roles are read from the database on every request, so a role change takes effect
  immediately without touching sessions. `POST /auth/logout-all` ends every session of the user.
- **Password change:** `POST /auth/password` needs the current password (same backoff/audit as
  login).
- **2FA (optional, per user):** TOTP (RFC 6238, SHA-1, 30 s, 6 digits, ±1 step). Enrolment needs
  the password (`/auth/totp/setup`, so a stolen session alone can't bind the account to the
  thief's authenticator), then a code (`/auth/totp/enable`), which returns 10 one-time recovery
  codes once (80 bits each, stored as SHA-256(user id ‖ code)). With 2FA on, a correct password
  returns `{mfa_required, mfa_token}` and no cookie; `/auth/login/mfa` exchanges the token plus
  a code or a recovery code for a session. A challenge allows 5 attempts in 5 minutes and isn't a
  session. **Replay:** a code is only accepted for a step later than the last accepted one (one
  conditional `UPDATE`, so two concurrent submissions of one code can't both pass); a recovery
  code is spent by one conditional `UPDATE … WHERE used_at IS NULL`. Turning 2FA off or
  regenerating codes needs the password and a code. **There is no email, so recovery codes are
  the only self-service way back in**; otherwise an admin resets the account with `invite`. The
  TOTP secret itself is stored raw (the server must recompute codes): a database leak exposes
  it.
- **CSRF:** every request other than GET/HEAD/OPTIONS on a logged-in route must carry
  `X-CSRF-Token` equal to the session's token (constant-time compare). The browser keeps it in
  memory only and re-reads it from `GET /auth/me` after a reload
  ([`web/lib/api.ts`](../web/lib/api.ts)). The open routes (login, MFA, signup, setup, logout)
  take JSON bodies and the cookies are `SameSite=Strict`.

### 6.2 Wallet scoping and roles: deny by default

[`crates/api/src/lib.rs`](../crates/api/src/lib.rs) (`router`) has three route groups: open
(`/health`, login/MFA/logout/me/signup/setup), account (logged in: invites, users, password,
2FA, logout-all, `/price`), and scoped (everything else). Scoped routes run `require_user` then
`require_membership` ([`auth.rs`](../crates/api/src/auth.rs)), which parses the path itself:

- `/wallets`, `/wallets/import`, `/dev/*` → no wallet scope (just logged in);
- `/wallets/{uuid}/…` → that wallet;
- `/proposals/{id}/…` → the proposal's wallet, looked up in the DB;
- **anything else → 404.** A route added later without a matching rule is denied, not opened.

Non-members get 404, not 403, so wallet and proposal ids can't be probed. `GET /wallets` lists
only the caller's wallets (with `role`); `GET /wallets/{id}` returns `my_role`.

Members then need a **role** ([`crates/api/src/roles.rs`](../crates/api/src/roles.rs) `required`,
one table keyed by method + path; a scoped (method, path) not in it gets 403 for everyone):

| Role | Can |
|---|---|
| viewer | read everything in the wallet (summary, history, UTXOs, addresses incl. allocating the next receive address, proposals, members, backup, Ledger registrations), sync, leave the wallet |
| proposer | + create proposals, upload signatures, execute, delete proposals **they** created, label addresses, address book, Ledger registrations |
| admin | + delete any proposal, wallet settings (`PATCH`), delete the wallet, add/remove members and change roles |

**Who can execute:** proposers and admins. Execute only succeeds once the proposal carries M
valid owner signatures, which are the real authorization; broadcasting is delivery. Viewers
can't, so a read-only share can't choose *when* a signed transaction goes out.

The creator becomes admin on create/import. Members that existed before roles were added were
migrated to admin (they could do everything before). New shares default to viewer. A wallet
always keeps at least one admin: demoting or removing the last admin is a 409 (`last_admin`),
and `delete-user` refuses while the user is the only admin of a wallet. Member changes lock the
wallet's member rows. Member routes act only on members of the wallet in the path (another
wallet's user id → 404).

Note: the signature-upload endpoint is behind login, membership and the proposer role. DESIGN.md
§6.7 left it open; the router is what counts, and it's scoped.

### 6.3 Rate limits and security headers

[`crates/api/src/ratelimit.rs`](../crates/api/src/ratelimit.rs) +
[`crates/store/src/limits.rs`](../crates/store/src/limits.rs): token buckets in Postgres
(`rate_limits`), one atomic `INSERT … ON CONFLICT DO UPDATE` per check, so every API process
shares them. A refused request spends nothing. If the database is unreachable the request fails
(no fail-open). Per client IP on every route (`RATE_IP`, default 300/min, burst 120), per user
on logged-in routes (`RATE_USER`, 600/min, burst 200), a strict login/setup/2FA bucket keyed by
IP and by email (`RATE_LOGIN`, 10/min, burst 5), signups per IP (`RATE_SIGNUP`, 5/hour, burst 3)
and overall (`RATE_SIGNUP_GLOBAL`, 60/hour, burst 20). IPv6 clients are keyed by their /64. Over
the limit: 429 with `Retry-After`. The client IP is the TCP peer unless `CLIENT_IP_HEADER` names
a proxy header (its last entry is used). Other limits: 1 MiB request bodies, ≤ 1000 outputs, a
capped final-witness size (2.3).

Security headers. API ([`headers.rs`](../crates/api/src/headers.rs), on every response including
errors and 429s): `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri
'none'; form-action 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, a Permissions-Policy that turns everything off, COOP
`same-origin`, `Cache-Control: no-store` unless set, and HSTS (2 years, subdomains) when
`COOKIE_SECURE`. Web ([`web/proxy.ts`](../web/proxy.ts), [`web/lib/csp.ts`](../web/lib/csp.ts)):
a fresh nonce per page request and

```
default-src 'self'; script-src 'self' 'nonce-…' 'strict-dynamic'; style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:; font-src 'self'; connect-src 'self' ws://127.0.0.1:21335;
frame-src https://suite.trezor.io; worker-src 'self' blob:; object-src 'none'; base-uri 'none';
form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests
```

(`'unsafe-eval'` added and `upgrade-insecure-requests` dropped in `next dev` only). Why each
exception: `style-src 'unsafe-inline'` because server-rendered React emits `style=""`
attributes; `ws://127.0.0.1:21335` is Trezor Suite desktop's local bridge, which Trezor Connect
10 tries first; `https://suite.trezor.io` hosts Trezor Connect's iframe/popup (Connect 10 no
longer uses `connect.trezor.io`). WebHID (Ledger) needs no CSP entry; `Permissions-Policy:
hid=(self), usb=(self)` and everything else `()`. Plus HSTS (production), `X-Frame-Options:
DENY`, nosniff, `Referrer-Policy: no-referrer` (setup links carry tokens) and COOP
`same-origin-allow-popups` (the Trezor popup keeps `postMessage`). Pages render dynamically so
each response gets its own nonce. `web/e2e/csp.mjs` loads every page in Chrome and fails on any
`securitypolicyviolation`.

### 6.4 The browser's independent cross-check

The server is trusted to coordinate, not to be honest. [`web/lib/bitcoin.ts`](../web/lib/bitcoin.ts)
`crossCheck` runs on every review screen (send flow and queue rows) and decodes the PSBT the server
serves with bitcoinjs-lib, then compares it with the server's own JSON summary:

- the PSBT's txid equals the server's `unsigned_txid`;
- the input set and every input amount match. Amounts come from `non_witness_utxo` only if that
  tx hashes to the outpoint's txid (and must agree with `witness_utxo` if both are present);
- the output count, and every output's address and amount, match;
- **every output the server calls change re-derives** in the browser as
  `wsh(sortedmulti(M, xpubs/1/index))`; otherwise "server calls it change but this browser derives
  …";
- the fee implied by the PSBT equals the server's fee; a PSBT without input amounts is a problem.

Any problem shows a mismatch banner, and **every hardware sign button (Ledger, Trezor, QR,
download) is gated on `check.ok`** ([`web/test/sign-gating.test.mjs`](../web/test/sign-gating.test.mjs)
enforces this). Receive addresses are re-derived in the browser too, and Settings shows the
browser-built descriptor next to the server's.

What it does **not** do: the xpubs it derives from also come from the server (the wallet summary).
Nothing in the browser pins them (no local storage of the wallet's keys), so a server that lies
consistently about the owner set passes the cross-check. Defences against that are the wallet
backup (descriptor/BSMS, checked at creation), the Ledger registration (which the device itself
reviewed), and each device's own display of outputs.

### 6.5 Threat model: a compromised server

| A compromised server **can** | A compromised server **cannot** |
|---|---|
| Refuse service, drop or delete proposals, hide signatures, stall execution | Sign anything: it has no keys, and nothing in the codebase can hold one |
| Show a wrong balance or history | Make an owner's device sign without the owner approving on the device |
| Serve a PSBT whose outputs differ from what it shows in JSON — **caught** by the browser cross-check before signing | Get a PSBT with tampered change past the cross-check *if* the xpubs the browser holds are the real ones |
| Serve fake owner xpubs consistently in both PSBT and summary — **not caught** by the cross-check; caught by comparing with the backup or by a Ledger whose registered policy doesn't match | Reuse a signature on a different tx: signatures are SIGHASH_ALL over the full tx |
| Hand out receive addresses it controls — **caught** by the browser re-derivation (same caveat about xpubs) | Spend with fewer than M owner signatures |
| Broadcast a fully signed tx at a time of its choosing, or keep a deleted-but-signed one to broadcast later | Change amounts after signing (amounts are in the BIP-143 sighash) |
| Read the Ledger registration HMACs it stores (they let the holder skip on-device policy review for that policy; they are not key material) | |
| Leak which users belong to which wallets, labels, and the address book | |

---

## 7. Hardware signing

Every signer path ends the same way: a PSBT with new partial signatures goes to
`POST /proposals/{id}/signatures` and through the full server validation in 2.3. Shared types:
[`web/lib/signers/types.ts`](../web/lib/signers/types.ts).

### 7.1 Ledger (WebHID)

[`web/lib/ledger.ts`](../web/lib/ledger.ts) (device I/O) and
[`web/lib/ledger-core.ts`](../web/lib/ledger-core.ts) (pure logic, runs in node), via LedgerHQ's
`ledger-bitcoin` client; needs app-bitcoin-new ≥ 2.1 and Chrome/Edge desktop.

- **Owner key:** reads the xpub at `m/48'/1'/0'/2'`.
- **Wallet policy:** `wsh(sortedmulti(M,@0/**,…))` with keys `[fp/path]xpub` in owner order. The
  server builds the same policy and its id in [`crates/core/src/ledger.rs`](../crates/core/src/ledger.rs)
  (wallet policy v2 serialization + the app's Merkle tree; checked against vectors produced by the
  JS client). The browser refuses a server policy that doesn't match its own rebuild from the
  owners, and checks the device returns the same id.
- **Registration:** the user reviews name, policy and every key on the device; the device returns
  an HMAC. `PUT /wallets/{id}/ledger/owners/{owner}` stores it per (wallet, owner) after checking
  that the policy is exactly this wallet's and the id hashes from it. The server can't verify the
  HMAC (it's keyed by a device secret).
- **Signing:** `signPsbt` with the stored policy + HMAC; the device shows outputs and fee.
  `mergePartialSigs` (ledger-core.ts line 64) requires each returned pubkey to be in that input's
  `bip32_derivation` and the signature to verify over the input's sighash before merging.
- **Show address:** `getWalletAddress(…, display = true)`.
- **Verified:** against the Speculos emulator (app-bitcoin-new 2.5.1, Nano S Plus) in node and in
  a real Chrome UI. **UNVERIFIED:** a physical Ledger, the WebHID picker/permission flow, Ledger
  Live holding the device, a locked device, wrong-app status words.

### 7.2 Trezor (Connect 10)

[`web/lib/signers/trezor.ts`](../web/lib/signers/trezor.ts) (Connect calls) and
[`web/lib/signers/trezor-tx.ts`](../web/lib/signers/trezor-tx.ts) (pure PSBT ↔ Connect
translation). Connect 10 routes every call through Trezor Suite (desktop over a localhost
WebSocket, or a Suite Web popup); signet uses coin `test`.

`buildTrezorRequest` (trezor-tx.ts line 183) first re-derives every input script and every change
address from the owners' xpubs (nothing the server sent is trusted), then builds the
`signTransaction` request: per input/change output, `address_n` = the device's own full path, and
`multisig` = every owner's xpub with the same `[chain, index]` suffix, `m`, and
`pubkeys_order = LEXICOGRAPHIC` (sortedmulti), owners always in wallet position order; plus the
previous transactions (`refTxs`) so the firmware can check amounts. `mergeSignatures` (line 276)
merges the returned signatures. Firmware older than core 2.8.7 / legacy 1.13.0 ignores
`pubkeys_order`; its "Input does not match scriptPubKey" error is mapped to an "update firmware"
message.

**Verified:** the request shape against a firmware-logic mock ([`web/test/trezor-mock.mjs`](../web/test/trezor-mock.mjs))
in unit tests and against the real API ([`web/e2e/trezor-server.mjs`](../web/e2e/trezor-server.mjs)).
**UNVERIFIED:** everything on a real Trezor + Suite, including "Show on Trezor".

### 7.3 Files and QR

[`web/components/signing.tsx`](../web/components/signing.tsx): download the PSBT, or show it as an
animated QR in **BBQr** (Coldcard Q, Sparrow) or **UR `crypto-psbt`** (Keystone, Jade, Sparrow,
Passport). Signed PSBTs come back as uploaded files or pasted base64 (there's no camera scanning).
Device acceptance of the PSBT and QR formats is **UNVERIFIED** until Phase 3.

---

## 8. Frontend structure

Next.js App Router, TypeScript, in `web/`.

| Route | File | What |
|---|---|---|
| `/` | `web/app/page.tsx` | wallet list; admin panel to invite users / reset passwords |
| `/login`, `/setup` | `web/app/login/page.tsx`, `web/app/setup/page.tsx` | login; one-time password setup |
| `/new` | `web/app/new/page.tsx` | create (owners from xpub, Ledger, Trezor) or import a wallet; the review step derives the descriptor and first addresses in the browser before the server is asked |
| `/w/[id]` | `web/app/w/[id]/page.tsx` + `layout.tsx` | home: balance, queue |
| `/w/[id]/send` | `web/app/w/[id]/send/page.tsx` | build → review (cross-check) → sign → execute |
| `/w/[id]/transactions` | `web/app/w/[id]/transactions/page.tsx` | queue and history |
| `/w/[id]/receive` | `web/app/w/[id]/receive/page.tsx` | receive address, re-derived in the browser; show on Ledger/Trezor |
| `/w/[id]/assets`, `/address-book`, `/settings` | `web/app/w/[id]/…` | coins, saved recipients, owners/members/backup/Ledger registration/ordering mode |

Key modules in `web/lib/`:

| Module | Role |
|---|---|
| `api.ts` | typed client; same-origin `/api/*`; CSRF header on writes; redirect to login on 401 |
| `bitcoin.ts` | address derivation, descriptor + BIP-380 checksum, PSBT decode, `crossCheck` |
| `ledger.ts`, `ledger-core.ts` | Ledger device I/O and pure logic |
| `signers/trezor.ts`, `signers/trezor-tx.ts`, `signers/types.ts` | Trezor adapter and shared signer types |
| `import-sniff.ts` | recognise pasted/uploaded wallet files (the server does the real parsing) |
| `warnings.ts` | turn the API's structured warnings into sentences |
| `format.ts` | sats/BTC parsing without float rounding, display helpers |
| `theme.ts` | light/dark/system preference (per browser) |

Components in `web/components/`: `auth.tsx` (page guard), `wallet-context.tsx`, `shell.tsx`,
`tx.tsx` (queue rows with the cross-check), `signing.tsx`, `ledger.tsx`, `trezor.tsx`,
`members.tsx`, `price.tsx` (display-only mainnet BTC/USD from the API's `/price`, fetched
server-side so the browser never calls a price API), `theme.tsx`, `ui.tsx`.

Security headers ([`web/next.config.ts`](../web/next.config.ts)): `X-Frame-Options: DENY`,
`nosniff`, `Referrer-Policy: no-referrer` (setup links carry a token), HSTS in production. No COOP
or CSP is set, on purpose: Trezor Connect needs to open/frame Suite Web.

---

## 9. Deployment

The reference deployment is three services, all on signet (any container host works):

```
            internet
               │ HTTPS
               ▼
        ┌─────────────┐   private network    ┌─────────────┐   private network   ┌──────────┐
        │  web        │ ── /api/* rewrite ─▶ │  api        │ ──────────────────▶ │ Postgres │
        │ Dockerfile. │                      │ Dockerfile  │                     │ (no      │
        │ web         │                      │ (+ public   │ ──▶ Esplora signet  │  public  │
        └─────────────┘                      │  domain for │     (HTTPS)         │  access) │
                                             │  health)    │                     └──────────┘
                                             └─────────────┘
```

- **api** — [`Dockerfile`](../Dockerfile): `rust:1-slim-bookworm` builds `btc-safe-api --release
  --locked`; runtime is `debian:bookworm-slim` + CA certs, non-root uid 10001, with
  `CHAIN=esplora NETWORK=signet` baked in. Binds `[::]:$PORT` when `PORT` is set.
- **web** — [`Dockerfile.web`](../Dockerfile.web):
  `node:25-bookworm-slim`, `npm ci`, `next build`, runs `next start` as `node`. `BTC_SAFE_API`
  is a **build arg**: Next.js fixes the rewrite target at build time, so changing the API address
  needs a rebuild. It points at the api service's private-network address.
- **Postgres** — private only.
- Deploy: build both images from the repo root. Admin CLI in the running api container:
  `btc-safe-api invite <email>`.

Rate-limit state is in process memory, so the design assumes one API instance.

---

## 10. Testing

| Suite | Covers | Needs |
|---|---|---|
| `crates/core/tests/validate.rs` | adversarial PSBT submissions: each test tries to get a bad PSBT accepted | — |
| `crates/core/tests/adversarial_review.rs` | the 2026-10-07 review's attacks on `validate` (2.3) | — |
| `crates/core/tests/props.rs`, `state.rs` | property tests (proptest) for validation and the state machine | — |
| `crates/core/tests/policy_import.rs` | policy rules, descriptor/BSMS/Caravan import round trips | — |
| `crates/wallet/tests/flow.rs` | in-memory 2-of-3: fund, propose, sign offline with test keys, finalize; reservations; strict-order chaining | — |
| `crates/store/tests/db.rs` | repositories and constraints | Postgres |
| `crates/watcher/tests/reconcile.rs` | reconcile against MemoryChain: soft/final confirmation, reorg back to mempool and out, conflicting tx or replacement winning a reorg (reservations checked), strict-order cascade from a soft proposal, final never re-checked, `CONFIRMATIONS_FINAL` honored, drop, invalidation, audit trail | Postgres |
| `crates/api/tests/e2e.rs` | full HTTP flow, in-process router + MemoryChain | Postgres |
| `crates/api/tests/auth.rs` | login, sessions, CSRF, membership, rate limits | Postgres |
| `crates/api/tests/ledger.rs` | Ledger registration endpoints, scoping, no HMAC in the audit log | Postgres |
| `crates/api/tests/adversarial_review.rs` | HTTP-level fixes: create/sync deadlock, concurrent creates, reconcile race, strict cascade on external broadcast, children of replaced parents, signature floods, huge amounts, illegal transitions, reservation bypass, concurrent double reservation | Postgres |
| `crates/chain/tests/signet_smoke.rs` | live public signet Esplora (`#[ignore]` by default) | network |
| `scripts/check-watch-only.sh` | clippy `-D warnings` + the watch-only invariants (1) | — |
| `npm test` (`web/lib/*.test.mjs`, `web/test/*.test.mjs`) | Ledger core logic, Trezor request building against a firmware mock, sign-button gating, import sniffing, warnings text, USD formatting, theme | node ≥ 23 |
| `web/e2e/walkthrough.mjs`, `auth.mjs` | real UI in system Chrome (playwright-core) against `CHAIN=memory` | API + `npm run dev` + dev account (`web/e2e/reset-dev.sh`) |
| `web/e2e/ledger-speculos.mjs`, `ledger-browser.mjs` | Ledger flows against Speculos, node and browser | Speculos ([`scripts/speculos/START.md`](../scripts/speculos/START.md)) |
| `web/e2e/trezor-server.mjs` | Trezor request path against the real API, mock device | API (`CHAIN=memory`) |
| `web/e2e/*-live.mjs` | read-mostly checks against the hosted site | demo credentials via env |

Running:

```sh
createdb btc_safe_test                     # or set BTC_SAFE_TEST_DATABASE_URL
cargo test --workspace
./scripts/check-watch-only.sh
cargo test -p btc-safe-chain --test signet_smoke -- --ignored
cd web && npm test && npm run typecheck
```

---

## 11. Known gaps and limits

The running list, with resume notes, is [PROGRESS.md](../PROGRESS.md). From the code:

- Signet only; mainnet is refused in config, in the schema's network check, and by the genesis
  check.
- One policy shape: P2WSH `sortedmulti`, 2–15 owners. No taproot, no timelocks/recovery paths.
- Finality is depth-based (`CONFIRMATIONS_FINAL`, default 2): a reorg deeper than that after a
  proposal went final is not noticed (2.7). 2 is thin for mainnet.
- No receive gap limit on address allocation (3.4).
- The browser cross-check trusts the server's xpubs (6.4).
- Deleting a proposal doesn't revoke its signatures; only spending one of its inputs does.
- The wallet cache is per process: one API instance (rate limits are shared in Postgres).
- Auth (6.1): no email delivery or verification (email is a username); TOTP secrets are stored
  raw; no passkeys/WebAuthn; no admin UI to delete users or list sessions (CLI only); any
  account can be added to a wallet by email without accepting.
- Real hardware (Ledger, Trezor, QR/file signers like Coldcard, Jade, Sparrow) is unverified;
  see section 7 and PROGRESS.md "Real device test".
