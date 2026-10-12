# BTC Safe — design doc

Working name: **btc-safe** (placeholder; we can't ship under the Safe name).
Status: v0.2, 2026-10-07 (decisions closed, Phase 1 build started). This is the original design document; [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) describes what was actually built.
Facts marked with a link were fetched on 2026-10-07. Anything that couldn't be confirmed from a primary source is marked **UNVERIFIED**.

---

## 1. Goal and non-goals

**Goal.** A self-hosted Bitcoin multisig wallet whose UI feels near-identical to Safe{Wallet} (app.safe.global): same sidebar, same account model, same "queue → confirm → execute" flow, same "1 of 2 confirmations" rows. Rust backend. Watch-only: the server holds xpubs and descriptors, never owner private keys.

**Non-goals (v1).**
- No custody. No server-held owner keys. (The optional co-signer in §4 is a separate, opt-in component.)
- No mainnet in v1. Signet only until the PSBT validation and change-verification code has been reviewed.
- No Lightning, no Ordinals/inscriptions, no coinjoin.
- No multi-tenant SaaS. One deployment per operator (an individual or a team).
- No pixel copy of Safe's assets, logo, or name (see §7).

**Why not Caravan, Sparrow, or Nunchuk?**

| Tool | What it does well | What it lacks for us |
|---|---|---|
| Caravan ([MIT](https://github.com/caravan-bitcoin/caravan)) | Stateless browser multisig coordinator, hardware-wallet support | Stateless by design: no shared server-side queue. Each signer passes PSBT files around by hand. No account dashboard. |
| Sparrow | Best-in-class desktop multisig UX, PSBT tooling | Desktop app, single-user. Co-signers coordinate out of band (files, QR). No shared queue. |
| Nunchuk | Mobile/desktop multisig with collaborative group wallets | Closed coordination service; we don't control the backend, can't add ETH-signature approvals, can't self-host. |

The gap is a **shared, stateful transaction queue** with Safe's UX: one person proposes, everyone sees the proposal in the same web app, each owner adds their signature from their own device, and the last signer clicks Execute. That's what Safe users are used to, and it's what teams coming from EVM multisigs will expect.

---

## 2. Safe → BTC concept map

| Safe concept | BTC equivalent | Notes |
|---|---|---|
| Safe account (contract address) | A **wallet descriptor**, e.g. `wsh(sortedmulti(2,[fp1/48'/1'/0'/2']tpubA/<0;1>/*,[fp2/...]tpubB/<0;1>/*))` | No single address. The descriptor derives a sequence of receive and change addresses. The "account" is the descriptor plus its UTXO set. |
| Owners | Cosigner **xpubs with key origin** (master fingerprint + derivation path) | One xpub per owner device. Fingerprint is how we match PSBT signatures to owners. |
| Threshold | `M` in `sortedmulti(M, ...)` | Enforced by Bitcoin Script, not by our server. |
| Nonce | **None.** | Bitcoin has no account nonce. Ordering and replay protection come from UTXOs: an input can be spent once. See "UTXO conflicts" below. |
| Tx queue | `proposals` table: unsigned/partially-signed PSBTs awaiting signatures | Server state, not chain state. Same UX as Safe's queue. |
| Tx history | Confirmed txs touching the descriptor's scripts (from Esplora/Electrum) plus our proposal records | History includes txs created outside the app (e.g. someone used Sparrow). We show those as "external". |
| Modules | **None in v1.** Closest equivalent: extra miniscript spending paths (v2) | Safe modules are arbitrary code with spend authority. Bitcoin has no arbitrary code; any extra authority has to be a branch of the spending policy, fixed at descriptor creation. |
| Guards | **None on-chain.** Off-chain only: server-side policy checks before we show "Execute" | A guard that blocks a valid signed tx is impossible: any party holding M signatures can broadcast through any node. Our checks are advisory. |
| Owner change / threshold change | **New descriptor + sweep tx** | Script is fixed per address. Changing owners = create new wallet, then a proposal that spends all UTXOs of the old wallet to the new one, signed under the OLD policy. UI wraps this as "Change owners" → "Migrate funds". |
| Spending limits | **None on-chain.** v2 option: a miniscript branch like `or(multi(2,A,B,C), and(pk(D), older(N)))` gives relative-timelock paths, not per-amount limits | Bitcoin Script can't check output amounts (no covenants on mainnet). Amount limits are only possible via the co-signer in §4a (it refuses to co-sign above a limit). |
| Address book | Same: label → address, stored server-side | Plus labels on our own UTXOs/addresses (BIP-329 import/export). |
| Safe Apps | **None.** | No dapp ecosystem to embed. Hide the nav item. |
| Message signing (EIP-1271) | **None for multisig.** BIP-322 can sign with a multisig in theory; wallet support is thin | Defer. |
| Gas / relayer | Fee rate (sat/vB), RBF, CPFP | Fee bumping is a first-class flow; Safe has no equivalent screen. |

### UTXO conflicts between queued transactions (the "no nonce" problem)

Safe serializes queued txs by nonce: tx #5 can't execute before #4. Bitcoin has no such ordering. Two queued proposals can either be independent (disjoint inputs, both can confirm) or conflicting (they share an input; at most one can confirm).

Rules:
1. **Input reservation.** When a proposal is created, its inputs are recorded in `proposal_inputs (outpoint UNIQUE WHERE status IN ('pending','signing','ready','broadcast'))`. Coin selection for a new proposal excludes reserved outpoints. Default case: queued txs never conflict.
2. **Explicit replacement.** A user can deliberately create a proposal that reuses a reserved input ("Replace" / "Cancel" / "Speed up"). That proposal is linked via `replaces_proposal_id`. The UI groups them like Safe groups same-nonce txs ("Replacement for #12"). Once either confirms, the other is marked `conflicted`.
3. **Chain is the source of truth.** A watcher polls the backend's chain source. If any input of a pending proposal is spent by a tx that isn't that proposal's tx (someone signed elsewhere), the proposal is marked `invalidated` with the conflicting txid.
4. **Insufficient unreserved funds.** If the balance is there but all coins are reserved, the Send flow says so and offers to replace an existing proposal rather than silently double-spending.
5. **Cancel** in Safe = a 0-value tx at the same nonce. Here, cancel is either (a) delete the proposal server-side if not yet broadcast (no on-chain action needed — but signatures already given are still valid for that PSBT; anyone holding them could finalize and broadcast), or (b) if broadcast and unconfirmed with RBF, a replacement that spends the same input back to ourselves. The UI must say plainly that (a) does not revoke signatures already given. The safe way to kill a fully-signed-but-unbroadcast proposal is to spend one of its inputs.

#### Ordering modes (per-wallet setting)

The rules above describe the default, **parallel** mode. A wallet can instead be set to **strict-order**.

| | Parallel (default) | Strict-order |
|---|---|---|
| How proposals relate | Disjoint inputs, reserved per proposal. Any queued proposal can confirm in any order. | Each queued proposal must spend the **previous queued proposal's change output** (the head of the queue spends confirmed/unreserved UTXOs). |
| What enforces order | Nothing on-chain. Order is a UI label. | **Consensus.** Proposal #N+1's input doesn't exist until #N's tx exists, so #N+1 can't confirm before #N. Same guarantee as Safe's nonce. |
| Coin selection | Any unreserved coin. | Constrained: a non-head proposal's inputs are the predecessor's change output (plus optionally other unreserved coins). The predecessor must therefore *have* a change output large enough to fund the next send; the server refuses to queue an exact-amount (changeless) proposal behind which another is queued. |

Costs of strict-order, stated plainly:
1. **A stuck tx blocks the queue.** If #N sits unconfirmed at a low fee, #N+1…#K can be broadcast as a package of descendants but won't confirm first. Fee-bumping later items via CPFP helps only if mempool package rules accept the chain.
2. **RBF on any queued tx invalidates everything after it.** An RBF bump of #N changes #N's txid, so #N's change outpoint changes. Every later proposal spends the old outpoint, so their signatures (which commit to that outpoint) are now worthless. The server marks them `invalidated` (reason: `predecessor_replaced`) and the owners must **rebuild and re-sign** each one. Same if #N is deleted or invalidated before broadcast.
3. **Constrained coin selection.** You can't pick coins freely for later proposals, and you can't send the full balance from a non-head proposal while earlier ones are queued.
4. **Re-signing cost scales with queue depth.** Bump #1 of a 5-deep queue and four proposals need fresh signatures from M owners each.

Use strict-order when the order of payments matters more than independence (e.g. a payroll batch that must land in sequence). Default stays parallel.

#### Why not a nonce in miniscript?

A natural question is whether the descriptor itself could enforce ordering. It can't:
- **Script has no state.** A script is evaluated against one spending tx and its own witness; it can't read a counter, a previous tx, or any storage. There is nothing to increment.
- **Replay protection is already there, without a nonce.** Every signature commits (via the BIP-143 sighash) to the exact outpoints being spent. An outpoint can be spent once, so a signature can never be replayed into a second tx. That's the job Ethereum's nonce does for accounts; UTXOs do it structurally.
- **Ordering, where wanted, comes from the UTXO graph.** Strict-order above is exactly that: chain each tx onto the previous one's output, and consensus does the rest.

---

## 3. Screens

Layout mirrors Safe: fixed left sidebar, top bar with network badge and connected-signer chip, content on the right. Mocks below are structural, not visual.

### 3.1 Sidebar (persistent)

```
┌──────────────────────────────┐
│ [identicon] Treasury 2/3      │  ← account name, threshold badge
│ tb1q…7h3k   [copy][qr][ext]   │  ← current receive addr (rotates)
│ 1.2345 BTC  ≈ $—              │  ← balance (fiat only if a price source is configured)
│ [ New transaction ]           │
├──────────────────────────────┤
│ ⌂ Home                        │
│ ◎ Assets                      │
│ ⇄ Transactions        (2)     │  ← queue count badge
│ ☰ Address book                │
│ ⚙ Settings                    │
├──────────────────────────────┤
│ ⛓ Signet  ▾                   │  ← network switcher
│ Switch account ▾              │
└──────────────────────────────┘
```

### 3.2 Home / dashboard

```
┌──────────────────────────────────────────────────────────────┐
│ Overview                                                      │
│ ┌──────────────┐ ┌──────────────┐ ┌───────────────────────┐  │
│ │ Total        │ │ Confirmed    │ │ Unconfirmed / reserved │  │
│ │ 1.2345 BTC   │ │ 1.2000       │ │ 0.0345 / 0.5000        │  │
│ └──────────────┘ └──────────────┘ └───────────────────────┘  │
│ [ Send ]  [ Receive ]                                         │
│                                                               │
│ Pending transactions                         View all →       │
│  #14  Send 0.25 BTC → tb1q…9xk     1 of 2 ✓    [Confirm]      │
│  #15  Send 0.10 BTC → Alice        0 of 2      [Confirm]      │
│                                                               │
│ Owners: 3   Threshold: 2   Policy: P2WSH sortedmulti          │
└──────────────────────────────────────────────────────────────┘
```
"Reserved" (coins locked by queued proposals) has no Safe equivalent. It's needed because of §2's input reservation.

### 3.3 Assets

Safe shows a token list. BTC has one asset, so the screen becomes a **UTXO / coin list** (coin control):

```
Assets                                              [ Send selected ]
☐ Outpoint         Address        Label     Amount     Conf  Status
☐ 3f1a…:0          tb1q…7h3k      invoice42 0.5000     144   available
☐ 9bc2…:1          tb1q…2ag1      change    0.2000     3     reserved (#14)
☐ 77de…:0          tb1q…zz8p      —         0.0345     0     unconfirmed
```
Tokens/NFTs tabs: no BTC meaning (Runes/Ordinals out of scope). Hide.

### 3.4 Transactions — Queue / History

```
Transactions      [ Queue ]  History

  Next
  ┌──────────────────────────────────────────────────────────┐
  │ #14  ↑ Send   0.25 BTC → tb1q…9xk   fee 2.1 sat/vB        │
  │      Created by Carol · 2h ago     1 of 2 confirmations   │
  │      ▸ expand                         [Confirm] [Execute]  │
  └──────────────────────────────────────────────────────────┘
  ┌──────────────────────────────────────────────────────────┐
  │ #16  ↻ Replacement for #14 (fee bump 8 sat/vB)            │
  │                                      0 of 2 confirmations  │
  └──────────────────────────────────────────────────────────┘
  ┌──────────────────────────────────────────────────────────┐
  │ #15  ↑ Send   0.10 BTC → Alice      0 of 2 confirmations  │
  └──────────────────────────────────────────────────────────┘
```

Expanded row (matches Safe's detail panel):
```
  Recipient       tb1q…9xk  (Address book: —)        0.25000000
  Change          tb1q…c41  ✓ verified ours (m/1/7)   0.84990000
  Fee             0.00000210 BTC · 2.1 sat/vB · 100 vB
  Inputs          3f1a…:0 (0.5) · 9bc2…:1 (0.6)
  RBF             enabled
  Confirmations   ✓ Carol (fp 7a3c…)  · ○ Alice (fp 1e09…) · ○ Bob
  Actions         [Download PSBT] [Show QR] [Upload signed PSBT] [Delete]
```
"Nonce" labels become proposal IDs (`#14`). They are display-only and imply no on-chain ordering — say so in a tooltip.

History tab: confirmed/broadcast txs, plus external txs, plus `conflicted`/`invalidated` proposals greyed out with the reason.

### 3.5 New transaction flow

Safe's three steps: Create → Review → Sign/Execute.

```
Step 1/3  Send
  Recipient   [ tb1q… or address-book name        ]  [+ add output]
  Amount      [ 0.25      ] BTC   [Max]
  Fee         ( ) Slow 1 sat/vB  (•) Normal 2.1  ( ) Fast 8  ( ) Custom
  ▸ Advanced: coin control, RBF on/off, change address override (off)
                                                      [ Next ]
Step 2/3  Review
  Sending 0.25 BTC to tb1q…9xk
  Change 0.8499 → tb1q…c41 ✓ derived from this wallet (m/1/7)
  Fee 0.0000021 (0.0008% of amount)
  ⚠ warnings appear here (high fee, new recipient, address reuse)
                                                      [ Next ]
Step 3/3  Sign
  Choose how to sign as an owner:
   [ Hardware wallet (USB) ]   ← v2 (WebHID Ledger/Trezor)
   [ Show QR / download PSBT ] ← v1: Coldcard, Jade, Keystone, Sparrow
   [ Approve with Ethereum wallet ] ← only if co-signer configured (§4)
   [ Save without signing ]     ← like Safe "create and let others sign"
```
Execute: shown when signatures ≥ M. Server finalizes, extracts, re-validates, broadcasts. Any user (even non-owner viewer) can click Execute, same as Safe.

### 3.6 Create account wizard

```
1. Name & network     [ Treasury ]   Network: (•) Signet ( ) Testnet4 ( ) Mainnet [disabled v1]
2. Owners             Owner 1  name [Carol]  key [ import ▾ ]
                         import ▾ = paste xpub+origin | scan QR (UR crypto-account)
                                   | upload Coldcard/Sparrow JSON | (v2) connect Ledger/Trezor
                         shows: fingerprint 7a3c91e0 · path m/48'/1'/0'/2' · tpub…
                      [+ Add owner]
3. Threshold          [ 2 ] out of 3 owners
4. Review             descriptor (with checksum), first 3 receive addresses,
                      "Verify address #0 on each device before funding" checklist
                      [ Create ]   [ Download wallet backup (descriptor + BSMS file) ]
```
Safe deploys a contract here; we deploy nothing. Creation is instant and free. The backup step is mandatory: a descriptor is needed to recover, and losing it on a multisig is worse than losing it on single-sig (xpubs of all cosigners are needed). Block "Create" until the user downloads or ticks "I have a backup".

"Add existing Safe" maps to "Import wallet" (paste descriptor or BSMS / Sparrow / Caravan config).

### 3.7 Settings

```
Settings   [ Setup ]  Address book  Notifications  Appearance  Advanced

Setup
  Owners (3)                                   Threshold: 2 of 3
   Carol    fp 7a3c91e0  m/48'/1'/0'/2'   tpub…   [verify addr]
   Alice    fp 1e09…                             [verify addr]
   Bob      fp …
  [ Change owners / threshold → creates new wallet + migration tx ]
  Descriptor   wsh(sortedmulti(2,…))#checksum   [copy] [export BSMS]
  Gap limit    20
  Chain source Esplora https://… (healthy, tip 312,456)
```
Safe's "Modules", "Guards", "Spending limits", "Safe Apps permissions" panels: no BTC meaning in v1. Hide; don't show disabled stubs.

### 3.8 Receive with on-device verification

```
Receive                     ┌───────────┐
 tb1q…7h3k  [copy]          │   QR      │
 Index m/0/12               └───────────┘
 ⚠ Before sending large amounts, verify this address on a device:
   [ Show on Ledger ] (v2)  [ Show on Trezor ] (v2)
   [ Coldcard: Address Explorer → match ]  [ Jade: Verify address ]
 [ New address ]  Label: [          ]
```
Verification matters more than on Safe: on Safe the address is fixed and on-chain; here the server derives addresses, so a compromised server could show an attacker's address. Device verification of the multisig address requires the device to have the wallet's descriptor registered (Coldcard/Jade/Ledger all require this for multisig display). **UNVERIFIED** per-device detail — check each device's current multisig-registration flow during the build.

---

## 4. Ethereum-signature approvals

The requirement: allow Ethereum signatures to approve BTC transactions, if possible.

### 4.1 Why an ETH wallet can't directly produce a valid BTC multisig signature

Both chains use secp256k1 ECDSA, so the key type matches. What doesn't match is *what gets signed*:

- A Bitcoin P2WSH input signature is ECDSA over the **BIP-143 sighash** (double-SHA256 of a specific serialization of the tx, input, amount, and script). Taproot uses the BIP-341 sighash with Schnorr (BIP-340), a different signature scheme entirely.
- `personal_sign` signs `keccak256("\x19Ethereum Signed Message:\n" + len + message)`. You can't choose a message whose prefixed keccak equals a given SHA256d sighash (that's a preimage attack on keccak).
- EIP-712 signs `keccak256("\x19\x01" ‖ domainSeparator ‖ structHash)`. Same problem.
- Bitcoin Script has no keccak opcode and can't parse EIP-712. `OP_CHECKSIG` only verifies a signature over the sighash it computes itself. So there's no script that says "accept a signature over the keccak digest of this tx".
- The one way a stock ETH wallet could sign an arbitrary 32-byte digest is `eth_sign` (raw hash signing). Current status, checked today:
  - **MetaMask: removed.** MetaMask/core changelogs record removal across packages ("Support for `eth_sign` is being removed", e.g. `@metamask/signature-controller` 17.0.0, PR [#4319](https://github.com/MetaMask/core/pull/4319); [changelog](https://github.com/MetaMask/core/blob/main/packages/signature-controller/CHANGELOG.md)). The extension's `MESSAGE_TYPE` list in [`shared/constants/app.ts`](https://github.com/MetaMask/metamask-extension/blob/main/shared/constants/app.ts) has `personal_sign`, `eth_signTypedData*`, `eth_signTransaction`, and no `eth_sign`.
  - **Rabby: refuses it.** Source: [`src/background/controller/provider/controller.ts`](https://github.com/RabbyHub/Rabby/blob/develop/src/background/controller/provider/controller.ts) — "Signing with 'eth_sign' can lead to asset loss. For your safety, Rabby does not support this method."
  - Rainbow, Ledger's ETH app, MetaMask Mobile and the Coinbase SDK also have no raw-hash path. See 4.1.1 (2) for sources. Long-tail wallets are **UNVERIFIED**. Even where raw-hash signing still works, the user sees a meaningless hex blob. That's blind signing, the exact phishing vector wallets removed it for. Building on it would be wrong even if it worked.
- Even with a raw ECDSA signature over the correct sighash, the ETH key would have to be a cosigner key in the descriptor, i.e. the owner's ETH private key is now also a BTC key. Possible (same curve), but it means the ETH wallet's single key controls BTC with no hardware-wallet BTC display. And it's moot because the signing method doesn't exist.

**Conclusion:** an ETH signature can be an *authorization* that something else turns into a BTC signature. It can't be the BTC signature.

### 4.1.1 "Can't miniscript enforce this?"

No. Miniscript is a structured subset of Bitcoin Script, so it can only enforce what Script can. Checked 2026-10-07.

**(1) What miniscript can express**

- **Keys:** `pk`, `pkh`, `multi` (P2WSH), `multi_a` (Tapscript), `thresh`.
- **Timelocks:** `after` (absolute) and `older` (relative).
- **Hash locks:** `sha256`, `hash256`, `ripemd160`, `hash160` preimages. There's no keccak.
- **Combinators:** the `and_*`, `or_*` and `andor` fragments.

Every signature check compiles to `OP_CHECKSIG(VERIFY)`/`OP_CHECKMULTISIG`. These verify a signature over the **sighash the interpreter computes from the spending tx**: BIP-143 for P2WSH, BIP-341 for Tapscript. No opcode on mainnet verifies a signature over a message taken from the stack. An EIP-191/712 approval is ECDSA over `keccak256(prefix ‖ …)`, so Script has no way to check it. It can't compute keccak, and it can't verify a signature over arbitrary data.

**(2) Closest on-chain option: the ETH key as a BTC owner key, blocked by the signer**

An Ethereum account key is a plain secp256k1 key. Its public key can be recovered from any `personal_sign` signature, compressed to 33 bytes, and placed directly in the descriptor:

```
wsh(multi(2, <eth_owner_pubkey_compressed>, OwnerB, OwnerC))
```

Script then enforces it like any other owner. It has to be the P2WSH/ECDSA form, because Taproot `multi_a` needs BIP-340 Schnorr signatures, which no ETH wallet produces. The coordinator could re-encode a 65-byte `(r,s,v)` as DER + sighash byte and normalize to low-S.

The blocker is the signer. The ETH wallet would have to ECDSA-sign the raw 32-byte BIP-143 sighash with **no prefix**. That is `eth_sign`, and the mainstream wallets no longer offer it:

| Wallet | Raw-hash signing? | Source |
|---|---|---|
| MetaMask (extension + mobile) | **No.** | The shared wallet middleware dispatch table has `personal_sign`, `eth_signTypedData*`, `eth_signTransaction` and no `eth_sign` ([`eth-json-rpc-middleware/src/wallet.ts`](https://github.com/MetaMask/core/blob/main/packages/eth-json-rpc-middleware/src/wallet.ts)). Removal: `signature-controller` 17.0.0, [#4319](https://github.com/MetaMask/core/pull/4319). Mobile still *advertises* `eth_sign` in its WalletConnect approved-methods list ([`wc-config.ts`](https://github.com/MetaMask/metamask-mobile/blob/main/app/core/WalletConnect/wc-config.ts)), but no handler signs it. |
| Rabby | **No**, refuses explicitly. | [`provider/controller.ts`](https://github.com/RabbyHub/Rabby/blob/develop/src/background/controller/provider/controller.ts): "Rabby does not support this method." |
| Ledger Ethereum app | **No raw-hash APDU.** | The [APDU list](https://github.com/LedgerHQ/app-ethereum/blob/master/doc/ethapp.adoc) has only SIGN TRANSACTION, SIGN PERSONAL MESSAGE, SIGN EIP 712 and SIGN EIP 7702 AUTHORIZATION. Personal message always hashes in `"\x19Ethereum Signed Message:\n"` ([`cmd_sign_message.c`](https://github.com/LedgerHQ/app-ethereum/blob/master/src/features/sign_message/cmd_sign_message.c)). Even the EIP-712 "v0" mode, which takes a precomputed domain hash and message hash, signs `keccak(0x19 0x01 ‖ domainHash ‖ messageHash)` ([`common_712.c`](https://github.com/LedgerHQ/app-ethereum/blob/master/src/features/sign_message_eip712_common/common_712.c)). Any ETH wallet using Ledger as its signer inherits this. |
| Rainbow (WalletConnect) | **No.** | [`onSessionRequest.ts`](https://github.com/rainbow-me/rainbow/blob/develop/src/features/wallet-connect/handlers/onSessionRequest.ts): accepts `eth_sign` in the session but responds "Rainbow does not support legacy eth_sign". |
| Coinbase Wallet / Base (SDK) | **No** `eth_sign` in the SDK's EIP-155 method list. | [`eip155/methods.ts`](https://github.com/coinbase/coinbase-wallet-sdk/blob/master/packages/wallet-sdk/src/core/namespaces/eip155/methods.ts). The SDK list is not the wallet backend, so this is strong evidence but not proof. |
| Long-tail WalletConnect wallets, Trust Wallet app | **UNVERIFIED**. | Not worth chasing. A wallet that still allows it is offering blind signing. |

Net: the on-chain path exists in Script, but no mainstream ETH wallet will produce the signature. If one did, the owner would be blind-signing a hex blob. That's the opposite of what anyone wants from "approve with my ETH wallet".

**(3) Covenant soft forks: not active, and wouldn't help directly**

- **BIP 348 `OP_CHECKSIGFROMSTACK`:**
  - **Status: Draft** ([bip-0348.md](https://github.com/bitcoin/bips/blob/master/bip-0348.md)).
  - Bitcoin Core implementation [#32247](https://github.com/bitcoin/bitcoin/pull/32247) is "regtest only" and still **open**.
  - Active on mainnet: **no**.
  - Active only on the Bitcoin Inquisition default signet, since block 272592 (2025-10-06) ([Inquisition 29.4 notes](https://delvingbitcoin.org/t/bitcoin-inquisition-29-4/2739)).
- **BIP 347 `OP_CAT`:**
  - **Status: Complete** ([bip-0347.mediawiki](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki)). Under BIP-3, "Complete" means the spec is finished, not activated. Activation is "Deployed".
  - Active on mainnet: **no**.
  - Active on Inquisition signet since block 193536 (2024-04-30).
- **Neither verifies an Ethereum signature, even if activated.** CSFS verifies a **BIP-340 Schnorr** signature against a 32-byte x-only key over a message from the stack (spec: "validated against the public key and message according to BIP 340"). ETH wallets produce **ECDSA** over **keccak**-prefixed digests. A different signature scheme and a different hash, with no keccak opcode to bridge them. Using CSFS would need the ETH wallet to produce BIP-340 signatures, which none do. Even with OP_CAT, Script would still have to compute keccak before an ECDSA check, and no proposal adds either.
- Signet-only availability means we could prototype covenant ideas there, but nothing about the ETH-approval problem changes.

**(4) Hash-preimage trick: same trust as the co-signer, and weaker**

Policy shape: `and_v(v:multi(...owners...), sha256(H))`. The coordinator holds the preimage of `H` and reveals it only once enough ETH approvals have landed.

- **Trust model:** identical to the co-signer in 4.2(a). An off-chain party checks the ETH approvals and holds the on-chain gate. If it is compromised, the gate opens. If it disappears, the gate stays shut unless there's a timelocked path around it. Bitcoin doesn't check the ETH approvals in either case.
- **It is strictly weaker than a co-signer signature:**
  1. A preimage isn't bound to a transaction. A signature commits to a specific sighash.
  2. Once revealed in any spend, the preimage is public forever. Every other UTXO locked to the same `H` loses its gate. So you'd need a fresh `H` per UTXO or per spend, plus re-funding.
- Use the co-signer instead. It has the same trust and better binding.

**Bottom line:** Bitcoin can't verify an ETH approval on-chain today, and the proposed soft forks wouldn't change that. Every working design has an off-chain verifier (our co-signer, an MPC network, or a preimage holder) that turns ETH approvals into a Bitcoin-valid witness. The trade-offs in 4.2 stand.

### 4.2 Viable architectures

#### (a) Policy co-signer (our own)

A service we run holds **one** BTC cosigner key in an HSM/KMS. It signs a PSBT only after it has verified K-of-L EIP-712 approvals from registered ETH addresses over that exact PSBT.

Descriptor (miniscript, v2 policy):
```
wsh(or_d(
  multi(2, OwnerA, OwnerB, CoSigner),           # normal path: 2-of-3, co-signer counts as one
  and_v(v:multi(2, OwnerA, OwnerB, RecoveryC), older(4320))  # ~30 days after funds last moved: owners recover without co-signer
))
```
(Exact shape TBD; the point is a timelocked path that excludes the co-signer.)

EIP-712 approval payload:
```
domain  { name: "btc-safe", version: "1", chainId: 1, verifyingContract: 0x0…0 (unused) , salt: walletId }
Approve { walletDescriptorHash: bytes32, unsignedTxid: bytes32, inputs: bytes32 (hash of outpoints+amounts),
          outputs: Output[] {scriptPubKeyHex: bytes, amountSats: uint64}, feeSats: uint64, expiry: uint64 }
```
The co-signer recomputes every field from the PSBT itself, never from the client's summary. `outputs` is shown in the wallet's EIP-712 prompt as hex scripts — readable enough to compare amounts, not addresses. Mitigation: include a `displayAddresses: string[]` field the co-signer also checks against the scripts, so MetaMask shows `tb1q…` strings.

- **Trust model:** whoever controls the co-signer key + the approval-verification code can sign *one* of M signatures. With 2-of-3 where the co-signer is one key, a compromised co-signer still needs one real owner. If you configure the ETH approvals to *replace* a hardware owner (e.g. 2-of-3 = OwnerA hardware + CoSigner + RecoveryC), then a compromised co-signer + one owner is enough, and the ETH approval set is only as strong as our server. Say this plainly to users.
- **Liveness:** if the co-signer goes down, the timelocked path recovers funds. Without that path, the operator can hold funds hostage. Required, not optional.
- **UX:** best of the three. Owners click "Approve with Ethereum wallet", sign one EIP-712 message in MetaMask/Rabby/Safe-via-1271 (bonus: an actual Safe on Ethereum could approve via EIP-1271 — **UNVERIFIED** effort, but it's just `isValidSignature` over RPC).
- **Cost:** AWS KMS supports `ECC_SECG_P256K1` signing keys (**UNVERIFIED** current pricing, ~$1/key/month + per-request historically). Engineering: ~25–35 agent-hours on top of MVP, plus the miniscript v2 policy work.
- **Main risk:** this is a custodial-ish component. Its code needs the same review bar as the wallet itself.

#### (b) MPC / threshold-signature networks

Status checked today:

| Network | Live? | How an ETH signature would authorize a BTC signature | Verdict |
|---|---|---|---|
| **NEAR Chain Signatures** | Yes. MPC contract `v1.signer` on mainnet, `v1.signer-prod.testnet` on testnet ([docs](https://docs.near.org/chain-abstraction/chain-signatures/implementation)). Docs show Bitcoin signing examples. | A NEAR contract we write verifies EIP-712 approvals (ecrecover in a NEAR contract), then calls `v1.signer` to sign the BIP-143 sighash for a key derived from our contract's account + path. | Works in principle. The derived key is controlled by our NEAR contract + the MPC network's threshold. It becomes one cosigner in the BTC multisig (same slot as the co-signer in (a)). Adds NEAR gas, NEAR account ops, and trust in the NEAR MPC node set. |
| **Ika** | "Live on mainnet in beta, coordinated on Sui; pre-alpha for builders on Solana" ([README](https://github.com/dwallet-labs/ika)). 2PC-MPC: every signature needs the user share + 2/3 of the network. | A Sui Move contract holding the dWallet's user-share capability verifies the approval, then requests a signature. Verifying secp256k1 ETH signatures in Move is possible (Sui has `ecdsa_k1`) — **UNVERIFIED** for EIP-712 hashing ergonomics. | Live but explicitly beta ("Using it involves many risks"). Strongest decentralization story; heaviest integration (Sui + Move). |
| **Lit Protocol** | Live, but **no longer an MPC network** in the current "Chipotle" docs: keys are held in a TEE enclave (Phala/dstack), authority recorded on Base, Lit Actions run in the enclave ([architecture](https://developer.litprotocol.com/architecture/index)). | A Lit Action verifies EIP-712 approvals and signs the sighash with a PKP. Least code of the three. | Trust model is "attested TEE", not threshold crypto. Bitcoin sighash signing via PKP: **UNVERIFIED** in current docs (I saw "sign on any chain", not a BTC example). |

All three put an external network's liveness and correctness in the signing path. All three only ever supply **one** cosigner key; the same timelocked recovery path from (a) is still required. Net: they swap "trust our HSM" for "trust their node set / TEE", at higher integration cost and external dependency. For a self-hosted tool with a handful of users per deployment, that's a worse trade than (a) today. Revisit if users explicitly can't accept the operator running the co-signer.

#### (c) ETH wallets that natively hold BTC keys

- **MetaMask has native Bitcoin support** (Dec 2025 rollout, per press: [Yahoo/Decrypt](https://finance.yahoo.com/news/metamask-adds-bitcoin-support-teases-061231942.html); I couldn't load MetaMask's own support article — **UNVERIFIED** from a MetaMask primary source beyond the code below). It's implemented as the Bitcoin Wallet Snap, now in [`MetaMask/internal-snaps/packages/bitcoin-wallet-snap`](https://github.com/MetaMask/internal-snaps) (the old [`snap-bitcoin-wallet`](https://github.com/MetaMask/snap-bitcoin-wallet) repo is archived).
- The snap has a **`signPsbt`** handler ([`AccountUseCases.ts`](https://github.com/MetaMask/internal-snaps/blob/main/packages/bitcoin-wallet-snap/src/use-cases/AccountUseCases.ts)) with a confirmation screen listing outputs. It calls BDK's `account.sign(psbt)` and takes an `origin`, so it's reachable from dapps through some API.
- This is **not** "an ETH signature approving a BTC tx". It's a BTC key that happens to live in MetaMask. But it gives the UX that's wanted: owner clicks one button, MetaMask pops up, done.
- Open questions, all **UNVERIFIED**, needing a ~3-hour signet spike:
  1. Can a dapp get the account's **xpub with key origin** (needed to put it in a multisig descriptor)? If MetaMask only exposes an address/pubkey per index, we'd need a single fixed pubkey in the descriptor (`wsh(sortedmulti(2, A_xpub/*, B_xpub/*, metamaskPubKey))`), which breaks per-address derivation unless we accept key reuse across addresses for that cosigner.
  2. Will BDK inside the snap sign a **P2WSH multisig input** it doesn't consider "its" wallet's script? BDK's signers match on `bip32_derivation` fingerprints, so it may work if we populate those correctly. Untested.
  3. What is the dapp-facing method (Wallet Standard / multichain API / `wallet_invokeSnap`)?
- Other wallets that sign arbitrary PSBTs from a dapp (Xverse, Leather, Unisat, OKX): these are BTC wallets, not ETH wallets. Worth supporting the same way in v2 (a "browser BTC wallet" signer type). **UNVERIFIED** which of them sign foreign multisig inputs.

### 4.3 Recommendation (adopted 2026-10-07)

1. **v1: no ETH approvals.** Ship the PSBT flow with hardware wallets. It's the safe base and it's needed regardless.
2. **v1.5 spike (≈3 agent-hours):** test MetaMask's Bitcoin snap as a multisig cosigner on signet (the three questions in 4.2c). If it works, it gives "approve in MetaMask" with no server key and no new trust. This is the best outcome and it's cheap to find out.
3. **v2: policy co-signer (a)**, run by the deployment's operator, with KMS key + mandatory timelocked recovery path, for users who want EVM-style approval flows (incl. approving from an existing Ethereum Safe via EIP-1271). Present it to users as "the server holds one of N keys; it can't move funds alone; if it disappears you recover after N days."
4. **Don't build on (b) now.** Write the co-signer behind a `CoSigner` trait so NEAR Chain Signatures or Ika can replace the KMS backend later without UI changes.
5. **Never** build on `eth_sign`, even in wallets that still allow it.

---

## 5. Architecture

```
 Browser (Next.js)  ──HTTPS/JSON──▶  api (axum)  ──▶ Postgres
   │  WebHID (v2)                     │   ├─▶ chain: Esplora (HTTP) or Electrum
   │  QR (UR/BBQr)                    │   └─▶ cosigner (optional, separate process) ──▶ KMS/HSM
   └─ MetaMask (EIP-712 / BTC snap)   └─ watcher task (polls tip, updates UTXOs/proposals)
```

### 5.1 Crate layout (cargo workspace)

```
btc-safe/
  crates/
    core/        # domain types, descriptor building (rust-miniscript), PSBT validation, fee checks; no I/O
    wallet/      # bdk_wallet wrapper: sync, coin selection w/ reservation filter, PSBT build/combine/finalize
    chain/       # trait ChainSource + esplora/electrum impls (bdk_esplora / bdk_electrum)
    store/       # sqlx Postgres repos + migrations
    api/         # axum routes, auth (SIWE for ETH-identity, or simple session auth), OpenAPI
    watcher/     # background sync: tip, UTXOs, mempool conflicts, proposal state transitions
    cosigner/    # v2, separate binary: EIP-712 verify (alloy), policy engine, KMS signer behind trait CoSigner
  web/           # Next.js app
```
Versions checked today: `bdk_wallet` latest release v3.2.0 (2026-09-22, [releases](https://github.com/bitcoindevkit/bdk_wallet/releases)). rust-miniscript has no GitHub "latest release" object; pin from crates.io at build time.

`core` has no network or DB access so the validation logic can be fuzzed and property-tested in isolation.

### 5.2 API (v1)

```
POST   /wallets                          create (name, network, threshold, owners[{name, xpub, fingerprint, path}])
POST   /wallets/import                   descriptor | BSMS | Sparrow/Caravan JSON
GET    /wallets/:id                      summary: balance, policy, owners, tip
GET    /wallets/:id/addresses?kind=receive&next=true
POST   /wallets/:id/addresses/:idx/label
GET    /wallets/:id/utxos
GET    /wallets/:id/history
GET    /wallets/:id/fees                 fee estimates from chain source
POST   /wallets/:id/proposals            {outputs[], feeRate, utxos?[], rbf, replaces?} → unsigned PSBT + review summary
GET    /wallets/:id/proposals?status=queue|history
GET    /proposals/:id                    PSBT (base64), decoded summary, signatures by owner
POST   /proposals/:id/signatures         {psbt} → server combines, verifies each new sig belongs to a known owner fp
POST   /proposals/:id/execute            finalize, extract, re-validate, broadcast
DELETE /proposals/:id                    soft-delete (with the "signatures still valid" warning)
GET/POST/DELETE /wallets/:id/address-book
-- v2
POST   /proposals/:id/eth-approvals      {signer, signature} (EIP-712)
POST   /proposals/:id/cosign             triggers cosigner once K-of-L ETH approvals present
```

### 5.3 DB schema (Postgres)

```sql
wallets(id uuid pk, name text, network text, descriptor_ext text, descriptor_int text,
        threshold int, policy_kind text /* sortedmulti_p2wsh | miniscript */, created_at timestamptz,
        next_receive_idx int, next_change_idx int,
        ordering_mode text /* parallel | strict */ default 'parallel')

owners(id uuid pk, wallet_id fk, name text, xpub text, fingerprint char(8), path text,
       kind text /* hardware | sparrow | metamask_btc | cosigner */, position int,
       unique(wallet_id, fingerprint))

proposals(id bigserial pk /* the "#14" shown in UI */, wallet_id fk, created_by text,
          status text, psbt bytea /* latest combined */, unsigned_txid char(64),
          fee_sats bigint, fee_rate numeric, replaces_proposal_id bigint null,
          predecessor_proposal_id bigint null /* strict-order chain */,
          broadcast_txid char(64) null, invalidated_by_txid char(64) null,
          created_at, updated_at)

proposal_inputs(proposal_id fk, outpoint text, amount_sats bigint)
  -- partial unique index: outpoint unique among non-terminal proposals that are NOT replacements of each other
  -- (enforced in code + a deferred constraint; replacements share inputs by design)

proposal_outputs(proposal_id fk, idx int, script_pubkey bytea, amount_sats bigint,
                 is_change bool, change_path text null)

signatures(proposal_id fk, owner_id fk, input_idx int, sig bytea, added_at,
           primary key(proposal_id, owner_id, input_idx))

eth_approvers(id, wallet_id fk, eth_address char(42), name, active bool)        -- v2
eth_approvals(proposal_id fk, approver_id fk, eip712_digest char(64), signature bytea,
              expiry timestamptz, verified_at timestamptz, primary key(proposal_id, approver_id))  -- v2

address_book(id, wallet_id fk, label text, address text, network text)
audit_log(id, wallet_id, actor, action, payload jsonb, at)
```

### 5.4 PSBT lifecycle state machine

```
             create
  (none) ───────────▶ PENDING ──sig added──▶ SIGNING ──sigs ≥ M──▶ READY
                        │                       │                    │ execute
                        │ delete                │ delete             ▼
                        ▼                       ▼                BROADCAST ──conf ≥ 1──▶ CONFIRMED
                     DELETED                 DELETED                 │
                                                                     │ input spent by other tx
  any non-terminal ──input spent by other tx──▶ INVALIDATED          ▼
  any non-terminal ──sibling replacement confirmed──▶ CONFLICTED   CONFLICTED / INVALIDATED
  BROADCAST ──dropped from mempool, inputs unspent──▶ READY (re-broadcast allowed)
```
**Strict-order wallets** add one rule and one transition:
- *Create rule:* if the wallet has any non-terminal proposals, the new proposal must spend the change output of the most recent non-terminal proposal (the queue tail). Its `predecessor_proposal_id` is set to that proposal. The server rejects a tail proposal with no change output (nothing to chain onto).
- *Cascade:* when a proposal is DELETED, INVALIDATED, CONFLICTED, or replaced (RBF → new txid), every non-terminal descendant is marked INVALIDATED with reason `predecessor_replaced`. Owners rebuild and re-sign them.
- In parallel mode none of this applies; reservations (§2 rule 1) keep proposals independent.

Transitions out of BROADCAST/READY are driven by the watcher reading the chain, never by the client. Every signature submission re-runs full validation (§6) against the stored unsigned tx: a submitted PSBT whose unsigned tx differs from ours by even one byte is rejected.

---

## 6. Security

1. **Watch-only invariant.** The `api` process has no code path that loads a private key. Enforced by: no `bitcoin::PrivateKey`/`Xpriv` types outside `cosigner` (CI grep + `#![deny]` via a clippy disallowed-types config), BDK wallets constructed only from public descriptors, and `cosigner` being a separate binary with its own deployment and credentials.
2. **PSBT validation on every write** (`core::validate`):
   - unsigned tx byte-equal to the stored proposal's;
   - every input is a UTXO of this wallet, with `witness_utxo` amounts matching the chain (stops the fee-lie attack on segwit v0 amounts);
   - every output marked change: its script is re-derived server-side from the wallet's internal descriptor at the claimed index, with `bip32_derivation` entries matching the owners' fingerprints; otherwise it's shown as an external recipient;
   - fee sanity: absolute fee ≤ configurable cap (default 0.01 BTC), fee rate ≤ 10× current "fast" estimate, fee < 5% of amount sent (warn) — hard-block above caps unless an override is typed;
   - no unknown sighash types (only `SIGHASH_ALL` / default);
   - each new partial signature: pubkey belongs to a registered owner (fingerprint + derived pubkey), and the signature verifies against the computed sighash. Bad sigs are rejected before storage.
3. **xpub fingerprint checks.** At wallet creation: no duplicate fingerprints or xpubs; xpub depth/path consistent with the claimed origin; network prefix matches network; warn if an xpub looks like a single-sig path (m/84') being used for multisig.
4. **Address verification on device.** UI prompts device verification before first deposit and for each receive; descriptor/BSMS export so devices can register the multisig. The server-rendered address is never the only check — the threat model includes a compromised server.
5. **Client-side re-check.** The frontend independently decodes the PSBT (bitcoinjs-lib or a WASM build of `core`) and recomputes the review summary, so a compromised API can't show a fake summary. Hardware devices remain the final check.
6. **No server-side key material** except the optional `cosigner`, which uses a KMS/HSM non-exportable key, its own policy limits (per-tx and per-day amount caps, allowed destination list optional), and logs every signature.
7. **Auth.** Viewing a wallet requires a session. Proposing requires an owner/proposer role. Signing doesn't need app auth (the signature itself is the authorization), same as Safe. SIWE (EIP-4361) for login is a natural fit if ETH approvals ship; otherwise passkeys.
8. **Backups.** Descriptor export + BSMS; Postgres holds only replaceable coordination state. Losing the DB loses the queue and labels, not funds.

---

## 7. Licensing and branding

- **safe-global/safe-wallet-monorepo is GPL-3.0** (checked via GitHub API today: `license.spdx_id = GPL-3.0`; [LICENSE](https://github.com/safe-global/safe-wallet-monorepo/blob/dev/LICENSE)). `safe-wallet-web` resolves to the same repo and license.
- Forking the frontend makes our frontend a derivative work under GPL-3.0. For a self-hosted tool that we distribute to others, we'd owe them source under GPL-3.0. GPL-3.0 (not AGPL) has no network clause, so pure hosting without distribution doesn't trigger source obligations — but handing someone a deployable build does. The Rust backend talks to it over HTTP and is a separate program; it isn't infected.
- **Branding:** we can't use "Safe", "Safe{Wallet}", or their logo/marks. GPL grants copyright permission, not trademark rights. **UNVERIFIED**: whether Safe publishes a specific trademark policy; assume the marks are protected.
- **Decision (2026-10-07): clean-room reimplementation of the look**, not a fork. Reasons: (1) the Safe codebase is built around EVM concepts (nonces, contract calls, tx service, Safe SDK) — we'd delete most of it; (2) a fork drags along GPL for code we're rewriting anyway; (3) layout, information architecture, and interaction patterns aren't copyrightable the way code is. Build with MUI (Safe's web app uses MUI — **UNVERIFIED** for the current monorepo) or shadcn/ui, match spacing/sidebar/row structure, different name, different logo, different palette accent. Don't copy their SVGs, illustrations, or CSS files.
- (Considered and rejected: forking and going GPL. Legitimate, but we chose clean-room.)

---

## 8. Scope and estimates (agent-hours)

### MVP (signet, 2-of-3 P2WSH sortedmulti, file/QR signing)

| Item | Agent-hours |
|---|---|
| Workspace, CI, Postgres migrations, config | 4 |
| `core`: descriptor build/import (incl. BSMS, Sparrow/Caravan JSON), PSBT validation, fee checks + property tests | 14 |
| `wallet` + `chain`: BDK sync via Esplora, coin selection with reservation, build/combine/finalize | 10 |
| `watcher`: UTXO + conflict detection, state machine transitions | 6 |
| `api`: endpoints above, auth (passkey or simple session) | 8 |
| Frontend shell: sidebar, routing, account switcher, theme | 6 |
| Screens: Home, Assets/UTXOs, Transactions queue/history, Send flow, Create wizard, Settings, Receive, Address book | 20 |
| PSBT QR (UR/BBQr animated) + file upload/download | 5 |
| Client-side PSBT re-decode for review | 4 |
| End-to-end on signet with Sparrow + one hardware device (Coldcard or Jade) | 6 |
| Review pass (adversarial on validation code) | 5 |
| **Total** | **≈ 88 agent-hours** |

Add real wall-clock for hands-on hardware-device testing; an agent can't press device buttons.

### v1.5
- MetaMask BTC snap cosigner spike: 3
- If it works, "MetaMask (Bitcoin)" signer type: 8

### v2
| Item | Agent-hours |
|---|---|
| WebHID Ledger + Trezor (incl. multisig registration flows) | 16 |
| Miniscript policies: timelocked recovery, policy editor, descriptor templates | 14 |
| Policy co-signer (separate binary, KMS signer, EIP-712 approvals, limits, audit log) | 30 |
| ETH approvals UI (connect wallet, approval rows "2 of 3 ETH approvals", EIP-1271 for Ethereum Safes) | 10 |
| Owner change → migration (sweep) flow | 8 |
| Mainnet hardening: external review, fee-cap tuning, monitoring | 12 |
| **v2 total** | **≈ 90 agent-hours** |

### Decisions (closed 2026-10-07)
1. **Clean-room rebuild of the Safe look** (not a fork). Safe's code is GPL-3.0; we can't use the Safe name or logo. See §7.
2. **"Approve in MetaMask" = MetaMask's own BTC key first** (v1.5 spike, §4.2c). ETH-address approvers come in v2 via the policy co-signer (§4.2a).
3. **The deployment's operator runs the co-signer.** Another party can take it over later; the `CoSigner` trait and separate binary keep that a deployment change.
4. **Ordering:** parallel by default; strict-order available per wallet (§2 "Ordering modes", §5.4).
