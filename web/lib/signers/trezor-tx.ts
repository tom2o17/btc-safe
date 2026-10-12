// Pure translation between our PSBTs and Trezor Connect's signTransaction shape. No SDK and no
// device here, so it runs in node unit tests (web/test/trezor-tx.test.mjs).
//
// What the Trezor needs for a P2WSH sortedmulti input or change output (firmware
// core/src/apps/bitcoin/{multisig.py,sign_tx/change_detector.py}):
//  - address_n: the device's own full path (origin path + chain + index);
//  - multisig: every owner's xpub with the same [chain, index] suffix, m, and
//    pubkeys_order = LEXICOGRAPHIC (sortedmulti; firmware ≥ 2.8.7 on Model T/Safe, ≥ 1.13.0 on Model One);
//  - the previous transactions (refTxs), which the firmware hashes to check amounts.
// Change is only recognized when its multisig fingerprint, wallet path and script type match the
// inputs'. The fingerprint hashes the nodes in the order given unless pubkeys_order is
// LEXICOGRAPHIC, so we always send the owners in wallet position order with LEXICOGRAPHIC.
//
// Nothing the server sent is trusted: every input's script and every change address is re-derived
// here from the owners' xpubs before the device is asked to sign.
//
// Watch-only: xpubs and public keys only.

import { Psbt, Transaction, address as baddress, networks, payments, script as bscript } from "bitcoinjs-lib";
import { BIP32Factory } from "bip32";
import * as ecc from "@bitcoinerlab/secp256k1";
import type { KeyOwner } from "../bitcoin";

const bip32 = BIP32Factory(ecc);

/** Trezor `MultisigPubkeysOrder.LEXICOGRAPHIC` (protobuf enum value). */
export const LEXICOGRAPHIC = 1;
/**
 * Firmware older than core 2.8.7 / legacy 1.13.0 drops `pubkeys_order` as an unknown field and
 * builds the script in the order sent (Trezor's own fixture: trezor-suite
 * packages/connect-core/e2e/__fixtures__/signTransactionMultisigPubkeysOrder.ts, legacyResults
 * '<2.8.7'). We've already checked every input script against its prev tx, so the device then
 * failing that same check (core apps/bitcoin/sign_tx/bitcoin.py "Input does not match
 * scriptPubKey") means its firmware is too old for sortedmulti.
 */
export const OLD_FIRMWARE_SYMPTOM = /input does not match scriptpubkey/i;
const HARDENED = 0x80000000;

export type TrezorCoin = "btc" | "test" | "regtest";

export type TrezorMultisig = {
  pubkeys: { node: string; address_n: number[] }[];
  signatures: string[];
  m: number;
  pubkeys_order: number;
};

export type TrezorInput = {
  address_n: number[];
  prev_hash: string;
  prev_index: number;
  amount: string;
  sequence: number;
  script_type: "SPENDWITNESS";
  multisig: TrezorMultisig;
};

export type TrezorOutput =
  | { address_n: number[]; amount: string; script_type: "PAYTOWITNESS"; multisig: TrezorMultisig }
  | { address: string; amount: string; script_type: "PAYTOADDRESS" }
  | { op_return_data: string; amount: "0"; script_type: "PAYTOOPRETURN" };

export type TrezorRefTx = {
  hash: string;
  version: number;
  lock_time: number;
  inputs: { prev_hash: string; prev_index: number; script_sig: string; sequence: number }[];
  bin_outputs: { amount: string; script_pubkey: string }[];
};

export type TrezorSignRequest = {
  coin: TrezorCoin;
  inputs: TrezorInput[];
  outputs: TrezorOutput[];
  refTxs: TrezorRefTx[];
  version: number;
  locktime: number;
  push: false;
};

export type BuiltRequest = {
  request: TrezorSignRequest;
  /** The device owner's pubkey for each input, for merging signatures back. */
  inputPubkeys: Uint8Array[];
  /** vouts the device will treat as change (it won't ask the user to confirm them). */
  changeVouts: number[];
};

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

export function networkFor(name: string) {
  if (name === "bitcoin" || name === "mainnet") return networks.bitcoin;
  if (name === "regtest") return networks.regtest;
  return networks.testnet; // signet, testnet3, testnet4: tb1 + tpub
}

/**
 * Trezor Connect has no signet coin (coinInfo `CoinSymbol`: btc, test, regtest). Signet shares
 * testnet's tb1 HRP, tpub version and SLIP-44 coin type 1, and we pass every previous tx
 * ourselves, so `test` signs signet transactions.
 */
export function trezorCoin(networkName: string): TrezorCoin {
  if (networkName === "bitcoin" || networkName === "mainnet") return "btc";
  if (networkName === "regtest") return "regtest";
  return "test";
}

/** "m/48'/1'/0'/2'" → [0x80000030, 0x80000001, 0x80000000, 0x80000002] */
export function parsePath(path: string): number[] {
  const p = path.trim().replace(/^m\/?/, "");
  if (!p) return [];
  return p.split("/").map((s) => {
    const m = s.match(/^(\d+)(['hH]?)$/);
    if (!m) throw new Error(`bad path element "${s}" in ${path}`);
    const n = Number(m[1]);
    if (n >= HARDENED) throw new Error(`path element ${n} out of range`);
    return m[2] ? (n | HARDENED) >>> 0 : n;
  });
}

/** Master fingerprint from Connect's numeric `rootFingerprint` (big-endian uint32). */
export function fingerprintHex(n: number): string {
  return (n >>> 0).toString(16).padStart(8, "0");
}

function childPubkey(o: KeyOwner, chain: number, index: number, network: typeof networks.testnet): Uint8Array {
  return Uint8Array.from(bip32.fromBase58(o.xpub, network).derive(chain).derive(index).publicKey);
}

/** sortedmulti witness script at chain/index. */
export function witnessScriptAt(owners: KeyOwner[], threshold: number, chain: number, index: number, network: typeof networks.testnet): Uint8Array {
  const pubkeys = owners.map((o) => childPubkey(o, chain, index, network)).sort((a, b) => (toHex(a) < toHex(b) ? -1 : 1));
  const redeem = payments.p2ms({ m: threshold, pubkeys, network });
  if (!redeem.output) throw new Error("could not build multisig script");
  return Uint8Array.from(redeem.output);
}

function p2wshOf(ws: Uint8Array, network: typeof networks.testnet) {
  const p = payments.p2wsh({ redeem: { output: ws, network }, network });
  if (!p.output || !p.address) throw new Error("could not build P2WSH");
  return { script: Uint8Array.from(p.output), address: p.address };
}

export function multisigAt(owners: KeyOwner[], threshold: number, chain: number, index: number): TrezorMultisig {
  return {
    pubkeys: owners.map((o) => ({ node: o.xpub, address_n: [chain, index] })),
    signatures: owners.map(() => ""),
    m: threshold,
    pubkeys_order: LEXICOGRAPHIC,
  };
}

/** chain/index of the device's key in a PSBT bip32_derivation list, if it's under the device's origin path. */
function deviceSuffix(derivs: { masterFingerprint: Uint8Array; path: string; pubkey: Uint8Array }[] | undefined, device: KeyOwner): { chain: number; index: number; pubkey: Uint8Array } | null {
  const origin = parsePath(device.path);
  for (const d of derivs ?? []) {
    if (toHex(d.masterFingerprint) !== device.fingerprint.toLowerCase()) continue;
    const p = parsePath(d.path);
    if (p.length !== origin.length + 2 || !origin.every((x, i) => x === p[i])) continue;
    return { chain: p[origin.length], index: p[origin.length + 1], pubkey: Uint8Array.from(d.pubkey) };
  }
  return null;
}

function refTxFrom(raw: Uint8Array): TrezorRefTx {
  const t = Transaction.fromBuffer(raw);
  return {
    hash: t.getId(),
    version: t.version,
    lock_time: t.locktime,
    inputs: t.ins.map((i) => ({ prev_hash: toHex(Uint8Array.from(i.hash).reverse()), prev_index: i.index, script_sig: toHex(i.script), sequence: i.sequence })),
    bin_outputs: t.outs.map((o) => ({ amount: String(o.value), script_pubkey: toHex(o.script) })),
  };
}

/**
 * Builds Trezor's signTransaction params for `device` (one of `owners`) from our PSBT.
 * Throws if any input isn't this wallet's, any input lacks its previous tx, or a script
 * doesn't match what the owners' xpubs derive.
 */
export function buildTrezorRequest(psbtB64: string, owners: KeyOwner[], threshold: number, networkName: string, device: KeyOwner, changeIndex?: Map<number, number>): BuiltRequest {
  const network = networkFor(networkName);
  const psbt = Psbt.fromBase64(psbtB64.trim(), { network });
  const tx = Transaction.fromBuffer(psbt.data.getTransaction());
  const origin = parsePath(device.path);
  const refs = new Map<string, TrezorRefTx>();
  const inputPubkeys: Uint8Array[] = [];

  const inputs: TrezorInput[] = psbt.data.inputs.map((inp, i) => {
    const txin = tx.ins[i];
    const prevTxid = toHex(Uint8Array.from(txin.hash).reverse());
    const s = deviceSuffix(inp.bip32Derivation, device);
    if (!s) throw new Error(`input ${i}: no key derivation for this device (fp ${device.fingerprint}) in the PSBT`);
    const mine = childPubkey(device, s.chain, s.index, network);
    if (!eq(mine, s.pubkey)) throw new Error(`input ${i}: PSBT's pubkey for this device doesn't match its xpub at ${s.chain}/${s.index}`);
    if (!inp.nonWitnessUtxo) throw new Error(`input ${i}: the PSBT lacks the previous transaction, which the Trezor requires`);
    const prev = Transaction.fromBuffer(inp.nonWitnessUtxo);
    if (prev.getId() !== prevTxid) throw new Error(`input ${i}: non_witness_utxo is not the transaction it claims to spend`);
    const out = prev.outs[txin.index];
    if (!out) throw new Error(`input ${i}: previous tx has no output ${txin.index}`);
    const ws = witnessScriptAt(owners, threshold, s.chain, s.index, network);
    if (!eq(Uint8Array.from(out.script), p2wshOf(ws, network).script)) throw new Error(`input ${i}: the coin being spent isn't this wallet's address at ${s.chain}/${s.index}`);
    // Required, not just checked: without it the signature can't be verified or merged afterwards.
    if (!inp.witnessScript) throw new Error(`input ${i}: the PSBT lacks the witness script`);
    if (!eq(Uint8Array.from(inp.witnessScript), ws)) throw new Error(`input ${i}: witness script differs from the owners' sortedmulti at ${s.chain}/${s.index}`);
    if (inp.witnessUtxo && BigInt(inp.witnessUtxo.value) !== BigInt(out.value)) throw new Error(`input ${i}: witness_utxo amount disagrees with the previous tx`);
    if (!refs.has(prevTxid)) refs.set(prevTxid, refTxFrom(inp.nonWitnessUtxo));
    inputPubkeys.push(mine);
    return {
      address_n: [...origin, s.chain, s.index],
      prev_hash: prevTxid,
      prev_index: txin.index,
      amount: String(out.value),
      sequence: txin.sequence,
      script_type: "SPENDWITNESS",
      multisig: multisigAt(owners, threshold, s.chain, s.index),
    };
  });

  const changeVouts: number[] = [];
  const outputs: TrezorOutput[] = tx.outs.map((o, vout) => {
    const amount = String(o.value);
    const spk = Uint8Array.from(o.script);
    // Change candidates: the PSBT's own derivation for this output, else the server's hint.
    // Either way it's re-derived; a mismatch is sent as an external output, which the device
    // shows to the user (safe direction).
    const s = deviceSuffix(psbt.data.outputs[vout]?.bip32Derivation, device);
    const cand = s ? { chain: s.chain, index: s.index } : changeIndex?.has(vout) ? { chain: 1, index: changeIndex.get(vout)! } : null;
    // Firmware limits for change (change_detector.py): chain ≤ 1, index ≤ 1,000,000, amount > 0.
    if (cand && cand.chain <= 1 && cand.index <= 1_000_000 && BigInt(o.value) > 0n) {
      const derived = p2wshOf(witnessScriptAt(owners, threshold, cand.chain, cand.index, network), network);
      if (eq(derived.script, spk)) {
        changeVouts.push(vout);
        return { address_n: [...origin, cand.chain, cand.index], amount, script_type: "PAYTOWITNESS", multisig: multisigAt(owners, threshold, cand.chain, cand.index) };
      }
    }
    if (spk[0] === 0x6a) {
      const chunks = bscript.decompile(spk) ?? [];
      // Trezor rebuilds OP_RETURN as a single push; anything else would sign a different tx.
      if (chunks.length !== 2 || typeof chunks[1] === "number") throw new Error(`output ${vout}: OP_RETURN must be a single data push for Trezor`);
      if (BigInt(o.value) !== 0n) throw new Error(`output ${vout}: OP_RETURN with a non-zero amount`);
      return { op_return_data: toHex(chunks[1] as Uint8Array), amount: "0", script_type: "PAYTOOPRETURN" };
    }
    let addr: string;
    try {
      addr = baddress.fromOutputScript(spk, network);
    } catch {
      throw new Error(`output ${vout}: script has no address form; Trezor can't show it`);
    }
    return { address: addr, amount, script_type: "PAYTOADDRESS" };
  });

  return {
    request: { coin: trezorCoin(networkName), inputs, outputs, refTxs: [...refs.values()], version: tx.version, locktime: tx.locktime, push: false },
    inputPubkeys,
    changeVouts,
  };
}

/** DER signature as Trezor returns it (no sighash byte) → PSBT partial-sig form (DER + 0x01). */
export function toPsbtSig(hex: string): Uint8Array {
  const b = fromHex(hex);
  if (b.length < 8 || b[0] !== 0x30) throw new Error("not a DER signature");
  const derLen = b[1] + 2;
  if (b.length === derLen) return Uint8Array.from([...b, 0x01]);
  if (b.length === derLen + 1 && b[derLen] === 0x01) return b;
  throw new Error("unexpected signature encoding");
}

/**
 * Merges the device's signatures (one hex DER per input, as Connect's `signatures`) into the PSBT.
 * Each one is verified against the input's BIP-143 sighash before it's added; a bad one throws.
 */
export function mergeSignatures(psbtB64: string, signatures: (string | undefined | null)[], inputPubkeys: Uint8Array[], networkName: string): { psbt: string; inputsSigned: number } {
  const psbt = Psbt.fromBase64(psbtB64.trim(), { network: networkFor(networkName) });
  if (signatures.length !== psbt.data.inputs.length) throw new Error(`device returned ${signatures.length} signatures for ${psbt.data.inputs.length} inputs`);
  let inputsSigned = 0;
  signatures.forEach((hex, i) => {
    if (!hex) return;
    const pubkey = inputPubkeys[i];
    const signature = toPsbtSig(hex);
    const existing = psbt.data.inputs[i].partialSig?.find((p) => eq(Uint8Array.from(p.pubkey), pubkey));
    if (!existing) psbt.updateInput(i, { partialSig: [{ pubkey, signature }] });
    const ok = psbt.validateSignaturesOfInput(i, (pk, msghash, sig) => ecc.verify(msghash, pk, sig), pubkey);
    if (!ok) throw new Error(`input ${i}: the device's signature doesn't verify`);
    inputsSigned++;
  });
  return { psbt: psbt.toBase64(), inputsSigned };
}

/** Trezor Connect `getAddress` params for one of the wallet's P2WSH addresses (receive chain 0, change 1). */
export type TrezorAddressRequest = {
  path: number[];
  coin: TrezorCoin;
  showOnTrezor: true;
  scriptType: "SPENDWITNESS";
  multisig: TrezorMultisig;
  /** Connect compares the device's address with this and fails with "Addresses do not match". */
  address: string;
};

/**
 * Builds the "show address on Trezor" request: the device's own full path plus the same multisig
 * structure the signer uses (every owner's xpub at [chain, index], m, LEXICOGRAPHIC order).
 * Refuses unless this browser's own derivation equals `expected`, so the device is only ever asked
 * to confirm an address we already re-derived from the owners' xpubs.
 */
export function buildTrezorAddressRequest(owners: KeyOwner[], threshold: number, networkName: string, device: KeyOwner, chain: 0 | 1, index: number, expected: string): TrezorAddressRequest {
  if (!Number.isInteger(index) || index < 0 || index >= 0x80000000) throw new Error(`bad address index ${index}`);
  const network = networkFor(networkName);
  const { address } = p2wshOf(witnessScriptAt(owners, threshold, chain, index, network), network);
  if (address !== expected) throw new Error(`this browser derives ${address} at ${chain}/${index}, not ${expected}`);
  return {
    path: [...parsePath(device.path), chain, index],
    coin: trezorCoin(networkName),
    showOnTrezor: true,
    scriptType: "SPENDWITNESS",
    multisig: multisigAt(owners, threshold, chain, index),
    address,
  };
}
