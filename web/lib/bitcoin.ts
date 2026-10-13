// Client-side Bitcoin checks. The server is trusted to coordinate, not to be honest: the
// review screen decodes the PSBT itself and re-derives change and receive addresses from
// the owners' xpubs, then flags any disagreement with the server's summary.
//
// Watch-only like the server: xpubs in, addresses out. No private keys exist here.

import { Psbt, Transaction, address as baddress, networks, payments } from "bitcoinjs-lib";
import { BIP32Factory } from "bip32";
import * as ecc from "@bitcoinerlab/secp256k1";
import type { Owner, Proposal } from "./api";

const bip32 = BIP32Factory(ecc);

export function networkFor(name: string) {
  return name === "bitcoin" || name === "mainnet" ? networks.bitcoin : networks.testnet; // signet/testnet share tb1 + tpub
}

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export type KeyOwner = Pick<Owner, "xpub" | "fingerprint" | "path"> & { name?: string };

/** P2WSH sortedmulti address at `<chain>/<index>` derived in the browser. */
export function deriveAddress(owners: KeyOwner[], threshold: number, chain: 0 | 1, index: number, network = networks.testnet): string {
  const pubkeys = owners
    .map((o) => bip32.fromBase58(o.xpub, network).derive(chain).derive(index).publicKey)
    .sort((a, b) => (toHex(a) < toHex(b) ? -1 : 1));
  const redeem = payments.p2ms({ m: threshold, pubkeys, network });
  const p = payments.p2wsh({ redeem, network });
  if (!p.address) throw new Error("could not derive address");
  return p.address;
}

/** Throws with a readable message if the xpub doesn't parse for the network. */
export function checkXpub(xpub: string, network = networks.testnet): string | null {
  try {
    bip32.fromBase58(xpub.trim(), network);
    return null;
  } catch (e) {
    return `not a valid ${network === networks.bitcoin ? "xpub" : "tpub"}: ${(e as Error).message}`;
  }
}

// ---- BIP-380 descriptor checksum ----
const INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGHH`#\"\\ ";
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function polymod(c: bigint, val: number): bigint {
  const c0 = c >> 35n;
  c = ((c & 0x7ffffffffn) << 5n) ^ BigInt(val);
  if (c0 & 1n) c ^= 0xf5dee51989n;
  if (c0 & 2n) c ^= 0xa9fdca3312n;
  if (c0 & 4n) c ^= 0x1bab10e32dn;
  if (c0 & 8n) c ^= 0x3706b1677an;
  if (c0 & 16n) c ^= 0x644d626ffdn;
  return c;
}
export function descriptorChecksum(desc: string): string {
  let c = 1n;
  let cls = 0;
  let clscount = 0;
  for (const ch of desc) {
    const pos = INPUT_CHARSET.indexOf(ch);
    if (pos < 0) throw new Error(`invalid descriptor character ${ch}`);
    c = polymod(c, pos & 31);
    cls = cls * 3 + (pos >> 5);
    if (++clscount === 3) {
      c = polymod(c, cls);
      cls = 0;
      clscount = 0;
    }
  }
  if (clscount > 0) c = polymod(c, cls);
  for (let j = 0; j < 8; j++) c = polymod(c, 0);
  c ^= 1n;
  let out = "";
  for (let j = 0; j < 8; j++) out += CHECKSUM_CHARSET[Number((c >> BigInt(5 * (7 - j))) & 31n)];
  return out;
}

export function buildDescriptor(owners: KeyOwner[], threshold: number): string {
  const keys = owners.map((o) => `[${o.fingerprint}${o.path.replace(/^m/, "").replace(/'/g, "h")}]${o.xpub}/<0;1>/*`);
  const d = `wsh(sortedmulti(${threshold},${keys.join(",")}))`;
  return `${d}#${descriptorChecksum(d)}`;
}

/** Parses `[fingerprint/48'/1'/0'/2']tpub…` (Sparrow/Core key-origin form). */
export function parseKeyExpression(s: string): { fingerprint: string; path: string; xpub: string } | null {
  const m = s.trim().match(/^\[([0-9a-fA-F]{8})((?:\/\d+['hH]?)*)\]([xtuvyzXTUVYZ]pub[1-9A-HJ-NP-Za-km-z]+)/);
  if (!m) return null;
  return { fingerprint: m[1].toLowerCase(), path: "m" + m[2].replace(/[hH]/g, "'"), xpub: m[3] };
}

// ---- PSBT decode + cross-check ----
export type DecodedPsbt = {
  txid: string;
  inputs: { outpoint: string; amount: number | null; signers: string[] }[];
  outputs: { vout: number; address: string; amount: number }[];
  fee: number | null;
};

export function decodePsbt(b64: string, network = networks.testnet): DecodedPsbt {
  const psbt = Psbt.fromBase64(b64.trim(), { network });
  const tx = Transaction.fromBuffer(psbt.data.getTransaction());
  const inputs = psbt.data.inputs.map((inp, i) => {
    const txin = tx.ins[i];
    const prevTxid = toHex(Uint8Array.from(txin.hash).reverse());
    // Amounts drive the fee. A full previous tx is only trusted if it hashes to the outpoint's
    // txid; a bare witness_utxo is unverifiable here (the signing device has the same limit).
    let amount: number | null = null;
    if (inp.nonWitnessUtxo) {
      const prev = Transaction.fromBuffer(inp.nonWitnessUtxo);
      if (prev.getId() !== prevTxid) throw new Error(`input ${i}: non_witness_utxo is not the transaction it claims to spend`);
      const out = prev.outs[txin.index];
      if (!out) throw new Error(`input ${i}: previous tx has no output ${txin.index}`);
      amount = Number(out.value);
      if (inp.witnessUtxo && Number(inp.witnessUtxo.value) !== amount) throw new Error(`input ${i}: witness_utxo amount disagrees with the previous tx`);
    } else if (inp.witnessUtxo) amount = Number(inp.witnessUtxo.value);
    // Map each partial signature's pubkey to the owner fingerprint that the PSBT says derived it.
    const signers = (inp.partialSig ?? []).map((ps) => {
      const d = (inp.bip32Derivation ?? []).find((b) => toHex(b.pubkey) === toHex(ps.pubkey));
      return d ? toHex(d.masterFingerprint) : `pubkey ${toHex(ps.pubkey).slice(0, 10)}…`;
    });
    return { outpoint: `${prevTxid}:${txin.index}`, amount, signers };
  });
  const outputs = tx.outs.map((o, vout) => {
    let addr: string;
    try {
      addr = baddress.fromOutputScript(o.script, network);
    } catch {
      addr = `script ${toHex(o.script)}`;
    }
    return { vout, address: addr, amount: Number(o.value) };
  });
  const totalIn = inputs.every((i) => i.amount !== null) ? inputs.reduce((s, i) => s + (i.amount ?? 0), 0) : null;
  const fee = totalIn === null ? null : totalIn - outputs.reduce((s, o) => s + o.amount, 0);
  return { txid: tx.getId(), inputs, outputs, fee };
}

export type CheckResult = { ok: boolean; problems: string[]; changeVerified: number[]; decoded: DecodedPsbt | null };

/**
 * Cross-checks the server's proposal summary against the PSBT it serves, and re-derives
 * every output the server calls "change" from the wallet's xpubs.
 */
export function crossCheck(p: Proposal, owners: KeyOwner[], threshold: number, networkName: string): CheckResult {
  const problems: string[] = [];
  const changeVerified: number[] = [];
  if (!p.psbt) return { ok: false, problems: ["server sent no PSBT"], changeVerified, decoded: null };
  const network = networkFor(networkName);
  let d: DecodedPsbt;
  try {
    d = decodePsbt(p.psbt, network);
  } catch (e) {
    return { ok: false, problems: [`PSBT does not decode: ${(e as Error).message}`], changeVerified, decoded: null };
  }
  if (d.txid !== p.unsigned_txid) problems.push(`txid: PSBT ${d.txid.slice(0, 12)}… vs server ${p.unsigned_txid.slice(0, 12)}…`);
  // The UI draws the server's rows, so they must map one-to-one onto the PSBT: every row names a
  // real input/output exactly once, and every PSBT input/output has a row. Otherwise a server could
  // hide an output (e.g. list a change vout twice in its place) and still match on count.
  if (p.inputs.length !== d.inputs.length) problems.push(`inputs: PSBT has ${d.inputs.length}, server lists ${p.inputs.length}`);
  const srvIn = new Map<string, number>();
  for (const i of p.inputs) {
    if (srvIn.has(i.outpoint)) problems.push(`server lists input ${i.outpoint.slice(0, 12)}… more than once`);
    else srvIn.set(i.outpoint, i.amount_sats);
  }
  const psbtIn = new Set(d.inputs.map((i) => i.outpoint));
  for (const o of srvIn.keys()) if (!psbtIn.has(o)) problems.push(`server lists input ${o.slice(0, 12)}…, which the PSBT doesn't spend`);
  for (const i of d.inputs) {
    if (!srvIn.has(i.outpoint)) problems.push(`input ${i.outpoint.slice(0, 12)}… is in the PSBT but not in the server summary`);
    else if (i.amount !== null && srvIn.get(i.outpoint) !== i.amount) problems.push(`input ${i.outpoint.slice(0, 12)}… amount differs`);
  }
  if (p.outputs.length !== d.outputs.length) problems.push(`outputs: PSBT has ${d.outputs.length}, server lists ${p.outputs.length}`);
  const srvOut = new Map<number, Proposal["outputs"][number]>();
  for (const s of p.outputs) {
    if (!Number.isInteger(s.vout) || s.vout < 0 || s.vout >= d.outputs.length) problems.push(`server lists output ${s.vout}, which the PSBT doesn't have`);
    else if (srvOut.has(s.vout)) problems.push(`server lists output ${s.vout} more than once`);
    else srvOut.set(s.vout, s);
  }
  for (const o of d.outputs) {
    const s = srvOut.get(o.vout);
    if (!s) {
      problems.push(`output ${o.vout}: PSBT pays ${o.amount} sats to ${o.address}, which the server summary doesn't show`);
      continue;
    }
    if (s.address !== o.address) problems.push(`output ${o.vout}: PSBT pays ${o.address}, server shows ${s.address}`);
    if (s.amount_sats !== o.amount) problems.push(`output ${o.vout}: amount ${o.amount} in PSBT vs ${s.amount_sats} on server`);
    if (s.is_change) {
      if (s.change_index === null) problems.push(`output ${o.vout}: marked change without an index`);
      else {
        try {
          const mine = deriveAddress(owners, threshold, 1, s.change_index, network);
          if (mine === o.address) changeVerified.push(o.vout);
          else problems.push(`output ${o.vout}: server calls it change (m/1/${s.change_index}) but this browser derives ${mine}`);
        } catch (e) {
          problems.push(`output ${o.vout}: could not derive change: ${(e as Error).message}`);
        }
      }
    }
  }
  if (d.fee !== null && d.fee !== p.fee_sats) problems.push(`fee: PSBT implies ${d.fee} sats, server says ${p.fee_sats}`);
  if (d.fee === null) problems.push("fee: PSBT lacks input amounts, can't compute it");
  return { ok: problems.length === 0, problems, changeVerified, decoded: d };
}
