// Model of the Trezor firmware's signTransaction checks, shared by the unit tests and
// e2e/trezor-server.mjs. TEST-ONLY KEYS: `testRoots` are throwaway seeds that play the devices.
//
// It follows trezor-firmware core/src/apps/bitcoin (multisig.py, addresses.py,
// sign_tx/change_detector.py): rebuilds the transaction from the request, checks every input
// script against its previous tx and refTx hashes, computes the multisig fingerprint and wallet
// path the same way, decides which outputs are change, and signs BIP-143 with the key at
// address_n. It's a model of the firmware, not the firmware.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Transaction, networks, payments, script as bscript, address as baddress } from "bitcoinjs-lib";
import { BIP32Factory } from "bip32";
import * as ecc from "@bitcoinerlab/secp256k1";
import { LEXICOGRAPHIC } from "../lib/signers/trezor-tx.ts";

const bip32 = BIP32Factory(ecc);
const net = networks.testnet;
export const PATH = "m/48'/1'/0'/2'";
const hex = (b) => Buffer.from(b).toString("hex");

export const testRoots = [1, 2, 3].map((n) => bip32.fromSeed(createHash("sha256").update(`btc-safe trezor test seed ${n}`).digest(), net));
export const testOwners = testRoots.map((r, i) => ({
  name: `Trezor ${i + 1}`,
  fingerprint: hex(r.fingerprint),
  path: PATH,
  xpub: r.derivePath(PATH).neutered().toBase58(),
}));

function nodeOf(xpub) {
  const n = bip32.fromBase58(xpub, net);
  return { depth: n.depth, fingerprint: n.parentFingerprint, child_num: n.index, chain_code: Buffer.from(n.chainCode), public_key: Buffer.from(n.publicKey), n };
}
function u32(x) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(x >>> 0);
  return b;
}
/** multisig.py multisig_fingerprint */
export function msFingerprint(ms) {
  let nodes = ms.pubkeys.map((p) => nodeOf(p.node));
  if (ms.pubkeys_order === LEXICOGRAPHIC) nodes = [...nodes].sort((a, b) => Buffer.compare(Buffer.concat([a.public_key, a.chain_code]), Buffer.concat([b.public_key, b.chain_code])));
  const h = createHash("sha256");
  h.update(u32(ms.m)).update(u32(nodes.length)).update(u32(ms.pubkeys_order ?? 0));
  for (const d of nodes) h.update(u32(d.depth)).update(u32(d.fingerprint)).update(u32(d.child_num)).update(d.chain_code).update(d.public_key);
  return h.digest("hex");
}
function msPubkeys(ms) {
  const pks = ms.pubkeys.map((p) => Buffer.from(nodeOf(p.node).n.derivePath(p.address_n.join("/")).publicKey));
  return ms.pubkeys_order === LEXICOGRAPHIC ? pks.sort(Buffer.compare) : pks;
}
const msScript = (ms) => Buffer.from(payments.p2ms({ m: ms.m, pubkeys: msPubkeys(ms), network: net }).output);
const p2wsh = (ws) => Buffer.from(payments.p2wsh({ redeem: { output: ws }, network: net }).output);
const singlePath = (ms) => ms.pubkeys.every((p) => p.address_n.join() === ms.pubkeys[0].address_n.join());

export function mockTrezor(req, deviceRoot, { firmwareBefore287 = false } = {}) {
  assert.equal(req.coin, "test");
  if (firmwareBefore287) {
    // Older firmware drops pubkeys_order as an unknown protobuf field: PRESERVED order.
    req = structuredClone(req);
    for (const io of [...req.inputs, ...req.outputs]) if (io.multisig) delete io.multisig.pubkeys_order;
  }
  // refTxs must rebuild to the txid they claim (the firmware hashes them).
  const refs = new Map();
  for (const r of req.refTxs) {
    const t = new Transaction();
    t.version = r.version;
    t.locktime = r.lock_time;
    for (const i of r.inputs) t.addInput(Buffer.from(i.prev_hash, "hex").reverse(), i.prev_index, i.sequence, Buffer.from(i.script_sig, "hex"));
    for (const o of r.bin_outputs) t.addOutput(Buffer.from(o.script_pubkey, "hex"), BigInt(o.amount));
    assert.equal(t.getId(), r.hash, "refTx doesn't hash to its txid");
    refs.set(r.hash, t);
  }
  const tx = new Transaction();
  tx.version = req.version;
  tx.locktime = req.locktime;
  let fp = null;
  let walletPath = null;
  for (const i of req.inputs) {
    assert.equal(i.script_type, "SPENDWITNESS");
    const prev = refs.get(i.prev_hash);
    assert.ok(prev, "missing refTx");
    const out = prev.outs[i.prev_index];
    assert.equal(String(out.value), i.amount, "amount differs from prev tx");
    // core sign_tx/bitcoin.py
    if (!Buffer.from(out.script).equals(p2wsh(msScript(i.multisig)))) throw new Error("Input does not match scriptPubKey");
    const myPub = Buffer.from(deviceRoot.derivePath("m/" + i.address_n.map((n) => (n >= 0x80000000 ? `${n - 0x80000000}'` : n)).join("/")).publicKey);
    assert.ok(msPubkeys(i.multisig).some((p) => p.equals(myPub)), "device key not in multisig");
    const f = msFingerprint(i.multisig);
    const wp = i.address_n.slice(0, -2).join("/");
    fp = fp === null || fp === f ? f : "mixed";
    walletPath = walletPath === null || walletPath === wp ? wp : "mixed";
    tx.addInput(Buffer.from(i.prev_hash, "hex").reverse(), i.prev_index, i.sequence);
  }
  const change = [];
  req.outputs.forEach((o, vout) => {
    let spk;
    if (o.script_type === "PAYTOWITNESS") {
      spk = p2wsh(msScript(o.multisig));
      // addresses.get_address: the device's key at address_n must be one of the multisig keys
      const own = Buffer.from(deviceRoot.derivePath("m/" + o.address_n.map((n) => (n >= 0x80000000 ? `${n - 0x80000000}'` : n)).join("/")).publicKey);
      assert.ok(msPubkeys(o.multisig).some((p) => p.equals(own)), `output ${vout}: device key not in multisig`);
      const isChange = singlePath(o.multisig) && msFingerprint(o.multisig) === fp && o.address_n.slice(0, -2).join("/") === walletPath && o.address_n.at(-2) <= 1 && o.address_n.at(-1) <= 1_000_000 && BigInt(o.amount) > 0n;
      assert.ok(isChange, `output ${vout} sent with multisig but the firmware wouldn't see it as change`);
      change.push(vout);
    } else if (o.script_type === "PAYTOADDRESS") spk = baddress.toOutputScript(o.address, net);
    else spk = bscript.compile([bscript.OPS.OP_RETURN, Buffer.from(o.op_return_data, "hex")]);
    tx.addOutput(spk, BigInt(o.amount));
  });
  const signatures = req.inputs.map((inp, i) => {
    const key = deviceRoot.derivePath("m/" + inp.address_n.map((n) => (n >= 0x80000000 ? `${n - 0x80000000}'` : n)).join("/"));
    const h = tx.hashForWitnessV0(i, msScript(inp.multisig), BigInt(inp.amount), Transaction.SIGHASH_ALL);
    const der = bscript.signature.encode(Buffer.from(key.sign(h)), Transaction.SIGHASH_ALL);
    return hex(der.subarray(0, der.length - 1)); // Trezor returns DER without the sighash byte
  });
  return { txid: tx.getId(), change, signatures };
}

