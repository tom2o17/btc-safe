// Device-free tests for lib/ledger-core.ts. Run: npm test (node --test).
// Throwaway keys from fixed seeds; they exist only in this file.
import test from "node:test";
import assert from "node:assert/strict";
import { Psbt, payments, networks } from "bitcoinjs-lib";
import { BIP32Factory } from "bip32";
import * as ecc from "@bitcoinerlab/secp256k1";
import { checkApp, classifyLedgerError, deviceName, expectedPolicy, mergePartialSigs } from "./ledger-core.ts";

const bip32 = BIP32Factory(ecc);
const net = networks.testnet;
const keys = [1, 2, 3].map((b) => bip32.fromSeed(new Uint8Array(32).fill(b), net));
const accts = keys.map((k) => k.derivePath("m/48'/1'/0'/2'"));
const hex = (b) => Buffer.from(b).toString("hex");

/** A 2-of-3 P2WSH input set (2 inputs at receive /0/0 and /0/1), unsigned. */
function unsigned() {
  const psbt = new Psbt({ network: net });
  for (const idx of [0, 1]) {
    const leaves = accts.map((a, i) => ({ i, pubkey: a.derive(0).derive(idx).publicKey }));
    leaves.sort((x, y) => Buffer.compare(Buffer.from(x.pubkey), Buffer.from(y.pubkey)));
    const ms = payments.p2ms({ m: 2, pubkeys: leaves.map((l) => l.pubkey), network: net });
    const wsh = payments.p2wsh({ redeem: ms, network: net });
    psbt.addInput({
      hash: "11".repeat(31) + idx.toString(16).padStart(2, "0"),
      index: 0,
      witnessUtxo: { script: wsh.output, value: 100_000n },
      witnessScript: ms.output,
      bip32Derivation: leaves.map((l) => ({
        masterFingerprint: keys[l.i].fingerprint,
        path: `m/48'/1'/0'/2'/0/${idx}`,
        pubkey: l.pubkey,
      })),
    });
  }
  psbt.addOutput({ address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", value: 150_000n });
  return psbt;
}

/** What the device returns: per input, the owner's pubkey and DER sig + sighash byte. */
function deviceSigs(owner) {
  const psbt = unsigned();
  const out = [];
  for (const idx of [0, 1]) {
    const child = accts[owner].derive(0).derive(idx);
    psbt.signInput(idx, { publicKey: child.publicKey, sign: (h) => ecc.sign(h, child.privateKey) });
    const ps = psbt.data.inputs[idx].partialSig[0];
    out.push({ inputIndex: idx, pubkey: ps.pubkey, signature: ps.signature });
  }
  return out;
}

test("merges device signatures that verify", () => {
  const base = unsigned().toBase64();
  const { psbt, added } = mergePartialSigs(base, deviceSigs(0));
  assert.equal(added, 2);
  const p = Psbt.fromBase64(psbt);
  assert.equal(p.data.inputs[0].partialSig.length, 1);
  // Second owner on top, then finalize: a full 2-of-3.
  const both = mergePartialSigs(psbt, deviceSigs(1));
  assert.equal(both.added, 2);
  const fin = Psbt.fromBase64(both.psbt).finalizeAllInputs();
  assert.ok(fin.extractTransaction().ins.every((i) => i.witness.length === 4));
});

test("re-merging the same signatures is a no-op", () => {
  const once = mergePartialSigs(unsigned().toBase64(), deviceSigs(0)).psbt;
  assert.equal(mergePartialSigs(once, deviceSigs(0)).added, 0);
});

test("rejects bad device output", () => {
  const base = unsigned().toBase64();
  const sigs = deviceSigs(0);
  assert.throws(() => mergePartialSigs(base, [{ ...sigs[0], inputIndex: 5 }]), /doesn't have/);
  assert.throws(() => mergePartialSigs(base, [{ ...sigs[0], inputIndex: 1 }]), /isn't one of this wallet's/);
  const flipped = Uint8Array.from(sigs[0].signature, (x, i) => (i === 12 ? x ^ 1 : x));
  assert.throws(() => mergePartialSigs(base, [{ ...sigs[0], signature: flipped }]), /verify/);
  const stranger = bip32.fromSeed(new Uint8Array(32).fill(9), net).derivePath("m/48'/1'/0'/2'/0/0");
  assert.throws(() => mergePartialSigs(base, [{ ...sigs[0], pubkey: stranger.publicKey }]), /isn't one of this wallet's/);
});

test("policy mirrors the Rust one", () => {
  assert.equal(deviceName("  Treasury ✓ "), "Treasury");
  assert.equal(deviceName("✓"), "BTC Safe");
  assert.equal(deviceName("a".repeat(80)).length, 64);
  const owners = accts.map((a, i) => ({ fingerprint: hex(keys[i].fingerprint), path: "m/48'/1'/0'/2'", xpub: a.neutered().toBase58(), position: 2 - i }));
  const p = expectedPolicy("Vault", owners, 2);
  assert.equal(p.descriptor_template, "wsh(sortedmulti(2,@0/**,@1/**,@2/**))");
  assert.equal(p.keys[0], `[${hex(keys[2].fingerprint)}/48'/1'/0'/2']${accts[2].neutered().toBase58()}`, "ordered by position");
});

test("classifies device states", () => {
  const sw = (statusCode) => Object.assign(new Error("x"), { name: "TransportStatusError", statusCode });
  assert.equal(classifyLedgerError(sw(0x6985)).state, "rejected");
  assert.equal(classifyLedgerError(sw(0x5515)).state, "locked");
  assert.equal(classifyLedgerError(sw(0x6e01)).state, "wrong_app");
  assert.equal(classifyLedgerError(sw(0xb008)).state, "bad_hmac");
  assert.equal(classifyLedgerError(Object.assign(new Error("no device"), { name: "TransportOpenUserCancelled" })).state, "not_connected");
  assert.equal(classifyLedgerError(sw(0x6a87)).state, "error");
  assert.equal(checkApp("Bitcoin Test", "2.5.1", "signet"), null);
  assert.equal(checkApp("BOLOS", "1.0", "signet").state, "wrong_app");
  assert.equal(checkApp("Bitcoin", "2.5.1", "signet").state, "wrong_app");
  assert.equal(checkApp("Ethereum", "1.0", "signet").state, "wrong_app");
  assert.equal(checkApp("Bitcoin Test", "2.0.6", "signet").state, "old_app");
  assert.equal(checkApp("Bitcoin Test", "2.1.0", "testnet4"), null);
});
