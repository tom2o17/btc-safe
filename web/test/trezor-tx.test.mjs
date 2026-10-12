// Unit tests for lib/signers/trezor-tx.ts. Run: npm test (node --test; node ≥ 23 strips TS types).
//
// TEST-ONLY KEYS (test/trezor-mock.mjs) play the hardware wallets; the app
// code under test never sees a private key.
//
// `mockTrezor` (test/trezor-mock.mjs) models the firmware's checks; see that file.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Psbt, Transaction, networks, payments, script as bscript, address as baddress } from "bitcoinjs-lib";
import { BIP32Factory } from "bip32";
import * as ecc from "@bitcoinerlab/secp256k1";
import { mockTrezor, msFingerprint, testRoots, testOwners, PATH } from "./trezor-mock.mjs";
import { buildTrezorAddressRequest, buildTrezorRequest, mergeSignatures, parsePath, fingerprintHex, toPsbtSig, trezorCoin, LEXICOGRAPHIC, OLD_FIRMWARE_SYMPTOM } from "../lib/signers/trezor-tx.ts";

const bip32 = BIP32Factory(ecc);
const net = networks.testnet;
const hex = (b) => Buffer.from(b).toString("hex");

const roots = testRoots;
const owners = testOwners;
const M = 2;

function wsAt(chain, index) {
  const pubkeys = owners.map((o) => bip32.fromBase58(o.xpub, net).derive(chain).derive(index).publicKey).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return payments.p2ms({ m: M, pubkeys, network: net }).output;
}
const addrAt = (chain, index) => payments.p2wsh({ redeem: { output: wsAt(chain, index) }, network: net }).address;
const derivs = (chain, index) =>
  roots.map((r) => ({ masterFingerprint: r.fingerprint, path: `${PATH}/${chain}/${index}`, pubkey: r.derivePath(`${PATH}/${chain}/${index}`).publicKey }));

/** Funding tx paying 2 wallet addresses, then a 2-input PSBT: external send + change at 1/3. */
function fixture({ changeDerivs = true, withPrev = true, lie = false, noWs = false, changeIdx = 3, extra = null } = {}) {
  const fund = new Transaction();
  fund.version = 2;
  fund.addInput(Buffer.alloc(32, 7), 0, 0xfffffffd, Buffer.from([0x51]));
  fund.addOutput(baddress.toOutputScript(addrAt(0, 0), net), 60_000n);
  fund.addOutput(baddress.toOutputScript("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", net), 5_000n);
  fund.addOutput(baddress.toOutputScript(addrAt(0, 1), net), 50_000n);
  const psbt = new Psbt({ network: net });
  psbt.setVersion(2);
  psbt.setLocktime(123);
  for (const [vout, idx, value] of [[0, 0, 60_000n], [2, 1, 50_000n]]) {
    psbt.addInput({
      hash: fund.getId(),
      index: vout,
      sequence: 0xfffffffd,
      ...(withPrev ? { nonWitnessUtxo: fund.toBuffer() } : {}),
      witnessUtxo: { script: baddress.toOutputScript(addrAt(0, idx), net), value },
      // `lie`: input 0 claims the 0/1 derivation and omits its witness script
      ...(lie && idx === 0 ? { bip32Derivation: derivs(0, 1) } : noWs && idx === 1 ? { bip32Derivation: derivs(0, idx) } : { witnessScript: wsAt(0, idx), bip32Derivation: derivs(0, idx) }),
    });
  }
  psbt.addOutput({ address: "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", value: 70_000n });
  psbt.addOutput({ address: addrAt(1, changeIdx), value: 39_000n, ...(changeDerivs ? { bip32Derivation: derivs(1, changeIdx) } : {}) });
  if (extra) psbt.addOutput({ script: extra, value: 0n });
  return { psbt, fund };
}

// ---- tests ----
test("parsePath / fingerprintHex / trezorCoin", () => {
  assert.deepEqual(parsePath("m/48'/1'/0'/2'"), [0x80000030, 0x80000001, 0x80000000, 0x80000002]);
  assert.deepEqual(parsePath("m/48h/1h/0H/2h/1/5"), [0x80000030, 0x80000001, 0x80000000, 0x80000002, 1, 5]);
  assert.throws(() => parsePath("m/48'/x"));
  assert.equal(fingerprintHex(0x0a1b2c3d), "0a1b2c3d");
  assert.equal(fingerprintHex(0xfa1b2c3d), "fa1b2c3d");
  assert.equal(trezorCoin("signet"), "test");
  assert.equal(trezorCoin("testnet4"), "test");
  assert.equal(trezorCoin("bitcoin"), "btc");
  assert.equal(trezorCoin("regtest"), "regtest");
});

test("request: device rebuilds our exact tx, change recognized, each owner works", () => {
  const { psbt } = fixture();
  const txid = Transaction.fromBuffer(psbt.data.getTransaction()).getId();
  for (let k = 0; k < 3; k++) {
    const built = buildTrezorRequest(psbt.toBase64(), owners, M, "signet", owners[k]);
    assert.deepEqual(built.changeVouts, [1]);
    assert.equal(built.request.inputs[0].multisig.pubkeys_order, LEXICOGRAPHIC);
    assert.deepEqual(built.request.inputs[1].address_n, [...parsePath(PATH), 0, 1]);
    assert.deepEqual(built.request.outputs[1].address_n, [...parsePath(PATH), 1, 3]);
    assert.equal(built.request.refTxs.length, 1, "one refTx per distinct prev tx");
    const dev = mockTrezor(built.request, roots[k]);
    assert.equal(dev.txid, txid);
    assert.deepEqual(dev.change, [1]);
  }
});

test("change found from the server hint when the PSBT output has no derivation", () => {
  const { psbt } = fixture({ changeDerivs: false });
  const none = buildTrezorRequest(psbt.toBase64(), owners, M, "signet", owners[0]);
  assert.deepEqual(none.changeVouts, []);
  assert.equal(none.request.outputs[1].script_type, "PAYTOADDRESS");
  const hinted = buildTrezorRequest(psbt.toBase64(), owners, M, "signet", owners[0], new Map([[1, 3]]));
  assert.deepEqual(hinted.changeVouts, [1]);
  assert.deepEqual(mockTrezor(hinted.request, roots[0]).change, [1]);
});

test("a lying change hint is sent as an external output (device shows it)", () => {
  const { psbt } = fixture({ changeDerivs: false });
  const b = buildTrezorRequest(psbt.toBase64(), owners, M, "signet", owners[0], new Map([[0, 3], [1, 4]]));
  assert.deepEqual(b.changeVouts, []);
  assert.ok(b.request.outputs.every((o) => o.script_type === "PAYTOADDRESS"));
});

test("sign → merge → second owner → finalize", () => {
  const { psbt } = fixture();
  const b = buildTrezorRequest(psbt.toBase64(), owners, M, "signet", owners[1]);
  const dev = mockTrezor(b.request, roots[1]);
  const merged = mergeSignatures(psbt.toBase64(), dev.signatures, b.inputPubkeys, "signet");
  assert.equal(merged.inputsSigned, 2);
  // merging again is idempotent
  assert.equal(mergeSignatures(merged.psbt, dev.signatures, b.inputPubkeys, "signet").psbt, merged.psbt);
  const p = Psbt.fromBase64(merged.psbt, { network: net });
  assert.equal(p.data.inputs[0].partialSig.length, 1);
  // a second "Trezor" (owner 3) adds its signatures to the merged PSBT
  const b3 = buildTrezorRequest(merged.psbt, owners, M, "signet", owners[2]);
  const dev3 = mockTrezor(b3.request, roots[2]);
  const both = Psbt.fromBase64(mergeSignatures(merged.psbt, dev3.signatures, b3.inputPubkeys, "signet").psbt, { network: net });
  assert.ok(both.validateSignaturesOfAllInputs((pk, h, s) => ecc.verify(h, pk, s)));
  both.finalizeAllInputs();
  const final = both.extractTransaction();
  assert.equal(final.ins[0].witness.length, 4); // OP_0 dummy, 2 sigs, witness script
});

test("merge rejects a signature that doesn't verify", () => {
  const { psbt } = fixture();
  const b = buildTrezorRequest(psbt.toBase64(), owners, M, "signet", owners[0]);
  const dev = mockTrezor(b.request, roots[0]);
  assert.throws(() => mergeSignatures(psbt.toBase64(), [dev.signatures[1], dev.signatures[0]], b.inputPubkeys, "signet"), /doesn't verify/);
  assert.throws(() => mergeSignatures(psbt.toBase64(), [dev.signatures[0]], b.inputPubkeys, "signet"), /2 inputs/);
});

test("signature encodings", () => {
  const der = "3006020101020101";
  assert.equal(hex(toPsbtSig(der)), der + "01");
  assert.equal(hex(toPsbtSig(der + "01")), der + "01");
  assert.throws(() => toPsbtSig("00"));
});

test("refuses: wrong device, foreign input, missing prev tx, tampered witness script", () => {
  const { psbt } = fixture();
  const stranger = { ...owners[0], fingerprint: "deadbeef" };
  assert.throws(() => buildTrezorRequest(psbt.toBase64(), owners, M, "signet", stranger), /no key derivation/);

  const noPrev = fixture({ withPrev: false }).psbt;
  assert.throws(() => buildTrezorRequest(noPrev.toBase64(), owners, M, "signet", owners[0]), /previous transaction/);

  const badWs = fixture().psbt;
  badWs.data.inputs[1].witnessScript = wsAt(0, 0);
  assert.throws(() => buildTrezorRequest(badWs.toBase64(), owners, M, "signet", owners[0]), /witness script differs/);

  // derivation claims index 0/1 for an input that actually pays 0/0
  const lie = fixture({ lie: true }).psbt;
  assert.throws(() => buildTrezorRequest(lie.toBase64(), owners, M, "signet", owners[0]), /isn't this wallet's address/);

  // other owners' set (wrong wallet) for the same device
  const otherOwners = [owners[0], owners[1], { ...owners[2], xpub: roots[0].derivePath("m/48'/1'/1'/2'").neutered().toBase58() }];
  assert.throws(() => buildTrezorRequest(psbt.toBase64(), otherOwners, M, "signet", owners[0]), /witness script differs|isn't this wallet's/);
});

test("PRESERVED order would break change detection across inputs (why we send LEXICOGRAPHIC)", () => {
  const { psbt } = fixture();
  const b = buildTrezorRequest(psbt.toBase64(), owners, M, "signet", owners[0]);
  const preserved = structuredClone(b.request);
  // pre-sorting per input with PRESERVED order: different node orders → different fingerprints
  for (const i of preserved.inputs) i.multisig.pubkeys_order = 0;
  preserved.inputs[1].multisig.pubkeys.reverse();
  for (const o of preserved.outputs) if (o.multisig) o.multisig.pubkeys_order = 0;
  assert.notEqual(msFingerprint(preserved.inputs[0].multisig), msFingerprint(preserved.inputs[1].multisig));
});

test("review fixes: missing witness script, OP_RETURN pushes, change index past the firmware limit", () => {
  assert.throws(() => buildTrezorRequest(fixture({ noWs: true }).psbt.toBase64(), owners, M, "signet", owners[0]), /lacks the witness script/);

  const one = bscript.compile([bscript.OPS.OP_RETURN, Buffer.from("hello")]);
  const b = buildTrezorRequest(fixture({ extra: one }).psbt.toBase64(), owners, M, "signet", owners[0]);
  assert.deepEqual(b.request.outputs[2], { op_return_data: hex(Buffer.from("hello")), amount: "0", script_type: "PAYTOOPRETURN" });
  assert.equal(mockTrezor(b.request, roots[0]).txid, Transaction.fromBuffer(fixture({ extra: one }).psbt.data.getTransaction()).getId());
  const two = bscript.compile([bscript.OPS.OP_RETURN, Buffer.from("ab"), Buffer.from("cd")]);
  assert.throws(() => buildTrezorRequest(fixture({ extra: two }).psbt.toBase64(), owners, M, "signet", owners[0]), /single data push/);

  // index 1,000,001 is ours but the device won't treat it as change: send it as an address (shown)
  const far = buildTrezorRequest(fixture({ changeIdx: 1_000_001 }).psbt.toBase64(), owners, M, "signet", owners[0]);
  assert.deepEqual(far.changeVouts, []);
  assert.equal(far.request.outputs[1].script_type, "PAYTOADDRESS");
  assert.deepEqual(mockTrezor(far.request, roots[0]).change, []);
});

test("firmware < 2.8.7 ignores pubkeys_order: fails loudly with the message we map to 'unsupported'", () => {
  const { psbt } = fixture();
  const b = buildTrezorRequest(psbt.toBase64(), owners, M, "signet", owners[0]);
  // precondition: for some input, wallet order != sorted order (else old firmware would agree by luck)
  const unsorted = b.request.inputs.some((i) => {
    const pks = i.multisig.pubkeys.map((p) => hex(bip32.fromBase58(p.node, net).derivePath(p.address_n.join("/")).publicKey));
    return pks.join() !== [...pks].sort().join();
  });
  assert.ok(unsorted, "fixture needs an input whose owner order isn't sorted");
  assert.throws(() => mockTrezor(b.request, roots[0], { firmwareBefore287: true }), (e) => OLD_FIRMWARE_SYMPTOM.test(e.message));
  assert.doesNotThrow(() => mockTrezor(b.request, roots[0]));
});

test("show-address request: device path + same multisig as signing; what the device would derive is our address", () => {
  for (const [chain, index] of [[0, 0], [0, 7], [1, 3]]) {
    const expected = addrAt(chain, index);
    for (let k = 0; k < 3; k++) {
      const r = buildTrezorAddressRequest(owners, M, "signet", owners[k], chain, index, expected);
      assert.deepEqual(r.path, [...parsePath(PATH), chain, index]);
      assert.equal(r.coin, "test");
      assert.equal(r.scriptType, "SPENDWITNESS");
      assert.equal(r.showOnTrezor, true);
      assert.equal(r.address, expected);
      assert.equal(r.multisig.m, M);
      assert.equal(r.multisig.pubkeys_order, LEXICOGRAPHIC);
      assert.deepEqual(r.multisig.signatures, ["", "", ""]);
      // Firmware: derive each node at address_n, sort (LEXICOGRAPHIC), p2ms → p2wsh.
      const pks = r.multisig.pubkeys.map((p) => bip32.fromBase58(p.node, net).derive(p.address_n[0]).derive(p.address_n[1]).publicKey);
      pks.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
      const devAddr = payments.p2wsh({ redeem: { output: payments.p2ms({ m: r.multisig.m, pubkeys: pks, network: net }).output }, network: net }).address;
      assert.equal(devAddr, expected);
      // The device's own key at `path` is one of the multisig's keys (else firmware refuses).
      const own = hex(roots[k].derivePath(`${PATH}/${chain}/${index}`).publicKey);
      assert.ok(pks.some((p) => hex(p) === own));
    }
  }
});

test("show-address request refuses an address this browser doesn't derive", () => {
  assert.throws(() => buildTrezorAddressRequest(owners, M, "signet", owners[0], 0, 1, addrAt(0, 2)), /this browser derives/);
  assert.throws(() => buildTrezorAddressRequest(owners, M, "signet", owners[0], 0, -1, addrAt(0, 0)), /bad address index/);
});
