// Unit tests for crossCheck (lib/bitcoin.ts): the browser's check that the server's proposal
// summary describes exactly the PSBT it serves. Run: npm test.
//
// TEST-ONLY KEYS (test/trezor-mock.mjs); the code under test only sees xpubs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Psbt, Transaction, networks, payments, address as baddress } from "bitcoinjs-lib";
import { BIP32Factory } from "bip32";
import * as ecc from "@bitcoinerlab/secp256k1";
import { testOwners } from "./trezor-mock.mjs";
import { crossCheck } from "../lib/bitcoin.ts";

const bip32 = BIP32Factory(ecc);
const net = networks.testnet;
const owners = testOwners;
const M = 2;
const RCPT = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
const ATTACKER = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

function addrAt(chain, index) {
  const pubkeys = owners.map((o) => bip32.fromBase58(o.xpub, net).derive(chain).derive(index).publicKey).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return payments.p2wsh({ redeem: payments.p2ms({ m: M, pubkeys, network: net }), network: net }).address;
}

/** A 1-input PSBT paying `outs` ([address, sats]) and the honest server summary for it. */
function proposal(outs, changeIdx = { 1: 3 }) {
  const fund = new Transaction();
  fund.version = 2;
  fund.addInput(Buffer.alloc(32, 7), 0, 0xfffffffd, Buffer.from([0x51]));
  fund.addOutput(baddress.toOutputScript(addrAt(0, 0), net), 100_000n);
  const psbt = new Psbt({ network: net });
  psbt.addInput({ hash: fund.getId(), index: 0, nonWitnessUtxo: fund.toBuffer() });
  for (const [address, value] of outs) psbt.addOutput({ address, value: BigInt(value) });
  const total = outs.reduce((s, [, v]) => s + v, 0);
  return {
    psbt: psbt.toBase64(),
    unsigned_txid: Transaction.fromBuffer(psbt.data.getTransaction()).getId(),
    inputs: [{ outpoint: `${fund.getId()}:0`, amount_sats: 100_000 }],
    outputs: outs.map(([address, amount_sats], vout) => ({
      vout,
      address,
      amount_sats,
      is_change: vout in changeIdx,
      change_index: vout in changeIdx ? changeIdx[vout] : null,
    })),
    fee_sats: 100_000 - total,
  };
}

const check = (p) => crossCheck(p, owners, M, "signet");

test("honest summary passes, change re-derived", () => {
  const r = check(proposal([[RCPT, 50_000], [addrAt(1, 3), 49_000]]));
  assert.deepEqual(r.problems, []);
  assert.equal(r.ok, true);
  assert.deepEqual(r.changeVerified, [1]);
});

test("hidden output: a change vout listed twice in place of the attacker's output is refused", () => {
  // PSBT: recipient, real change at 1/3, attacker. Server: recipient, change 1/3, and vout 1 again
  // labelled as a second change. Counts, fee and txid all match the PSBT.
  const p = proposal([[RCPT, 50_000], [addrAt(1, 3), 24_000], [ATTACKER, 25_000]]);
  p.outputs[2] = { ...p.outputs[1], change_index: 3 };
  const r = check(p);
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((x) => x.includes("more than once")), r.problems.join("; "));
  assert.ok(r.problems.some((x) => x.includes(ATTACKER) && x.includes("doesn't show")), r.problems.join("; "));
});

test("a row naming a vout the PSBT doesn't have is refused", () => {
  const p = proposal([[RCPT, 50_000], [ATTACKER, 49_000]], {});
  p.outputs[1] = { ...p.outputs[1], vout: 7 };
  const r = check(p);
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((x) => x.includes("output 7, which the PSBT doesn't have")), r.problems.join("; "));
  assert.ok(r.problems.some((x) => x.includes(ATTACKER)), r.problems.join("; "));
});

test("non-integer vout is refused", () => {
  const p = proposal([[RCPT, 50_000], [addrAt(1, 3), 49_000]]);
  p.outputs[1] = { ...p.outputs[1], vout: "1" };
  assert.equal(check(p).ok, false);
});

test("dropped output (count mismatch) is refused", () => {
  const p = proposal([[RCPT, 50_000], [ATTACKER, 49_000]], {});
  p.outputs.pop();
  const r = check(p);
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((x) => x.includes(ATTACKER)), r.problems.join("; "));
});

test("duplicate or unknown input rows are refused", () => {
  const dup = proposal([[RCPT, 50_000], [addrAt(1, 3), 49_000]]);
  dup.inputs.push({ ...dup.inputs[0] });
  assert.equal(check(dup).ok, false);
  const swapped = proposal([[RCPT, 50_000], [addrAt(1, 3), 49_000]]);
  swapped.inputs = [{ outpoint: `${"ab".repeat(32)}:0`, amount_sats: 100_000 }];
  const r = check(swapped);
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((x) => x.includes("which the PSBT doesn't spend")), r.problems.join("; "));
});

test("change that isn't ours is still refused", () => {
  const p = proposal([[RCPT, 50_000], [ATTACKER, 49_000]], { 1: 3 });
  assert.equal(check(p).ok, false);
});
