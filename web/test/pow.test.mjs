import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { checkPow, leadingZeroBits, sha256, solvePow } from "../lib/pow.ts";

const nodeSha = (b) => new Uint8Array(createHash("sha256").update(b).digest());
const zeroBits = (bytes) => {
  let n = 0;
  for (const b of bytes) {
    if (b === 0) { n += 8; continue; }
    return n + Math.clz32(b) - 24;
  }
  return n;
};
const noYield = { yieldFn: async () => {} };

test("sha256 matches node:crypto across lengths and padding boundaries", () => {
  for (const len of [0, 1, 3, 31, 32, 55, 56, 57, 63, 64, 65, 119, 120, 128, 200, 1000]) {
    const b = new Uint8Array(randomBytes(len));
    assert.deepEqual(sha256(b), nodeSha(b), `len ${len}`);
  }
  assert.equal(Buffer.from(sha256(new TextEncoder().encode("abc"))).toString("hex"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("leadingZeroBits counts big-endian, MSB first", () => {
  assert.equal(leadingZeroBits([0x80000000, 0]), 0);
  assert.equal(leadingZeroBits([0x00000001, 0]), 31);
  assert.equal(leadingZeroBits([0, 0x00f00000]), 40);
  assert.equal(leadingZeroBits([0, 0, 0, 0, 0, 0, 0, 0]), 256);
});

test("solvePow returns the smallest qualifying nonce (checked with node:crypto)", async () => {
  for (const [challenge, bits] of [["c2lnbnVw.abc123", 8], ["challenge-ü-utf8", 12], ["x", 0], ["0123456789abcdef", 16]]) {
    const n = await solvePow(challenge, bits, noYield);
    assert.match(n, /^(0|[1-9]\d*)$/);
    const h = nodeSha(Buffer.from(`${challenge}:${n}`, "utf8"));
    assert.ok(zeroBits(h) >= bits, `${challenge}/${bits}: ${n}`);
    for (let i = 0; i < Number(n); i++) assert.ok(zeroBits(nodeSha(Buffer.from(`${challenge}:${i}`, "utf8"))) < bits, `smaller nonce ${i} also works`);
    assert.equal(checkPow(challenge, n, bits), true);
  }
});

test("solvePow yields between batches and can be aborted", async () => {
  let yields = 0;
  const ac = new AbortController();
  await assert.rejects(
    solvePow("never", 64, { batch: 100, signal: ac.signal, yieldFn: async () => { if (++yields === 3) ac.abort(); } }),
    /aborted/,
  );
  assert.equal(yields, 3);
  await assert.rejects(solvePow("x", 65, noYield), /unsupported/);
});
