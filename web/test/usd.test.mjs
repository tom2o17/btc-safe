import { test } from "node:test";
import assert from "node:assert/strict";
import { usd } from "../lib/format.ts";

test("usd formats 2 decimals with separators", () => {
  assert.equal(usd(10_000, 83176), "≈ $8.32");
  assert.equal(usd(100_000_000, 83176.5), "≈ $83,176.50");
  assert.equal(usd(0, 83176), "≈ $0.00");
  assert.equal(usd(-50_000, 80000), "≈ -$40.00");
});

test("usd shows < $0.01 for tiny amounts", () => {
  assert.equal(usd(1, 83176), "< $0.01");
  assert.equal(usd(6, 83176), "< $0.01"); // $0.00499
  assert.equal(usd(7, 83176), "≈ $0.01"); // $0.00582 rounds up
});

test("usd hides when price or amount unknown", () => {
  for (const p of [null, undefined, 0, -1, NaN, Infinity]) assert.equal(usd(1000, p), null);
  for (const s of [null, undefined, NaN]) assert.equal(usd(s, 80000), null);
});
