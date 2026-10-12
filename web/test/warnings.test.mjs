import { test } from "node:test";
import assert from "node:assert/strict";
import { warningText } from "../lib/warnings.ts";

// The JSON shapes are what serde emits for each Rust variant (tag = "kind", snake_case).
test("fee warnings read as sentences", () => {
  assert.equal(
    warningText({ kind: "high_share_of_sent", fee_sats: 800, sent_sats: 10000, bps: 800 }),
    "Fee is 8.0% of the amount sent (800 sats fee to send 10,000 sats).",
  );
  assert.equal(
    warningText({ kind: "high_share_of_sent", fee_sats: 300, sent_sats: 0, bps: 18446744073709551615 }),
    "Fee is 300 sats and nothing goes to a recipient.",
  );
  assert.match(warningText({ kind: "no_fast_estimate" }), /^No fee estimate was available/);
  assert.equal(
    warningText({ kind: "cap_overridden", reason: "fee 0.01 BTC exceeds the absolute cap 0.005 BTC" }),
    "A fee safety cap was exceeded and you overrode it: fee 0.01 BTC exceeds the absolute cap 0.005 BTC.",
  );
});

test("strict-order, import and policy warnings read as sentences", () => {
  assert.match(warningText({ kind: "strict_order_descendants", message: "x", proposals: [4, 5] }), /proposals #4, #5;/);
  assert.match(warningText({ kind: "strict_order_descendants", proposals: [4] }), /proposal #4;/);
  assert.match(warningText({ kind: "change_path_assumed" }), /change path was assumed/);
  assert.match(warningText({ kind: "single_sig_path", owner: "Alice", path: "m/84'/1'/0'" }), /^Owner Alice uses m\/84'\/1'\/0' path/);
  assert.match(warningText({ kind: "non_standard_path", owner: "Bob", path: "m/1'" }), /BIP-48/);
});

test("never renders raw JSON", () => {
  for (const w of [
    { kind: "high_share_of_sent", fee_sats: 1, sent_sats: 2, bps: 5000 },
    { kind: "brand_new_kind", fee_sats: 5, nested: { a: 1 } },
    { message: "plain message" },
    {},
    "already a string",
  ]) {
    const s = warningText(w);
    assert.ok(!s.includes("{") && !s.includes('"'), s);
  }
  assert.equal(warningText({ kind: "brand_new_kind", fee_sats: 5 }), "Brand new kind: fee sats 5.");
  assert.equal(warningText({ message: "plain message" }), "plain message");
});

// Guard against a new Rust warning variant shipping without a sentence here.
test("every Rust warning variant has a sentence", async () => {
  const { readFileSync } = await import("node:fs");
  const src = ["fees", "policy", "import"].map((f) => readFileSync(new URL(`../../crates/core/src/${f}.rs`, import.meta.url), "utf8")).join("\n");
  const kinds = [];
  for (const m of src.matchAll(/pub enum (\w+Warning) \{([\s\S]*?)\n\}/g)) {
    for (const v of m[2].matchAll(/^\s{4}([A-Z]\w*)/gm)) kinds.push(v[1].replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase());
  }
  kinds.push("strict_order_descendants");
  assert.ok(kinds.length >= 7, kinds.join(","));
  for (const kind of kinds) {
    const s = warningText({ kind, owner: "A", path: "m/1'", fee_sats: 1, sent_sats: 1, bps: 1, reason: "r", proposals: [1] });
    assert.ok(!s.toLowerCase().startsWith(kind.replace(/_/g, " ")), `no sentence for ${kind}: ${s}`);
  }
});
