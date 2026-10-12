import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { chainStatus, STATUS_LABEL } from "../lib/format.ts";

const bc = (count, final_at = 2, fin = false) => ({ count, final_at, final: fin });

test("soft confirmed reads as waiting for final, with the depth", () => {
  const s = chainStatus({ status: "soft_confirmed", status_reason: "soft_confirmed", block_confirmations: bc(1) });
  assert.equal(s.label, "1 block confirmation, waiting for final");
  assert.equal(s.tone, "warn");
  assert.match(s.note, /final at 2/);
  assert.match(s.note, /reorganization/);
  assert.equal(chainStatus({ status: "soft_confirmed", status_reason: null, block_confirmations: bc(2, 6) }).label, "2 block confirmations, waiting for final");
  // Older API without block_confirmations still says something sensible.
  assert.equal(chainStatus({ status: "soft_confirmed", status_reason: null }).label, "1 block confirmation, waiting for final");
});

test("confirmed reads as Final", () => {
  const s = chainStatus({ status: "confirmed", status_reason: "final", block_confirmations: bc(5, 2, true) });
  assert.equal(s.label, "Final");
  assert.equal(s.tone, "ok");
  assert.equal(STATUS_LABEL.confirmed, "Final");
});

test("a reorged-back proposal says it was reorged, not just Broadcast", () => {
  const back = chainStatus({ status: "broadcast", status_reason: "reorged_back_to_mempool", block_confirmations: bc(null) });
  assert.equal(back.label, "Reorged, waiting to be mined again");
  assert.match(back.note, /back in the mempool/);
  const gone = chainStatus({ status: "broadcast", status_reason: "reorged_out", block_confirmations: bc(null) });
  assert.equal(gone.label, "Reorged, not in a block");
  assert.equal(chainStatus({ status: "broadcast", status_reason: "seen_in_mempool" }).label, "Broadcast");
});

test("every status the server can send has a label (read from the Rust enum)", () => {
  const rust = readFileSync(new URL("../../crates/core/src/state.rs", import.meta.url), "utf8");
  const body = rust.slice(rust.indexOf("pub fn as_str"), rust.indexOf("pub fn parse"));
  const all = [...body.matchAll(/=> "([a-z_]+)"/g)].map((m) => m[1]);
  assert.ok(all.includes("soft_confirmed") && all.length >= 9, String(all));
  for (const s of all) {
    assert.ok(STATUS_LABEL[s], s);
    assert.ok(chainStatus({ status: s, status_reason: null }).label, s);
  }
});
