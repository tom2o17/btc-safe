import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Every hardware sign button must be gated on the browser-side PSBT cross-check (`check.ok`).
// JSX can't run under `node --test`, so this checks the call sites in the source.
const files = ["../components/tx.tsx", "../app/w/[id]/send/page.tsx"].map((f) => new URL(f, import.meta.url));

test("every <TrezorSign> and <LedgerSign> gets disabled={!check?.ok}", () => {
  let seen = 0;
  for (const f of files) {
    const src = readFileSync(f, "utf8");
    for (const m of src.matchAll(/<(TrezorSign|LedgerSign)\b([\s\S]*?)\/>/g)) {
      seen++;
      assert.match(m[2], /disabled=\{!check\?\.ok\}/, `${m[1]} in ${f.pathname.split("/").slice(-2).join("/")} isn't gated`);
    }
  }
  assert.equal(seen, 4);
});

test("TrezorSign itself honours disabled (button and handler)", () => {
  const src = readFileSync(new URL("../components/trezor.tsx", import.meta.url), "utf8");
  assert.match(src, /if \(!proposal\.psbt \|\| disabled\) return;/);
  assert.match(src, /<button className="btn" disabled=\{disabled \|\|/);
});
