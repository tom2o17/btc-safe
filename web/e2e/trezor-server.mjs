// Trezor path against the real API (CHAIN=memory), with no device:
//  1. server: a 2-of-3 wallet whose owners are test/trezor-mock.mjs keys. For each signer, our
//     builder makes the Trezor request from the server's PSBT, the firmware model signs it, our
//     merge adds the signatures, and POST /proposals/:id/signatures (unchanged server validation)
//     must accept them. Then execute → mine → confirmed.
//  2. browser: "Add from Trezor" and "Sign with Trezor" with no Trezor Suite reachable must show the
//     "Trezor not connected" state. Requests to *.trezor.io are blocked, so Connect's Suite Web
//     fallback fails locally. (NEXT_PUBLIC_TREZOR_CORE_MODE=suite-desktop is optional.)
//
//   API=http://127.0.0.1:8091 WEB=http://localhost:3091 node e2e/trezor-server.mjs
//
// TEST-ONLY KEYS: the mock's seeds play the devices; the app code never sees a private key.

import { browserLogin, devAuth } from "./session.mjs";
import assert from "node:assert/strict";
import { chromium } from "playwright-core";
import { buildTrezorRequest, mergeSignatures } from "../lib/signers/trezor-tx.ts";
import { mockTrezor, testOwners, testRoots } from "../test/trezor-mock.mjs";

const WEB = process.env.WEB ?? "http://localhost:3000";
const API = process.env.API ?? "http://127.0.0.1:8080";
const AUTH = await devAuth(API);
const log = (...a) => console.log("•", ...a);

async function call(p, body, method) {
  const r = await fetch(`${API}${p}`, {
    method: method ?? (body === undefined ? "GET" : "POST"),
    headers: { ...AUTH, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`${p}: ${r.status} ${text}`);
  return text ? JSON.parse(text) : {};
}

// ---- 1. server ----
const w = await call("/wallets", { name: `Trezor e2e ${Date.now()}`, network: "signet", threshold: 2, owners: testOwners });
log("wallet", w.id);
for (const amt of [150_000, 90_000]) {
  const a = await call(`/wallets/${w.id}/addresses?kind=receive&next=true`);
  await call("/dev/fund", { address: a.address, amount_sats: amt });
}
await call("/dev/mine", {});
await call(`/wallets/${w.id}/sync`, {});
const created = await call(`/wallets/${w.id}/proposals`, { outputs: [{ address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", amount_sats: 200_000 }], fee_rate_sat_vb: 2 });
const id = created.id ?? created.proposal?.id;
let p = await call(`/proposals/${id}`);
log(`proposal #${id}: ${p.inputs.length} inputs, ${p.outputs.length} outputs`);

const wallet = await call(`/wallets/${w.id}`);
const owners = [...wallet.owners].sort((a, b) => a.position - b.position);
const changeIndex = new Map(p.outputs.filter((o) => o.is_change).map((o) => [o.vout, o.change_index]));
assert.ok(changeIndex.size === 1, "expected one change output");

for (const k of [0, 2]) {
  const device = owners.find((o) => o.fingerprint === testOwners[k].fingerprint);
  const built = buildTrezorRequest(p.psbt, owners, wallet.threshold, wallet.network, device, changeIndex);
  assert.deepEqual(built.changeVouts, [...changeIndex.keys()], "device would not see the server's change as change");
  const dev = mockTrezor(built.request, testRoots[k]);
  assert.equal(dev.txid, p.unsigned_txid, "device would sign a different tx");
  assert.deepEqual(dev.change, [...changeIndex.keys()]);
  const merged = mergeSignatures(p.psbt, dev.signatures, built.inputPubkeys, wallet.network);
  const r = await call(`/proposals/${id}/signatures`, { psbt: merged.psbt });
  assert.equal(r.accepted.new_signatures, p.inputs.length, "server should accept one signature per input");
  log(`${device.name}: server accepted ${r.accepted.new_signatures} signature(s) → ${r.confirmations.count} of ${r.confirmations.threshold}`);
  p = await call(`/proposals/${id}`);
}
// A corrupted Trezor signature must not get past our merge (and the server would reject it anyway).
{
  const device = owners.find((o) => o.fingerprint === testOwners[1].fingerprint);
  const built = buildTrezorRequest(p.psbt, owners, wallet.threshold, wallet.network, device, changeIndex);
  const dev = mockTrezor(built.request, testRoots[1]);
  const bad = dev.signatures.map((s) => s.slice(0, -2) + (s.endsWith("00") ? "01" : "00"));
  assert.throws(() => mergeSignatures(p.psbt, bad, built.inputPubkeys, wallet.network));
  log("corrupted signature refused by merge");
}
assert.ok(p.confirmations.ready);

// ---- 2. browser states (before execute, so the queue row still has its actions) ----
const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  page.on("console", (m) => m.text().includes("[trezor]") && log("browser console:", m.text().slice(0, 300)));
  // Keep the test offline: Connect falls back to Suite Web (suite.trezor.io) when Suite desktop
  // isn't running; block it so the failure is local and deterministic.
  await page.route(/trezor\.io/, (r) => r.abort());
  await browserLogin(page, WEB);

  await page.goto(`${WEB}/new`);
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("button", { name: "Add from Trezor" }).first().click();
  const e1 = page.getByTestId("trezor-error").first();
  await e1.waitFor({ timeout: 30_000 });
  assert.equal(await e1.getAttribute("data-code"), "not_connected", await e1.innerText());
  log("wizard: Add from Trezor → 'Trezor not connected'");
  await page.screenshot({ path: "/tmp/btcsafe-trezor-01-add-owner.png", fullPage: true });

  await page.goto(`${WEB}/w/${w.id}/transactions?open=${id}`);
  await page.getByRole("button", { name: "Sign with Trezor" }).first().click();
  await page.getByTestId("trezor-sign").getByRole("button", { name: "Sign with Trezor" }).click();
  const e2 = page.getByTestId("trezor-sign").getByTestId("trezor-error");
  await e2.waitFor({ timeout: 30_000 });
  assert.equal(await e2.getAttribute("data-code"), "not_connected", await e2.innerText());
  log("queue: Sign with Trezor → 'Trezor not connected'");
  await page.screenshot({ path: "/tmp/btcsafe-trezor-02-sign.png", fullPage: true });
} finally {
  await browser.close();
}

// ---- execute ----
const ex = await call(`/proposals/${id}/execute`, {});
log("executed", ex.status, ex.txid ?? ex.broadcast_txid ?? "");
await call("/dev/mine", { blocks: 2 });
await call(`/wallets/${w.id}/sync`, {});
p = await call(`/proposals/${id}`);
assert.equal(p.status, "confirmed");
log(`#${id} confirmed. Trezor e2e passed.`);
