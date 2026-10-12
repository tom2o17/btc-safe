// Ledger flows in a real browser (system Chrome via playwright-core), device = Speculos.
// The page runs the real UI and the real bundled ledger-bitcoin client; only the USB hop is
// replaced: the dev-only `__btcSafeLedgerBridge` hook (lib/ledger.ts) relays APDUs to
// Speculos over TCP. Device buttons are pressed through Speculos' REST API.
//
// Needs: Speculos (.speculos-vm/START.md), API via e2e/reset-dev.sh, `next dev` on :3000,
// testsigner built. Screenshots: web/screenshots/ledger-*.png.
import { browserLogin, devAuth } from "./session.mjs";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { openTransport, drive } from "./speculos.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const SIGNER = path.join(ROOT, "target/debug/examples/testsigner");
const SHOTS = path.join(HERE, "../screenshots");
const WEB = process.env.WEB ?? "http://localhost:3000";
const API = process.env.API ?? "http://127.0.0.1:8080";
const AUTH = await devAuth(API);
const RCPT = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
mkdirSync(SHOTS, { recursive: true });

const log = (...a) => console.log("✓", ...a);
async function apiCall(method, p, body) {
  const r = await fetch(`${API}${p}`, {
    method,
    headers: { ...AUTH, ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) throw new Error(`${method} ${p}: ${r.status} ${await r.text()}`);
  const t = await r.text();
  return t ? JSON.parse(t) : null;
}
const shot = (page, name) => page.screenshot({ path: path.join(SHOTS, `ledger-${name}.png`), fullPage: true });

const transport = await openTransport();
const browser = await chromium.launch({ channel: "chrome", headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
const page = await ctx.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
await page.exposeFunction("__btcSafeLedgerBridge", async (hex) => (await transport.exchange(Buffer.from(hex, "hex"))).toString("hex"));

const status = (state) => page.locator(`[data-testid=ledger-status][data-state=${state}]`).first();
/** Click, then work the device until the UI reaches `state`. */
async function onDevice(click, target, state) {
  await click();
  const reached = status(state).waitFor({ timeout: 90_000 });
  const seen = await drive(reached, target, { max: 150 });
  await reached;
  return seen;
}

try {
  const others = JSON.parse(execFileSync(SIGNER, ["owners"]).toString());

  // 1. Token, then the create wizard with owner 1 from the Ledger.
  await browserLogin(page, WEB);
  await page.getByRole("link", { name: "Create account" }).click();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("button", { name: "+ Add owner" }).click();
  await page.getByRole("button", { name: "Connect Ledger" }).first().click();
  await page.getByText("✓ Ledger f5acc2fd").waitFor();
  const keyExpr = (o) => `[${o.fingerprint}/48'/1'/0'/2']${o.xpub}`;
  await page.getByPlaceholder("[fingerprint/48'/1'/0'/2']tpub…").nth(1).fill(keyExpr(others[1]));
  await page.getByPlaceholder("[fingerprint/48'/1'/0'/2']tpub…").nth(2).fill(keyExpr(others[2]));
  await page.getByLabel("Owner 1 name").fill("My Ledger");
  await page.getByText(`✓ fp ${others[2].fingerprint}`).waitFor();
  await shot(page, "01-wizard-owner");
  log("wizard: owner 1 filled from the Ledger (fp f5acc2fd)");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByLabel("Threshold").selectOption("2");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("button", { name: "Create account" }).click();
  await page.getByText("first addresses match").waitFor();
  const dl = page.waitForEvent("download");
  await page.getByRole("button", { name: "⇩ Download BSMS backup" }).click();
  await dl;
  await page.getByRole("button", { name: "Open account" }).click();
  await page.getByRole("heading", { name: "Overview" }).waitFor();
  const walletUrl = page.url();
  const wid = walletUrl.split("/w/")[1];

  // 2. Settings → register on the device.
  await page.goto(`${walletUrl}/settings`);
  await page.getByText("not registered").first().waitFor();
  let seen = await onDevice(() => page.getByRole("button", { name: "Register on connected Ledger" }).click(), /^Reject/i, "rejected");
  log(`register rejected on device -> UI shows 'rejected' (${seen.length} screens)`);
  seen = await onDevice(() => page.getByRole("button", { name: "Try again" }).click(), /^Register account/i, "ok");
  await page.getByRole("cell", { name: /✓ registered/ }).waitFor();
  await shot(page, "02-settings-registered");
  const reg = await apiCall("GET", `/wallets/${wid}/ledger`);
  assert.equal(reg.registrations.length, 1);
  log(`registered from the UI; HMAC stored server-side (${seen.length} device screens)`);

  // 3. Receive → show on device.
  await page.goto(`${walletUrl}/receive`);
  await page.getByText("This browser derived the same address").waitFor();
  const addr = (await page.getByTestId("receive-address").innerText()).split(/\s/)[0];
  seen = await onDevice(() => page.getByRole("button", { name: "Show on Ledger" }).click(), /^(Confirm|Approve|Done|Accept)/i, "ok");
  assert.ok(seen.some((s) => s.replace(/ \| /g, "").includes(addr.slice(0, 12))), `device showed ${addr}: ${seen.join(" / ")}`);
  await shot(page, "03-receive-shown");
  log(`receive address ${addr} shown on device and matched`);

  // 4. Fund, propose in the UI, sign with Ledger at step 3.
  await apiCall("POST", "/dev/fund", { address: addr, amount_sats: 200_000 });
  await apiCall("POST", "/dev/fund", { address: addr, amount_sats: 80_000 });
  await apiCall("POST", "/dev/mine", { blocks: 1 });
  await apiCall("POST", `/wallets/${wid}/sync`);
  await page.getByRole("link", { name: "New transaction" }).click();
  await page.getByLabel("Recipient 1").fill(RCPT);
  await page.getByLabel("Amount 1").fill("0.0015");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByText("matches the server summary").waitFor();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByText("Ledger (USB)").click();
  seen = await onDevice(() => page.getByRole("button", { name: "Sign with Ledger" }).click(), /^Reject/i, "rejected");
  await shot(page, "04-sign-rejected");
  log("sign rejected on device -> UI shows 'rejected'");
  seen = await onDevice(() => page.getByRole("button", { name: "Try again" }).click(), /^(Sign transaction|Accept|Hold to sign|Approve|Sign)/i, "ok");
  await page.getByText(/Ledger f5acc2fd signed: 1 of 2/).waitFor();
  await shot(page, "05-sign-ok");
  log(`signed on device from the send flow -> 1 of 2 (${seen.length} review screens)`);

  // 5. Second signer, execute via API, confirmed.
  const q = await apiCall("GET", `/wallets/${wid}/proposals?status=queue`);
  const p1 = q[q.length - 1];
  const full = await apiCall("GET", `/proposals/${p1.id}`);
  const s2 = execFileSync(SIGNER, ["sign", "1", full.psbt], { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  await apiCall("POST", `/proposals/${p1.id}/signatures`, { psbt: s2 });
  await apiCall("POST", `/proposals/${p1.id}/execute`);
  await apiCall("POST", "/dev/mine", { blocks: 2 });
  await apiCall("POST", `/wallets/${wid}/sync`);
  assert.equal((await apiCall("GET", `/proposals/${p1.id}`)).status, "confirmed");
  log(`#${p1.id} executed and confirmed`);

  // 6. Queue row, after forgetting the registration: 'not registered' → register then sign.
  await page.goto(`${walletUrl}/settings`);
  await page.getByRole("button", { name: "Forget" }).click();
  await page.getByText("not registered").first().waitFor();
  const p2 = await apiCall("POST", `/wallets/${wid}/proposals`, { outputs: [{ address: RCPT, amount_sats: 20_000 }], fee_rate_sat_vb: 2.0 });
  await page.goto(`${walletUrl}/transactions?open=${p2.id}`);
  await page.getByRole("button", { name: "Sign with Ledger" }).first().click();
  await page.getByTestId("ledger-sign").getByRole("button", { name: "Sign with Ledger" }).click();
  await status("not_registered").waitFor();
  await shot(page, "06-queue-not-registered");
  log("queue: device without registration -> 'not registered' + register-then-sign offered");
  await page.getByRole("button", { name: "Register wallet on this Ledger, then sign" }).click();
  const signed = page.getByText("Ledger f5acc2fd signed").waitFor({ timeout: 120_000 });
  await drive(signed, /^(Register account|Sign transaction|Accept|Hold to sign|Approve|Sign)/i, { max: 200 });
  await signed;
  await shot(page, "07-queue-signed");
  log("queue: registered + signed in one go");

  // 7. A browser without WebHID gets a clear message.
  const ctx2 = await browser.newContext();
  await ctx2.addInitScript(() => {
    delete Navigator.prototype.hid;
  });
  const p3 = await ctx2.newPage();
  await browserLogin(p3, WEB);
  await p3.goto(`${walletUrl}/settings`);
  await p3.getByText("only Chrome and Edge").first().waitFor();
  await p3.getByRole("button", { name: "Register on connected Ledger" }).click();
  await p3.locator("[data-testid=ledger-status][data-state=unsupported]").waitFor();
  await p3.screenshot({ path: path.join(SHOTS, "ledger-08-unsupported.png"), fullPage: true });
  log("no WebHID -> 'Browser not supported' message");

  assert.deepEqual(errors, [], "no page errors");
  console.log("LEDGER BROWSER E2E PASSED");
} catch (e) {
  await shot(page, "zz-failure").catch(() => undefined);
  console.error("errors:", errors.slice(0, 5));
  throw e;
} finally {
  await browser.close();
  await transport.close();
}
