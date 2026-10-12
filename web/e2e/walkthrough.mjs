// End-to-end walkthrough in a real browser (system Chrome via playwright-core).
// Needs: the API on :8080 with CHAIN=memory and a dev account, `next dev` on :3000,
// and the testsigner example built (cargo build -p btc-safe-testkit --example testsigner).
//
//   node e2e/walkthrough.mjs            # screenshots land in web/screenshots/
//
// The testsigner plays the owners' hardware wallets with deterministic TEST keys.

import { browserLogin, devAuth } from "./session.mjs";
import { chromium } from "playwright-core";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

const WEB = process.env.WEB ?? "http://localhost:3000";
const API = process.env.API ?? "http://127.0.0.1:8080";
const AUTH = await devAuth(API);
const ROOT = path.resolve(import.meta.dirname, "../..");
const SIGNER = path.join(ROOT, "target/debug/examples/testsigner");
const SHOTS = path.resolve(import.meta.dirname, "../screenshots");
const TMP = "/tmp/btcsafe-e2e";
mkdirSync(SHOTS, { recursive: true });
mkdirSync(TMP, { recursive: true });

const log = (...a) => console.log("•", ...a);
async function dev(p, body) {
  const r = await fetch(`${API}${p}`, { method: "POST", headers: { ...AUTH, "content-type": "application/json" }, body: JSON.stringify(body ?? {}) });
  if (!r.ok) throw new Error(`${p}: ${r.status} ${await r.text()}`);
  return r.json().catch(() => ({}));
}
const shot = (page, name) => page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });

const browser = await chromium.launch({ channel: "chrome", headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
const page = await ctx.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
page.on("console", (m) => m.type() === "error" && errors.push(m.text()));

try {
  // 1. Token + accounts
  await browserLogin(page, WEB);
  await page.getByText("No accounts yet").waitFor();
  log("logged in, empty account list");

  // 2. Create account wizard
  await page.getByRole("link", { name: "Create account" }).click();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByText("Paste all owners as JSON").click();
  const owners = execFileSync(SIGNER, ["owners"]).toString();
  await page.getByLabel("Owners JSON").fill(owners);
  await page.getByRole("button", { name: "Fill owners" }).click();
  await page.getByText("✓ fp 4ba43603").waitFor();
  await shot(page, "01-create-owners");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByLabel("Threshold").selectOption("2");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByText("Descriptor (computed in this browser)").waitFor();
  await shot(page, "02-create-review");
  await page.getByRole("button", { name: "Create account" }).click();
  await page.getByText("first addresses match").waitFor();
  const dl = page.waitForEvent("download");
  await page.getByRole("button", { name: "⇩ Download BSMS backup" }).click();
  const bsms = await dl;
  await bsms.saveAs(path.join(TMP, "backup.bsms"));
  log("created; BSMS downloaded:", readFileSync(path.join(TMP, "backup.bsms"), "utf8").split("\n")[0]);
  await shot(page, "03-create-backup");
  await page.getByRole("button", { name: "Open account" }).click();
  await page.getByRole("heading", { name: "Overview" }).waitFor();
  const walletUrl = page.url();
  const wid = walletUrl.split("/w/")[1];
  log("wallet", wid);

  // 3. Receive, then fund that address on the simulated chain
  await page.locator("a.btn", { hasText: "↓ Receive" }).click();
  await page.getByText("This browser derived the same address").waitFor();
  const addr = (await page.getByTestId("receive-address").innerText()).split(/\s/)[0];
  await shot(page, "04-receive");
  log("receive", addr);
  await dev("/dev/fund", { address: addr, amount_sats: 250_000 });
  await dev("/dev/fund", { address: addr, amount_sats: 120_000 });
  await dev("/dev/mine", {});
  await dev(`/wallets/${wid}/sync`);

  // 4. Address book entry, used as a recipient name
  await page.getByRole("link", { name: "Address book" }).click();
  await page.getByLabel("Entry name").fill("Exchange");
  await page.getByLabel("Entry address").fill("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
  await page.getByRole("button", { name: "Add" }).click();
  await page.getByRole("cell", { name: "Exchange" }).waitFor();

  // 5. New transaction: Send → Review → Sign
  await page.getByRole("link", { name: "New transaction" }).click();
  await page.getByLabel("Recipient 1").fill("Exchange");
  await page.getByLabel("Amount 1").fill("0.001");
  await page.getByText("Normal", { exact: false }).first().click();
  await shot(page, "05-send");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByText("matches the server summary").waitFor();
  await shot(page, "06-review");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByText("Step 3 of 3").waitFor();
  await page.getByText("▦ Show QR").click();
  await page.getByText(/Frame \d+ of \d+/).waitFor();
  await page.waitForTimeout(600);
  await shot(page, "07-sign-qr");
  await page.getByText("⇩ Download PSBT").first().click();
  const dl2 = page.waitForEvent("download");
  await page.getByRole("button", { name: /Download btc-safe-proposal-/ }).click();
  const psbtFile = await dl2;
  const unsignedPath = path.join(TMP, psbtFile.suggestedFilename());
  await psbtFile.saveAs(unsignedPath);
  const unsignedB64 = readFileSync(unsignedPath).toString("base64");
  // Owners 0 and 2 sign "on their devices"; each returns a signed PSBT file.
  for (const i of [0, 2]) {
    const signed = execFileSync(SIGNER, ["sign", String(i), unsignedB64]).toString().trim();
    const f = path.join(TMP, `signed-${i}.psbt`);
    writeFileSync(f, Buffer.from(signed, "base64")); // binary, like an SD card file
    await page.getByTestId("psbt-file").setInputFiles(f);
    await page.getByText(`signed-${i}.psbt:`).waitFor();
  }
  await page.getByText("2 of 2", { exact: false }).first().waitFor();
  await shot(page, "08-signed");
  log("2 of 2 signatures uploaded");

  // 6. A second proposal signed by one owner only, to show a queue row at 1 of 2.
  await page.getByRole("link", { name: "New transaction" }).click();
  await page.getByLabel("Recipient 1").fill("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7");
  await page.getByLabel("Amount 1").fill("0.0005");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByText("matches the server summary").waitFor();
  const p2 = await (await fetch(`${API}/wallets/${wid}/proposals?status=queue`, { headers: AUTH })).json();
  const second = p2[p2.length - 1];
  const full2 = await (await fetch(`${API}/proposals/${second.id}`, { headers: AUTH })).json();
  const s1 = execFileSync(SIGNER, ["sign", "1", full2.psbt]).toString().trim();
  await dev(`/proposals/${second.id}/signatures`, { psbt: s1 });

  // 7. Queue with expandable rows, then execute #1
  await page.goto(`${walletUrl}/transactions`);
  await page.locator(".txgroup-label", { hasText: "Awaiting confirmations" }).waitFor();
  await page.getByTestId(`tx-${second.id}`).locator(".txhead").click();
  await page.getByTestId(`tx-${second.id}`).getByText("Decoded in this browser").waitFor();
  await shot(page, "09-queue-expanded");
  const first = p2[0];
  const row1 = page.getByTestId(`tx-${first.id}`);
  await row1.locator(".txhead").click();
  await row1.getByText("Decoded in this browser").waitFor();
  await shot(page, "09b-ready-to-execute");
  await row1.getByRole("button", { name: "Execute" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Execute" }).click();
  await row1.getByText(/Broadcast [0-9a-f]{64}/).waitFor();
  log("executed #" + first.id);
  await shot(page, "10-executed");

  // 8. Confirm on the simulated chain; history, assets, settings, home
  await dev("/dev/mine", {});
  await dev(`/wallets/${wid}/sync`);
  await page.goto(`${walletUrl}/transactions?tab=history`);
  await page.getByText("Block", { exact: false }).first().waitFor();
  const conf = await (await fetch(`${API}/proposals/${first.id}`, { headers: AUTH })).json();
  log("proposal status after mine+sync:", conf.status);
  await shot(page, "11-history");

  // 8b. Soft vs final, and a reorg (CONFIRMATIONS_FINAL defaults to 2).
  if (conf.status !== "soft_confirmed") throw new Error(`expected soft_confirmed after 1 block, got ${conf.status}`);
  await page.goto(`${walletUrl}/transactions?open=${first.id}`);
  const softRow = page.getByTestId(`tx-${first.id}`);
  await softRow.getByText("1 block confirmation, waiting for final").first().waitFor();
  await softRow.getByTestId("block-depth").getByText("final at 2").waitFor();
  await shot(page, "11b-soft-confirmed");
  await dev("/dev/reorg", { depth: 1, back_to_mempool: true });
  await dev(`/wallets/${wid}/sync`);
  await page.reload();
  await page.getByTestId(`tx-${first.id}`).getByText("Reorged, waiting to be mined again").first().waitFor();
  await shot(page, "11c-reorged");
  log("soft-confirmed proposal rolled back after a reorg");
  await dev("/dev/mine", { blocks: 2 });
  await dev(`/wallets/${wid}/sync`);
  await page.goto(`${walletUrl}/transactions?tab=history&open=${first.id}`);
  await page.getByTestId(`tx-${first.id}`).getByTestId("status-tag").getByText("Final", { exact: true }).first().waitFor();
  await shot(page, "11d-final");
  log("re-mined: final after 2 block confirmations");
  await page.goto(`${walletUrl}/assets`);
  await page.getByText("reserved (#").first().waitFor();
  await shot(page, "12-assets");
  await page.goto(`${walletUrl}/settings`);
  await page.getByText("Owners (3)").waitFor();
  await shot(page, "13-settings");
  await page.goto(walletUrl);
  await page.getByText("Pending transactions").waitFor();
  await page.waitForTimeout(500);
  await shot(page, "00-home");

  // 9. Tampered server response: the browser must flag it.
  await page.route(`**/api/proposals/${second.id}`, async (route) => {
    const r = await route.fetch();
    const j = await r.json();
    j.fee_sats = j.fee_sats - 150;
    const ch = j.outputs.find((o) => o.is_change);
    if (ch) ch.change_index += 3;
    await route.fulfill({ response: r, json: j });
  });
  await page.goto(`${walletUrl}/transactions?open=${second.id}`);
  await page.getByTestId("mismatch").waitFor();
  await shot(page, "14-tampered-mismatch");
  log("tampered response flagged");

  // 10. Import the BSMS backup downloaded in step 2 as a second account.
  await page.unroute(`**/api/proposals/${second.id}`);
  await page.goto(`${WEB}/new?mode=import`);
  await page.getByLabel(/Name \(optional/).fill("Imported copy");
  await page.getByTestId("import-data").fill(readFileSync(path.join(TMP, "backup.bsms"), "utf8"));
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await page.getByText("first addresses match").waitFor();
  await shot(page, "15-import-backup");
  log("BSMS import round-trips; addresses match");

  console.log("RESULT: walkthrough OK; page errors:", errors.length ? errors.slice(0, 5) : "none");
} catch (e) {
  await shot(page, "zz-failure").catch(() => undefined);
  console.log("RESULT: FAILED:", String(e).slice(0, 600));
  console.log("page errors:", errors.slice(0, 5));
  process.exitCode = 1;
} finally {
  await browser.close();
}
