// Dark-mode check against the LIVE site. Read-only: views pages and opens modals, never signs,
// executes or deletes anything.
//   WEB=https://your-instance DEMO_EMAIL=… DEMO_PASSWORD=… node e2e/dark-live.mjs
import { chromium } from "playwright-core";

const WEB = process.env.WEB ?? (() => { throw new Error("set WEB to the instance URL"); })();
const SHOTS = new URL("../screenshots/", import.meta.url).pathname;
const TMP = process.env.TMP_SHOTS ?? "/tmp/btcsafe-dark";
const out = [];
const log = (s) => { out.push(s); console.log("•", s); };

// Pre-hydration evidence: theme + body colour at the very first animation frame of each load.
const FIRST_FRAME = () => {
  requestAnimationFrame(() => {
    const b = document.body ? getComputedStyle(document.body).backgroundColor : "no-body";
    window.__first = { theme: document.documentElement.getAttribute("data-theme"), bg: b };
  });
};

const browser = await chromium.launch({ channel: "chrome", headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "light" });
await ctx.addInitScript(FIRST_FRAME);
const page = await ctx.newPage();
page.on("pageerror", (e) => log(`pageerror: ${String(e).slice(0, 160)}`));
page.on("console", (m) => m.type() === "error" && log(`console: ${m.text().slice(0, 160)}`));
const first = () => page.waitForFunction(() => window.__first).then((h) => h.jsonValue());
const settle = () => page.waitForLoadState("networkidle").catch(() => {});

try {
  const html = await (await fetch(WEB + "/login")).text();
  const head = html.slice(0, html.indexOf("</head>"));
  log(`init script in <head>: ${head.includes("btcsafe.theme") && head.includes("data-theme")}`);

  await page.goto(WEB);
  await page.waitForURL(/\/login/);
  await page.getByLabel("Email").fill(process.env.DEMO_EMAIL);
  await page.getByLabel("Password").fill(process.env.DEMO_PASSWORD);
  await page.getByRole("button", { name: /log in|sign in/i }).click();
  await page.getByRole("heading", { name: "Accounts" }).waitFor({ timeout: 20000 });
  await settle();
  log(`default (system=light): ${JSON.stringify(await first())}`);

  await page.getByTestId("theme-picker").getByRole("radio", { name: "Dark" }).click();
  log(`after click: data-theme=${await page.evaluate(() => document.documentElement.dataset.theme)}`);

  await page.reload();
  const f = await first();
  log(`reload, first frame: ${JSON.stringify(f)}`);
  if (f.theme !== "dark") throw new Error("theme did not persist to first frame");
  await page.getByRole("heading", { name: "Accounts" }).waitFor();
  await settle();
  log(`Dark radio checked after reload: ${await page.getByRole("radio", { name: "Dark" }).getAttribute("aria-checked")}`);
  await page.screenshot({ path: SHOTS + "dark-home.png", fullPage: true });

  // System follows the OS while selected; an explicit Dark ignores it.
  await page.emulateMedia({ colorScheme: "light" });
  log(`OS light + pref dark: ${await page.evaluate(() => document.documentElement.dataset.theme)}`);

  await page.locator('a.card[href^="/w/"]').first().click();
  await page.waitForURL(/\/w\//);
  await settle();
  await page.screenshot({ path: `${TMP}/wallet-home.png` });
  // Sidebar receive QR: already-loaded address, opening it changes nothing.
  await page.locator('.iconbtn[title="QR code"]').click();
  await page.locator(".qrbox img").waitFor({ timeout: 10000 });
  const qrBg = await page.locator(".qrbox").evaluate((e) => getComputedStyle(e).backgroundColor);
  log(`receive QR box bg in dark: ${qrBg}`);
  await page.screenshot({ path: `${TMP}/modal-receive-qr.png` });
  await page.keyboard.press("Escape");
  if (await page.locator(".modal").count()) await page.locator(".modal-backdrop").click({ position: { x: 5, y: 5 } });
  await page.getByRole("link", { name: "Transactions" }).first().click();
  await page.waitForURL(/transactions/);
  await settle();
  if (!(await page.locator(".txhead").count())) {
    // Empty queue: use the newest proposal under History (same row component). Creating one would touch wallet data.
    log("queue empty; using History");
    await page.locator(".tabs").getByRole("button", { name: "History" }).click();
    await page.locator(".txhead").first().waitFor({ timeout: 15000 });
  }
  await page.locator(".txhead").first().click();
  await page.waitForTimeout(2500);
  await page.screenshot({ path: SHOTS + "dark-queue.png", fullPage: true });

  for (const [name, btn] of [["qr", /Show QR/], ["ledger", /Ledger/], ["trezor", /Trezor/]]) {
    const b = page.locator(".actions button").filter({ hasText: btn }).first();
    if (!(await b.count()) || (await b.isDisabled())) { log(`${name}: button missing/disabled`); continue; }
    await b.click();
    await page.waitForTimeout(1500);
    await page.screenshot({ path: `${TMP}/modal-${name}.png` });
    await page.keyboard.press("Escape");
    const close = page.locator(".modal").getByRole("button", { name: /close|cancel|×/i }).first();
    if (await page.locator(".modal").count()) await close.click().catch(() => {});
    await page.waitForTimeout(300);
  }

  await page.getByRole("link", { name: "Settings" }).first().click();
  await page.waitForURL(/settings/);
  await page.getByRole("button", { name: "Appearance" }).click();
  await page.getByTestId("appearance").waitFor();
  await page.screenshot({ path: `${TMP}/wallet-settings-appearance.png` });
  await page.getByRole("button", { name: "Setup" }).click();
  await settle();
  await page.screenshot({ path: `${TMP}/wallet-settings.png`, fullPage: true });

  // Light screenshots of the same pages, for comparison.
  await page.getByRole("button", { name: "Appearance" }).click();
  await page.getByTestId("theme-picker").getByRole("radio", { name: "System" }).click();
  log(`System + OS light: ${await page.evaluate(() => document.documentElement.dataset.theme)}`);
  await page.emulateMedia({ colorScheme: "dark" });
  await page.waitForTimeout(200);
  log(`System + OS dark (live switch): ${await page.evaluate(() => document.documentElement.dataset.theme)}`);
  log(`stored after System: ${await page.evaluate(() => localStorage.getItem("btcsafe.theme"))}`);
} catch (e) {
  log(`FAILED: ${String(e).slice(0, 300)}`);
  await page.screenshot({ path: `${TMP}/failure.png` }).catch(() => {});
  process.exitCode = 1;
} finally {
  await browser.close();
}
