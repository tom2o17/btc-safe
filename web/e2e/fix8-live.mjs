// Live check of the 8 fixes (2026-10-07) as the demo user, against the demo's own wallet only.
// Creates one tiny proposal (never signed or executed) and deletes it at the end.
//   WEB=https://your-instance CARAVAN=path/to/2of3.json DEMO_EMAIL=… DEMO_PASSWORD=… node e2e/fix8-live.mjs
import { chromium } from "playwright-core";
import { readFileSync, writeFileSync } from "node:fs";

const WEB = process.env.WEB ?? (() => { throw new Error("set WEB to the instance URL"); })();
const API = WEB + "/api";
const SHOTS = new URL("../screenshots/", import.meta.url).pathname;
const CARAVAN = process.env.CARAVAN ?? (() => { throw new Error("set CARAVAN to a Caravan JSON wallet file"); })();
const RCPT = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
const results = {};
const ok = (k, v, detail = "") => {
  results[k] = v;
  console.log(v ? "PASS" : "FAIL", k, detail ? `— ${String(detail).slice(0, 200)}` : "");
};

// A separate API session for the direct-request checks and cleanup.
async function apiSession() {
  const r = await fetch(API + "/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: process.env.DEMO_EMAIL, password: process.env.DEMO_PASSWORD }) });
  const j = await r.json();
  const cookie = r.headers.get("set-cookie").split(";")[0];
  return (method, path, body) =>
    fetch(API + path, { method, headers: { cookie, "x-csrf-token": j.csrf_token, ...(body ? { "content-type": "application/json" } : {}) }, body: body ? JSON.stringify(body) : undefined }).then(async (res) => ({ status: res.status, body: await res.json().catch(() => null) }));
}

const call = await apiSession();
const [wallet] = (await call("GET", "/wallets")).body;
if (!wallet || wallet.name.includes("Treasury")) throw new Error("expected the demo wallet");
const W = `${WEB}/w/${wallet.id}`;
let pid = null;

const browser = await chromium.launch({ channel: "chrome", headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "light" });
const page = await ctx.newPage();
page.on("pageerror", (e) => console.log("pageerror:", String(e).slice(0, 160)));

try {
  // Bug 1 (API): a spoofed proposer is refused before anything is built.
  const spoof = await call("POST", `/wallets/${wallet.id}/proposals`, { outputs: [{ address: RCPT, amount_sats: 1000 }], created_by: "Mallory" });
  ok("1-api-spoof-refused", spoof.status === 400, `${spoof.status} ${spoof.body?.message}`);

  await page.goto(WEB + "/login");
  await page.getByLabel("Email").fill(process.env.DEMO_EMAIL);
  await page.getByLabel("Password").fill(process.env.DEMO_PASSWORD);
  await page.getByRole("button", { name: /log in|sign in/i }).click();
  await page.getByRole("heading", { name: "Accounts" }).waitFor({ timeout: 20000 });

  // Bug 6: Receive in the sidebar. Bug 8: Show on Trezor is a real button now.
  await page.goto(W);
  const recv = page.locator("nav.nav").getByRole("link", { name: "Receive" });
  await recv.waitFor({ timeout: 20000 });
  ok("6-sidebar-receive-link", (await recv.count()) === 1);
  await recv.click();
  await page.waitForURL(/\/receive$/);
  await page.getByText("This browser derived the same address").waitFor({ timeout: 20000 });
  const tbtn = page.getByRole("button", { name: "Show on Trezor" });
  ok("8-show-on-trezor-enabled", (await tbtn.count()) === 1 && (await tbtn.isEnabled()));
  await tbtn.click();
  // No Trezor here: Connect either errors or waits on the Suite popup. Either way, never a false ✓.
  const outcome = await Promise.race([
    page.getByTestId("trezor-not-verified").waitFor({ timeout: 45000 }).then(() => "not-verified message"),
    page.waitForTimeout(45000).then(() => "still waiting for Suite after 45 s"),
  ]);
  const falseOk = await page.getByText("derived the same address. That only counts").count();
  ok("8-trezor-no-false-success", falseOk === 0, outcome);
  results["8-outcome"] = outcome;
  const err = await page.getByTestId("trezor-error").innerText().catch(() => "");
  if (err) console.log("   trezor error shown:", err.replace(/\s+/g, " ").slice(0, 200));
  for (const p of ctx.pages()) if (p !== page) await p.close();
  await page.screenshot({ path: SHOTS + "fix8-receive.png", fullPage: true });

  // Bug 1 (UI) + Bug 2: proposer is the login; the fee warning is a sentence.
  await page.goto(W + "/send");
  await page.getByText("Advanced").click();
  const by = await page.getByText("Proposed by:").innerText();
  ok("1-send-shows-login-as-proposer", by.includes(process.env.DEMO_EMAIL) && (await page.locator("label", { hasText: "Proposed by" }).count()) === 0, by);
  await page.getByLabel("Recipient 1").fill(RCPT);
  await page.getByLabel("Amount 1").fill("0.00001");
  // Signet's estimate is ~0.1 sat/vB; 2 sat/vB on 1,000 sats is well over the 5% warning line.
  await page.locator("label", { hasText: "Custom" }).click();
  await page.getByLabel("Custom fee rate").fill("2");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByText(/Step 2 of 3/).waitFor({ timeout: 30000 });
  pid = Number((await page.getByText(/Step 2 of 3/).innerText()).match(/#(\d+)/)?.[1] ?? NaN);
  const warn = page.locator(".alert.warn", { hasText: "Warnings" });
  await warn.waitFor({ timeout: 10000 });
  const wtext = (await warn.innerText()).replace(/\s+/g, " ");
  ok("2-warning-is-text", /Fee is \d+\.\d% of the amount sent/.test(wtext) && !wtext.includes("{"), wtext);
  await page.screenshot({ path: SHOTS + "fix8-review-warning.png", fullPage: true });

  // Bug 7: Trezor sign button on the send page: enabled only once the cross-check passed.
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("button", { name: /Trezor/ }).first().click();
  const sendTrezor = page.getByTestId("trezor-sign").getByRole("button", { name: "Sign with Trezor" });
  ok("7-send-trezor-enabled-after-check", await sendTrezor.isEnabled());

  if (!Number.isFinite(pid)) {
    const q = (await call("GET", `/wallets/${wallet.id}/proposals`)).body;
    pid = (Array.isArray(q) ? q : q.proposals ?? [])[0]?.id;
  }
  // Bug 1: queue row shows the proposer; the server stored the login.
  const stored = (await call("GET", `/proposals/${pid}`)).body;
  ok("1-server-stored-proposer", stored.created_by === process.env.DEMO_EMAIL, stored.created_by);
  await page.goto(`${W}/transactions`);
  const proposer = page.getByTestId(`tx-${pid}`).getByTestId("proposer");
  ok("1-queue-shows-proposer", (await proposer.innerText()).includes(process.env.DEMO_EMAIL), await proposer.innerText());

  // Bug 7 (queue): a PSBT that disagrees with the server's summary disables both hardware buttons.
  await page.route(`**/api/proposals/${pid}`, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    const res = await route.fetch();
    const j = await res.json();
    j.fee_sats += 1;
    await route.fulfill({ response: res, json: j });
  });
  await page.goto(`${W}/transactions?open=${pid}`);
  await page.getByTestId("mismatch").waitFor({ timeout: 20000 });
  const qTrezor = page.getByTestId(`tx-${pid}`).getByRole("button", { name: "Sign with Trezor" });
  const qLedger = page.getByTestId(`tx-${pid}`).getByRole("button", { name: "Sign with Ledger" });
  ok("7-queue-gated-on-mismatch", (await qTrezor.isDisabled()) && (await qLedger.isDisabled()));
  await page.unroute(`**/api/proposals/${pid}`);

  // Bugs 3 + 4: a Caravan file pasted into "Paste all owners" moves to Import with its name.
  const caravan = readFileSync(CARAVAN, "utf8");
  const fileName = JSON.parse(caravan).name;
  await page.goto(WEB + "/new");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByText("Paste all owners as JSON").click();
  await page.getByLabel("Owners JSON").fill(caravan);
  await page.getByRole("button", { name: "Fill owners" }).click();
  const notice = await page.getByTestId("import-notice").innerText({ timeout: 5000 });
  ok("3-paste-switches-to-import", /Caravan\/Sparrow JSON wallet file/.test(notice) && (await page.getByTestId("import-data").inputValue()) === caravan, notice);
  ok("4-name-prefilled", (await page.getByTestId("import-name").inputValue()) === fileName, await page.getByTestId("import-name").inputValue());
  await page.screenshot({ path: SHOTS + "fix8-import-switch.png", fullPage: true });

  // Bug 5: file upload fills the box (and the name, from this file).
  const tmp = "/tmp/fix8-upload.json";
  writeFileSync(tmp, JSON.stringify({ ...JSON.parse(caravan), name: "Uploaded via file picker" }, null, 2));
  await page.goto(WEB + "/new?mode=import");
  await page.getByTestId("import-file").setInputFiles(tmp);
  await page.getByTestId("import-notice").waitFor();
  ok(
    "5-file-upload-fills-import",
    (await page.getByTestId("import-data").inputValue()).includes("Uploaded via file picker") && (await page.getByTestId("import-name").inputValue()) === "Uploaded via file picker",
    await page.getByTestId("import-notice").innerText(),
  );
} finally {
  if (Number.isFinite(pid) && pid) {
    const d = await call("DELETE", `/proposals/${pid}`);
    console.log("cleanup: delete proposal", pid, d.status);
  }
  const q = (await call("GET", `/wallets/${wallet.id}`)).body;
  console.log("demo wallet queue after:", q.queue_count);
  await browser.close();
  console.log(JSON.stringify(results));
}
