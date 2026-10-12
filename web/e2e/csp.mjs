// CSP / security-header check in a real browser (system Chrome via playwright-core).
//
// Full run (needs e2e/reset-dev.sh and the web app, ideally `npm run build && npm start` so the
// production policy is the one tested; `npm run dev` adds 'unsafe-eval'):
//   node e2e/csp.mjs
// API-less run (stubs /api/* in the browser; covers /login, /signup, /account, /new + Trezor):
//   MOCK_API=1 node e2e/csp.mjs
//
// Asserts on every page: a Content-Security-Policy header with a fresh nonce, the inline theme
// script carries that nonce, zero `securitypolicyviolation` events and zero CSP console errors.
// Also: navigator.hid exists (Permissions-Policy hid=(self)), /api/price isn't blocked, and the
// Trezor Connect path (WebSocket to Suite desktop, then the Suite Web iframe + popup) runs
// without a CSP violation. No device is needed: the flow is abandoned once the iframe exists.
import { chromium } from "playwright-core";
import { execFileSync } from "node:child_process";
import path from "node:path";

const WEB = process.env.WEB ?? "http://localhost:3000";
const API = process.env.API ?? "http://127.0.0.1:8080";
const MOCK = process.env.MOCK_API === "1";
const log = (...a) => console.log("•", ...a);
const fail = (m) => {
  throw new Error(m);
};

const browser = await chromium.launch({ channel: "chrome", headless: true });
const ctx = await browser.newContext();
// Runs before any page script and isn't subject to the page's CSP.
await ctx.addInitScript(() => {
  window.__csp = [];
  document.addEventListener("securitypolicyviolation", (e) =>
    window.__csp.push(`${e.violatedDirective} blocked ${e.blockedURI || "inline"} (${e.sourceFile}:${e.lineNumber})`),
  );
});
const page = await ctx.newPage();
const consoleCsp = [];
const errors = [];
page.on("console", (m) => {
  const t = m.text();
  if (/content security policy|refused to (load|execute|connect|frame|apply)|permissions-policy/i.test(t)) consoleCsp.push(t.slice(0, 300));
});
page.on("pageerror", (e) => errors.push(String(e).slice(0, 200)));
page.on("popup", (p) => log("popup opened:", p.url() || "(about:blank)"));

if (MOCK) {
  const me = { email: "csp@btcsafe.local", is_admin: false, csrf_token: "x", totp_enabled: false, recovery_codes_left: 0, session_expires_at: new Date(Date.now() + 864e5).toISOString(), idle_timeout_secs: 7200 };
  const stubs = {
    "/api/auth/me": me,
    "/api/auth/signup": { open: true, min_password: 12, pow: { challenge: "mock", bits: 8 } },
    "/api/health": { ok: true, chain: "memory", tip: 1 },
    "/api/wallets": [],
    "/api/price": { usd: 60000 },
  };
  await page.route("**/api/**", (route) => {
    const p = new URL(route.request().url()).pathname;
    return route.fulfill({ status: p in stubs ? 200 : 404, json: stubs[p] ?? { error: "not_found", message: "stub" } });
  });
}

const seen = new Set();
async function check(url, ready) {
  const res = await page.goto(url);
  const csp = res.headers()["content-security-policy"] ?? fail(`${url}: no CSP header`);
  const nonce = csp.match(/'nonce-([^']+)'/)?.[1] ?? fail(`${url}: CSP has no nonce: ${csp}`);
  if (seen.has(nonce)) fail(`${url}: nonce reused`);
  seen.add(nonce);
  for (const d of ["default-src 'self'", "'strict-dynamic'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"]) if (!csp.includes(d)) fail(`${url}: CSP lacks ${d}`);
  if (/script-src[^;]*'unsafe-inline'/.test(csp)) fail(`${url}: script-src allows unsafe-inline`);
  if (ready) await ready();
  await page.waitForLoadState("networkidle").catch(() => undefined);
  const inline = await page.evaluate(() => [...document.querySelectorAll("script:not([src])")].filter((s) => s.textContent.trim()).map((s) => s.nonce));
  if (inline.some((n) => n !== nonce)) fail(`${url}: inline script without the nonce (${inline.length} inline)`);
  await assertClean(url);
  log(`${new URL(url).pathname}: CSP ok, nonce ${nonce.slice(0, 6)}…, ${inline.length} inline script(s) nonced, no violations`);
  return csp;
}
async function assertClean(where) {
  const v = await page.evaluate(() => window.__csp);
  if (v.length) fail(`${where}: CSP violations: ${v.join(" | ")}`);
  if (consoleCsp.length) fail(`${where}: CSP console errors: ${consoleCsp.join(" | ")}`);
}

try {
  const csp = await check(`${WEB}/login`, () => page.getByRole("heading", { name: "Log in" }).waitFor());
  log("CSP:", csp.replace(/'nonce-[^']+'/, "'nonce-…'"));
  const prod = !csp.includes("'unsafe-eval'");
  log(prod ? "production policy (no unsafe-eval)" : "dev policy ('unsafe-eval' present: run against `next start` to test production)");
  const heads = (await page.request.get(`${WEB}/login`)).headers();
  for (const [k, v] of [
    ["x-frame-options", "DENY"],
    ["x-content-type-options", "nosniff"],
    ["referrer-policy", "no-referrer"],
    ["cross-origin-opener-policy", "same-origin-allow-popups"],
  ])
    if (heads[k] !== v) fail(`${k}: ${heads[k]}`);
  if (!/hid=\(self\)/.test(heads["permissions-policy"] ?? "") || !/camera=\(\)/.test(heads["permissions-policy"])) fail(`permissions-policy: ${heads["permissions-policy"]}`);
  if (prod && !heads["strict-transport-security"]?.includes("max-age=63072000")) fail("no HSTS in production");
  log("security headers ok");

  await check(`${WEB}/signup`, () => page.getByRole("heading", { name: "Create an account" }).waitFor());
  if (!(await page.evaluate(() => "hid" in navigator && !!navigator.hid))) fail("navigator.hid missing");
  log("navigator.hid present");

  let wid = null;
  if (!MOCK) {
    const { browserLogin, devAuth } = await import("./session.mjs");
    const AUTH = await devAuth(API);
    const signer = path.resolve(import.meta.dirname, "../../target/debug/examples/testsigner");
    const owners = JSON.parse(execFileSync(signer, ["owners"]).toString());
    const r = await fetch(`${API}/wallets`, {
      method: "POST",
      headers: { ...AUTH, "content-type": "application/json" },
      body: JSON.stringify({ name: `csp-${Date.now()}`, network: "signet", threshold: 2, ordering_mode: "parallel", owners }),
    });
    if (!r.ok) fail(`create wallet: ${r.status} ${await r.text()}`);
    wid = (await r.json()).id;
    await browserLogin(page, WEB);
    await assertClean("login flow");
  }

  await check(`${WEB}/account`, () => page.getByRole("heading", { name: "Your account" }).waitFor());
  await check(`${WEB}/new`, () => page.getByRole("button", { name: "Next", exact: true }).waitFor());
  if (wid) {
    await check(`${WEB}/w/${wid}`, () => page.getByRole("heading", { name: "Overview" }).waitFor());
    await check(`${WEB}/w/${wid}/send`, () => page.getByLabel("Recipient 1").waitFor());
    await check(`${WEB}/w/${wid}/settings`, () => page.getByRole("heading", { name: "Settings" }).waitFor());
  }

  const price = await page.evaluate(() => fetch("/api/price", { cache: "no-store" }).then((r) => `HTTP ${r.status}`, (e) => `blocked: ${e}`));
  if (price.startsWith("blocked")) fail(`/api/price ${price}`);
  await assertClean("/api/price fetch");
  log("/api/price from the page:", price);

  // Trezor Connect: "auto" mode tries ws://127.0.0.1:21335 (Suite desktop; refused here), then
  // falls back to Suite Web: a hidden iframe + popup on https://suite.trezor.io.
  await page.goto(`${WEB}/new`);
  await page.getByRole("button", { name: "Next", exact: true }).click();
  const addTrezor = page.getByRole("button", { name: "Add from Trezor" }).first();
  await addTrezor.waitFor();
  await addTrezor.click();
  const frame = await page
    .waitForFunction(() => document.getElementById("trezor-connect-bootstrap")?.getAttribute("src") ?? null, null, { timeout: 20_000 })
    .then((h) => h.jsonValue(), () => null);
  await page.waitForTimeout(2_000); // let the iframe load (or get blocked)
  await assertClean("Trezor Connect init");
  if (frame) {
    if (!frame.startsWith("https://suite.trezor.io/")) fail(`Trezor iframe from an unexpected origin: ${frame}`);
    log("Trezor Connect: Suite Web iframe", frame.split("?")[0], "loaded with no CSP violation");
  } else {
    const shown = await page.locator(".alert").allInnerTexts();
    log("Trezor Connect: no Suite Web iframe within 20 s (Suite desktop running, or offline?); no CSP violation. UI:", shown.join(" | ").slice(0, 200));
  }

  console.log(`RESULT: csp e2e OK (${MOCK ? "mock API" : "live API"}); page errors: ${errors.length ? errors.join(" | ") : "none"}`);
} catch (e) {
  console.log("FAILED:", String(e.message).split("\n")[0], "| page errors:", errors.join(" | ") || "none");
  process.exitCode = 1;
} finally {
  await browser.close();
}
