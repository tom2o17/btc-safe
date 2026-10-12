// Per-wallet roles in a real browser (system Chrome via playwright-core).
// Needs: e2e/reset-dev.sh (API on :8080, CHAIN=memory, dev admin), `npm run dev` on :3000, and
// the testsigner example (cargo build -p btc-safe-testkit --example testsigner).
//
//   node e2e/roles.mjs
//
// The dev admin creates a wallet, shares it with a viewer and a proposer through the Sharing tab,
// then: the viewer gets no send form, no sign/execute/delete buttons, no address-book editing and
// no member management, and a hand-made API POST from the viewer's browser gets 403; the proposer
// can open the send form, execute, and delete only their own proposal; the admin changes a role;
// demoting the last admin is refused with the 409 message.
import { browserLogin, devAuth, DEV_EMAIL } from "./session.mjs";
import { chromium } from "playwright-core";
import { execFileSync } from "node:child_process";
import path from "node:path";

const WEB = process.env.WEB ?? "http://localhost:3000";
const API = process.env.API ?? "http://127.0.0.1:8080";
const SIGNER = path.resolve(import.meta.dirname, "../../target/debug/examples/testsigner");
const PASSWORD = "role test password 1234";
const log = (...a) => console.log("•", ...a);
const fail = (m) => {
  throw new Error(m);
};

async function call(auth, method, p, body) {
  const r = await fetch(`${API}${p}`, {
    method,
    headers: { ...auth, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  if (!r.ok) fail(`${method} ${p}: ${r.status} ${text}`);
  return text ? JSON.parse(text) : undefined;
}

/** Create a user through an admin invite (works whether or not open signup is on). */
async function makeUser(admin, email) {
  const { setup_path } = await call(admin, "POST", "/auth/invites", { email, admin: false });
  const token = new URL(setup_path, "http://x").searchParams.get("token");
  await call({}, "POST", "/auth/setup", { token, password: PASSWORD });
}

async function apiLogin(email) {
  const r = await fetch(`${API}/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password: PASSWORD }) });
  if (!r.ok) fail(`login ${email}: ${r.status}`);
  const { csrf_token } = await r.json();
  return { cookie: r.headers.get("set-cookie").split(";")[0], "x-csrf-token": csrf_token };
}

async function uiLogin(page, email) {
  await page.goto(`${WEB}/login`);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
}

const browser = await chromium.launch({ channel: "chrome", headless: true });
const errors = [];
async function newPage() {
  const p = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  p.on("pageerror", (e) => errors.push(String(e).slice(0, 200)));
  p.on("dialog", (d) => void d.accept());
  return p;
}
const none = async (loc, what) => {
  if ((await loc.count()) !== 0) fail(`should not be offered: ${what}`);
};

try {
  const ADMIN = await devAuth(API);
  const stamp = Date.now();
  const viewer = `viewer-${stamp}@example.test`;
  const proposer = `proposer-${stamp}@example.test`;
  await makeUser(ADMIN, viewer);
  await makeUser(ADMIN, proposer);
  log("users:", viewer, proposer);

  // Wallet + funds + one proposal by the admin.
  const owners = JSON.parse(execFileSync(SIGNER, ["owners"]).toString());
  const w = await call(ADMIN, "POST", "/wallets", { name: `roles-${stamp}`, network: "signet", threshold: 2, ordering_mode: "parallel", owners });
  const W = `${WEB}/w/${w.id}`;
  const recv = await call(ADMIN, "GET", `/wallets/${w.id}/addresses?kind=receive`);
  await call(ADMIN, "POST", "/dev/fund", { address: recv.address, amount_sats: 300_000 });
  await call(ADMIN, "POST", "/dev/fund", { address: recv.address, amount_sats: 200_000 });
  await call(ADMIN, "POST", "/dev/mine", {});
  await call(ADMIN, "POST", `/wallets/${w.id}/sync`, {});
  const out = { address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", amount_sats: 10_000 };
  const adminProp = await call(ADMIN, "POST", `/wallets/${w.id}/proposals`, { outputs: [out], fee_rate_sat_vb: 2, rbf: true });
  log("wallet", w.id, "funded; admin proposal #" + adminProp.id);

  // Admin shares through the UI.
  const admin = await newPage();
  await browserLogin(admin, WEB);
  await admin.goto(`${W}/settings`);
  await admin.getByRole("button", { name: "Sharing" }).click();
  for (const [email, role] of [
    [viewer, "viewer"],
    [proposer, "proposer"],
  ]) {
    await admin.getByLabel("Share with (email)").fill(email);
    await admin.getByLabel("Role", { exact: true }).selectOption(role);
    await admin.getByRole("button", { name: "Share", exact: true }).click();
    await admin.getByTestId(`member-${email}`).waitFor();
  }
  const members = await call(ADMIN, "GET", `/wallets/${w.id}/members`);
  const roleOf = (ms, e) => ms.find((m) => m.email === e)?.role;
  if (roleOf(members, viewer) !== "viewer" || roleOf(members, proposer) !== "proposer") fail(`members after sharing: ${JSON.stringify(members)}`);
  // Invited accounts: no confirmation, not flagged.
  if (members.some((m) => m.self_signup)) fail(`invited members flagged self_signup: ${JSON.stringify(members)}`);
  log("shared: viewer + proposer");

  // A self-registered account (signed up in its own browser): sharing asks for confirmation
  // because nobody verified the email, and the list flags it.
  const selfie = `selfie-${stamp}@example.test`;
  const sp = await newPage();
  await sp.goto(`${WEB}/signup`);
  await sp.getByLabel("Email").fill(selfie);
  await sp.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await sp.getByLabel("Repeat password").fill(PASSWORD);
  await sp.getByRole("button", { name: "Create account" }).click();
  await sp.waitForURL((u) => !u.pathname.startsWith("/signup"), { timeout: 60_000 });
  const dialogs = [];
  admin.on("dialog", (d) => dialogs.push(d.message()));
  await admin.getByLabel("Share with (email)").fill(selfie);
  await admin.getByLabel("Role", { exact: true }).selectOption("viewer");
  await admin.getByRole("button", { name: "Share", exact: true }).click();
  await admin.getByTestId(`member-${selfie}`).getByText("self-registered").waitFor();
  if (!dialogs.some((m) => m.includes("never verified"))) fail(`no unverified-account confirmation: ${JSON.stringify(dialogs)}`);
  log("self-registered account: confirmation asked, shared, flagged");

  // Proposer's own proposal (through the API with their session).
  const PROP = await apiLogin(proposer);
  const ownProp = await call(PROP, "POST", `/wallets/${w.id}/proposals`, { outputs: [{ ...out, amount_sats: 12_000 }], fee_rate_sat_vb: 2, rbf: true });

  // ---- Viewer ----
  const v = await newPage();
  await uiLogin(v, viewer);
  await v.goto(W);
  await v.getByRole("heading", { name: "Overview" }).waitFor();
  await none(v.getByRole("link", { name: "New transaction" }), "viewer: New transaction link");
  await v.goto(`${W}/send`);
  await v.getByText("Your role is viewer: you can't propose").waitFor();
  await none(v.getByLabel("Recipient 1"), "viewer: send form");
  await v.goto(`${W}/transactions?open=${adminProp.id}`);
  const vrow = v.getByTestId(`tx-${adminProp.id}`);
  await vrow.getByText("View only").waitFor();
  for (const b of ["Delete", "Execute", "Sign with Ledger", "Sign with Trezor", "⇪ Upload signed PSBT"]) await none(vrow.getByRole("button", { name: b, exact: true }), `viewer: ${b}`);
  await v.goto(`${W}/receive`);
  await v.getByText("bitcoin:").first().waitFor();
  await none(v.getByRole("button", { name: "New address" }), "viewer: new address");
  await v.goto(`${W}/address-book`);
  await v.getByRole("heading", { name: "Address book" }).waitFor();
  await none(v.getByLabel("Entry name"), "viewer: address book form");
  await v.goto(`${W}/settings`);
  await v.getByRole("button", { name: "Sharing" }).click();
  await v.getByTestId(`member-${viewer}`).waitFor();
  await none(v.getByLabel("Share with (email)"), "viewer: share form");
  await none(v.getByLabel(`Role of ${proposer}`), "viewer: role select");
  await none(v.getByTestId("members").getByRole("button", { name: "Remove" }), "viewer: remove member");
  const forced = await v.evaluate(async (wid) => {
    const me = await (await fetch("/api/auth/me")).json();
    const r = await fetch(`/api/wallets/${wid}/proposals`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": me.csrf_token },
      body: JSON.stringify({ outputs: [{ address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", amount_sats: 5000 }], fee_rate_sat_vb: 2, rbf: true }),
    });
    return { status: r.status, body: await r.text() };
  }, w.id);
  if (forced.status !== 403 || !forced.body.includes("forbidden")) fail(`viewer forced POST: ${forced.status} ${forced.body}`);
  log("viewer: no send form / sign / execute / delete / address book / sharing; forced POST → 403 forbidden");

  // ---- Proposer ----
  const p = await newPage();
  await uiLogin(p, proposer);
  await p.goto(`${W}/send`);
  await p.getByLabel("Recipient 1").waitFor();
  await p.goto(`${W}/transactions?open=${adminProp.id}`);
  const prow = p.getByTestId(`tx-${adminProp.id}`);
  await prow.getByRole("button", { name: "Execute", exact: true }).waitFor();
  await none(prow.getByRole("button", { name: "Delete", exact: true }), "proposer: Delete on the admin's proposal");
  await p.goto(`${W}/transactions?open=${ownProp.id}`);
  await p.getByTestId(`tx-${ownProp.id}`).getByRole("button", { name: "Delete", exact: true }).waitFor();
  await p.goto(`${W}/settings`);
  if (!(await p.getByLabel("Ordering mode").isDisabled())) fail("proposer: ordering mode should be disabled");
  log("proposer: send form, Execute, Delete only on own proposal, settings read-only");

  // ---- Admin changes a role ----
  await admin.goto(`${W}/settings`);
  await admin.getByRole("button", { name: "Sharing" }).click();
  await admin.getByLabel(`Role of ${proposer}`).selectOption("viewer");
  await admin.waitForFunction(
    async ([wid, email]) => (await (await fetch(`/api/wallets/${wid}/members`)).json()).find((m) => m.email === email)?.role === "viewer",
    [w.id, proposer],
  );
  await p.goto(`${W}/send`);
  await p.getByText("Your role is viewer: you can't propose").waitFor();
  log("admin demoted the proposer to viewer; their send page now refuses");

  // ---- Last admin ----
  await admin.getByLabel(`Role of ${DEV_EMAIL}`).selectOption("proposer");
  await admin.getByText("An account needs at least one admin").waitFor();
  if (roleOf(await call(ADMIN, "GET", `/wallets/${w.id}/members`), DEV_EMAIL) !== "admin") fail("last admin was demoted");
  if ((await admin.getByLabel(`Role of ${DEV_EMAIL}`).inputValue()) !== "admin") fail("role select didn't snap back to admin");
  log("demoting the last admin refused (409 last_admin) and shown");

  console.log(`RESULT: roles e2e OK; page errors: ${errors.length ? errors.join(" | ") : "none"}`);
} catch (e) {
  console.log("FAILED:", String(e.message).split("\n")[0], "| page errors:", errors.join(" | ") || "none");
  process.exitCode = 1;
} finally {
  await browser.close();
}
