// Browser checks for login (needs e2e/reset-dev.sh, which starts the API with OPEN_SIGNUP=1, and
// `npm run dev`, or WEB=<deployed url> with DEV_EMAIL/DEV_PASSWORD of an admin and open signup):
// the guard redirects to /login, a wrong password is refused, an admin invite produces a setup
// link that sets a password and logs the invitee in, the invitee sees none of the admin's
// accounts, and logout ends the session.
// Then, on a fresh self-signup account (never the dev admin, so other scripts keep logging in
// without a second factor): signup lands logged in, a weak password is refused, TOTP enable ->
// logout -> login needs the code, a recovery code works once and only once, "Log out everywhere"
// ends another browser's session, and a password change does too.
import { browserLogin } from "./session.mjs";
import { freshTotp } from "./totp.mjs";
import { chromium } from "playwright-core";

const WEB = process.env.WEB ?? "http://localhost:3000";
const log = (...a) => console.log("•", ...a);
const browser = await chromium.launch({ channel: "chrome", headless: true });
const errors = [];
try {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(String(e)));

  await page.goto(`${WEB}/transactions?x=1`);
  await page.waitForURL(/\/login\?next=/);
  log("guard: redirected to", new URL(page.url()).pathname + new URL(page.url()).search);

  await page.getByLabel("Email").fill("dev@btcsafe.local");
  await page.getByLabel("Password").fill("not the password!");
  await page.getByRole("button", { name: "Log in" }).click();
  await page.getByText("bad email or password").waitFor();
  log("wrong password refused");

  await browserLogin(page, WEB);
  await page.getByText("Invite a user").waitFor();
  const invitee = `friend-${Date.now()}@example.test`;
  await page.getByLabel("Invite email").fill(invitee);
  await page.getByRole("button", { name: "Create setup link" }).click();
  const link = (await page.locator("code", { hasText: "/setup?token=" }).textContent()).trim();
  log("invite link created for", invitee);

  const ctx2 = await browser.newContext();
  const p2 = await ctx2.newPage();
  p2.on("pageerror", (e) => errors.push(String(e)));
  await p2.goto(link);
  await p2.getByText(invitee).waitFor();
  if (p2.url().includes("token=")) throw new Error("token left in the address bar");
  await p2.getByLabel("New password", { exact: true }).fill("friend password 1234");
  await p2.getByLabel("Repeat password").fill("friend password 1234");
  await p2.getByRole("button", { name: "Set password and log in" }).click();
  await p2.getByText("No accounts yet").waitFor();
  const cookies = await ctx2.cookies();
  const sess = cookies.find((c) => c.name.endsWith("bsid"));
  if (!sess || !sess.httpOnly || sess.sameSite !== "Strict") throw new Error(`bad session cookie ${JSON.stringify(sess)}`);
  log("invitee set a password, logged in, sees no accounts; cookie httpOnly+Strict, secure =", sess.secure);
  if (await p2.evaluate(() => document.cookie.includes("bsid"))) throw new Error("session cookie readable from JS");

  // The used link is dead.
  const p3 = await (await browser.newContext()).newPage();
  await p3.goto(link);
  await p3.getByText("invalid, used or expired").waitFor();
  log("setup link is single-use");

  await p2.getByRole("button", { name: "Log out", exact: true }).click();
  await p2.waitForURL(/\/login/);
  await p2.goto(`${WEB}/`);
  await p2.waitForURL(/\/login/);
  log("logout ends the session");

  // ---- Self-signup, TOTP, recovery codes, session revocation ----
  const fresh = async () => {
    const c = await browser.newContext({ acceptDownloads: true });
    const p = await c.newPage();
    p.on("pageerror", (e) => errors.push(String(e)));
    p.on("dialog", (d) => void d.accept());
    return p;
  };
  const user = `self-${Date.now()}@example.test`;
  let password = "correct horse battery staple 42";

  const s1 = await fresh();
  await s1.goto(`${WEB}/signup`);
  await s1.getByText("There is no email verification").waitFor();
  await s1.getByLabel("Email").fill(`weak-${Date.now()}@example.test`);
  await s1.getByLabel("Password", { exact: true }).fill("password1234");
  await s1.getByLabel("Repeat password").fill("password1234");
  await s1.getByRole("button", { name: "Create account" }).click();
  await s1.locator(".alert.err").waitFor({ timeout: 60_000 });
  log("weak password refused:", (await s1.locator(".alert.err").innerText()).slice(0, 120));
  if (!s1.url().includes("/signup")) throw new Error("weak password left the signup page");

  await s1.getByLabel("Email").fill(user);
  await s1.getByLabel("Password", { exact: true }).fill(password);
  await s1.getByLabel("Repeat password").fill(password);
  await s1.getByRole("button", { name: "Create account" }).click();
  await s1.getByText("No accounts yet").waitFor({ timeout: 60_000 });
  log("signup (with proof of work) created", user, "and landed logged in");

  // Enable TOTP from the account page.
  await s1.getByRole("link", { name: "Account", exact: true }).click();
  await s1.getByRole("heading", { name: "Your account" }).waitFor();
  await s1.getByTestId("session-expires").waitFor();
  log("session ends:", await s1.getByTestId("session-expires").innerText(), "| idle:", await s1.getByTestId("idle-timeout").innerText());
  await s1.getByRole("button", { name: "Set up two-factor" }).click();
  await s1.getByLabel("Confirm with your password").fill(password);
  await s1.getByRole("button", { name: "Continue" }).click();
  const secret = (await s1.getByTestId("totp-secret").innerText()).trim();
  const used = new Set();
  await s1.getByLabel("Authenticator code").fill(await freshTotp(secret, used));
  await s1.getByRole("button", { name: "Turn on two-factor" }).click();
  await s1.getByText("Save these now.").waitFor();
  const codes = (await s1.getByTestId("recovery-codes").locator("pre").innerText()).split(/\s+/).filter(Boolean);
  if (codes.length !== 10) throw new Error(`expected 10 recovery codes, got ${codes.length}`);
  await s1.getByTestId("recovery-left").getByText("10 recovery codes left").waitFor();
  log("TOTP enabled; 10 recovery codes shown once");

  /** Password step, then the second factor: a TOTP code, or a recovery code when given. */
  async function login(p, { recovery, pw = password } = {}) {
    await p.goto(`${WEB}/login`);
    await p.getByLabel("Email").fill(user);
    await p.getByLabel("Password").fill(pw);
    await p.getByRole("button", { name: "Log in" }).click();
    await p.getByLabel("Authenticator code").waitFor();
    if (recovery) {
      await p.getByRole("button", { name: "Use a recovery code instead" }).click();
      await p.getByLabel("Recovery code").fill(recovery);
    } else {
      await p.getByLabel("Authenticator code").fill(await freshTotp(secret, used));
    }
    await p.getByRole("button", { name: "Verify" }).click();
  }
  const loggedIn = (p) => p.waitForURL((u) => !u.pathname.startsWith("/login"));

  await s1.getByRole("button", { name: "Log out", exact: true }).click();
  await s1.waitForURL(/\/login/);
  await login(s1);
  await loggedIn(s1);
  log("login now asks for the authenticator code; TOTP accepted");

  await s1.getByRole("button", { name: "Log out", exact: true }).click();
  await s1.waitForURL(/\/login/);
  await login(s1, { recovery: codes[0] });
  await loggedIn(s1);
  await s1.goto(`${WEB}/account`);
  await s1.getByTestId("recovery-left").getByText("9 recovery codes left").waitFor();
  await s1.getByRole("button", { name: "Log out", exact: true }).click();
  await s1.waitForURL(/\/login/);
  await login(s1, { recovery: codes[0] });
  await s1.getByText("isn't valid").waitFor();
  log("recovery code works once, refused the second time");

  // "Log out everywhere" from one browser ends the other.
  await login(s1, { recovery: codes[1] });
  await loggedIn(s1);
  const s2 = await fresh();
  await login(s2, { recovery: codes[2] });
  await loggedIn(s2);
  await s1.goto(`${WEB}/account`);
  await s1.getByRole("button", { name: "Log out everywhere" }).click();
  await s1.waitForURL(/\/login/);
  await s2.goto(`${WEB}/`);
  await s2.waitForURL(/\/login/);
  log("log out everywhere ended the other browser's session too");

  // Password change keeps this session and ends the other one.
  await login(s1, { recovery: codes[3] });
  await loggedIn(s1);
  await login(s2, { recovery: codes[4] });
  await loggedIn(s2);
  const newPassword = "an even better passphrase 43";
  await s1.goto(`${WEB}/account`);
  await s1.getByLabel("Current password").fill(password);
  await s1.getByLabel("New password", { exact: true }).fill(newPassword);
  await s1.getByLabel("Repeat new password").fill(newPassword);
  await s1.getByRole("button", { name: "Change password" }).click();
  await s1.getByText("Password changed.").waitFor();
  await s1.goto(`${WEB}/`);
  await s1.getByText("No accounts yet").waitFor();
  await s2.goto(`${WEB}/`);
  await s2.waitForURL(/\/login/);
  password = newPassword;
  await s1.getByRole("button", { name: "Log out", exact: true }).click();
  await s1.waitForURL(/\/login/);
  await login(s1, { recovery: codes[5] });
  await loggedIn(s1);
  log("password change kept this session (rotated), ended the other, and the new password works");

  console.log(`RESULT: auth e2e OK; page errors: ${errors.length ? errors.join(" | ") : "none"}`);
} catch (e) {
  console.log("FAILED:", e.message.split("\n")[0], "| page errors:", errors.join(" | ") || "none");
  process.exitCode = 1;
} finally {
  await browser.close();
}
