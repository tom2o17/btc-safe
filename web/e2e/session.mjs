// Dev login for the e2e scripts. reset-dev.sh creates this admin account
// (COOKIE_SECURE=false, local http only).
export const DEV_EMAIL = process.env.DEV_EMAIL ?? "dev@btcsafe.local";
export const DEV_PASSWORD = process.env.DEV_PASSWORD ?? "devpassword-123";

/** Log in against the API directly; returns headers carrying the session cookie and CSRF token. */
export async function devAuth(api) {
  const r = await fetch(`${api}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: DEV_EMAIL, password: DEV_PASSWORD }),
  });
  if (!r.ok) throw new Error(`dev login failed: ${r.status} ${await r.text()} (run e2e/reset-dev.sh)`);
  const cookie = r.headers.get("set-cookie").split(";")[0];
  const { csrf_token } = await r.json();
  return { cookie, "x-csrf-token": csrf_token };
}

/** Log in through the web UI. */
export async function browserLogin(page, web) {
  await page.goto(`${web}/login`);
  await page.getByLabel("Email").fill(DEV_EMAIL);
  await page.getByLabel("Password").fill(DEV_PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
}
