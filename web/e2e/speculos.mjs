// Speculos helpers for the Ledger e2e: Ledger's node transport (CJS; its ESM build doesn't
// load in node) plus the REST API for reading the screen and pressing buttons.
import { createRequire } from "node:module";
const SpeculosTransport = createRequire(import.meta.url)("@ledgerhq/hw-transport-node-speculos").default;

export const API = process.env.SPECULOS_API ?? "http://127.0.0.1:5000";
export const APDU_PORT = Number(process.env.SPECULOS_APDU_PORT ?? 9999);

export const openTransport = () => SpeculosTransport.open({ apduPort: APDU_PORT });

export async function screen() {
  const r = await fetch(`${API}/events?currentscreenonly=true`);
  const j = await r.json();
  return (j.events ?? []).map((e) => e.text).join(" | ");
}

export async function press(button) {
  await fetch(`${API}/button/${button}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "press-and-release" }) });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Walk the device's review screens while `pending` runs: press right until a screen matches
 * `target`, then press both. Returns the screens seen, so tests can assert on what the user
 * would have been shown.
 */
export async function drive(pending, target, { max = 60 } = {}) {
  const seen = [];
  let done = false;
  pending = Promise.resolve(pending);
  pending.then(() => (done = true), () => (done = true));
  await sleep(300);
  for (let i = 0; i < max && !done; i++) {
    const s = await screen();
    if (s && seen[seen.length - 1] !== s) seen.push(s);
    if (target.test(s)) {
      await press("both");
      await sleep(400);
      continue;
    }
    await press("right");
    await sleep(150);
  }
  // Out of presses: wait for the outcome; the caller awaits `pending` itself for the result.
  await Promise.allSettled([pending]);
  return seen;
}
