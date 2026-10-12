import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { loadPref, parsePref, resolveTheme, savePref, THEME_INIT_SCRIPT, THEME_KEY } from "../lib/theme.ts";

function memStorage(init = {}) {
  const m = new Map(Object.entries(init));
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => void m.set(k, String(v)),
    removeItem: (k) => void m.delete(k),
    map: m,
  };
}

test("resolveTheme: system follows the OS, light/dark override it", () => {
  assert.equal(resolveTheme("system", false), "light");
  assert.equal(resolveTheme("system", true), "dark");
  assert.equal(resolveTheme("light", true), "light");
  assert.equal(resolveTheme("dark", false), "dark");
});

test("parsePref: unknown values fall back to system", () => {
  assert.equal(parsePref("dark"), "dark");
  assert.equal(parsePref("light"), "light");
  for (const v of [null, undefined, "", "system", "DARK", "auto"]) assert.equal(parsePref(v), "system");
});

test("persistence round-trips; system is stored as absence", () => {
  const s = memStorage();
  assert.equal(loadPref(s), "system");
  savePref(s, "dark");
  assert.equal(s.map.get(THEME_KEY), "dark");
  assert.equal(loadPref(s), "dark");
  savePref(s, "light");
  assert.equal(loadPref(s), "light");
  savePref(s, "system");
  assert.equal(s.map.has(THEME_KEY), false);
  assert.equal(loadPref(s), "system");
});

test("blocked storage degrades to system without throwing", () => {
  const boom = { getItem() { throw new Error("denied"); }, setItem() { throw new Error("denied"); }, removeItem() { throw new Error("denied"); } };
  assert.equal(loadPref(boom), "system");
  assert.doesNotThrow(() => savePref(boom, "dark"));
  assert.equal(loadPref(null), "system");
});

function runInit(stored, systemDark, { throwStorage = false } = {}) {
  const attrs = {};
  const ctx = {
    localStorage: throwStorage ? { getItem() { throw new Error("denied"); } } : memStorage(stored == null ? {} : { [THEME_KEY]: stored }),
    window: { matchMedia: (q) => ({ matches: q === "(prefers-color-scheme: dark)" && systemDark }) },
    document: { documentElement: { setAttribute: (k, v) => (attrs[k] = v) } },
  };
  vm.runInNewContext(THEME_INIT_SCRIPT, ctx);
  return attrs["data-theme"];
}

test("the pre-hydration script agrees with resolveTheme for every case", () => {
  for (const stored of [null, "light", "dark", "garbage"])
    for (const sys of [false, true])
      assert.equal(runInit(stored, sys), resolveTheme(parsePref(stored), sys), `stored=${stored} sys=${sys}`);
  assert.equal(runInit(null, true, { throwStorage: true }), "light"); // never leaves data-theme unset
});

// ---- WCAG AA contrast on the actual palettes in globals.css ----

const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
function block(selector) {
  const i = css.indexOf(selector + " {");
  assert.ok(i >= 0, selector);
  const body = css.slice(i, css.indexOf("}", i));
  return Object.fromEntries([...body.matchAll(/--([\w-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1], m[2]]));
}
const light = block(":root");
const dark = { ...light, ...block(':root[data-theme="dark"]') };

function lum(hex) {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function ratio(a, b) {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

// [text token, background token]: every text-on-surface pairing the stylesheet uses.
const PAIRS = [
  ["text", "bg"], ["text", "paper"], ["text", "paper-2"], ["muted", "bg"], ["muted", "paper"], ["muted", "paper-2"],
  ["faint", "paper"], ["link", "paper"], ["on-primary", "primary"], ["on-accent", "accent"], ["text", "accent-soft"],
  ["warn", "accent-soft"], ["on-ok", "ok"], ["err", "paper"],
  ["ok", "ok-soft"], ["warn", "warn-soft"], ["err", "err-soft"], // tags / status chips
  ["ok-ink", "ok-soft"], ["warn-ink", "warn-soft"], ["err-ink", "err-soft"], ["info-ink", "info-soft"], // alerts, mismatch banner
];

for (const [name, pal] of [["light", light], ["dark", dark]]) {
  test(`${name} palette meets WCAG AA (4.5:1) for text`, () => {
    const bad = PAIRS.filter(([t, b]) => ratio(pal[t], pal[b]) < 4.5).map(([t, b]) => `${t}/${b} ${ratio(pal[t], pal[b]).toFixed(2)}`);
    assert.deepEqual(bad, []);
  });
}

test("the QR box pins dark-on-white in both themes", () => {
  const rule = css.slice(css.indexOf(".qrbox {"), css.indexOf("}", css.indexOf(".qrbox {")));
  assert.match(rule, /background: #fff;/);
  const txt = rule.match(/--text: (#[0-9a-f]{6})/i)[1];
  const muted = rule.match(/--muted: (#[0-9a-f]{6})/i)[1];
  assert.ok(ratio(txt, "#ffffff") >= 4.5 && ratio(muted, "#ffffff") >= 4.5);
});
