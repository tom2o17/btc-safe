import { test } from "node:test";
import assert from "node:assert/strict";
import { buildCsp, cspDirectives, makeNonce, PERMISSIONS_POLICY, securityHeaders } from "../lib/csp.ts";

const NONCE = "AAAAAAAAAAAAAAAAAAAAAA==";
const parse = (csp) => new Map(csp.split("; ").map((d) => { const [k, ...v] = d.split(" "); return [k, v]; }));

test("production CSP: every directive pinned", () => {
  const d = parse(buildCsp({ nonce: NONCE, dev: false }));
  assert.deepEqual(Object.fromEntries(d), {
    "default-src": ["'self'"],
    "script-src": ["'self'", `'nonce-${NONCE}'`, "'strict-dynamic'"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'"],
    "connect-src": ["'self'", "ws://127.0.0.1:21335"],
    "frame-src": ["https://suite.trezor.io"],
    "worker-src": ["'self'", "blob:"],
    "object-src": ["'none'"],
    "base-uri": ["'none'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
    "upgrade-insecure-requests": [],
  });
});

test("no unsafe-inline or unsafe-eval for scripts in production; no wildcards anywhere", () => {
  const csp = buildCsp({ nonce: NONCE, dev: false });
  const script = parse(csp).get("script-src");
  assert.ok(!script.includes("'unsafe-inline'") && !script.includes("'unsafe-eval'"));
  assert.ok(!/(^|\s)\*|https:(\s|;|$)|http:(\s|;|$)/.test(csp), csp);
});

test("dev adds only unsafe-eval and drops upgrade-insecure-requests", () => {
  const prod = parse(buildCsp({ nonce: NONCE, dev: false }));
  const dev = parse(buildCsp({ nonce: NONCE, dev: true }));
  assert.deepEqual(dev.get("script-src"), [...prod.get("script-src"), "'unsafe-eval'"]);
  assert.equal(dev.has("upgrade-insecure-requests"), false);
  for (const [k, v] of prod) if (k !== "script-src" && k !== "upgrade-insecure-requests") assert.deepEqual(dev.get(k), v, k);
});

test("nonce: fresh, 128-bit, and rejected when malformed", () => {
  const a = makeNonce();
  const b = makeNonce();
  assert.notEqual(a, b);
  assert.equal(Buffer.from(a, "base64").length, 16);
  assert.match(buildCsp({ nonce: a, dev: false }), new RegExp(`'nonce-${a.replace(/[+/=]/g, "\\$&")}'`));
  for (const bad of ["", "short", "abc'; script-src *", "x".repeat(15)]) assert.throws(() => cspDirectives({ nonce: bad, dev: false }));
});

test("security headers: HSTS only in production; COOP keeps popups; permissions locked down", () => {
  const prod = Object.fromEntries(securityHeaders(true).map((h) => [h.key, h.value]));
  const dev = Object.fromEntries(securityHeaders(false).map((h) => [h.key, h.value]));
  assert.equal(prod["Strict-Transport-Security"], "max-age=63072000; includeSubDomains");
  assert.equal(dev["Strict-Transport-Security"], undefined);
  for (const h of [prod, dev]) {
    assert.equal(h["X-Frame-Options"], "DENY");
    assert.equal(h["X-Content-Type-Options"], "nosniff");
    assert.equal(h["Referrer-Policy"], "no-referrer");
    assert.equal(h["Cross-Origin-Opener-Policy"], "same-origin-allow-popups");
    assert.equal(h["Permissions-Policy"], PERMISSIONS_POLICY);
  }
  const pp = new Map(PERMISSIONS_POLICY.split(", ").map((x) => x.split("=")));
  assert.equal(pp.get("hid"), "(self)");
  assert.equal(pp.get("usb"), "(self)");
  for (const [k, v] of pp) if (k !== "hid" && k !== "usb") assert.equal(v, "()", k);
  assert.equal(pp.get("camera"), "()");
});
