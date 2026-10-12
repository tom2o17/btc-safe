// Content-Security-Policy and the other response security headers, as pure functions so the unit
// test (test/csp.test.mjs) can pin every directive. proxy.ts calls these on every page request.
// Kept import-free: node:test loads this file directly.

/**
 * Trezor Connect 10 (@trezor/connect-web 10.0.1, see lib/signers/trezor.ts) has no iframe of its
 * own on connect.trezor.io any more. In "auto" core mode it first opens a WebSocket to Trezor Suite
 * desktop on ws://127.0.0.1:21335/connect-ws (impl/core-in-suite-desktop.js), and on
 * Desktop_ConnectionMissing falls back to Suite Web: a hidden bootstrap iframe plus a popup, both
 * https://suite.trezor.io/web/connect-popup/bootstrap.html (impl/getSuiteWebUrl.js, popup/web.js).
 * The popup is a window.open, which CSP doesn't govern; the iframe needs frame-src.
 */
export const TREZOR_SUITE_WEB = "https://suite.trezor.io";
export const TREZOR_SUITE_DESKTOP_WS = "ws://127.0.0.1:21335";

export type CspOptions = { nonce: string; dev: boolean };

export function cspDirectives({ nonce, dev }: CspOptions): [string, string[]][] {
  if (!/^[A-Za-z0-9+/=_-]{16,}$/.test(nonce)) throw new Error("CSP nonce must be at least 16 base64 characters");
  return [
    ["default-src", ["'self'"]],
    // 'strict-dynamic': scripts loaded by a nonced script (Next's chunk loader, the dynamic
    // import of Trezor Connect) are trusted; host allowlists and 'self' are then ignored by
    // CSP3 browsers. React needs eval only in development (error stack reconstruction).
    ["script-src", ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'", ...(dev ? ["'unsafe-eval'"] : [])]],
    // 'unsafe-inline' for styles: the server-rendered HTML carries React style={{…}} attributes
    // (and the identicon/QR placeholders) that a nonce can't cover; style attributes can't run
    // script. A style nonce would also switch 'unsafe-inline' off, so none is listed here.
    ["style-src", ["'self'", "'unsafe-inline'"]],
    ["img-src", ["'self'", "data:", "blob:"]], // QR codes are data: URLs
    ["font-src", ["'self'"]],
    // 'self' covers /api (proxied to the Rust API) and, in CSP3, same-origin ws: for dev HMR.
    // upgrade-insecure-requests does not rewrite ws://127.0.0.1 (a potentially trustworthy origin).
    ["connect-src", ["'self'", TREZOR_SUITE_DESKTOP_WS]],
    ["frame-src", [TREZOR_SUITE_WEB]],
    ["worker-src", ["'self'", "blob:"]],
    ["object-src", ["'none'"]],
    ["base-uri", ["'none'"]],
    ["form-action", ["'self'"]],
    ["frame-ancestors", ["'none'"]],
    ...(dev ? [] : ([["upgrade-insecure-requests", []]] as [string, string[]][])),
  ];
}

export function buildCsp(opts: CspOptions): string {
  return cspDirectives(opts)
    .map(([k, v]) => (v.length ? `${k} ${v.join(" ")}` : k))
    .join("; ");
}

/** 128 random bits, base64. */
export function makeNonce(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b));
}

// Ledger signs over WebHID; nothing here uses the camera, mic or location.
export const PERMISSIONS_POLICY = [
  "hid=(self)",
  "usb=(self)",
  "camera=()",
  "microphone=()",
  "geolocation=()",
  "payment=()",
  "serial=()",
  "bluetooth=()",
  "midi=()",
  "magnetometer=()",
  "gyroscope=()",
  "accelerometer=()",
  "display-capture=()",
  "browsing-topics=()",
].join(", ");

/** Headers for every response (pages and static files). CSP is added per page by proxy.ts. */
export function securityHeaders(prod: boolean): { key: string; value: string }[] {
  return [
    { key: "X-Frame-Options", value: "DENY" },
    { key: "X-Content-Type-Options", value: "nosniff" },
    // Setup links carry a one-time token; never leak URLs to other origins.
    { key: "Referrer-Policy", value: "no-referrer" },
    { key: "Permissions-Policy", value: PERMISSIONS_POLICY },
    // Not plain same-origin: the Trezor Suite Web popup must keep window.opener/postMessage.
    { key: "Cross-Origin-Opener-Policy", value: "same-origin-allow-popups" },
    ...(prod ? [{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" }] : []),
  ];
}
