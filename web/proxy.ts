// Next 16 Proxy (formerly middleware): a fresh CSP nonce per page request. Next reads the nonce
// back out of the request's Content-Security-Policy header while rendering and stamps it on its
// own scripts; app/layout.tsx reads x-nonce for the inline theme script. Using headers() there
// makes every page dynamic, which nonces require.
import { NextResponse, type NextRequest } from "next/server";
import { buildCsp, makeNonce } from "@/lib/csp";

export function proxy(request: NextRequest) {
  const nonce = makeNonce();
  const csp = buildCsp({ nonce, dev: process.env.NODE_ENV === "development" });
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    // Pages only: /api goes to the Rust API (JSON, no scripts), static assets need no CSP,
    // and router prefetches aren't documents.
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico|icon.svg).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
