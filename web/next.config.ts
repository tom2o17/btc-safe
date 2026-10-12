import type { NextConfig } from "next";
import { securityHeaders } from "./lib/csp";

// The browser only talks to this origin; /api/* is proxied to the Rust API so it needs no CORS.
const API = process.env.BTC_SAFE_API ?? "http://127.0.0.1:8080";

const config: NextConfig = {
  reactStrictMode: true,
  agentRules: false,
  devIndicators: false,
  poweredByHeader: false,
  // Content-Security-Policy is per request (it carries a nonce): see proxy.ts.
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders(process.env.NODE_ENV === "production"),
      },
    ];
  },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API}/:path*` }];
  },
};

export default config;
