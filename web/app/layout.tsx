import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";
import { AuthGate } from "@/components/auth";
import { ThemeSync } from "@/components/theme";
import { THEME_INIT_SCRIPT } from "@/lib/theme";

export const metadata: Metadata = {
  title: "BTC Safe",
  description: "Self-hosted Bitcoin multisig coordinator",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // proxy.ts puts a per-request nonce in the CSP; the inline theme script must carry it.
  // Reading headers() also makes every page dynamic, which per-request nonces need.
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    // data-theme is set by the inline script before hydration, so React must not fight it.
    <html lang="en" suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body>
        <ThemeSync />
        <AuthGate>{children}</AuthGate>
      </body>
    </html>
  );
}
