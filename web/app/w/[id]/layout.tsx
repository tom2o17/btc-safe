"use client";

import { use } from "react";
import { PriceProvider } from "@/components/price";
import { Sidebar, TopBar } from "@/components/shell";
import { ErrorBox } from "@/components/ui";
import { WalletProvider, useWalletMaybe } from "@/components/wallet-context";

function Gate({ children }: { children: React.ReactNode }) {
  const ctx = useWalletMaybe();
  if (ctx?.error && !ctx.wallet) return <ErrorBox error={ctx.error} />;
  if (!ctx?.wallet) return <div className="muted">Loading account…</div>;
  return <>{children}</>;
}

export default function WalletLayout({ children, params }: { children: React.ReactNode; params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <WalletProvider id={id}>
      <PriceProvider>
      <TopBar />
      <Sidebar />
      <main className="main">
        <Gate>{children}</Gate>
      </main>
      </PriceProvider>
    </WalletProvider>
  );
}
