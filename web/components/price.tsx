"use client";

// Mainnet BTC/USD from the API's /price (fetched server-side; the browser never calls a price
// API). Display only: nothing here may feed amounts, fees or validation.

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { usd } from "@/lib/format";

export type PriceQuote = { usd: number; source: string; fetched_at: string; stale?: boolean };

const PriceCtx = createContext<PriceQuote | null>(null);

export function PriceProvider({ children }: { children: ReactNode }) {
  const [quote, setQuote] = useState<PriceQuote | null>(null);
  useEffect(() => {
    let live = true;
    const load = () =>
      fetch("/api/price", { cache: "no-store" })
        .then((r) => (r.ok ? (r.json() as Promise<PriceQuote>) : null))
        .then((q) => {
          if (live && q && Number.isFinite(q.usd) && q.usd > 0) setQuote(q);
        })
        .catch(() => undefined);
    void load();
    const t = setInterval(load, 60_000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, []);
  return <PriceCtx.Provider value={quote}>{children}</PriceCtx.Provider>;
}

export function usePrice(): PriceQuote | null {
  return useContext(PriceCtx);
}

/** "≈ $X.XX" for an amount in sats; renders nothing when the price (or amount) is unknown. */
export function Usd({ sats, className = "usd" }: { sats: number | null | undefined; className?: string }) {
  const q = usePrice();
  const s = usd(sats, q?.usd);
  if (!s) return null;
  return (
    <span className={className} title={q?.stale ? "Price may be out of date" : undefined}>
      {s}
    </span>
  );
}

/** The persistent disclaimer shown near the balance; hidden when there's no price. */
export function UsdNote() {
  const q = usePrice();
  if (!q) return null;
  return (
    <div className="usd-note small faint">
      USD at mainnet BTC price · signet coins have no real value
      {q.stale ? " · price may be out of date" : ""}
    </div>
  );
}
