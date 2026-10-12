"use client";

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, type AddressInfo, type Wallet } from "@/lib/api";

type Ctx = {
  wallet: Wallet | null;
  receive: AddressInfo | null;
  error: unknown;
  refresh: () => Promise<void>;
  sync: () => Promise<void>;
  setReceive: (a: AddressInfo) => void;
};

const WalletCtx = createContext<Ctx | null>(null);

export function useWallet(): Ctx & { wallet: Wallet } {
  const c = useContext(WalletCtx);
  if (!c || !c.wallet) throw new Error("useWallet outside a loaded WalletProvider");
  return c as Ctx & { wallet: Wallet };
}

export function useWalletMaybe(): Ctx | null {
  return useContext(WalletCtx);
}

export function WalletProvider({ id, children }: { id: string; children: ReactNode }) {
  const [wallet, setWallet] = useState<Wallet | null>(null);
  const [receive, setReceive] = useState<AddressInfo | null>(null);
  const [error, setError] = useState<unknown>(null);

  const refresh = useCallback(async () => {
    try {
      setWallet(await api<Wallet>(`/wallets/${id}`));
      setError(null);
    } catch (e) {
      setError(e);
    }
  }, [id]);

  const sync = useCallback(async () => {
    try {
      await api(`/wallets/${id}/sync`, { method: "POST" });
    } finally {
      await refresh();
    }
  }, [id, refresh]);

  useEffect(() => {
    void refresh();
    // Current receive address (allocates #0 on a fresh wallet; never skips ahead).
    api<AddressInfo>(`/wallets/${id}/addresses?kind=receive`).then(setReceive, () => undefined);
    const t = setInterval(() => void refresh(), 10_000);
    return () => clearInterval(t);
  }, [id, refresh]);

  return <WalletCtx.Provider value={{ wallet, receive, error, refresh, sync, setReceive }}>{children}</WalletCtx.Provider>;
}
