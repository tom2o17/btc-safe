"use client";

import { usePathname } from "next/navigation";
import { createContext, useContext, useEffect, useState } from "react";
import { fetchMe, goToLogin, setSession, type Me } from "@/lib/api";

const PUBLIC = ["/login", "/setup", "/signup"];
const Ctx = createContext<Me | null>(null);

export function useMe(): Me | null {
  return useContext(Ctx);
}

/** Auth guard for every page: nothing but /login, /signup and /setup renders without a session. */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const path = usePathname() ?? "/";
  const isPublic = PUBLIC.some((p) => path === p || path.startsWith(`${p}/`));
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isPublic) return;
    fetchMe().then(
      (m) => {
        setMe(m);
        if (!m) goToLogin();
      },
      (e: Error) => setError(e.message),
    );
  }, [isPublic, path]);

  if (isPublic) return <>{children}</>;
  if (error) return <main className="main full"><div className="card">API unavailable: {error}</div></main>;
  if (!me) return <main className="main full"><div className="muted">Checking session…</div></main>;
  return <Ctx.Provider value={me}>{children}</Ctx.Provider>;
}

/** End every session of this account (all browsers), then go to /login. */
export async function logoutAll() {
  const { api } = await import("@/lib/api");
  await api("/auth/logout-all", { method: "POST" });
  setSession(null);
  window.location.assign("/login");
}

export async function logout() {
  const { api } = await import("@/lib/api");
  try {
    await api("/auth/logout", { method: "POST" });
  } finally {
    setSession(null);
    window.location.assign("/login");
  }
}
