"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { TopBar } from "@/components/shell";
import { ErrorBox, Identicon } from "@/components/ui";
import { useMe } from "@/components/auth";
import { AppearanceCard } from "@/components/theme";
import { api, type WalletListItem } from "@/lib/api";
import { parseRole, ROLE_LABEL } from "@/lib/roles";

export default function Accounts() {
  const [wallets, setWallets] = useState<WalletListItem[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const me = useMe();

  const load = () =>
    api<WalletListItem[]>("/wallets").then(
      (w) => {
        setWallets(w);
        setError(null);
      },
      (e) => {
        setWallets(null);
        setError(e);
      },
    );

  useEffect(() => {
    void load();
  }, []);

  return (
    <>
      <TopBar />
      <main className="main full">
        <div className="row between" style={{ marginBottom: 20 }}>
          <h1 style={{ margin: 0 }}>Accounts</h1>
          <div className="row">
            <Link href="/new?mode=import" className="btn secondary">
              Import existing
            </Link>
            <Link href="/new" className="btn">
              Create account
            </Link>
          </div>
        </div>

        <ErrorBox error={error} />
        {wallets && wallets.length === 0 ? (
          <div className="card empty">
            <h2>No accounts yet</h2>
            <p>Create a multisig account from your owners&apos; xpubs, or import a descriptor, BSMS file or Sparrow/Caravan export.</p>
          </div>
        ) : null}
        <div className="stack">
          {wallets?.map((w) => (
            <Link key={w.id} href={`/w/${w.id}`} className="card row" style={{ display: "flex" }}>
              <Identicon seed={w.id} size={40} />
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 700 }}>
                  {w.name} <span className="threshold-badge">{w.threshold}/{w.owners_count}</span>
                </div>
                <div className="small muted">
                  {w.network} · P2WSH sortedmulti · {w.ordering_mode} ordering
                  {w.role ? <> · <span className="tag">{ROLE_LABEL[parseRole(w.role)]}</span></> : null}
                </div>
              </div>
              <span className="muted">→</span>
            </Link>
          ))}
        </div>

        {me?.is_admin ? <InviteUser /> : null}

        <div className="section-title">
          <h2 style={{ margin: 0 }}>Settings</h2>
        </div>
        <AppearanceCard />
      </main>
    </>
  );
}

/** Admin: create an account (or reset one) and get a one-time setup link to hand over. */
function InviteUser() {
  const [email, setEmail] = useState("");
  const [admin, setAdmin] = useState(false);
  const [link, setLink] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  async function invite() {
    setError(null);
    setLink(null);
    try {
      const r = await api<{ setup_path: string; expires_in_hours: number }>("/auth/invites", { body: { email: email.trim(), admin } });
      setLink(`${window.location.origin}${r.setup_path}`);
    } catch (e) {
      setError(e);
    }
  }
  return (
    <div className="card stack" style={{ marginTop: 28 }}>
      <h2>Invite a user</h2>
      <p className="small muted">
        Creates the account (or resets its password) and shows a one-time setup link, valid 72 hours. Send it privately. To share an account with them
        afterwards, add them under the account&apos;s Settings → Sharing.
      </p>
      <div className="row">
        <input type="email" placeholder="email" value={email} onChange={(e) => setEmail(e.target.value)} aria-label="Invite email" />
        <label className="row small">
          <input type="checkbox" checked={admin} onChange={(e) => setAdmin(e.target.checked)} /> admin
        </label>
        <button className="btn" onClick={() => void invite()} disabled={!email.includes("@")}>
          Create setup link
        </button>
      </div>
      <ErrorBox error={error} />
      {link ? <code className="mono small" style={{ wordBreak: "break-all" }}>{link}</code> : null}
    </div>
  );
}
