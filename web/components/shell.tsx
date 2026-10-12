"use client";

import { Usd } from "@/components/price";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { logout, useMe } from "@/components/auth";
import { api, type Health, type WalletListItem } from "@/lib/api";
import { btc, short } from "@/lib/format";
import { can, parseRole, ROLE_LABEL } from "@/lib/roles";
import { CopyButton, Identicon, Logo, Modal, Qr } from "./ui";
import { useWalletMaybe } from "./wallet-context";

export function TopBar() {
  const [health, setHealth] = useState<Health | null>(null);
  const me = useMe();
  const w = useWalletMaybe()?.wallet;
  useEffect(() => {
    const load = () => fetch("/api/health").then((r) => r.json()).then(setHealth, () => setHealth(null));
    load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  }, []);
  return (
    <header className="topbar">
      <Link href="/" className="brand">
        <Logo /> BTC Safe
      </Link>
      <div className="spacer" />
      <span className="chip" title={health?.chain}>
        {health ? (health.ok ? `● Tip ${health.tip.toLocaleString()}` : "● API unhealthy") : "○ API offline"}
      </span>
      {me ? (
        <span className="chip" title={me.is_admin ? "admin" : undefined}>
          {me.email}
          <Link href="/account" className="linkbtn" style={{ marginLeft: 8 }}>
            Account
          </Link>
          <button className="linkbtn" style={{ marginLeft: 8 }} onClick={() => void logout()}>
            Log out
          </button>
        </span>
      ) : null}
      <span className="netbadge">{(w?.network ?? "signet").replace(/^./, (c) => c.toUpperCase())}</span>
    </header>
  );
}

const NAV = [
  { href: "", label: "Home", ico: "⌂" },
  { href: "/assets", label: "Assets", ico: "◎" },
  { href: "/receive", label: "Receive", ico: "↓" },
  { href: "/transactions", label: "Transactions", ico: "⇄" },
  { href: "/address-book", label: "Address book", ico: "☰" },
  { href: "/settings", label: "Settings", ico: "⚙" },
];

export function Sidebar() {
  const ctx = useWalletMaybe();
  const path = usePathname();
  const router = useRouter();
  const [qr, setQr] = useState(false);
  const [wallets, setWallets] = useState<WalletListItem[]>([]);
  const [syncing, setSyncing] = useState(false);
  useEffect(() => {
    api<WalletListItem[]>("/wallets").then(setWallets, () => undefined);
  }, []);
  if (!ctx?.wallet) return <aside className="sidebar" />;
  const { wallet, receive } = ctx;
  const base = `/w/${wallet.id}`;
  const total = wallet.balance ? wallet.balance.confirmed_sats + wallet.balance.unconfirmed_sats : null;

  return (
    <aside className="sidebar">
      <div className="acct">
        <div className="acct-head">
          <Identicon seed={wallet.id} />
          <div style={{ minWidth: 0 }}>
            <div className="acct-name">
              {wallet.name}
              <span className="threshold-badge">
                {wallet.threshold}/{wallet.owners_count}
              </span>
            </div>
            <div className="acct-addr">
              <span className="mono">{short(receive?.address, 6, 4)}</span>
              {receive ? <CopyButton text={receive.address} /> : null}
              {receive ? (
                <button className="iconbtn" title="QR code" onClick={() => setQr(true)}>
                  ▦
                </button>
              ) : null}
              {receive ? (
                <a className="iconbtn" title="Open in explorer" target="_blank" rel="noreferrer" href={`https://mempool.space/signet/address/${receive.address}`}>
                  ↗
                </a>
              ) : null}
            </div>
          </div>
        </div>
        <div className="acct-bal">
          {btc(total)} <small>BTC</small>
        </div>
        <div className="small muted" style={{ marginBottom: 12 }}>
          <Usd sats={total} className="" />
        </div>
        {can(wallet.my_role, "propose") ? (
          <Link href={`${base}/send`} className="btn block accent" onClick={() => window.dispatchEvent(new Event("btcsafe:new-tx"))}>
            New transaction
          </Link>
        ) : (
          <div className="small muted" data-testid="role-note">
            Your role: {ROLE_LABEL[parseRole(wallet.my_role)]}
          </div>
        )}
      </div>
      <nav className="nav">
        {NAV.map((n) => {
          const href = base + n.href;
          const active = n.href === "" ? path === base : path.startsWith(href);
          return (
            <Link key={n.label} href={href} className={active ? "active" : ""}>
              <span className="ico">{n.ico}</span>
              {n.label}
              {n.label === "Transactions" && wallet.queue_count > 0 ? <span className="count">{wallet.queue_count}</span> : null}
            </Link>
          );
        })}
      </nav>
      <div className="sidebar-foot">
        <div className="row between small">
          <span className="muted">⛓ {wallet.network}</span>
          <button
            className="btn secondary small"
            disabled={syncing}
            onClick={async () => {
              setSyncing(true);
              await ctx.sync().catch(() => undefined);
              setSyncing(false);
            }}
          >
            {syncing ? "Syncing…" : "Sync now"}
          </button>
        </div>
        <select aria-label="Switch account" value={wallet.id} onChange={(e) => router.push(e.target.value === "__new" ? "/new" : `/w/${e.target.value}`)}>
          {wallets.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name} ({w.threshold}/{w.owners_count})
            </option>
          ))}
          <option value="__new">+ Create or import account</option>
        </select>
      </div>
      {qr && receive ? (
        <Modal title="Receive address" onClose={() => setQr(false)}>
          <div className="stack" style={{ textAlign: "center" }}>
            <div className="qrbox">
              <Qr value={`bitcoin:${receive.address}`} size={220} />
            </div>
            <div className="addrbig">{receive.address}</div>
            <Link className="btn secondary" href={`${base}/receive`} onClick={() => setQr(false)}>
              Open Receive (verify on device)
            </Link>
          </div>
        </Modal>
      ) : null}
    </aside>
  );
}
