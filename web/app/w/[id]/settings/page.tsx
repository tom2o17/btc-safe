"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { LedgerRegistrations } from "@/components/ledger";
import { CopyButton, ErrorBox, Warnings } from "@/components/ui";
import { useWallet } from "@/components/wallet-context";
import { Members } from "@/components/members";
import { AppearanceCard } from "@/components/theme";
import { api, type Backup, type Health } from "@/lib/api";
import { buildDescriptor, deriveAddress, networkFor } from "@/lib/bitcoin";
import { download, short } from "@/lib/format";
import { can } from "@/lib/roles";

export default function Settings() {
  const { wallet, refresh } = useWallet();
  const [tab, setTab] = useState<"setup" | "sharing" | "appearance">("setup");
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [addr0, setAddr0] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/health").then((r) => r.json()).then(setHealth, () => undefined);
    try {
      setAddr0(deriveAddress(wallet.owners, wallet.threshold, 0, 0, networkFor(wallet.network)));
    } catch {
      setAddr0(null);
    }
  }, [wallet]);

  async function exportBsms() {
    try {
      const b = await api<Backup>(`/wallets/${wallet.id}/backup`);
      download(`${wallet.name.replace(/\W+/g, "-")}.bsms`, b.bsms, "text/plain");
    } catch (e) {
      setError(e);
    }
  }

  async function setOrdering(m: string) {
    setError(null);
    try {
      await api(`/wallets/${wallet.id}`, { method: "PATCH", body: { ordering_mode: m } });
      await refresh();
    } catch (e) {
      setError(e);
    }
  }

  const sorted = [...wallet.owners].sort((a, b) => a.position - b.position);

  return (
    <div style={{ maxWidth: 980 }}>
      <h1>Settings</h1>
      <div className="tabs">
        <button className={tab === "setup" ? "active" : ""} onClick={() => setTab("setup")}>
          Setup
        </button>
        <Link href={`/w/${wallet.id}/address-book`}>Address book</Link>
        <button className={tab === "sharing" ? "active" : ""} onClick={() => setTab("sharing")}>
          Sharing
        </button>
        <button className={tab === "appearance" ? "active" : ""} onClick={() => setTab("appearance")}>
          Appearance
        </button>
      </div>
      <ErrorBox error={error} />
      {tab === "setup" ? (
        <>
          <div className="card">
            <div className="row between" style={{ marginBottom: 12 }}>
              <h2 style={{ margin: 0 }}>Owners ({wallet.owners_count})</h2>
              <span>
                Threshold:{" "}
                <strong>
                  {wallet.threshold} of {wallet.owners_count}
                </strong>
              </span>
            </div>
            <table className="list">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Fingerprint</th>
                  <th>Path</th>
                  <th>xpub</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((o) => (
                  <tr key={o.id}>
                    <td style={{ fontWeight: 600 }}>{o.name}</td>
                    <td className="mono small">{o.fingerprint}</td>
                    <td className="mono small">{o.path}</td>
                    <td className="mono small">
                      {short(o.xpub, 10, 6)} <CopyButton text={o.xpub} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="small muted" style={{ marginTop: 12 }}>
              Bitcoin multisig keys are fixed in the address script. Changing owners or the threshold means creating a new account and moving the funds with a
              migration transaction (not automated in v1). Verify receive address #0 on each device: <span className="mono">{addr0 ?? "—"}</span>
            </p>
          </div>
          <div className="card stack">
            <h2>Descriptor</h2>
            <div className="mono small break card" style={{ padding: 12 }}>
              {wallet.descriptor.multipath} <CopyButton text={wallet.descriptor.multipath} />
            </div>
            <details>
              <summary className="small muted" style={{ cursor: "pointer" }}>
                Receive / change descriptors, and the browser-built one
              </summary>
              <div className="mono small break stack" style={{ marginTop: 8 }}>
                <div>{wallet.descriptor.external}</div>
                <div>{wallet.descriptor.internal}</div>
                <div className="muted">browser: {buildDescriptor(sorted, wallet.threshold)}</div>
              </div>
            </details>
            <div className="row">
              <button className="btn secondary" onClick={() => void exportBsms()}>
                ⇩ Export BSMS
              </button>
              <button className="btn secondary" onClick={() => download(`${wallet.name.replace(/\W+/g, "-")}-descriptor.txt`, wallet.descriptor.multipath + "\n", "text/plain")}>
                ⇩ Descriptor
              </button>
            </div>
            <Warnings items={wallet.warnings} />
          </div>
          <div className="card">
            <h2>Ledger</h2>
            <LedgerRegistrations wallet={wallet} />
          </div>
          <div className="card">
            <h2>Queue ordering</h2>
            <div className="row">
              <select
                value={wallet.ordering_mode}
                onChange={(e) => void setOrdering(e.target.value)}
                style={{ maxWidth: 360 }}
                aria-label="Ordering mode"
                disabled={!can(wallet.my_role, "settings")}
              >
                <option value="parallel">Parallel (independent coins)</option>
                <option value="strict">Strict order (each spends the previous change)</option>
              </select>
              <span className="small muted">
                {can(wallet.my_role, "settings") ? "Can only be changed while the queue is empty." : "Only an admin of this account can change it."}
              </span>
            </div>
          </div>
          <div className="card kv">
            <span className="k">Policy</span>
            <span>{wallet.policy}</span>
            <span className="k">Chain source</span>
            <span>
              {health ? `${health.chain} (${health.ok ? "healthy" : "unhealthy"}, tip ${health.tip.toLocaleString()})` : "unreachable"}
            </span>
            <span className="k">Last sync</span>
            <span>{wallet.last_synced_at ? new Date(wallet.last_synced_at).toLocaleString() : "never"}</span>
            <span className="k">Next receive index</span>
            <span>{wallet.next_receive_index}</span>
            <span className="k">Account id</span>
            <span className="mono small">{wallet.id}</span>
          </div>
        </>
      ) : tab === "appearance" ? (
        <AppearanceCard />
      ) : (
        <Members walletId={wallet.id} role={wallet.my_role} />
      )}
    </div>
  );
}
