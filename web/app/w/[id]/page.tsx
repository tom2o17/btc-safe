"use client";

import { Usd, UsdNote } from "@/components/price";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Confs, recipients, StatusTag, txTitle } from "@/components/tx";
import { useWallet } from "@/components/wallet-context";
import { api, type Proposal } from "@/lib/api";
import { btc, short } from "@/lib/format";

export default function Home() {
  const { wallet, refresh } = useWallet();
  const [queue, setQueue] = useState<Proposal[]>([]);
  const load = useCallback(() => api<Proposal[]>(`/wallets/${wallet.id}/proposals?status=queue`).then(setQueue, () => undefined), [wallet.id]);
  useEffect(() => {
    void load();
  }, [load, wallet.queue_count]);
  const b = wallet.balance;
  const base = `/w/${wallet.id}`;

  return (
    <>
      <h1>Overview</h1>
      <div className="grid3">
        <div className="card stat">
          <div className="label">Total</div>
          <div className="value">{btc(b ? b.confirmed_sats + b.unconfirmed_sats : null)} BTC</div>
          {b ? <Usd sats={b.confirmed_sats + b.unconfirmed_sats} className="usd big" /> : null}
          <div className="sub">
            {b ? `${btc(b.available_sats)} available to spend` : "Not synced yet"} {b ? <Usd sats={b.available_sats} /> : null}
          </div>
          <UsdNote />
        </div>
        <div className="card stat">
          <div className="label">Confirmed</div>
          <div className="value">{btc(b?.confirmed_sats)}</div>
          <Usd sats={b?.confirmed_sats} className="usd big" />
          <div className="sub">{wallet.tip_height !== null ? `Tip ${wallet.tip_height.toLocaleString()}` : "—"}</div>
        </div>
        <div className="card stat">
          <div className="label">Unconfirmed / reserved</div>
          <div className="value">
            {btc(b?.unconfirmed_sats)} <span className="faint">/</span> {btc(b?.reserved_sats)}
          </div>
          <div className="sub" title="Coins locked as inputs of queued transactions">Reserved = locked by queued transactions</div>
        </div>
      </div>
      <div className="row" style={{ marginTop: 16 }}>
        <Link href={`${base}/send`} className="btn">
          ↑ Send
        </Link>
        <Link href={`${base}/receive`} className="btn secondary">
          ↓ Receive
        </Link>
        <button className="btn secondary" onClick={() => void refresh()}>
          Refresh
        </button>
      </div>

      <div className="section-title">
        <h2 style={{ margin: 0 }}>Pending transactions</h2>
        <Link href={`${base}/transactions`} className="small" style={{ fontWeight: 600 }}>
          View all →
        </Link>
      </div>
      {queue.length === 0 ? (
        <div className="card empty">No queued transactions.</div>
      ) : (
        <table className="list">
          <tbody>
            {queue.slice(0, 5).map((p) => {
              const r = recipients(p)[0];
              return (
                <tr key={p.id}>
                  <td className="txnum" style={{ width: 60 }}>
                    #{p.id}
                  </td>
                  <td>
                    {txTitle(p).label} {r ? <strong>{btc(p.sent_sats)} BTC</strong> : null} {r ? <Usd sats={p.sent_sats} /> : null} {r ? <span className="muted">→ {short(r.address)}</span> : null}
                  </td>
                  <td>{["broadcast", "soft_confirmed"].includes(p.status) ? <StatusTag p={p} /> : <Confs p={p} />}</td>
                  <td style={{ textAlign: "right" }}>
                    <Link href={`${base}/transactions?open=${p.id}`} className="btn small secondary">
                      {["broadcast", "soft_confirmed"].includes(p.status) ? "View" : p.confirmations.ready ? "Execute" : "Confirm"}
                    </Link>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <div className="card row wrap" style={{ marginTop: 28, gap: 32 }}>
        <span>
          <span className="muted">Owners</span> <strong>{wallet.owners_count}</strong>
        </span>
        <span>
          <span className="muted">Threshold</span> <strong>{wallet.threshold}</strong>
        </span>
        <span>
          <span className="muted">Policy</span> <strong>{wallet.policy}</strong>
        </span>
        <span>
          <span className="muted">Ordering</span> <strong>{wallet.ordering_mode}</strong>
        </span>
      </div>
    </>
  );
}
