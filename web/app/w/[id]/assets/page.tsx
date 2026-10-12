"use client";

import { Usd } from "@/components/price";
import Link from "next/link";
import { useEffect, useState } from "react";
import { ErrorBox } from "@/components/ui";
import { useWallet } from "@/components/wallet-context";
import { api, type Utxo } from "@/lib/api";
import { btc, short } from "@/lib/format";

export default function Assets() {
  const { wallet } = useWallet();
  const [utxos, setUtxos] = useState<Utxo[] | null>(null);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    api<Utxo[]>(`/wallets/${wallet.id}/utxos`).then(setUtxos, setError);
  }, [wallet.id, wallet.balance?.confirmed_sats, wallet.balance?.unconfirmed_sats, wallet.queue_count]);

  const toggle = (o: string) =>
    setSel((s) => {
      const n = new Set(s);
      if (n.has(o)) n.delete(o);
      else n.add(o);
      return n;
    });
  const total = utxos?.filter((u) => sel.has(u.outpoint)).reduce((s, u) => s + u.amount_sats, 0) ?? 0;

  return (
    <>
      <div className="row between" style={{ marginBottom: 20 }}>
        <h1 style={{ margin: 0 }}>Assets</h1>
        <div className="row">
          {sel.size ? <span className="small muted">{sel.size} selected · {btc(total)} BTC <Usd sats={total} /></span> : null}
          <Link
            className={`btn ${sel.size ? "" : "secondary"}`}
            href={`/w/${wallet.id}/send${sel.size ? `?utxos=${encodeURIComponent([...sel].join(","))}` : ""}`}
            aria-disabled={!sel.size}
          >
            Send selected
          </Link>
        </div>
      </div>
      <p className="small muted">Bitcoin has one asset, so this is the coin list (coin control). Reserved coins are locked by a queued transaction.</p>
      <ErrorBox error={error} />
      {utxos && utxos.length === 0 ? <div className="card empty">No coins yet. Use Receive to get an address.</div> : null}
      {utxos && utxos.length ? (
        <table className="list">
          <thead>
            <tr>
              <th style={{ width: 36 }} />
              <th>Outpoint</th>
              <th>Address</th>
              <th>Label</th>
              <th style={{ textAlign: "right" }}>Amount (BTC)</th>
              <th>Conf</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {utxos.map((u) => (
              <tr key={u.outpoint}>
                <td>
                  <input type="checkbox" disabled={u.status === "reserved"} checked={sel.has(u.outpoint)} onChange={() => toggle(u.outpoint)} aria-label={`select ${u.outpoint}`} />
                </td>
                <td className="mono small">{short(u.outpoint, 8, 4)}</td>
                <td className="mono small" title={u.address ?? ""}>
                  {short(u.address, 8, 4)} <span className="faint">m/{u.keychain === "external" ? 0 : 1}/{u.index}</span>
                </td>
                <td>{u.label ?? (u.keychain === "internal" ? <span className="faint">change</span> : <span className="faint">—</span>)}</td>
                <td style={{ textAlign: "right" }}>
                  <strong>{btc(u.amount_sats)}</strong>
                  <Usd sats={u.amount_sats} className="usd block" />
                </td>
                <td>{u.confirmations}</td>
                <td>
                  {u.status === "reserved" ? (
                    <Link href={`/w/${wallet.id}/transactions?open=${u.reserved_by}`} className="tag warn">
                      reserved (#{u.reserved_by})
                    </Link>
                  ) : u.status === "unconfirmed" ? (
                    <span className="tag">unconfirmed</span>
                  ) : (
                    <span className="tag ok">available</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </>
  );
}
