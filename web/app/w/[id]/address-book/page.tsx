"use client";

import { useCallback, useEffect, useState } from "react";
import { address as baddress } from "bitcoinjs-lib";
import { CopyButton, ErrorBox } from "@/components/ui";
import { useWallet } from "@/components/wallet-context";
import { api, type BookEntry } from "@/lib/api";
import { networkFor } from "@/lib/bitcoin";
import { can } from "@/lib/roles";

export default function AddressBook() {
  const { wallet } = useWallet();
  const [rows, setRows] = useState<BookEntry[]>([]);
  const [label, setLabel] = useState("");
  const [addr, setAddr] = useState("");
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(() => api<BookEntry[]>(`/wallets/${wallet.id}/address-book`).then(setRows, setError), [wallet.id]);
  useEffect(() => {
    void load();
  }, [load]);

  const editable = can(wallet.my_role, "label");
  let addrErr: string | null = null;
  if (addr.trim()) {
    try {
      baddress.toOutputScript(addr.trim(), networkFor(wallet.network));
    } catch {
      addrErr = "not a valid address for this network";
    }
  }

  async function add() {
    setError(null);
    try {
      await api(`/wallets/${wallet.id}/address-book`, { body: { label: label.trim(), address: addr.trim() } });
      setLabel("");
      setAddr("");
      void load();
    } catch (e) {
      setError(e);
    }
  }

  return (
    <div style={{ maxWidth: 860 }}>
      <h1>Address book</h1>
      {editable ? (
        <div className="card stack">
          <div className="row">
            <input type="text" placeholder="Name" value={label} onChange={(e) => setLabel(e.target.value)} style={{ maxWidth: 220 }} aria-label="Entry name" />
            <input type="text" placeholder="tb1q…" value={addr} onChange={(e) => setAddr(e.target.value)} aria-label="Entry address" />
            <button className="btn" disabled={!label.trim() || !addr.trim() || !!addrErr} onClick={() => void add()}>
              Add
            </button>
          </div>
          {addrErr ? <div className="small" style={{ color: "var(--err)" }}>{addrErr}</div> : null}
          <ErrorBox error={error} />
        </div>
      ) : (
        <ErrorBox error={error} />
      )}
      <div style={{ marginTop: 16 }}>
        {rows.length === 0 ? (
          <div className="card empty">No entries. Names show up on transactions and in the Send recipient box.</div>
        ) : (
          <table className="list">
            <thead>
              <tr>
                <th>Name</th>
                <th>Address</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td style={{ fontWeight: 600 }}>{r.label}</td>
                  <td className="mono small">
                    {r.address} <CopyButton text={r.address} />
                  </td>
                  <td style={{ textAlign: "right" }}>
                    {editable ? (
                      <button
                        className="btn danger small"
                        onClick={() =>
                          api(`/wallets/${wallet.id}/address-book/${r.id}`, { method: "DELETE" }).then(
                            () => void load(),
                            (e) => setError(e),
                          )
                        }
                      >
                        Remove
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
