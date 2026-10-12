"use client";

import { Usd } from "@/components/price";
import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { TxRow } from "@/components/tx";
import { ErrorBox } from "@/components/ui";
import { useWallet } from "@/components/wallet-context";
import { api, type BookEntry, type HistoryTx, type Proposal } from "@/lib/api";
import { btc, short } from "@/lib/format";

function Transactions() {
  const { wallet, refresh } = useWallet();
  const params = useSearchParams();
  const openId = Number(params.get("open") ?? 0);
  const [tab, setTab] = useState<"queue" | "history">(params.get("tab") === "history" ? "history" : "queue");
  const [queue, setQueue] = useState<Proposal[] | null>(null);
  const [hist, setHist] = useState<{ transactions: HistoryTx[]; proposals: Proposal[] } | null>(null);
  const [book, setBook] = useState<BookEntry[]>([]);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    try {
      const [q, h, b] = await Promise.all([
        api<Proposal[]>(`/wallets/${wallet.id}/proposals?status=queue`),
        api<{ transactions: HistoryTx[]; proposals: Proposal[] }>(`/wallets/${wallet.id}/history`),
        api<BookEntry[]>(`/wallets/${wallet.id}/address-book`),
      ]);
      setQueue(q);
      setHist(h);
      setBook(b);
      setError(null);
    } catch (e) {
      setError(e);
    }
  }, [wallet.id]);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 10_000);
    return () => clearInterval(t);
  }, [load]);

  const onChange = () => {
    void load();
    void refresh();
  };

  return (
    <>
      <h1>Transactions</h1>
      <div className="tabs">
        <button className={tab === "queue" ? "active" : ""} onClick={() => setTab("queue")}>
          Queue {queue?.length ? `(${queue.length})` : ""}
        </button>
        <button className={tab === "history" ? "active" : ""} onClick={() => setTab("history")}>
          History
        </button>
      </div>
      <ErrorBox error={error} />
      {tab === "queue" ? (
        queue === null ? (
          <div className="muted">Loading…</div>
        ) : queue.length === 0 ? (
          <div className="card empty">Queued transactions will appear here.</div>
        ) : (
          <>
            <div className="small muted" style={{ marginBottom: 8 }}>
              {wallet.ordering_mode === "strict"
                ? "Strict order: each transaction spends the previous one's change and must be executed in order."
                : "Parallel: queued transactions use separate coins and can be executed in any order. #ids are display order only."}
            </div>
            {/* One flat keyed list, so a row keeps its state (e.g. the execute result) when it
                moves between groups. */}
            {queueGroups(queue, wallet.ordering_mode === "strict").flatMap(([label, rows]) =>
              rows.length
                ? [
                    <div key={`label-${label}`} className="txgroup-label">
                      {label}
                    </div>,
                    ...rows.map((p) => (
                      <TxRow key={p.id} p={p} wallet={wallet} book={book} onChange={onChange} defaultOpen={openId === p.id || queue.length === 1} />
                    )),
                  ]
                : [],
            )}
          </>
        )
      ) : hist === null ? (
        <div className="muted">Loading…</div>
      ) : (
        <>
          <div className="txgroup-label">On-chain</div>
          {hist.transactions.length === 0 ? <div className="card empty">No on-chain transactions yet.</div> : null}
          {hist.transactions.length ? (
            <table className="list">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Txid</th>
                  <th>Amount</th>
                  <th>Fee</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {hist.transactions.map((t) => (
                  <tr key={t.txid}>
                    <td>
                      {t.origin === "incoming" ? "↓ Received" : t.origin === "proposal" ? `↑ Sent (#${t.proposal_id})` : "↑ External spend"}
                    </td>
                    <td className="mono small">
                      <a target="_blank" rel="noreferrer" href={`https://mempool.space/signet/tx/${t.txid}`}>
                        {short(t.txid, 10, 6)} ↗
                      </a>
                    </td>
                    <td>
                      <strong style={{ color: t.received_sats >= t.sent_sats ? "var(--ok)" : undefined }}>
                        {t.received_sats >= t.sent_sats ? "+" : "−"}
                        {btc(Math.abs(t.received_sats - t.sent_sats))} BTC
                      </strong>{" "}
                      <Usd sats={Math.abs(t.received_sats - t.sent_sats)} />
                    </td>
                    <td className="small muted">{t.fee_sats !== null && t.origin !== "incoming" ? btc(t.fee_sats) : "—"}</td>
                    <td>
                      <ChainDepth height={t.height} tip={wallet.tip_height} finalAt={wallet.confirmations_final} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
          <div className="txgroup-label">Finished proposals</div>
          {hist.proposals.length === 0 ? <div className="card empty">None yet.</div> : null}
          {hist.proposals.map((p) => (
            <TxRow key={p.id} p={p} wallet={wallet} book={book} onChange={onChange} dim={["conflicted", "invalidated", "deleted"].includes(p.status)} defaultOpen={openId === p.id} />
          ))}
        </>
      )}
    </>
  );
}

export default function Page() {
  return (
    <Suspense>
      <Transactions />
    </Suspense>
  );
}

/** "Block N" when final (by depth), "Block N · 1 block confirmation, waiting for final" before. */
function ChainDepth({ height, tip, finalAt }: { height: number | null; tip: number | null; finalAt?: number }) {
  if (height === null) return <span className="tag warn">Unconfirmed</span>;
  const n = tip !== null && tip >= height ? tip - height + 1 : 1;
  if (finalAt === undefined || n >= finalAt) return <span className="tag ok" title={`${n} block confirmations`}>Block {height.toLocaleString()}</span>;
  return (
    <span className="tag warn" title={`Final at ${finalAt} block confirmations; a chain reorganization can still undo it until then.`}>
      Block {height.toLocaleString()} · {n} block confirmation{n === 1 ? "" : "s"}, waiting for final
    </span>
  );
}

/** Sent (broadcast or soft-confirmed): nothing left to sign; waiting for the chain. */
function inFlight(p: Proposal) {
  return p.status === "broadcast" || p.status === "soft_confirmed";
}

/** Queue sections. In-flight first; then strict order (next, then the rest) or parallel (by readiness). */
function queueGroups(queue: Proposal[], strict: boolean): [string, Proposal[]][] {
  const sent = queue.filter(inFlight);
  const rest = queue.filter((p) => !inFlight(p));
  if (strict) {
    return [
      ["Sent, waiting for final", sent],
      ["Next", rest.slice(0, 1)],
      ["Queued (must execute in order)", rest.slice(1)],
    ];
  }
  return [
    ["Sent, waiting for final", sent],
    ["Ready to execute", rest.filter((p) => p.confirmations.ready)],
    ["Awaiting confirmations", rest.filter((p) => !p.confirmations.ready)],
  ];
}
