"use client";

import { Usd } from "@/components/price";
import { useEffect, useMemo, useState } from "react";
import { api, type BookEntry, type Proposal, type Wallet } from "@/lib/api";
import { crossCheck } from "@/lib/bitcoin";
import { ago, btc, chainStatus, short } from "@/lib/format";
import { can, canDeleteProposal } from "@/lib/roles";
import { useMe } from "./auth";
import { LedgerSign } from "./ledger";
import { AnimatedQr, downloadPsbt, UploadSigned } from "./signing";
import { TrezorSign } from "./trezor";
import { ErrorBox, Modal } from "./ui";

export function recipients(p: Proposal) {
  return p.outputs.filter((o) => !o.is_change);
}

export function txTitle(p: Proposal): { icon: string; label: string } {
  if (p.replaces !== null) return { icon: "↻", label: `Replacement for #${p.replaces}` };
  if (recipients(p).length === 0) return { icon: "⟲", label: "Self-transfer" };
  return { icon: "↑", label: "Send" };
}

export function Confs({ p }: { p: Proposal }) {
  const c = p.confirmations;
  return (
    <span className={`confs ${c.ready ? "ready" : ""}`}>
      <span className="dot" />
      {c.count} of {c.threshold} confirmations
    </span>
  );
}

function bookName(book: BookEntry[], addr: string) {
  return book.find((b) => b.address === addr)?.label;
}

/** Status chip: "1 block confirmation, waiting for final", "Final", "Reorged, …" etc. */
export function StatusTag({ p }: { p: Pick<Proposal, "status" | "status_reason" | "block_confirmations"> }) {
  const s = chainStatus(p);
  return (
    <span className={`tag ${s.tone}`} title={s.note ?? undefined} data-testid="status-tag" data-status={p.status}>
      {s.label}
    </span>
  );
}

export function TxRow({
  p,
  wallet,
  book,
  onChange,
  defaultOpen = false,
  dim = false,
}: {
  p: Proposal;
  wallet: Wallet;
  book: BookEntry[];
  onChange: () => void;
  defaultOpen?: boolean;
  dim?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const [full, setFull] = useState<Proposal | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [modal, setModal] = useState<null | "qr" | "upload" | "ledger" | "trezor" | "execute" | "delete">(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    api<Proposal>(`/proposals/${p.id}`).then(setFull, setError);
  }, [open, p.id, p.updated_at, p.confirmations.count]);

  const view = full ?? p;
  const t = txTitle(view);
  const rec = recipients(view);
  const first = rec[0];
  const check = useMemo(() => (full ? crossCheck(full, wallet.owners, wallet.threshold, wallet.network) : null), [full, wallet]);
  const active = ["pending", "signing", "ready"].includes(view.status);
  const me = useMe();
  const canSign = can(wallet.my_role, "sign");
  const canExecute = can(wallet.my_role, "execute");
  const canDelete = canDeleteProposal(wallet.my_role, view.created_by, me?.email);

  async function execute() {
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ txid: string; status: string; invalidated_descendants: number[] }>(`/proposals/${p.id}/execute`, { method: "POST" });
      setResult(`Broadcast ${r.txid}${r.invalidated_descendants.length ? `; invalidated #${r.invalidated_descendants.join(", #")}` : ""}`);
      setModal(null);
      onChange();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  async function del() {
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ warning: string }>(`/proposals/${p.id}`, { method: "DELETE" });
      setResult(r.warning);
      setModal(null);
      onChange();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={`txrow ${dim ? "dim" : ""}`} data-testid={`tx-${p.id}`}>
      <div className="txhead" onClick={() => setOpen((o) => !o)}>
        <span className="txnum" title="Display order only. Bitcoin has no nonce; this number implies no on-chain ordering.">
          #{p.id}
        </span>
        <span className="txtype">
          <span className="txicon">{t.icon}</span>
          {t.label}
        </span>
        <span>
          {first ? (
            <>
              <strong>{btc(view.sent_sats)} BTC</strong> <Usd sats={view.sent_sats} />{" "}
              <span className="muted">→ {bookName(book, first.address) ?? short(first.address, 6, 4)}</span>
              {rec.length > 1 ? <span className="muted"> +{rec.length - 1}</span> : null}
            </>
          ) : (
            <span className="muted">fee {view.fee_rate_sat_vb} sat/vB</span>
          )}
        </span>
        <span className="small muted" data-testid="proposer" title={view.created_by ? `Proposed by ${view.created_by}` : undefined}>
          {ago(view.created_at)}
          {view.created_by ? <span className="break"> · {view.created_by}</span> : null}
        </span>
        <span>{active ? <Confs p={view} /> : <StatusTag p={view} />}</span>
        <span className={`chev ${open ? "open" : ""}`}>›</span>
      </div>
      {open ? (
        <>
          <div className="txbody">
            <div className="txdetails stack">
              {check && !check.ok ? (
                <div className="alert err" data-testid="mismatch">
                  <strong>⚠ The PSBT does not match the server&apos;s summary.</strong> Don&apos;t sign until this is explained.
                  <ul>
                    {check.problems.map((x) => (
                      <li key={x}>{x}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {check?.ok ? <div className="alert ok small">✓ Decoded in this browser: inputs, outputs, fee and txid match the server; change re-derived from the owners&apos; xpubs.</div> : null}
              <div className="kv">
                {view.outputs.map((o) => (
                  <FragmentRow key={o.vout}>
                    <span className="k">{o.is_change ? "Change" : "Recipient"}</span>
                    <span>
                      <span className="mono small break">{o.address}</span>{" "}
                      {o.is_change ? (
                        check?.changeVerified.includes(o.vout) ? (
                          <span className="tag ok">✓ ours (m/1/{o.change_index})</span>
                        ) : (
                          <span className="tag warn">server says ours (m/1/{o.change_index})</span>
                        )
                      ) : bookName(book, o.address) ? (
                        <span className="tag">{bookName(book, o.address)}</span>
                      ) : null}
                      <div>
                        <strong>{btc(o.amount_sats)} BTC</strong> <Usd sats={o.amount_sats} />
                      </div>
                    </span>
                  </FragmentRow>
                ))}
                <span className="k">Fee</span>
                <span>
                  {btc(view.fee_sats)} BTC <Usd sats={view.fee_sats} /> · {view.fee_rate_sat_vb} sat/vB · ~{view.est_vsize} vB
                </span>
                <span className="k">Inputs</span>
                <span className="mono small">
                  {view.inputs.map((i) => (
                    <div key={i.outpoint}>
                      {short(i.outpoint, 8, 6)} ({btc(i.amount_sats)})
                    </div>
                  ))}
                </span>
                <span className="k">RBF</span>
                <span>{view.rbf ? "enabled" : "disabled"}</span>
                <span className="k">Proposed by</span>
                <span>
                  {view.created_by ?? "—"} · {new Date(view.created_at).toLocaleString()}
                </span>
                <span className="k">Status</span>
                <span>
                  <StatusTag p={view} />
                  {chainStatus(view).note ? <div className="small muted" data-testid="status-note">{chainStatus(view).note}</div> : null}
                </span>
                {view.confirmed_height !== null ? (
                  <>
                    <span className="k">Block</span>
                    <span data-testid="block-depth">
                      {view.confirmed_height.toLocaleString()}
                      {view.block_confirmations?.count ? (
                        <span className="muted">
                          {" "}
                          · {view.block_confirmations.count} block confirmation{view.block_confirmations.count === 1 ? "" : "s"}
                          {view.status === "confirmed" ? " · final" : ` · final at ${view.block_confirmations.final_at}`}
                        </span>
                      ) : null}
                    </span>
                  </>
                ) : null}
                {view.broadcast_txid ? (
                  <>
                    <span className="k">Txid</span>
                    <a className="mono small break" target="_blank" rel="noreferrer" href={`https://mempool.space/signet/tx/${view.broadcast_txid}`}>
                      {view.broadcast_txid} ↗
                    </a>
                  </>
                ) : null}
                {view.predecessor ? (
                  <>
                    <span className="k">Chained on</span>
                    <span>#{view.predecessor} (strict order)</span>
                  </>
                ) : null}
              </div>
            </div>
            <div className="signers">
              <h3>Confirmations</h3>
              <div className="small muted" style={{ marginBottom: 8 }}>
                {view.confirmations.count} of {view.confirmations.threshold} required
              </div>
              {view.confirmations.owners.map((o) => (
                <div key={o.fingerprint} className={`signer-step ${o.signed ? "done" : ""}`}>
                  <span className="mark">{o.signed ? "✓" : ""}</span>
                  <div>
                    <div className="who">{o.name ?? "Owner"}</div>
                    <div className="small muted mono">fp {o.fingerprint}</div>
                    {!o.signed && o.inputs_signed > 0 ? <div className="small muted">signed {o.inputs_signed} input(s), not all</div> : null}
                  </div>
                </div>
              ))}
              <div className={`signer-step ${["broadcast", "soft_confirmed", "confirmed"].includes(view.status) ? "done" : ""}`}>
                <span className="mark">{["broadcast", "soft_confirmed", "confirmed"].includes(view.status) ? "✓" : ""}</span>
                <div className="who">Executed</div>
              </div>
              <div className={`signer-step ${["soft_confirmed", "confirmed"].includes(view.status) ? "done" : ""}`}>
                <span className="mark">{["soft_confirmed", "confirmed"].includes(view.status) ? "✓" : ""}</span>
                <div className="who">In a block</div>
              </div>
              <div className={`signer-step ${view.status === "confirmed" ? "done" : ""}`} data-testid="final-step">
                <span className="mark">{view.status === "confirmed" ? "✓" : ""}</span>
                <div>
                  <div className="who">Final</div>
                  {view.block_confirmations ? <div className="small muted">after {view.block_confirmations.final_at} block confirmations</div> : null}
                </div>
              </div>
            </div>
          </div>
          {active ? (
            <div className="actions">
              <button className="btn secondary small" onClick={() => full && downloadPsbt(full)} disabled={!full || !check?.ok}>
                ⇩ Download PSBT
              </button>
              <button className="btn secondary small" onClick={() => setModal("qr")} disabled={!full || !check?.ok}>
                ▦ Show QR
              </button>
              {canSign ? (
                <>
                  <button className="btn secondary small" onClick={() => setModal("upload")}>
                    ⇪ Upload signed PSBT
                  </button>
                  <button className="btn secondary small" onClick={() => setModal("ledger")} disabled={!full || !check?.ok}>
                    Sign with Ledger
                  </button>
                  <button className="btn secondary small" onClick={() => setModal("trezor")} disabled={!full || !check?.ok}>
                    Sign with Trezor
                  </button>
                </>
              ) : null}
              <span style={{ flex: 1 }} />
              {canDelete ? (
                <button className="btn danger small" onClick={() => setModal("delete")}>
                  Delete
                </button>
              ) : null}
              {canExecute ? (
                <button
                  className="btn small accent"
                  disabled={!view.confirmations.ready}
                  onClick={() => setModal("execute")}
                  title={view.confirmations.ready ? "" : "Needs more confirmations"}
                >
                  Execute
                </button>
              ) : (
                <span className="small muted">View only</span>
              )}
            </div>
          ) : null}
          {result ? <div className="alert ok" style={{ margin: 12 }}>{result}</div> : null}
          {error ? (
            <div style={{ margin: 12 }}>
              <ErrorBox error={error} />
            </div>
          ) : null}
        </>
      ) : null}

      {modal === "qr" && full?.psbt ? (
        <Modal title={`Sign #${p.id} with a QR device`} onClose={() => setModal(null)}>
          <AnimatedQr psbtB64={full.psbt} size={280} />
        </Modal>
      ) : null}
      {modal === "ledger" && full ? (
        <Modal title={`Sign #${p.id} with Ledger`} onClose={() => setModal(null)}>
          <LedgerSign
            wallet={wallet}
            proposal={full}
            disabled={!check?.ok}
            onDone={(np) => {
              setFull(np);
              onChange();
            }}
          />
        </Modal>
      ) : null}
      {modal === "upload" ? (
        <Modal title={`Add signatures to #${p.id}`} onClose={() => setModal(null)}>
          <UploadSigned
            proposalId={p.id}
            onDone={(np) => {
              setFull(np);
              onChange();
            }}
          />
        </Modal>
      ) : null}
      {modal === "trezor" && full ? (
        <Modal title={`Sign #${p.id} with Trezor`} onClose={() => setModal(null)}>
          <TrezorSign
            proposal={full}
            wallet={wallet}
            disabled={!check?.ok}
            onDone={(np) => {
              setFull(np);
              onChange();
            }}
          />
        </Modal>
      ) : null}
      {modal === "execute" ? (
        <Modal title={`Execute #${p.id}`} onClose={() => setModal(null)}>
          <div className="stack">
            <p>
              The server finalizes the PSBT, re-validates every signature and the fee, then broadcasts. This can&apos;t be undone once the transaction is in
              the mempool (only replaced with RBF).
            </p>
            <div className="kv">
              <span className="k">Sending</span>
              <span>
                {btc(view.sent_sats)} BTC <Usd sats={view.sent_sats} />
              </span>
              <span className="k">Fee</span>
              <span>
                {btc(view.fee_sats)} BTC <Usd sats={view.fee_sats} /> ({view.fee_rate_sat_vb} sat/vB)
              </span>
            </div>
            {check && !check.ok ? <div className="alert err">The PSBT failed the browser cross-check. Resolve that first.</div> : null}
            <ErrorBox error={error} />
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button className="btn secondary" onClick={() => setModal(null)}>
                Cancel
              </button>
              <button className="btn accent" disabled={busy || (check !== null && !check.ok)} onClick={() => void execute()}>
                {busy ? "Broadcasting…" : "Execute"}
              </button>
            </div>
          </div>
        </Modal>
      ) : null}
      {modal === "delete" ? (
        <Modal title={`Delete #${p.id}?`} onClose={() => setModal(null)}>
          <div className="stack">
            {view.confirmations.count > 0 ? (
              <div className="alert warn">
                Deleting does not revoke signatures already given. Anyone holding enough of them can still broadcast this exact transaction. To kill it for
                certain, spend one of its inputs in a new transaction.
              </div>
            ) : (
              <p>No signatures were collected, so deleting is final. Its coins are released.</p>
            )}
            <ErrorBox error={error} />
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button className="btn secondary" onClick={() => setModal(null)}>
                Keep
              </button>
              <button className="btn danger" disabled={busy} onClick={() => void del()}>
                Delete
              </button>
            </div>
          </div>
        </Modal>
      ) : null}
    </div>
  );
}

function FragmentRow({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
