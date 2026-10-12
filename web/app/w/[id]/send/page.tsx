"use client";

import { Usd } from "@/components/price";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";
import { address as baddress } from "bitcoinjs-lib";
import { LedgerSign } from "@/components/ledger";
import { AnimatedQr, downloadPsbt, UploadSigned } from "@/components/signing";
import { TrezorSign } from "@/components/trezor";
import { useMe } from "@/components/auth";
import { ErrorBox, Warnings } from "@/components/ui";
import { useWallet } from "@/components/wallet-context";
import { api, ApiError, type BookEntry, type Fees, type Proposal } from "@/lib/api";
import { crossCheck, networkFor } from "@/lib/bitcoin";
import { btc, parseBtc } from "@/lib/format";
import { can, parseRole } from "@/lib/roles";

type Out = { to: string; amount: string };
type FeeChoice = "slow" | "normal" | "fast" | "custom";

function Send() {
  const { wallet, refresh } = useWallet();
  const router = useRouter();
  const params = useSearchParams();
  const preselected = useMemo(() => (params.get("utxos") ?? "").split(",").filter(Boolean), [params]);
  const [step, setStep] = useState(1);
  const [outs, setOuts] = useState<Out[]>([{ to: "", amount: "" }]);
  const [sendMax, setSendMax] = useState(false);
  const [fees, setFees] = useState<Fees | null>(null);
  const [fee, setFee] = useState<FeeChoice>("normal");
  const [custom, setCustom] = useState("2");
  const [rbf, setRbf] = useState(true);
  const me = useMe();
  const [book, setBook] = useState<BookEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [needOverride, setNeedOverride] = useState(false);
  const [proposal, setProposal] = useState<Proposal | null>(null);
  const [signMode, setSignMode] = useState<null | "qr" | "file" | "ledger" | "trezor">(null);

  // The sidebar's "New transaction" link points at this same URL; start over when it's clicked.
  useEffect(() => {
    const reset = () => {
      setStep(1);
      setOuts([{ to: "", amount: "" }]);
      setSendMax(false);
      setProposal(null);
      setSignMode(null);
      setError(null);
      setNeedOverride(false);
    };
    window.addEventListener("btcsafe:new-tx", reset);
    return () => window.removeEventListener("btcsafe:new-tx", reset);
  }, []);

  useEffect(() => {
    api<Fees>(`/wallets/${wallet.id}/fees`).then(setFees, () => undefined);
    api<BookEntry[]>(`/wallets/${wallet.id}/address-book`).then(setBook, () => undefined);
  }, [wallet.id]);

  const net = networkFor(wallet.network);
  const resolve = (to: string) => book.find((b) => b.label.toLowerCase() === to.trim().toLowerCase())?.address ?? to.trim();
  const outErrors = outs.map((o, i) => {
    const addr = resolve(o.to);
    if (!addr) return "recipient required";
    try {
      baddress.toOutputScript(addr, net);
    } catch {
      return "not a valid address for this network";
    }
    if (sendMax && i === 0) return null;
    const s = parseBtc(o.amount);
    if (s === null || s <= 0) return "amount required";
    if (s < 330) return "below dust (330 sats)";
    return null;
  });
  const feeRate = fee === "custom" ? Number(custom) : fees ? fees[`${fee}_sat_vb`] : undefined;
  const formOk = outErrors.every((e) => e === null) && (fee !== "custom" || (feeRate !== undefined && feeRate > 0));

  async function create(override = false) {
    setBusy(true);
    setError(null);
    setNeedOverride(false);
    try {
      const p = await api<Proposal>(`/wallets/${wallet.id}/proposals`, {
        body: {
          outputs: outs.map((o, i) => ({ address: resolve(o.to), amount_sats: sendMax && i === 0 ? 0 : (parseBtc(o.amount) ?? 0) })),
          fee_rate_sat_vb: feeRate,
          rbf,
          send_max: sendMax || undefined,
          utxos: preselected.length ? preselected : undefined,
          fee_override: override || undefined,
        },
      });
      setProposal(p);
      setStep(2);
      void refresh();
    } catch (e) {
      if (e instanceof ApiError && e.code === "fee_cap") setNeedOverride(true);
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  async function discard() {
    if (!proposal) return;
    setBusy(true);
    try {
      await api(`/proposals/${proposal.id}`, { method: "DELETE" });
      setProposal(null);
      setStep(1);
      void refresh();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  const check = useMemo(() => (proposal ? crossCheck(proposal, wallet.owners, wallet.threshold, wallet.network) : null), [proposal, wallet]);
  const recipients = proposal?.outputs.filter((o) => !o.is_change) ?? [];

  return (
    <div style={{ maxWidth: 760 }}>
      <h1>New transaction</h1>
      <div className="stepper">
        {[1, 2, 3].map((s) => (
          <div key={s} className={`s ${s <= step ? "on" : ""}`} />
        ))}
      </div>

      {step === 1 ? (
        <div className="card stack">
          <h2>Step 1 of 3 · Send</h2>
          <datalist id="book">
            {book.map((b) => (
              <option key={b.id} value={b.label}>
                {b.address}
              </option>
            ))}
          </datalist>
          {outs.map((o, i) => (
            <div key={i} className="stack" style={{ borderBottom: outs.length > 1 ? "1px solid var(--border-light)" : undefined, paddingBottom: 12 }}>
              <label className="field">
                <span>Recipient {outs.length > 1 ? i + 1 : ""}</span>
                <input
                  type="text"
                  list="book"
                  placeholder="tb1q… or address-book name"
                  value={o.to}
                  onChange={(e) => setOuts((os) => os.map((x, j) => (j === i ? { ...x, to: e.target.value } : x)))}
                  aria-label={`Recipient ${i + 1}`}
                />
              </label>
              {o.to && resolve(o.to) !== o.to.trim() ? <div className="small muted mono">→ {resolve(o.to)}</div> : null}
              <div className="row">
                <label className="field" style={{ flex: 1 }}>
                  <span>Amount (BTC)</span>
                  <input
                    type="text"
                    inputMode="decimal"
                    placeholder="0.00"
                    disabled={sendMax && i === 0}
                    value={sendMax && i === 0 ? "everything available" : o.amount}
                    onChange={(e) => setOuts((os) => os.map((x, j) => (j === i ? { ...x, amount: e.target.value } : x)))}
                    aria-label={`Amount ${i + 1}`}
                  />
                  {!(sendMax && i === 0) ? <Usd sats={parseBtc(o.amount)} className="usd small" /> : null}
                </label>
                {i === 0 && outs.length === 1 ? (
                  <button className={`btn ${sendMax ? "" : "secondary"}`} style={{ marginTop: 20 }} onClick={() => setSendMax((m) => !m)}>
                    Max
                  </button>
                ) : null}
                {outs.length > 1 ? (
                  <button className="btn secondary" style={{ marginTop: 20 }} onClick={() => setOuts((os) => os.filter((_, j) => j !== i))}>
                    Remove
                  </button>
                ) : null}
              </div>
              {o.to && outErrors[i] ? <div className="small" style={{ color: "var(--err)" }}>{outErrors[i]}</div> : null}
            </div>
          ))}
          {!sendMax ? (
            <div>
              <button className="btn secondary small" onClick={() => setOuts((os) => [...os, { to: "", amount: "" }])}>
                + Add output
              </button>
            </div>
          ) : null}
          <div>
            <div className="small muted" style={{ fontWeight: 600, marginBottom: 6 }}>
              Fee rate {fees ? <span className="faint">({fees.source})</span> : null}
            </div>
            <div className="row wrap">
              {(["slow", "normal", "fast"] as const).map((f) => (
                <label key={f} className={`btn small ${fee === f ? "" : "secondary"}`}>
                  <input type="radio" name="fee" hidden checked={fee === f} onChange={() => setFee(f)} />
                  {f[0].toUpperCase() + f.slice(1)} {fees ? `${fees[`${f}_sat_vb`]} sat/vB` : ""}
                </label>
              ))}
              <label className={`btn small ${fee === "custom" ? "" : "secondary"}`}>
                <input type="radio" name="fee" hidden checked={fee === "custom"} onChange={() => setFee("custom")} />
                Custom
              </label>
              {fee === "custom" ? <input type="number" min="0.1" step="0.1" value={custom} onChange={(e) => setCustom(e.target.value)} style={{ width: 110 }} aria-label="Custom fee rate" /> : null}
            </div>
          </div>
          <details>
            <summary className="small muted" style={{ cursor: "pointer" }}>
              Advanced
            </summary>
            <div className="stack" style={{ marginTop: 10 }}>
              <label className="row">
                <input type="checkbox" checked={rbf} onChange={(e) => setRbf(e.target.checked)} style={{ width: "auto" }} /> Replace-by-fee (lets you bump the fee
                later)
              </label>
              <div className="small muted">
                Proposed by: <b>{me?.email ?? "you"}</b> (set by the server from your login)
              </div>
              <div className="small muted">
                Coin control:{" "}
                {preselected.length ? (
                  <>
                    spending {preselected.length} selected coin(s). <Link href={`/w/${wallet.id}/send`}>Clear</Link>
                  </>
                ) : (
                  <>
                    automatic. Pick coins on <Link href={`/w/${wallet.id}/assets`}>Assets</Link>.
                  </>
                )}
              </div>
            </div>
          </details>
          <ErrorBox error={error} />
          {needOverride ? (
            <button className="btn danger" disabled={busy} onClick={() => void create(true)}>
              I understand, create with this fee anyway
            </button>
          ) : null}
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button className="btn" disabled={!formOk || busy} onClick={() => void create(false)}>
              {busy ? "Building…" : "Next"}
            </button>
          </div>
        </div>
      ) : null}

      {step === 2 && proposal ? (
        <div className="card stack">
          <h2>Step 2 of 3 · Review #{proposal.id}</h2>
          {check && !check.ok ? (
            <div className="alert err" data-testid="mismatch">
              <strong>⚠ The PSBT the server built does not match its own summary.</strong> Do not sign it.
              <ul>
                {check.problems.map((x) => (
                  <li key={x}>{x}</li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="alert ok small">✓ PSBT decoded in this browser matches the server summary. Change re-derived from the owners&apos; xpubs.</div>
          )}
          <div className="kv">
            {recipients.map((o) => (
              <Frag key={o.vout}>
                <span className="k">Sending</span>
                <span>
                  <strong>{btc(o.amount_sats)} BTC</strong> <Usd sats={o.amount_sats} /> to <span className="mono small break">{o.address}</span>
                  {book.find((b) => b.address === o.address) ? <span className="tag" style={{ marginLeft: 6 }}>{book.find((b) => b.address === o.address)?.label}</span> : null}
                </span>
              </Frag>
            ))}
            {proposal.outputs
              .filter((o) => o.is_change)
              .map((o) => (
                <Frag key={o.vout}>
                  <span className="k">Change</span>
                  <span>
                    {btc(o.amount_sats)} <Usd sats={o.amount_sats} /> → <span className="mono small">{o.address}</span>{" "}
                    {check?.changeVerified.includes(o.vout) ? <span className="tag ok">✓ derived from this wallet (m/1/{o.change_index})</span> : <span className="tag err">not verified</span>}
                  </span>
                </Frag>
              ))}
            <span className="k">Fee</span>
            <span>
              {btc(proposal.fee_sats)} BTC <Usd sats={proposal.fee_sats} /> · {proposal.fee_rate_sat_vb} sat/vB · ~{proposal.est_vsize} vB
              {proposal.sent_sats > 0 ? <span className="muted"> ({((proposal.fee_sats / proposal.sent_sats) * 100).toFixed(3)}% of amount)</span> : null}
            </span>
            <span className="k">Inputs</span>
            <span className="small">{proposal.inputs.length} coin(s), reserved for this transaction until it&apos;s executed or deleted</span>
            <span className="k">RBF</span>
            <span>{proposal.rbf ? "enabled" : "disabled"}</span>
          </div>
          <Warnings items={proposal.warnings} />
          <ErrorBox error={error} />
          <div className="row between">
            <button className="btn secondary" disabled={busy} onClick={() => void discard()}>
              Back (discard)
            </button>
            <button className="btn" disabled={!check?.ok} onClick={() => setStep(3)}>
              Next
            </button>
          </div>
        </div>
      ) : null}

      {step === 3 && proposal ? (
        <div className="card stack">
          <h2>Step 3 of 3 · Sign #{proposal.id}</h2>
          <p className="muted">Choose how to sign as an owner. Each owner signs on their own device; the server only collects signatures.</p>
          <div className="grid3" style={{ gridTemplateColumns: "1fr 1fr" }}>
            <button className={`card opt ${signMode === "qr" ? "selected" : ""}`} onClick={() => setSignMode("qr")}>
              <strong>▦ Show QR</strong>
              <span className="small muted">Coldcard Q, Jade, Keystone, Passport, Sparrow</span>
            </button>
            <button className={`card opt ${signMode === "file" ? "selected" : ""}`} onClick={() => setSignMode("file")}>
              <strong>⇩ Download PSBT</strong>
              <span className="small muted">SD card / USB: Coldcard, Sparrow, Electrum</span>
            </button>
            <button className={`card opt ${signMode === "ledger" ? "selected" : ""}`} onClick={() => setSignMode("ledger")}>
              <strong>Ledger (USB)</strong>
              <span className="small muted">Chrome/Edge over WebHID</span>
            </button>
            <button className={`card opt ${signMode === "trezor" ? "selected" : ""}`} onClick={() => setSignMode("trezor")}>
              <strong>Trezor</strong>
              <span className="small muted">Through Trezor Suite (desktop or web)</span>
            </button>
            <button className="card opt" onClick={() => router.push(`/w/${wallet.id}/transactions?open=${proposal.id}`)}>
              <strong>Save without signing</strong>
              <span className="small muted">Leave it in the queue for the other owners</span>
            </button>
          </div>
          {signMode === "qr" && proposal.psbt ? <AnimatedQr psbtB64={proposal.psbt} /> : null}
          {signMode === "ledger" ? (
            <LedgerSign wallet={wallet} proposal={proposal} disabled={!check?.ok} onDone={(p) => setProposal({ ...proposal, ...p })} />
          ) : null}
          {signMode === "trezor" ? <TrezorSign proposal={proposal} wallet={wallet} disabled={!check?.ok} onDone={(p) => setProposal({ ...proposal, ...p })} /> : null}
          {signMode === "file" ? (
            <div className="row">
              <button className="btn" onClick={() => downloadPsbt(proposal)}>
                ⇩ Download btc-safe-proposal-{proposal.id}.psbt
              </button>
            </div>
          ) : null}
          <h3 style={{ marginTop: 12 }}>Then upload the signed PSBT</h3>
          <UploadSigned proposalId={proposal.id} onDone={(p) => setProposal({ ...proposal, ...p })} />
          <div className="row between">
            <span>
              <strong>
                {proposal.confirmations.count} of {proposal.confirmations.threshold}
              </strong>{" "}
              confirmations
            </span>
            <Link href={`/w/${wallet.id}/transactions?open=${proposal.id}`} className={`btn ${proposal.confirmations.ready ? "accent" : "secondary"}`}>
              {proposal.confirmations.ready ? "Go to Execute →" : "Done: view in queue →"}
            </Link>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function Frag({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}

export default function Page() {
  const { wallet } = useWallet();
  if (!can(wallet.my_role, "propose")) {
    return (
      <div style={{ maxWidth: 720 }}>
        <h1>New transaction</h1>
        <div className="card" data-testid="no-propose">
          Your role is {parseRole(wallet.my_role)}: you can&apos;t propose transactions on this account. An admin can change your role under Settings →
          Sharing.
        </div>
      </div>
    );
  }
  return (
    <Suspense>
      <Send />
    </Suspense>
  );
}
