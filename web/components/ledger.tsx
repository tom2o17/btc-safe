"use client";

// Ledger buttons: add owner (wizard), register policy (settings), sign (send + queue), show
// address (receive). All device state goes through <DeviceStatus>.

import { useEffect, useState } from "react";
import { api, type Proposal, type Wallet } from "@/lib/api";
import { can } from "@/lib/roles";
import {
  LedgerError,
  UNSUPPORTED_MESSAGE,
  ledgerInfo,
  readOwnerKey,
  registerOnLedger,
  showOnLedger,
  signOnLedger,
  webHidSupported,
  type DeviceProblem,
  type LedgerInfo,
} from "@/lib/ledger";

type Phase = { kind: "idle" } | { kind: "busy"; text: string } | { kind: "ok"; text: string } | { kind: "problem"; problem: DeviceProblem };

const HELP: Partial<Record<DeviceProblem["state"], string>> = {
  not_connected: "Plug in the Ledger, unlock it, open the Bitcoin Test app, and close Ledger Live.",
  wrong_app: "Install it from Ledger Live (My Ledger → App catalog; testnet apps need Settings → Experimental features → Developer mode).",
};

function toPhase(e: unknown): Phase {
  if (e instanceof LedgerError) return { kind: "problem", problem: e.problem };
  return { kind: "problem", problem: { state: "error", message: e instanceof Error ? e.message : String(e) } };
}

export function DeviceStatus({ phase, onRetry }: { phase: Phase; onRetry?: () => void }) {
  if (phase.kind === "idle") return null;
  if (phase.kind === "busy")
    return (
      <div className="alert" data-testid="ledger-status" data-state="busy">
        ⏳ {phase.text}
      </div>
    );
  if (phase.kind === "ok")
    return (
      <div className="alert ok" data-testid="ledger-status" data-state="ok">
        {phase.text}
      </div>
    );
  const p = phase.problem;
  const cls = p.state === "rejected" ? "warn" : "err";
  return (
    <div className={`alert ${cls}`} data-testid="ledger-status" data-state={p.state}>
      <strong>{TITLES[p.state]}</strong> {p.message}
      {HELP[p.state] ? <div className="small">{HELP[p.state]}</div> : null}
      {onRetry && p.state !== "unsupported" ? (
        <div style={{ marginTop: 6 }}>
          <button className="btn secondary small" onClick={onRetry}>
            Try again
          </button>
        </div>
      ) : null}
    </div>
  );
}

const TITLES: Record<DeviceProblem["state"], string> = {
  unsupported: "Browser not supported.",
  not_connected: "Ledger not connected.",
  locked: "Ledger locked.",
  wrong_app: "Wrong app open.",
  old_app: "App too old.",
  not_registered: "Wallet not registered on this Ledger.",
  rejected: "Rejected on device.",
  bad_hmac: "Registration not recognised.",
  error: "Ledger error.",
};

export function UnsupportedNote() {
  const [ok, setOk] = useState(true);
  useEffect(() => setOk(webHidSupported()), []);
  return ok ? null : <div className="small muted">{UNSUPPORTED_MESSAGE}</div>;
}

/** Wizard: fill an owner from the connected Ledger. */
export function LedgerOwnerButton({ network, onKey }: { network: string; onKey: (k: { fingerprint: string; path: string; xpub: string }) => void }) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  async function go() {
    setPhase({ kind: "busy", text: "Connecting to Ledger…" });
    try {
      const k = await readOwnerKey(network);
      onKey(k);
      setPhase({ kind: "ok", text: `✓ Ledger ${k.fingerprint} · ${k.path}` });
    } catch (e) {
      setPhase(toPhase(e));
    }
  }
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div>
        <button className="btn secondary small" type="button" onClick={() => void go()} disabled={phase.kind === "busy"}>
          Connect Ledger
        </button>
      </div>
      <DeviceStatus phase={phase} onRetry={() => void go()} />
    </div>
  );
}

/** Settings: which owners have this wallet registered on their Ledger, and a register button. */
export function LedgerRegistrations({ wallet }: { wallet: Wallet }) {
  const [info, setInfo] = useState<LedgerInfo | null>(null);
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const canRegister = can(wallet.my_role, "ledger");
  const load = () => ledgerInfo(wallet).then(setInfo, (e) => setPhase(toPhase(e)));
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wallet.id]);

  async function register() {
    setPhase({ kind: "busy", text: "Connecting to Ledger…" });
    try {
      const r = await registerOnLedger(wallet, () =>
        setPhase({ kind: "busy", text: "Review the wallet on your Ledger: name, policy and every key. Approve only if the keys match the owners listed here." }),
      );
      setPhase({ kind: "ok", text: `✓ Registered on Ledger ${r.fingerprint}.` });
      await load();
    } catch (e) {
      setPhase(toPhase(e));
    }
  }

  async function forget(ownerId: string) {
    await api(`/wallets/${wallet.id}/ledger/owners/${ownerId}`, { method: "DELETE" });
    await load();
  }

  return (
    <div className="stack" data-testid="ledger-registrations">
      <p className="small muted">
        A Ledger only signs for (or shows addresses of) a multisig it has registered. Registering shows the policy on the device for you to approve; the
        device returns a code (HMAC) that is stored on the server for this wallet only. It isn&apos;t a key, but it lets the device skip that review next time.
      </p>
      {info ? (
        <table className="list">
          <tbody>
            {wallet.owners.map((o) => {
              const r = info.registrations.find((x) => x.owner_id === o.id);
              return (
                <tr key={o.id}>
                  <td>{o.name}</td>
                  <td className="mono small">{o.fingerprint}</td>
                  <td className="small">
                    {r ? `✓ registered ${new Date(r.registered_at).toLocaleString()}${r.matches_wallet ? "" : " (old wallet name)"}` : <span className="muted">not registered</span>}
                  </td>
                  <td>
                    {r && canRegister ? (
                      <button className="iconbtn" onClick={() => void forget(o.id)} title="Forget the stored HMAC (the device keeps its own copy)">
                        Forget
                      </button>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : null}
      {info ? (
        <details>
          <summary className="small">Policy shown on the device</summary>
          <pre className="mono small" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {`Name: ${info.policy.name}\nPolicy: ${info.policy.descriptor_template}\n${info.policy.keys.map((k, i) => `@${i}: ${k}`).join("\n")}`}
          </pre>
        </details>
      ) : null}
      {canRegister ? (
        <div>
          <button className="btn secondary" onClick={() => void register()} disabled={phase.kind === "busy"}>
            Register on connected Ledger
          </button>
        </div>
      ) : null}
      <UnsupportedNote />
      <DeviceStatus phase={phase} onRetry={() => void register()} />
    </div>
  );
}

/** Sign a proposal on the Ledger and upload the signatures. */
export function LedgerSign({
  wallet,
  proposal,
  disabled,
  onDone,
}: {
  wallet: Wallet;
  proposal: Pick<Proposal, "id" | "psbt">;
  disabled?: boolean;
  onDone: (p: Proposal) => void;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });

  async function sign() {
    setPhase({ kind: "busy", text: "Connecting to Ledger…" });
    try {
      const psbt = proposal.psbt ?? (await api<Proposal>(`/proposals/${proposal.id}`)).psbt;
      if (!psbt) throw new Error("proposal has no PSBT");
      const r = await signOnLedger(wallet, proposal.id, psbt, () =>
        setPhase({ kind: "busy", text: "Confirm on your Ledger: check every recipient, amount and the fee on the device screen, then sign." }),
      );
      setPhase({ kind: "busy", text: "Uploading signatures…" });
      const res = await api<Proposal & { accepted: { new_signatures: number } }>(`/proposals/${proposal.id}/signatures`, { body: { psbt: r.psbt } });
      setPhase({ kind: "ok", text: `✓ Ledger ${r.fingerprint} signed: ${res.confirmations.count} of ${res.confirmations.threshold}.` });
      onDone(res);
    } catch (e) {
      setPhase(toPhase(e));
    }
  }

  async function registerThenSign() {
    setPhase({ kind: "busy", text: "Connecting to Ledger…" });
    try {
      await registerOnLedger(wallet, () => setPhase({ kind: "busy", text: "Review and approve the wallet registration on your Ledger…" }));
    } catch (e) {
      setPhase(toPhase(e));
      return;
    }
    await sign();
  }

  const notRegistered = phase.kind === "problem" && (phase.problem.state === "not_registered" || phase.problem.state === "bad_hmac");
  return (
    <div className="stack" style={{ gap: 8 }} data-testid="ledger-sign">
      <div className="row wrap">
        <button className="btn" onClick={() => void sign()} disabled={disabled || phase.kind === "busy"}>
          Sign with Ledger
        </button>
        {notRegistered ? (
          <button className="btn secondary" onClick={() => void registerThenSign()}>
            Register wallet on this Ledger, then sign
          </button>
        ) : null}
      </div>
      <UnsupportedNote />
      <DeviceStatus phase={phase} onRetry={() => void sign()} />
    </div>
  );
}

/** Receive: show the address on the Ledger and compare with what this page shows. */
export function ShowOnLedger({ wallet, chain, index, expected }: { wallet: Wallet; chain: 0 | 1; index: number; expected: string }) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  async function go() {
    setPhase({ kind: "busy", text: "Connecting to Ledger…" });
    try {
      const a = await showOnLedger(wallet, chain, index, () => setPhase({ kind: "busy", text: "Compare the address on your Ledger with the one on this page…" }));
      setPhase(
        a === expected
          ? { kind: "ok", text: "✓ The Ledger derived the same address. Check that its screen matched this page." }
          : { kind: "problem", problem: { state: "error", message: `MISMATCH: the Ledger derived ${a}. Do not use the address on this page.` } },
      );
    } catch (e) {
      setPhase(toPhase(e));
    }
  }
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div>
        <button className="btn secondary small" onClick={() => void go()} disabled={phase.kind === "busy"}>
          Show on Ledger
        </button>
      </div>
      <DeviceStatus phase={phase} onRetry={() => void go()} />
    </div>
  );
}
