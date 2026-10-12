"use client";

// Trezor UI: "Add owner from Trezor" (wizard) and "Sign with Trezor" (send step 3, queue row).
// Talks to the device through lib/signers/trezor.ts (Trezor Connect 10 → Trezor Suite).

import { useState } from "react";
import { api, type Proposal, type Wallet } from "@/lib/api";
import type { BuiltRequest } from "@/lib/signers/trezor-tx";
import { SignerError, type XpubResult } from "@/lib/signers/types";
import { ErrorBox } from "./ui";

const SUITE_HINT = "Trezor Suite (desktop) running, or allow the Suite Web popup (Chrome, Edge or Brave).";

function help(e: SignerError, network: string): string {
  switch (e.code) {
    case "not_connected":
      return `No Trezor reachable. Plug it in and unlock it, with ${SUITE_HINT}`;
    case "cancelled":
      return "Cancelled on the Trezor or in Trezor Suite. Nothing was signed or shared.";
    case "wrong_network":
      return network === "bitcoin"
        ? `Wrong network: ${e.message}`
        : `Trezor can't use ${network} here (${e.message}). In Trezor Suite: Settings → Crypto → enable "Bitcoin Testnet". Trezor has no signet coin; this app signs signet as testnet, which uses the same keys and addresses.`;
    case "wrong_device":
      return e.message;
    case "busy":
      return "The Trezor is in use by another app or tab. Close it there and try again.";
    case "unsupported":
      return `${e.message}. Sortedmulti needs firmware ≥ 2.8.7 (Model T, Safe 3/5/7) or ≥ 1.13.0 (Model One).`;
    default:
      return e.message;
  }
}

function DeviceError({ error, network }: { error: unknown; network: string }) {
  if (!error) return null;
  if (error instanceof SignerError)
    return (
      <div className="alert err" data-testid="trezor-error" data-code={error.code}>
        <strong>{error.code === "cancelled" ? "Cancelled" : error.code === "not_connected" ? "Trezor not connected" : error.code === "wrong_network" ? "Wrong network" : error.code === "wrong_device" ? "Wrong Trezor" : "Trezor error"}</strong>
        <div>{help(error, network)}</div>
      </div>
    );
  return <ErrorBox error={error} />;
}

/** Fills an owner row from the connected Trezor (xpub + master fingerprint at `path`). */
export function TrezorAddOwner({ path, network, onOwner }: { path: string; network: string; onOwner: (x: XpubResult) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="row wrap">
        <button
          className="btn secondary small"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError(null);
            try {
              const { trezor } = await import("@/lib/signers/trezor");
              onOwner(await trezor.getXpub(path, network));
            } catch (e) {
              setError(e);
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Waiting for Trezor…" : "Add from Trezor"}
        </button>
        {busy ? <span className="small muted">Approve the request in Trezor Suite.</span> : null}
      </div>
      <DeviceError error={error} network={network} />
    </div>
  );
}

type Phase = "idle" | "identify" | "sign" | "submit";

/** Signs a proposal on a Trezor and submits the signatures to the server (same validation as any upload). */
/** `disabled` must stay true until the browser-side PSBT cross-check passes (same gate as LedgerSign). */
export function TrezorSign({ proposal, wallet, disabled, onDone }: { proposal: Proposal; wallet: Wallet; disabled?: boolean; onDone: (p: Proposal) => void }) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<unknown>(null);
  const [log, setLog] = useState<string | null>(null);
  const [built, setBuilt] = useState<BuiltRequest | null>(null);
  const owners = [...wallet.owners].sort((a, b) => a.position - b.position);
  const changeIndex = new Map(proposal.outputs.filter((o) => o.is_change && o.change_index !== null).map((o) => [o.vout, o.change_index as number]));

  async function go() {
    if (!proposal.psbt || disabled) return;
    setError(null);
    setLog(null);
    setBuilt(null);
    try {
      const { trezor } = await import("@/lib/signers/trezor");
      setPhase("identify");
      const ctx = { owners, threshold: wallet.threshold, network: wallet.network, changeIndex };
      const { owner } = await trezor.identify(owners, wallet.network);
      setPhase("sign");
      // What the device will show comes from our own decoding of the PSBT, not the server's summary.
      const res = await trezor.signAs(proposal.psbt, ctx, owner, setBuilt);
      setPhase("submit");
      const r = await api<Proposal & { accepted: { new_signatures: number; already_present: number } }>(`/proposals/${proposal.id}/signatures`, { body: { psbt: res.psbt } });
      setLog(
        `Signed by ${res.signer.name ?? "owner"} (fp ${res.signer.fingerprint}) on ${res.inputsSigned} input(s): ${r.accepted.new_signatures} new, ${r.accepted.already_present} already present → ${r.confirmations.count} of ${r.confirmations.threshold}`,
      );
      onDone(r);
    } catch (e) {
      setError(e);
    } finally {
      setPhase("idle");
    }
  }

  return (
    <div className="stack" data-testid="trezor-sign">
      <div className="row wrap">
        <button className="btn" disabled={disabled || phase !== "idle" || !proposal.psbt} onClick={() => void go()}>
          {phase === "idle" ? "Sign with Trezor" : phase === "submit" ? "Submitting…" : "Waiting for Trezor…"}
        </button>
        <span className="small muted">{disabled ? "Waiting for the in-browser PSBT check to pass." : <>Needs {SUITE_HINT}</>}</span>
      </div>
      {phase === "identify" ? <div className="alert warn">Approve access in Trezor Suite. The app reads the device&apos;s xpub to work out which owner it is.</div> : null}
      {phase === "sign" && built ? <DeviceExpect built={built} /> : null}
      <DeviceError error={error} network={wallet.network} />
      {log ? <div className="alert ok">{log}</div> : null}
    </div>
  );
}

/** What the Trezor should display, derived in this browser from the PSBT (not the server's JSON). */
function DeviceExpect({ built }: { built: BuiltRequest }) {
  const shown = built.request.outputs.flatMap((o) =>
    o.script_type === "PAYTOADDRESS" ? [`${o.address} (${o.amount} sats)`] : o.script_type === "PAYTOOPRETURN" ? [`OP_RETURN ${o.op_return_data.slice(0, 16)}…`] : [],
  );
  return (
    <div className="alert warn" data-testid="trezor-expect">
      Check the Trezor screen. It should ask you to confirm exactly {shown.length} output(s): {shown.join(", ")}, then the fee.{" "}
      {built.changeVouts.length ? `${built.changeVouts.length} change output(s) were verified as this account's and won't be shown.` : "There's no change."} If it
      shows anything else, reject on the device.
    </div>
  );
}

/**
 * Receive: show the address on the Trezor (getAddress with this wallet's multisig) and compare.
 * UNVERIFIED on a real Trezor: built against Connect 10.0.1's types and a firmware-logic mock only.
 */
export function ShowOnTrezor({ wallet, chain, index, expected }: { wallet: Wallet; chain: 0 | 1; index: number; expected: string }) {
  const [phase, setPhase] = useState<"idle" | "identify" | "device">("idle");
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  async function go() {
    setError(null);
    setResult(null);
    try {
      const { trezor } = await import("@/lib/signers/trezor");
      setPhase("identify");
      const owners = [...wallet.owners].sort((a, b) => a.position - b.position);
      const r = await trezor.showAddress(owners, wallet.threshold, wallet.network, chain, index, expected, () => setPhase("device"));
      setResult(
        r.address === expected
          ? { ok: true, text: `✓ The Trezor (${r.owner.name ?? "owner"}) derived the same address. That only counts if its screen showed exactly this address and you confirmed it there.` }
          : { ok: false, text: `MISMATCH: the Trezor derived ${r.address}. Do not use the address on this page.` },
      );
    } catch (e) {
      setError(e);
    } finally {
      setPhase("idle");
    }
  }

  return (
    <div className="stack" style={{ gap: 6 }} data-testid="trezor-show">
      <div>
        <button className="btn secondary small" disabled={phase !== "idle"} onClick={() => void go()}>
          {phase === "idle" ? "Show on Trezor" : "Waiting for Trezor…"}
        </button>
      </div>
      {phase === "identify" ? <div className="alert warn small">Approve access in Trezor Suite; the app reads the device&apos;s xpub to find which owner it is.</div> : null}
      {phase === "device" ? <div className="alert warn small">Compare the address on the Trezor screen with the one on this page, character by character.</div> : null}
      {result ? <div className={`alert ${result.ok ? "ok" : "err"} small`}>{result.text}</div> : null}
      {error ? (
        <>
          <DeviceError error={error} network={wallet.network} />
          <div className="small muted" data-testid="trezor-not-verified">
            Not verified on a device. This address has only been checked in this browser.
          </div>
        </>
      ) : null}
      <div className="small faint">Trezor address display has not been tested on a real device yet.</div>
    </div>
  );
}
