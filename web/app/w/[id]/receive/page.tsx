"use client";

import { useMemo, useState } from "react";
import { ShowOnLedger } from "@/components/ledger";
import { ShowOnTrezor } from "@/components/trezor";
import { CopyButton, ErrorBox, Qr } from "@/components/ui";
import { useWallet } from "@/components/wallet-context";
import { api, type AddressInfo } from "@/lib/api";
import { deriveAddress, networkFor } from "@/lib/bitcoin";
import { can } from "@/lib/roles";

export default function Receive() {
  const { wallet, receive, setReceive } = useWallet();
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);

  // The server derives addresses, so a compromised server could show its own. Re-derive here.
  const browser = useMemo(() => {
    if (!receive) return null;
    try {
      return deriveAddress(wallet.owners, wallet.threshold, 0, receive.index, networkFor(wallet.network));
    } catch {
      return null;
    }
  }, [receive, wallet]);
  const match = receive && browser === receive.address;

  async function fresh() {
    setBusy(true);
    setError(null);
    try {
      const a = await api<AddressInfo>(`/wallets/${wallet.id}/addresses?kind=receive&next=true`);
      setReceive(a);
      setLabel("");
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  async function saveLabel() {
    if (!receive) return;
    try {
      await api(`/wallets/${wallet.id}/addresses/${receive.index}/label`, { body: { label, kind: "receive" } });
      setReceive({ ...receive, label });
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    } catch (e) {
      setError(e);
    }
  }

  if (!receive) return <div className="muted">Loading address…</div>;

  return (
    <div style={{ maxWidth: 820 }}>
      <h1>Receive</h1>
      <div className="card" style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 24 }}>
        <div className="stack">
          <div className="small muted">
            {wallet.name} · {wallet.threshold}-of-{wallet.owners_count} · {wallet.network}
          </div>
          <div className="addrbig" data-testid="receive-address">
            {receive.address} <CopyButton text={receive.address} />
          </div>
          <div className="small muted">
            Index <span className="mono">{receive.path}</span>
            {receive.label ? (
              <>
                {" "}
                · label <strong>{receive.label}</strong>
              </>
            ) : null}
          </div>
          {match ? (
            <div className="alert ok small">✓ This browser derived the same address from the owners&apos; xpubs.</div>
          ) : (
            <div className="alert err">✗ This browser derives {browser ?? "nothing"} for {receive.path}. Don&apos;t use this address.</div>
          )}
          <div className="alert warn">
            <strong>Before sending large amounts, verify this address on a signing device.</strong> The device must have this wallet registered (import the
            BSMS file from Settings first).
            <ul>
              <li>Coldcard: Address Explorer → pick this multisig wallet → find index {receive.index} and match every character.</li>
              <li>Jade: Options → Wallet → Verify address, scan the QR.</li>
              <li>Sparrow: Addresses tab → receive #{receive.index}.</li>
            </ul>
            <div className="small">Device menu paths are not yet checked against current firmware.</div>
          </div>
          <div className="row">
            {match ? <ShowOnLedger wallet={wallet} chain={0} index={receive.index} expected={receive.address} /> : null}
            {match ? <ShowOnTrezor wallet={wallet} chain={0} index={receive.index} expected={receive.address} /> : null}
          </div>
        </div>
        <div className="qrbox" style={{ alignSelf: "start" }}>
          <Qr value={`bitcoin:${receive.address}`} size={220} />
          <span className="small muted">bitcoin:{receive.address.slice(0, 10)}…</span>
        </div>
      </div>
      <div className="card row">
        {can(wallet.my_role, "label") ? (
          <>
            <input type="text" placeholder="Label (e.g. invoice 42)" value={label} onChange={(e) => setLabel(e.target.value)} aria-label="Address label" />
            <button className="btn secondary" disabled={!label.trim()} onClick={() => void saveLabel()}>
              {saved ? "Saved ✓" : "Save label"}
            </button>
          </>
        ) : (
          <span style={{ flex: 1 }} />
        )}
        {can(wallet.my_role, "allocate") ? (
          <button className="btn" disabled={busy} onClick={() => void fresh()}>
            New address
          </button>
        ) : null}
      </div>
      <ErrorBox error={error} />
    </div>
  );
}
