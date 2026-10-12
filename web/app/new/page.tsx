"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { TopBar } from "@/components/shell";
import { TrezorAddOwner } from "@/components/trezor";
import { CopyButton, ErrorBox, Warnings } from "@/components/ui";
import { api, type CreatedWallet } from "@/lib/api";
import { LedgerOwnerButton } from "@/components/ledger";
import { buildDescriptor, checkXpub, deriveAddress, networkFor, parseKeyExpression } from "@/lib/bitcoin";
import { download } from "@/lib/format";
import { formatLabel, MAX_IMPORT_BYTES, sniffWalletFile, walletFileName } from "@/lib/import-sniff";

type OwnerDraft = { name: string; fingerprint: string; path: string; xpub: string };
const blank = (n: number): OwnerDraft => ({ name: `Owner ${n}`, fingerprint: "", path: "m/48'/1'/0'/2'", xpub: "" });

function ownerProblem(o: OwnerDraft): string | null {
  if (!o.name.trim()) return "name is required";
  if (!/^[0-9a-f]{8}$/i.test(o.fingerprint)) return "fingerprint must be 8 hex chars";
  if (!/^m(\/\d+'?)*$/.test(o.path)) return "path must look like m/48'/1'/0'/2'";
  if (!o.xpub) return "xpub is required";
  return checkXpub(o.xpub);
}

function Wizard() {
  const params = useSearchParams();
  const router = useRouter();
  const [mode, setMode] = useState<"create" | "import">(params.get("mode") === "import" ? "import" : "create");
  const [step, setStep] = useState(1);
  const [name, setName] = useState("Treasury");
  const [ordering, setOrdering] = useState<"parallel" | "strict">("parallel");
  const [owners, setOwners] = useState<OwnerDraft[]>([blank(1), blank(2)]);
  const [threshold, setThreshold] = useState(2);
  const [bulk, setBulk] = useState("");
  const [importData, setImportData] = useState("");
  // Import keeps its own name: prefilled from the file until the user edits it.
  const [importName, setImportName] = useState("");
  const [importNameEdited, setImportNameEdited] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [created, setCreated] = useState<CreatedWallet | null>(null);

  useEffect(() => setThreshold((t) => Math.min(Math.max(t, 1), owners.length)), [owners.length]);

  const problems = owners.map(ownerProblem);
  const ownersOk = owners.length >= 2 && problems.every((p) => p === null);

  // Review: everything here is computed in the browser from the xpubs, before the server sees them.
  const review = useMemo((): { descriptor: string; addrs: string[] } | { error: string } | null => {
    if (!ownersOk) return null;
    try {
      return {
        descriptor: buildDescriptor(owners, threshold),
        addrs: [0, 1, 2].map((i) => deriveAddress(owners, threshold, 0, i)),
      };
    } catch (e) {
      return { error: (e as Error).message };
    }
  }, [owners, threshold, ownersOk]);

  function update(i: number, patch: Partial<OwnerDraft>) {
    setOwners((os) => os.map((o, j) => (j === i ? { ...o, ...patch } : o)));
  }

  function setImportText(t: string) {
    setImportData(t);
    if (!importNameEdited) setImportName(walletFileName(t) ?? "");
  }

  async function loadImportFile(f: File | undefined) {
    setError(null);
    setNotice(null);
    if (!f) return;
    if (f.size > MAX_IMPORT_BYTES) {
      setError(new Error(`${f.name} is ${Math.round(f.size / 1024)} KB; wallet files are a few KB. Pick the wallet config export.`));
      return;
    }
    const text = await f.text();
    setImportText(text);
    const fmt = sniffWalletFile(text);
    setNotice(fmt ? `Loaded ${f.name} (${formatLabel(fmt)}).` : `Loaded ${f.name}, but it doesn't look like a descriptor, BSMS or Caravan file. The server will say what's wrong.`);
  }

  function applyBulk() {
    setError(null);
    setNotice(null);
    // A whole wallet file pasted here belongs in Import, which validates it server-side.
    const fmt = sniffWalletFile(bulk);
    if (fmt) {
      const fileName = walletFileName(bulk);
      setImportText(bulk);
      setBulk("");
      setMode("import");
      setNotice(
        `That's a ${formatLabel(fmt)} wallet file, not an owner list, so it was moved to Import${fileName ? ` (name "${fileName}")` : ""}. Check it and press Import.`,
      );
      return;
    }
    try {
      const v = JSON.parse(bulk) as OwnerDraft[];
      if (!Array.isArray(v) || v.length < 2)
        throw new Error("Expected a JSON array of at least 2 owners ({name, xpub, fingerprint, path}). For a Caravan/Sparrow, BSMS or descriptor file, use the Import tab.");
      setOwners(v.map((o, i) => ({ name: o.name ?? `Owner ${i + 1}`, fingerprint: o.fingerprint, path: o.path, xpub: o.xpub })));
      setBulk("");
    } catch (e) {
      setError(e);
    }
  }

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const w = await api<CreatedWallet>("/wallets", {
        body: { name, network: "signet", threshold, ordering_mode: ordering, owners: owners.map((o) => ({ ...o, fingerprint: o.fingerprint.toLowerCase() })) },
      });
      setCreated(w);
      setStep(5);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  async function doImport() {
    setBusy(true);
    setError(null);
    try {
      const w = await api<CreatedWallet>("/wallets/import", { body: { name: importName.trim() || undefined, network: "signet", data: importData, ordering_mode: ordering } });
      setCreated(w);
      setStep(5);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  if (created) return <BackupStep w={created} clientAddrs={review && "addrs" in review ? review.addrs : null} onOpen={() => router.push(`/w/${created.id}`)} />;

  return (
    <>
      <div className="row between" style={{ marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>{mode === "create" ? "Create new account" : "Import existing account"}</h1>
        <Link href="/" className="btn secondary small">
          Cancel
        </Link>
      </div>
      <div className="tabs">
        <button className={mode === "create" ? "active" : ""} onClick={() => (setMode("create"), setNotice(null))}>
          Create from owner keys
        </button>
        <button className={mode === "import" ? "active" : ""} onClick={() => setMode("import")}>
          Import descriptor / BSMS / JSON
        </button>
      </div>

      {mode === "import" ? (
        <div className="card stack">
          {notice ? (
            <div className="alert info" data-testid="import-notice">
              {notice}
            </div>
          ) : null}
          <label className="field">
            <span>Name {walletFileName(importData) && importName === walletFileName(importData) ? "(from the file; you can change it)" : "(optional; defaults to the file's name)"}</span>
            <input
              type="text"
              value={importName}
              maxLength={100}
              data-testid="import-name"
              onChange={(e) => (setImportName(e.target.value), setImportNameEdited(e.target.value !== ""))}
            />
          </label>
          <div className="field">
            <span>Wallet file</span>
            <input
              type="file"
              accept=".json,.txt,.bsms,application/json,text/plain"
              data-testid="import-file"
              onChange={(e) => {
                void loadImportFile(e.target.files?.[0]);
                e.target.value = "";
              }}
            />
          </div>
          <label className="field">
            <span>…or paste a descriptor, BSMS 1.0 file, or Sparrow/Caravan JSON export</span>
            <textarea rows={10} value={importData} data-testid="import-data" onChange={(e) => setImportText(e.target.value)} placeholder="wsh(sortedmulti(2,[4ba43603/48h/1h/0h/2h]tpub…/<0;1>/*,…))#…" />
          </label>
          <ErrorBox error={error} />
          <div className="row">
            <button className="btn" disabled={busy || !importData.trim()} onClick={() => void doImport()}>
              {busy ? "Importing…" : "Import"}
            </button>
            <span className="small muted">Only P2WSH sortedmulti is supported in v1. Every import is round-tripped by the server.</span>
          </div>
        </div>
      ) : (
        <>
          <div className="stepper">
            {[1, 2, 3, 4].map((s) => (
              <div key={s} className={`s ${s <= step ? "on" : ""}`} />
            ))}
          </div>

          {step === 1 ? (
            <div className="card stack">
              <h2>1. Name &amp; network</h2>
              <label className="field">
                <span>Account name</span>
                <input type="text" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
              </label>
              <div className="field">
                <span className="small muted" style={{ fontWeight: 600 }}>
                  Network
                </span>
                <div className="row" style={{ marginTop: 6 }}>
                  <label>
                    <input type="radio" checked readOnly /> Signet
                  </label>
                  <label className="faint">
                    <input type="radio" disabled /> Testnet4
                  </label>
                  <label className="faint">
                    <input type="radio" disabled /> Mainnet (disabled in v1)
                  </label>
                </div>
              </div>
              <label className="field">
                <span>Queue ordering</span>
                <select value={ordering} onChange={(e) => setOrdering(e.target.value as "parallel" | "strict")}>
                  <option value="parallel">Parallel: queued transactions are independent (default)</option>
                  <option value="strict">Strict order: each spends the previous one&apos;s change</option>
                </select>
              </label>
              <div className="row" style={{ justifyContent: "flex-end" }}>
                <button className="btn" disabled={!name.trim()} onClick={() => setStep(2)}>
                  Next
                </button>
              </div>
            </div>
          ) : null}

          {step === 2 ? (
            <div className="card stack">
              <h2>2. Owners</h2>
              <p className="small muted">
                Each owner exports an xpub from their signing device (Sparrow, Coldcard, Jade, Keystone), or connects a Ledger (Chrome/Edge, Bitcoin Test app open) or a Trezor (through Trezor Suite). Paste a key expression like{" "}
                <code>[4ba43603/48&apos;/1&apos;/0&apos;/2&apos;]tpub…</code> to fill all three fields. Only public keys: this app never asks for a seed.
              </p>
              {owners.map((o, i) => (
                <div key={i} className="card" style={{ padding: 16 }}>
                  <div className="row between" style={{ marginBottom: 10 }}>
                    <strong>Owner {i + 1}</strong>
                    {owners.length > 2 ? (
                      <button className="iconbtn" onClick={() => setOwners((os) => os.filter((_, j) => j !== i))}>
                        Remove
                      </button>
                    ) : null}
                  </div>
                  <div className="owner-line">
                    <label className="field">
                      <span>Name</span>
                      <input type="text" value={o.name} onChange={(e) => update(i, { name: e.target.value })} aria-label={`Owner ${i + 1} name`} />
                    </label>
                    <label className="field">
                      <span>Paste key expression (optional)</span>
                      <input
                        type="text"
                        placeholder="[fingerprint/48'/1'/0'/2']tpub…"
                        onChange={(e) => {
                          const k = parseKeyExpression(e.target.value);
                          if (k) update(i, k);
                        }}
                      />
                    </label>
                    <label className="field">
                      <span>Fingerprint</span>
                      <input type="text" value={o.fingerprint} onChange={(e) => update(i, { fingerprint: e.target.value.trim() })} placeholder="7a3c91e0" aria-label={`Owner ${i + 1} fingerprint`} />
                    </label>
                    <label className="field">
                      <span>Derivation path</span>
                      <input type="text" value={o.path} onChange={(e) => update(i, { path: e.target.value.trim() })} aria-label={`Owner ${i + 1} path`} />
                    </label>
                  </div>
                  <div style={{ marginTop: 10 }}>
                    <LedgerOwnerButton network="signet" onKey={(k) => update(i, k)} />
                  </div>
                  <label className="field" style={{ marginTop: 10 }}>
                    <span>xpub / tpub</span>
                    <input type="text" value={o.xpub} onChange={(e) => update(i, { xpub: e.target.value.trim() })} placeholder="tpubD…" aria-label={`Owner ${i + 1} xpub`} />
                  </label>
                  <div style={{ marginTop: 10 }}>
                    <TrezorAddOwner
                      path={o.path || "m/48'/1'/0'/2'"}
                      network="signet"
                      onOwner={(x) => update(i, { ...x, name: /^Owner \d+$/.test(o.name) ? `Trezor ${x.fingerprint}` : o.name })}
                    />
                  </div>
                  {o.xpub && problems[i] ? <div className="small" style={{ color: "var(--err)", marginTop: 6 }}>{problems[i]}</div> : null}
                  {!problems[i] ? (
                    <div className="small muted" style={{ marginTop: 6 }}>
                      ✓ fp {o.fingerprint} · {o.path} · {o.xpub.slice(0, 12)}…
                    </div>
                  ) : null}
                </div>
              ))}
              <div className="row wrap">
                <button className="btn secondary" disabled={owners.length >= 15} onClick={() => setOwners((os) => [...os, blank(os.length + 1)])}>
                  + Add owner
                </button>
              </div>
              <details>
                <summary className="small muted" style={{ cursor: "pointer" }}>
                  Paste all owners as JSON
                </summary>
                <textarea rows={5} value={bulk} onChange={(e) => setBulk(e.target.value)} placeholder='[{"name":"Alice","xpub":"tpub…","fingerprint":"4ba43603","path":"m/48&apos;/1&apos;/0&apos;/2&apos;"}, …]' aria-label="Owners JSON" />
                <button className="btn secondary small" style={{ marginTop: 8 }} onClick={applyBulk} disabled={!bulk.trim()}>
                  Fill owners
                </button>
              </details>
              <ErrorBox error={error} />
              <div className="row between">
                <button className="btn secondary" onClick={() => setStep(1)}>
                  Back
                </button>
                <button className="btn" disabled={!ownersOk} onClick={() => setStep(3)}>
                  Next
                </button>
              </div>
            </div>
          ) : null}

          {step === 3 ? (
            <div className="card stack">
              <h2>3. Threshold</h2>
              <p className="muted">Any transaction needs confirmations from this many owners.</p>
              <div className="row">
                <select value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} style={{ width: 100 }} aria-label="Threshold">
                  {owners.map((_, i) => (
                    <option key={i + 1} value={i + 1}>
                      {i + 1}
                    </option>
                  ))}
                </select>
                <span>out of {owners.length} owner(s)</span>
              </div>
              {threshold === 1 ? <div className="alert warn">1-of-N means any single owner can spend alone.</div> : null}
              <div className="row between">
                <button className="btn secondary" onClick={() => setStep(2)}>
                  Back
                </button>
                <button className="btn" onClick={() => setStep(4)}>
                  Next
                </button>
              </div>
            </div>
          ) : null}

          {step === 4 ? (
            <div className="card stack">
              <h2>4. Review</h2>
              <div className="kv">
                <span className="k">Name</span>
                <span>{name}</span>
                <span className="k">Network</span>
                <span>Signet</span>
                <span className="k">Policy</span>
                <span>
                  P2WSH sortedmulti, {threshold} of {owners.length}
                </span>
                <span className="k">Owners</span>
                <span>
                  {owners.map((o) => (
                    <div key={o.xpub}>
                      {o.name} <span className="muted mono">fp {o.fingerprint}</span>
                    </div>
                  ))}
                </span>
              </div>
              {review && "error" in review ? <div className="alert err">{review.error}</div> : null}
              {review && "descriptor" in review ? (
                <>
                  <div>
                    <h3>Descriptor (computed in this browser)</h3>
                    <div className="mono break small card" style={{ padding: 12 }}>
                      {review.descriptor} <CopyButton text={review.descriptor} />
                    </div>
                  </div>
                  <div>
                    <h3>First receive addresses</h3>
                    {review.addrs.map((a, i) => (
                      <div key={a} className="mono small">
                        #{i} {a}
                      </div>
                    ))}
                  </div>
                  <div className="alert info">
                    <strong>Before funding:</strong> register the wallet (BSMS file) on each signing device and check that address #0 shown on the device matches{" "}
                    <span className="mono">{review.addrs[0].slice(0, 10)}…</span>
                  </div>
                </>
              ) : null}
              <ErrorBox error={error} />
              <div className="row between">
                <button className="btn secondary" onClick={() => setStep(3)}>
                  Back
                </button>
                <button className="btn accent" disabled={busy || !review || "error" in review} onClick={() => void create()}>
                  {busy ? "Creating…" : "Create account"}
                </button>
              </div>
            </div>
          ) : null}
        </>
      )}
    </>
  );
}

function BackupStep({ w, clientAddrs, onOpen }: { w: CreatedWallet; clientAddrs: string[] | null; onOpen: () => void }) {
  const [downloaded, setDownloaded] = useState(false);
  const [ticked, setTicked] = useState(false);
  // Independent check: re-derive the server's first addresses from the owners it stored.
  const derived = useMemo(() => {
    try {
      return [0, 1, 2].map((i) => deriveAddress(w.owners, w.threshold, 0, i, networkFor(w.network)));
    } catch {
      return null;
    }
  }, [w]);
  const match = derived !== null && derived.every((a, i) => a === w.first_addresses[i]) && (!clientAddrs || clientAddrs.every((a, i) => a === w.first_addresses[i]));
  return (
    <div className="card stack">
      <h1>Back up “{w.name}”</h1>
      {match ? (
        <div className="alert ok">✓ The server&apos;s first addresses match the ones this browser derived from the owner xpubs.</div>
      ) : (
        <div className="alert err">
          ✗ Address mismatch between the server and this browser. Do not fund this account until you understand why.
          <ul>
            {w.first_addresses.map((a, i) => (
              <li key={a} className="mono">
                server #{i} {a} · browser {derived?.[i] ?? "—"}
              </li>
            ))}
          </ul>
        </div>
      )}
      <Warnings items={[...(w.warnings ?? []), ...(w.import?.warnings ?? [])]} />
      <p>{w.backup.notice}</p>
      <div className="row wrap">
        <button
          className="btn"
          onClick={() => {
            download(`${w.name.replace(/\W+/g, "-")}.bsms`, w.backup.bsms, "text/plain");
            setDownloaded(true);
          }}
        >
          ⇩ Download BSMS backup
        </button>
        <button
          className="btn secondary"
          onClick={() => {
            download(`${w.name.replace(/\W+/g, "-")}-descriptor.txt`, w.backup.descriptor + "\n", "text/plain");
            setDownloaded(true);
          }}
        >
          ⇩ Download descriptor
        </button>
      </div>
      <div className="mono small break card" style={{ padding: 12 }}>
        {w.backup.descriptor}
      </div>
      <div>
        <h3>First receive addresses</h3>
        {w.first_addresses.map((a, i) => (
          <div key={a} className="mono small">
            #{i} {a}
          </div>
        ))}
      </div>
      <div className="alert info">{w.verify}</div>
      <label className="row">
        <input type="checkbox" checked={ticked} onChange={(e) => setTicked(e.target.checked)} style={{ width: "auto" }} /> I have stored a backup of this
        descriptor.
      </label>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button className="btn accent" disabled={!(downloaded || ticked)} onClick={onOpen}>
          Open account
        </button>
      </div>
    </div>
  );
}

export default function NewAccount() {
  return (
    <>
      <TopBar />
      <main className="main full">
        <Suspense>
          <Wizard />
        </Suspense>
      </main>
    </>
  );
}
