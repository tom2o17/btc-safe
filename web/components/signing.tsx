"use client";

import { useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import { splitQRs } from "bbqr";
import { api, type Proposal } from "@/lib/api";
import { base64ToBytes, bytesToBase64, download } from "@/lib/format";
import { ErrorBox } from "./ui";

type Format = "bbqr" | "ur";

/**
 * Animated QR for air-gapped signers. BBQr (Coinkite's format: Coldcard Q, Sparrow) via the
 * `bbqr` package, or UR `crypto-psbt` (Keystone, Jade, Sparrow, Passport) via `@ngraveio/bc-ur`.
 * Device acceptance is UNVERIFIED until Phase 3 tests real devices.
 */
export function AnimatedQr({ psbtB64, size = 300 }: { psbtB64: string; size?: number }) {
  const [format, setFormat] = useState<Format>("bbqr");
  const [frame, setFrame] = useState<{ src: string; i: number; n: number | null } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [fps, setFps] = useState(4);

  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setInterval> | undefined;
    const bytes = base64ToBytes(psbtB64);
    setErr(null);
    (async () => {
      let next: () => { data: string; i: number; n: number | null };
      if (format === "bbqr") {
        const { parts } = splitQRs(bytes, "P", { encoding: "Z", maxVersion: 15 });
        let i = 0;
        next = () => {
          const r = { data: parts[i], i: i + 1, n: parts.length };
          i = (i + 1) % parts.length;
          return r;
        };
      } else {
        const { Buffer } = await import("buffer");
        (globalThis as { Buffer?: unknown }).Buffer ??= Buffer;
        const { UR, UREncoder } = await import("@ngraveio/bc-ur");
        const ur = new UR(UR.fromBuffer(Buffer.from(bytes)).cbor, "crypto-psbt");
        const enc = new UREncoder(ur, 200);
        const n = enc.fragmentsLength;
        let i = 0;
        next = () => ({ data: enc.nextPart().toUpperCase(), i: (i++ % Math.max(n, 1)) + 1, n: n > 1 ? n : 1 });
      }
      const tick = async () => {
        const f = next();
        const src = await QRCode.toDataURL(f.data, { width: size, margin: 1, errorCorrectionLevel: "L" });
        if (!stop) setFrame({ src, i: f.i, n: f.n });
      };
      await tick();
      timer = setInterval(() => void tick(), 1000 / fps);
    })().catch((e) => setErr(String(e)));
    return () => {
      stop = true;
      if (timer) clearInterval(timer);
    };
  }, [psbtB64, format, size, fps]);

  return (
    <div className="stack" style={{ textAlign: "center" }}>
      <div className="tabs" style={{ justifyContent: "center" }}>
        <button className={format === "bbqr" ? "active" : ""} onClick={() => setFormat("bbqr")}>
          BBQr
        </button>
        <button className={format === "ur" ? "active" : ""} onClick={() => setFormat("ur")}>
          UR (crypto-psbt)
        </button>
      </div>
      {err ? <div className="alert err">{err}</div> : null}
      <div className="qrbox">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        {frame ? <img src={frame.src} width={size} height={size} alt="Animated PSBT QR" /> : <div style={{ width: size, height: size }} />}
        <span className="small muted">
          Frame {frame?.i ?? "–"} of {frame?.n ?? "–"}
          {format === "ur" ? " (fountain-coded: keep scanning)" : ""}
        </span>
      </div>
      <div className="row" style={{ justifyContent: "center" }}>
        <span className="small muted">Speed</span>
        {[2, 4, 8].map((f) => (
          <button key={f} className={`btn small ${fps === f ? "" : "secondary"}`} onClick={() => setFps(f)}>
            {f} fps
          </button>
        ))}
      </div>
      <p className="small muted">
        {format === "bbqr" ? "For Coldcard Q and Sparrow." : "For Keystone, Jade, Passport and Sparrow."} Scan, check the
        amounts and change on the device screen, sign, then upload the signed PSBT below.
      </p>
    </div>
  );
}

/** Accepts binary PSBT (`psbt\xff…`), base64 or hex; returns base64. */
export function normalizePsbt(raw: Uint8Array): string {
  if (raw.length > 5 && raw[0] === 0x70 && raw[1] === 0x73 && raw[2] === 0x62 && raw[3] === 0x74 && raw[4] === 0xff) return bytesToBase64(raw);
  const text = new TextDecoder().decode(raw).trim();
  if (/^[0-9a-fA-F]+$/.test(text) && text.startsWith("70736274ff")) {
    const b = new Uint8Array(text.length / 2);
    for (let i = 0; i < b.length; i++) b[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
    return bytesToBase64(b);
  }
  if (!text.startsWith("cHNidP")) throw new Error("That file is not a PSBT (expected binary, base64 or hex).");
  return text.replace(/\s+/g, "");
}

export function downloadPsbt(p: Proposal) {
  if (!p.psbt) return;
  download(`btc-safe-proposal-${p.id}.psbt`, base64ToBytes(p.psbt));
}

/** Upload one or more signed PSBT files (or paste base64) and submit them to the server. */
export function UploadSigned({ proposalId, onDone }: { proposalId: number; onDone: (p: Proposal) => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [paste, setPaste] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [log, setLog] = useState<string[]>([]);

  async function submit(b64: string, name: string) {
    const r = await api<Proposal & { accepted: { new_signatures: number; already_present: number; status: string } }>(
      `/proposals/${proposalId}/signatures`,
      { body: { psbt: b64 } },
    );
    setLog((l) => [
      ...l,
      `${name}: ${r.accepted.new_signatures} new signature(s), ${r.accepted.already_present} already present → ${r.confirmations.count} of ${r.confirmations.threshold}`,
    ]);
    onDone(r);
  }

  async function onFiles(files: FileList | null) {
    if (!files) return;
    setBusy(true);
    setErr(null);
    try {
      for (const f of Array.from(files)) await submit(normalizePsbt(new Uint8Array(await f.arrayBuffer())), f.name);
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  return (
    <div className="stack">
      <div className="row wrap">
        <input ref={fileRef} type="file" accept=".psbt,.txt,application/octet-stream" multiple hidden onChange={(e) => void onFiles(e.target.files)} data-testid="psbt-file" />
        <button className="btn" disabled={busy} onClick={() => fileRef.current?.click()}>
          ⇪ Upload signed PSBT
        </button>
        <span className="small muted">Binary, base64 or hex. Several files at once is fine.</span>
      </div>
      <details>
        <summary className="small muted" style={{ cursor: "pointer" }}>
          …or paste base64
        </summary>
        <textarea rows={4} value={paste} onChange={(e) => setPaste(e.target.value)} placeholder="cHNidP8B…" />
        <button
          className="btn secondary small"
          style={{ marginTop: 8 }}
          disabled={busy || !paste.trim()}
          onClick={async () => {
            setBusy(true);
            setErr(null);
            try {
              await submit(normalizePsbt(new TextEncoder().encode(paste)), "pasted PSBT");
              setPaste("");
            } catch (e) {
              setErr(e);
            } finally {
              setBusy(false);
            }
          }}
        >
          Submit pasted PSBT
        </button>
      </details>
      <ErrorBox error={err} />
      {log.length ? (
        <div className="alert ok">
          {log.map((l, i) => (
            <div key={i}>{l}</div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
