"use client";

import { useEffect, useState, type ReactNode } from "react";
import QRCode from "qrcode";
import { warningText } from "@/lib/warnings";

/** Our own mark: an amber shield with a keyhole. Not derived from any Safe asset. */
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
      <path d="M16 2 28 7v8c0 7.5-5.2 12.8-12 15C9.2 27.8 4 22.5 4 15V7z" fill="#e8820c" />
      <circle cx="16" cy="14" r="4" fill="#fff" />
      <rect x="14.4" y="16" width="3.2" height="7" rx="1.2" fill="#fff" />
    </svg>
  );
}

function hash(s: string): number[] {
  // FNV-1a, expanded: enough entropy for a 5x5 mirrored grid + a hue.
  const out: number[] = [];
  let h = 0x811c9dc5;
  for (let r = 0; r < 4; r++) {
    for (const c of s + r) {
      h ^= c.charCodeAt(0);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    out.push(h);
  }
  return out;
}

/** Deterministic blocky avatar for an account id. */
export function Identicon({ seed, size = 36 }: { seed: string; size?: number }) {
  const h = hash(seed);
  const hue = h[0] % 360;
  const cells: ReactNode[] = [];
  for (let y = 0; y < 5; y++)
    for (let x = 0; x < 3; x++) {
      const bit = (h[1 + (y % 3)] >> (x * 5 + y)) & 1;
      if (!bit) continue;
      cells.push(<rect key={`${x}-${y}`} x={x} y={y} width="1" height="1" />);
      if (x < 2) cells.push(<rect key={`m${x}-${y}`} x={4 - x} y={y} width="1" height="1" />);
    }
  return (
    <svg width={size} height={size} viewBox="-0.5 -0.5 6 6" style={{ borderRadius: "50%", background: `hsl(${hue} 60% 92%)`, flex: "none" }} aria-hidden>
      <g fill={`hsl(${hue} 55% 45%)`}>{cells}</g>
    </svg>
  );
}

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="iconbtn"
      title="Copy"
      onClick={() => {
        void navigator.clipboard?.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1200);
      }}
    >
      {done ? "✓" : "⧉"}
      {label ? <span style={{ marginLeft: 4 }}>{done ? "Copied" : label}</span> : null}
    </button>
  );
}

export function Qr({ value, size = 200 }: { value: string; size?: number }) {
  const [src, setSrc] = useState<string>("");
  useEffect(() => {
    QRCode.toDataURL(value, { width: size, margin: 1, errorCorrectionLevel: "L" }).then(setSrc, () => setSrc(""));
  }, [value, size]);
  // eslint-disable-next-line @next/next/no-img-element
  return src ? <img src={src} width={size} height={size} alt="QR code" /> : <div style={{ width: size, height: size }} />;
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" role="dialog" aria-label={title} onClick={(e) => e.stopPropagation()}>
        <div className="row between" style={{ marginBottom: 16 }}>
          <h2 style={{ margin: 0 }}>{title}</h2>
          <button className="iconbtn" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof Error ? error.message : String(error);
  return <div className="alert err">{msg}</div>;
}

export function Warnings({ items }: { items: unknown[] | undefined }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="alert warn">
      <strong>Warnings</strong>
      <ul>
        {items.map((w, i) => (
          <li key={i}>{warningText(w)}</li>
        ))}
      </ul>
    </div>
  );
}
