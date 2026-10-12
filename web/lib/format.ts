export const SATS = 100_000_000;

export function btc(sats: number | null | undefined, digits = 8): string {
  if (sats === null || sats === undefined) return "—";
  const neg = sats < 0;
  const s = Math.abs(sats);
  const whole = Math.floor(s / SATS);
  const frac = String(s % SATS).padStart(8, "0").slice(0, digits);
  return `${neg ? "-" : ""}${whole.toLocaleString("en-US")}.${frac}`;
}

/** Parses a BTC decimal string into sats without float rounding. */
export function parseBtc(s: string): number | null {
  const m = s.trim().match(/^(\d*)(?:\.(\d{0,8}))?$/);
  if (!m || (m[1] === "" && !m[2])) return null;
  return Number(m[1] || "0") * SATS + Number((m[2] ?? "").padEnd(8, "0"));
}

export function short(s: string | null | undefined, head = 6, tail = 4): string {
  if (!s) return "—";
  return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
}

export function ago(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function download(filename: string, data: string | Uint8Array, mime = "application/octet-stream") {
  const blob = new Blob([data as BlobPart], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

export const STATUS_LABEL: Record<string, string> = {
  pending: "Awaiting confirmations",
  signing: "Awaiting confirmations",
  ready: "Ready to execute",
  broadcast: "Broadcast",
  soft_confirmed: "In a block, waiting for final",
  confirmed: "Final",
  conflicted: "Conflicted",
  invalidated: "Invalidated",
  deleted: "Deleted",
};

export type BlockConfirmations = { count: number | null; final_at: number; final: boolean };

/**
 * Plain-words status of a proposal on chain. "Block confirmations" (depth) are kept apart from
 * owner "confirmations" (signatures), which the queue also shows.
 * - soft_confirmed: "1 block confirmation, waiting for final" (a reorg can still undo it)
 * - confirmed: "Final"
 * - broadcast after a reorg: says so, instead of a bare "Broadcast"
 */
export function chainStatus(p: { status: string; status_reason: string | null; block_confirmations?: BlockConfirmations | null }): {
  label: string;
  tone: "ok" | "warn" | "err" | "";
  note: string | null;
} {
  const bc = p.block_confirmations;
  const reorged = p.status_reason === "reorged_back_to_mempool" || p.status_reason === "reorged_out";
  switch (p.status) {
    case "soft_confirmed": {
      const n = Math.max(1, bc?.count ?? 1);
      return {
        label: `${n} block confirmation${n === 1 ? "" : "s"}, waiting for final`,
        tone: "warn",
        note: `In a block, not final yet${bc ? ` (final at ${bc.final_at})` : ""}. Until then a chain reorganization can still undo it.`,
      };
    }
    case "confirmed":
      return { label: "Final", tone: "ok", note: bc ? `Final at ${bc.final_at} block confirmation${bc.final_at === 1 ? "" : "s"}. No longer re-checked.` : null };
    case "broadcast":
      if (p.status_reason === "reorged_back_to_mempool")
        return { label: "Reorged, waiting to be mined again", tone: "warn", note: "Its block was replaced by a chain reorganization. The transaction is back in the mempool and should be mined again." };
      if (p.status_reason === "reorged_out")
        return { label: "Reorged, not in a block", tone: "warn", note: "Its block was replaced by a chain reorganization and the transaction is not in the mempool. If it stays missing it returns to Ready, and can be sent again." };
      return { label: "Broadcast", tone: "warn", note: null };
    case "ready":
      return { label: STATUS_LABEL.ready, tone: "warn", note: p.status_reason === "dropped_from_mempool" ? "It was sent but dropped out of the mempool (or reorged out). Execute sends it again." : null };
    case "conflicted":
      return { label: STATUS_LABEL.conflicted, tone: "err", note: p.status_reason === "replacement_confirmed" ? "A replacement of this transaction is final instead." : null };
    case "invalidated":
      return { label: STATUS_LABEL.invalidated, tone: "err", note: reorged ? null : p.status_reason === "input_spent_elsewhere" ? "One of its coins was spent by another transaction." : null };
    case "deleted":
      return { label: STATUS_LABEL.deleted, tone: "err", note: null };
    default:
      return { label: STATUS_LABEL[p.status] ?? p.status, tone: "", note: null };
  }
}

/**
 * "≈ $X.XX" for an amount at a BTC/USD price, or null when either is unknown. Display only:
 * never feed the result (or the price) into amounts, fees or validation.
 */
export function usd(sats: number | null | undefined, usdPerBtc: number | null | undefined): string | null {
  if (sats === null || sats === undefined || !Number.isFinite(sats)) return null;
  if (!usdPerBtc || !Number.isFinite(usdPerBtc) || usdPerBtc <= 0) return null;
  const v = (Math.abs(sats) * usdPerBtc) / SATS;
  const neg = sats < 0 ? "-" : "";
  if (v > 0 && v < 0.005) return "< $0.01";
  return `≈ ${neg}$${v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}
