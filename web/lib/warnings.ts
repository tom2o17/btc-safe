// Turns the backend's structured warnings into sentences. Every `kind` the API emits is listed
// here (core::fees::FeeWarning, core::policy::PolicyWarning, core::import::ImportWarning and the
// strict-order warning in api/src/proposals.rs). Unknown kinds fall back to their `message`, or a
// readable "kind: field=value" line, never raw JSON.

type W = { kind?: unknown; message?: unknown; [k: string]: unknown };

const n = (x: unknown) => (typeof x === "number" && Number.isFinite(x) ? x : null);
const sats = (x: unknown) => (n(x) === null ? "?" : `${(n(x) as number).toLocaleString("en-US")} sats`);

export function warningText(w: unknown): string {
  if (typeof w === "string") return w;
  if (!w || typeof w !== "object") return String(w);
  const o = w as W;
  switch (o.kind) {
    case "high_share_of_sent": {
      // The server sends bps = u64::MAX when nothing is sent (e.g. a cancel back to ourselves).
      if (n(o.sent_sats) === 0) return `Fee is ${sats(o.fee_sats)} and nothing goes to a recipient.`;
      const bps = n(o.bps);
      const pct = bps === null ? "a large share" : `${(bps / 100).toFixed(1)}%`;
      return `Fee is ${pct} of the amount sent (${sats(o.fee_sats)} fee to send ${sats(o.sent_sats)}).`;
    }
    case "no_fast_estimate":
      return "No fee estimate was available, so the fee-rate cap could not be checked. Double-check the fee before signing.";
    case "cap_overridden":
      return `A fee safety cap was exceeded and you overrode it: ${typeof o.reason === "string" ? o.reason : "reason not given"}.`;
    case "strict_order_descendants": {
      const ids = Array.isArray(o.proposals) ? o.proposals.map((x) => `#${x}`).join(", ") : "";
      return `Executing this replacement invalidates queued proposal${Array.isArray(o.proposals) && o.proposals.length === 1 ? "" : "s"} ${ids || "after it"}; they must be rebuilt and re-signed.`;
    }
    case "change_path_assumed":
      return "Only a receive descriptor was given; the change path was assumed to be /1/*.";
    case "single_sig_path":
      return `Owner ${o.owner ?? "?"} uses ${o.path ?? "a"} path, which looks like a single-sig account (44'/49'/84'/86'), not a multisig one.`;
    case "non_standard_path":
      return `Owner ${o.owner ?? "?"} uses ${o.path ?? "a non-standard path"}, not the BIP-48 multisig path m/48'/coin'/account'/2'.`;
  }
  if (typeof o.message === "string" && o.message) return o.message;
  const fields = Object.entries(o)
    .filter(([k]) => k !== "kind")
    .map(([k, v]) => `${k.replace(/_/g, " ")} ${typeof v === "object" ? "…" : String(v)}`);
  const head = typeof o.kind === "string" ? o.kind.replace(/_/g, " ") : "Warning";
  return fields.length ? `${head[0].toUpperCase()}${head.slice(1)}: ${fields.join(", ")}.` : `${head[0].toUpperCase()}${head.slice(1)}.`;
}
