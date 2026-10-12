// Recognise wallet files (Caravan/Sparrow JSON, BSMS, output descriptors) pasted or uploaded in
// the create/import screens. The server does the real parsing and validation (core::import);
// this only routes the text to the right box and reads the wallet name for the Name field.

export type WalletFileFormat = "caravan" | "bsms" | "descriptor";

/** Largest file the import box takes: the API's body limit is 1 MiB. */
export const MAX_IMPORT_BYTES = 512 * 1024;

const FORMAT_LABEL: Record<WalletFileFormat, string> = {
  caravan: "Caravan/Sparrow JSON",
  bsms: "BSMS 1.0",
  descriptor: "output descriptor",
};

export function formatLabel(f: WalletFileFormat): string {
  return FORMAT_LABEL[f];
}

function parseObject(t: string): Record<string, unknown> | null {
  if (!t.startsWith("{")) return null;
  try {
    const v: unknown = JSON.parse(t);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Which wallet-file format `text` is, or null if it isn't one (e.g. an owners array). */
export function sniffWalletFile(text: string): WalletFileFormat | null {
  const t = text.replace(/^﻿/, "").trim();
  if (!t) return null;
  if (t.startsWith("BSMS")) return "bsms";
  const o = parseObject(t);
  if (o) return "extendedPublicKeys" in o || "quorum" in o || "addressType" in o ? "caravan" : null;
  // Descriptor: any non-comment line that starts like a script descriptor.
  const lines = t.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  if (lines.some((l) => /^(wsh|sh|tr|wpkh|pkh)\(/.test(l))) return "descriptor";
  return null;
}

/** The wallet name stored in the file, if the format carries one (Caravan/Sparrow JSON `name`). */
export function walletFileName(text: string): string | null {
  const o = parseObject(text.replace(/^﻿/, "").trim());
  if (!o) return null;
  const n = typeof o.name === "string" ? o.name : typeof o.label === "string" ? o.label : null;
  const clean = n?.trim().slice(0, 100);
  return clean ? clean : null;
}
