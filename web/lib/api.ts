import type { BlockConfirmations } from "./format";
// Typed client for the Rust API (DESIGN.md §5.2). All calls go through the /api proxy
// (next.config.ts). Amounts are satoshis; PSBTs are base64.

// Auth: an HttpOnly session cookie (set by /auth/login or /auth/setup, never readable here) plus
// a CSRF token that every state-changing request sends as X-CSRF-Token. The CSRF token lives
// only in memory and is re-read from /auth/me after a reload.

import type { Role } from "./roles";

export type { Role };

/** What every session-establishing response returns (login, signup, MFA, password/TOTP changes). */
export type Session = { email: string; is_admin: boolean; csrf_token: string; totp_enabled: boolean };

export type Me = Session & {
  recovery_codes_left?: number;
  session_expires_at?: string;
  idle_timeout_secs?: number;
};

let csrf: string | null = null;

/** Any response carrying csrf_token means the server rotated the session: adopt the new token. */
export function setSession(me: { csrf_token?: string } | null) {
  csrf = me?.csrf_token ?? null;
}

/** The current user, or null when logged out. */
export async function fetchMe(): Promise<Me | null> {
  const res = await fetch("/api/auth/me", { cache: "no-store" });
  if (res.status === 401) {
    setSession(null);
    return null;
  }
  if (!res.ok) throw new ApiError(res.status, String(res.status), `auth check failed (${res.status})`);
  const me = (await res.json()) as Me;
  setSession(me);
  return me;
}

export function goToLogin() {
  if (typeof window === "undefined") return;
  const p = window.location.pathname;
  if (p.startsWith("/login") || p.startsWith("/setup") || p.startsWith("/signup")) return;
  window.location.assign(`/login?next=${encodeURIComponent(p + window.location.search)}`);
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message);
  }
}

export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const headers: Record<string, string> = {};
  const method = init.method ?? (init.body !== undefined ? "POST" : "GET");
  if (method !== "GET" && method !== "HEAD") {
    if (!csrf) await fetchMe().catch(() => null);
    if (csrf) headers["x-csrf-token"] = csrf;
  }
  if (init.body !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    cache: "no-store",
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let json: unknown = undefined;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    /* non-JSON body */
  }
  if (!res.ok) {
    const j = (json ?? {}) as { error?: string; message?: string; details?: unknown };
    if (res.status === 401) goToLogin();
    const msg =
      res.status === 401
        ? "Logged out: please log in again."
        : res.status === 429
          ? (j.message ?? "Too many requests: wait a moment and retry.")
          : (j.message ?? (text || res.statusText));
    throw new ApiError(res.status, j.error ?? String(res.status), msg, j.details);
  }
  adoptRotatedCsrf(json);
  return json as T;
}

function adoptRotatedCsrf(json: unknown) {
  if (json && typeof json === "object" && typeof (json as { csrf_token?: unknown }).csrf_token === "string") {
    csrf = (json as { csrf_token: string }).csrf_token;
  }
}

/**
 * Pre-session auth calls (signup, login, MFA): no CSRF header, and a 401 is an answer
 * (wrong password, bad code), not a reason to bounce to /login. Errors carry the server's
 * {error, message}.
 */
export async function authCall<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  const j = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    const msg = typeof j.message === "string" ? j.message : res.status === 429 ? "Too many attempts. Wait a minute and try again." : `request failed (${res.status})`;
    throw new ApiError(res.status, typeof j.error === "string" ? j.error : String(res.status), msg, j.details);
  }
  adoptRotatedCsrf(j);
  return j as T;
}

export type SignupInfo = { open: boolean; min_password: number; pow: { challenge: string; bits: number } | null };

export type LoginResult = Session | { mfa_required: true; mfa_token: string };

export type TotpSetup = { secret: string; otpauth_uri: string };

export type Member = { user_id: string; email: string; role: Role; added_at: string; self_signup?: boolean };

export type Balance = { confirmed_sats: number; unconfirmed_sats: number; reserved_sats: number; available_sats: number };

export type Owner = { id: string; name: string; fingerprint: string; path: string; xpub: string; kind: string; position: number };

export type WalletListItem = { id: string; name: string; network: string; threshold: number; owners_count: number; ordering_mode: string; role?: Role };

export type Wallet = WalletListItem & {
  /** The logged-in user's role on this wallet. */
  my_role?: Role;
  owners: Owner[];
  policy: string;
  descriptor: { external: string; internal: string; multipath: string };
  balance: Balance | null;
  queue_count: number;
  tip_height: number | null;
  /** CONFIRMATIONS_FINAL: block depth at which a sent transaction is final. */
  confirmations_final?: number;
  last_synced_at: string | null;
  next_receive_index: number;
  warnings: string[];
  created_at: string;
};

export type CreatedWallet = Wallet & {
  first_addresses: string[];
  backup: { bsms: string; descriptor: string; notice: string };
  verify: string;
  import?: { format: string; warnings: string[] };
};

export type Backup = { name: string; network: string; descriptor: string; external: string; internal: string; bsms: string; first_addresses: string[] };

export type AddressInfo = { keychain: string; index: number; path: string; address: string; witness_script: string; label: string | null; verify: string };

export type Utxo = {
  outpoint: string;
  amount_sats: number;
  address: string | null;
  keychain: string;
  index: number;
  confirmations: number;
  status: "available" | "reserved" | "unconfirmed";
  reserved_by: number | null;
  label: string | null;
};

export type OwnerConfirmation = { owner_id: string | null; name: string | null; fingerprint: string; signed: boolean; inputs_signed: number };

export type Proposal = {
  id: number;
  wallet_id: string;
  status: string;
  status_reason: string | null;
  created_by: string | null;
  unsigned_txid: string;
  fee_sats: number;
  fee_rate_sat_vb: number;
  est_vsize: number;
  sent_sats: number;
  rbf: boolean;
  fee_override: boolean;
  replaces: number | null;
  replacement_group: string | null;
  predecessor: number | null;
  broadcast_txid: string | null;
  invalidated_by_txid: string | null;
  confirmed_height: number | null;
  /** Block depth. `final` = CONFIRMATIONS_FINAL reached; never re-checked after that. */
  block_confirmations?: BlockConfirmations;
  inputs: { outpoint: string; amount_sats: number; keychain: string; index: number }[];
  outputs: { vout: number; address: string; amount_sats: number; is_change: boolean; change_index: number | null }[];
  confirmations: { threshold: number; count: number; ready: boolean; owners: OwnerConfirmation[] };
  created_at: string;
  updated_at: string;
  note: string;
  psbt?: string;
  warnings?: unknown[];
  signature_log?: unknown[];
  final_tx_hex?: string;
};

export type HistoryTx = {
  txid: string;
  height: number | null;
  received_sats: number;
  sent_sats: number;
  fee_sats: number | null;
  proposal_id: number | null;
  origin: "proposal" | "external" | "incoming";
};

export type Fees = { fast_sat_vb: number; normal_sat_vb: number; slow_sat_vb: number; source: string };

export type BookEntry = { id: string; label: string; address: string };

export type Health = { ok: boolean; chain: string; tip: number };
