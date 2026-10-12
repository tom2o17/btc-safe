// Trezor signer over Trezor Connect 10 (@trezor/connect-web). Connect 10 has no iframe of its own:
// every call goes to Trezor Suite, either Suite desktop over a localhost WebSocket or Suite Web in a
// popup (suite.trezor.io). Suite shows the permission prompt, PIN and passphrase; the device shows
// the outputs. The page must not send `Cross-Origin-Opener-Policy: same-origin`, and any CSP must
// allow framing https://suite.trezor.io (we set neither).
//
// Watch-only: Connect returns xpubs and signatures; keys stay on the device.

import { BIP32Factory } from "bip32";
import * as ecc from "@bitcoinerlab/secp256k1";
import type { KeyOwner } from "../bitcoin";
import { OLD_FIRMWARE_SYMPTOM, buildTrezorAddressRequest, buildTrezorRequest, fingerprintHex, mergeSignatures, networkFor, trezorCoin, type BuiltRequest } from "./trezor-tx";
import { SignerError, type SignContext, type SignResult, type SignerAdapter, type SignerErrorCode, type XpubResult } from "./types";

type Ok<T> = { success: true; payload: T };
// Connect 10 failures are `{ success: false, error: { message, code } }` (v9 used payload.error).
type Fail = { success: false; error?: { message?: string; code?: string }; payload?: { error?: string; code?: string } };
type Res<T> = Ok<T> | Fail;
type HDNode = { xpub: string; publicKey: string; chainCode: string; rootFingerprint?: number; descriptor?: string; serializedPath: string; depth: number };

// Narrow view of the public API we use; the package's own types are much larger.
type Connect = {
  init(s: { manifest: { appName: string; appUrl: string; email: string; appIcon?: string }; coreMode?: string }): Promise<void>;
  getPublicKey(p: { bundle: { path: string; coin: string; showOnTrezor?: boolean }[] }): Promise<Res<HDNode[]>>;
  signTransaction(p: unknown): Promise<Res<{ signatures: string[]; serializedTx: string }>>;
  // @trezor/connect-common types/api/account/getAddress.d.ts (10.0.1).
  getAddress(p: unknown): Promise<Res<{ address: string; path: number[]; serializedPath: string }>>;
};

const bip32 = BIP32Factory(ecc);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

let ready: Promise<Connect> | null = null;

function connect(): Promise<Connect> {
  if (typeof window === "undefined") return Promise.reject(new SignerError("not_connected", "Trezor needs a browser"));
  ready ??= (async () => {
    const mod = await import("@trezor/connect-web");
    const T = mod.default as unknown as Connect;
    try {
      await T.init({
        manifest: {
          appName: "BTC Safe",
          appUrl: window.location.origin,
          email: process.env.NEXT_PUBLIC_TREZOR_MANIFEST_EMAIL ?? "btc-safe@example.com",
          appIcon: `${window.location.origin}/icon.svg`,
        },
        // "auto" (default): Suite desktop if running, else Suite Web popup. Note Connect 10.0.1
        // falls back to Suite Web on Desktop_ConnectionMissing even when pinned to "suite-desktop".
        coreMode: process.env.NEXT_PUBLIC_TREZOR_CORE_MODE ?? "auto",
      });
    } catch (e) {
      if (!String((e as Error)?.message ?? e).includes("already initialized")) throw e;
    }
    return T;
  })().catch((e) => {
    ready = null;
    throw toSignerError(e);
  });
  return ready;
}

const CODE: Record<string, SignerErrorCode> = {
  Method_Interrupted: "cancelled",
  Method_Cancel: "cancelled",
  Method_PermissionsNotGranted: "cancelled",
  Failure_ActionCancelled: "cancelled",
  Failure_PinCancelled: "cancelled",
  Device_NotFound: "not_connected",
  Device_Disconnected: "not_connected",
  Transport_Missing: "not_connected",
  Desktop_ConnectionMissing: "not_connected",
  Popup_ConnectionMissing: "not_connected",
  Handshake_Error: "not_connected",
  Browser_LocalNetworkPermissionMissing: "not_connected",
  Method_UnknownCoin: "wrong_network",
  Method_UnsupportedCoinForHost: "wrong_network",
  Device_UsedElsewhere: "busy",
  Device_CallInProgress: "busy",
  Device_MissingCapability: "unsupported",
  Device_MissingCapabilityBtcOnly: "unsupported",
  Method_Unsupported: "unsupported",
};

function toSignerError(e: unknown): SignerError {
  if (e instanceof SignerError) return e;
  const p = (e ?? {}) as { code?: string; error?: string; message?: string };
  const msg = p.message ?? p.error ?? (e === undefined ? "Trezor Suite returned an error without details" : typeof e === "object" ? JSON.stringify(e) : String(e));
  let code: SignerErrorCode = (p.code && CODE[p.code]) || "failed";
  if (code === "failed" && /unknown coin|not supported by trezor suite/i.test(msg)) code = "wrong_network";
  if (code === "failed" && OLD_FIRMWARE_SYMPTOM.test(msg)) return new SignerError("unsupported", `${msg}: the Trezor built a different script than this wallet's, so its firmware ignores sortedmulti ordering`);
  // "Forbidden key path" can be a mainnet path on a testnet coin, a nonstandard origin, or a
  // chain/index past the firmware's BIP-48 limits; say that instead of guessing.
  if (code === "failed" && /forbidden key path/i.test(msg)) return new SignerError("failed", `${msg}: the device refuses this derivation path (wrong network's path, nonstandard origin, or index out of range)`);
  // getAddress with `address` set: the device derived something else.
  if (p.code === "Method_AddressNotMatch" || /addresses do not match/i.test(msg))
    return new SignerError("failed", "MISMATCH: the Trezor derived a different address than the one on this page. Do not use this address");
  if (code === "failed" && /cancel/i.test(msg)) code = "cancelled";
  // No Suite desktop and the Suite Web popup/iframe never answered (blocked popup, offline, or a
  // CSP/COOP header in the way). Connect reports this without a code.
  if (code === "failed" && /handshake|websocket|timeout/i.test(msg)) code = "not_connected";
  return new SignerError(code, msg);
}

async function call<T>(f: (T: Connect) => Promise<Res<T>>): Promise<T> {
  const T = await connect();
  let r: Res<T>;
  try {
    r = await f(T);
  } catch (e) {
    throw toSignerError(e);
  }
  if (!r.success) throw toSignerError(r.error ?? r.payload);
  return r.payload;
}

function rootFp(n: HDNode): string {
  if (typeof n.rootFingerprint === "number") return fingerprintHex(n.rootFingerprint);
  const m = n.descriptor?.match(/\[([0-9a-fA-F]{8})/);
  if (m) return m[1].toLowerCase();
  throw new SignerError("unsupported", "Trezor didn't return the master fingerprint; update the firmware and Trezor Suite");
}

function samePubkey(xpubA: string, xpubB: string, network: string): boolean {
  try {
    const a = bip32.fromBase58(xpubA, networkFor(network));
    const b = bip32.fromBase58(xpubB, networkFor(network));
    return a.depth === b.depth && hex(a.publicKey) === hex(b.publicKey) && hex(a.chainCode) === hex(b.chainCode);
  } catch {
    return false;
  }
}

/** Returns the device's key at each path (one Suite prompt for all). */
async function keysAt(paths: string[], network: string): Promise<HDNode[]> {
  const coin = trezorCoin(network);
  return call((T) => T.getPublicKey({ bundle: paths.map((path) => ({ path, coin, showOnTrezor: false })) }));
}

function checkNetwork(n: HDNode, network: string) {
  try {
    bip32.fromBase58(n.xpub, networkFor(network));
  } catch {
    throw new SignerError("wrong_network", `Trezor returned ${n.xpub.slice(0, 4)}…, which isn't a ${network} key`);
  }
}

/** Which of `owners` is the connected Trezor (matching its xpub at each owner's path). */
export async function identify(owners: KeyOwner[], network: string): Promise<{ owner: KeyOwner; deviceFingerprint: string }> {
  const paths = [...new Set(owners.map((o) => o.path))];
  const nodes = await keysAt(paths, network);
  const fps = new Set<string>();
  for (let i = 0; i < paths.length; i++) {
    const n = nodes[i];
    checkNetwork(n, network);
    const fp = rootFp(n);
    fps.add(fp);
    for (const o of owners.filter((o) => o.path === paths[i])) {
      if (o.fingerprint.toLowerCase() === fp && (samePubkey(o.xpub, n.xpub, network))) return { owner: o, deviceFingerprint: fp };
    }
  }
  const fp = [...fps].join(", ");
  const sameFp = owners.find((o) => fps.has(o.fingerprint.toLowerCase()));
  throw new SignerError(
    "wrong_device",
    sameFp
      ? `This Trezor (fp ${fp}) has the fingerprint of ${sameFp.name ?? "an owner"} but a different xpub at ${sameFp.path}. Check the passphrase/hidden wallet selected in Trezor Suite.`
      : `This Trezor (fp ${fp}) isn't one of this account's owners. Connect the right device, or check the passphrase.`,
  );
}

/** Signs as a known owner (from identify()). Re-derives everything before the device sees it. */
async function signAs(psbtB64: string, ctx: SignContext, owner: KeyOwner, onBuilt?: (b: BuiltRequest) => void): Promise<SignResult> {
  let built;
  try {
    built = buildTrezorRequest(psbtB64, ctx.owners, ctx.threshold, ctx.network, owner, ctx.changeIndex);
  } catch (e) {
    throw new SignerError("failed", `Not sending this to the Trezor: ${(e as Error).message}`);
  }
  onBuilt?.(built);
  const out = await call((T) => T.signTransaction(built.request));
  try {
    const merged = mergeSignatures(psbtB64, out.signatures, built.inputPubkeys, ctx.network);
    return { psbt: merged.psbt, signer: owner, inputsSigned: merged.inputsSigned };
  } catch (e) {
    // Old firmware can also skip the input check and sign over its own (unsorted) script.
    throw new SignerError("unsupported", `Trezor's signatures didn't check out (${(e as Error).message}); nothing was merged. Most likely the firmware ignores sortedmulti ordering`);
  }
}

/**
 * Shows one of the wallet's addresses on the Trezor (getAddress with the multisig structure and
 * showOnTrezor) and returns what the device derived. UNVERIFIED on a real device.
 */
async function showAddress(owners: KeyOwner[], threshold: number, network: string, chain: 0 | 1, index: number, expected: string, onDevice?: () => void): Promise<{ address: string; owner: KeyOwner }> {
  const { owner } = await identify(owners, network);
  let req;
  try {
    req = buildTrezorAddressRequest(owners, threshold, network, owner, chain, index, expected);
  } catch (e) {
    throw new SignerError("failed", `Not asking the Trezor: ${(e as Error).message}`);
  }
  onDevice?.();
  const r = await call((T) => T.getAddress(req));
  return { address: r.address, owner };
}

export const trezor: SignerAdapter & { identify: typeof identify; signAs: typeof signAs; showAddress: typeof showAddress } = {
  id: "trezor",
  label: "Trezor",
  identify,
  signAs,
  showAddress,

  async getXpub(path: string, network: string): Promise<XpubResult> {
    const [n] = await keysAt([path], network);
    checkNetwork(n, network);
    return { xpub: n.xpub, fingerprint: rootFp(n), path };
  },

  async signPsbt(psbtB64: string, ctx: SignContext): Promise<SignResult> {
    const { owner } = await identify(ctx.owners, ctx.network);
    return signAs(psbtB64, ctx, owner);
  },
};
