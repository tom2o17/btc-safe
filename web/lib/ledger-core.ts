// Ledger logic that doesn't touch the device: the wallet policy the device registers, merging
// the partial signatures it returns into our PSBT, and turning device errors into states the
// UI can show. No `@/` imports, so node can load this file directly (e2e/ledger-speculos.mjs).
//
// The device talks to us through LedgerHQ's `ledger-bitcoin` client (app-bitcoin-new ≥ 2.1).
// Mirrors crates/core/src/ledger.rs; the server rejects a registration whose policy differs.

import { Psbt } from "bitcoinjs-lib";
import * as ecc from "@bitcoinerlab/secp256k1";

/** BIP-48 P2WSH multisig account on test networks (coin type 1'). */
export const OWNER_PATH = "m/48'/1'/0'/2'";
export const MIN_APP_VERSION = "2.1.0";
const MAX_NAME_LEN = 64;

export type LedgerPolicyJson = { name: string; descriptor_template: string; keys: string[] };
export type LedgerRegistration = {
  owner_id: string;
  fingerprint: string | null;
  policy: LedgerPolicyJson;
  policy_id: string;
  hmac: string;
  matches_wallet: boolean;
  registered_at: string;
};
export type LedgerInfo = { policy: LedgerPolicyJson; policy_id: string; registrations: LedgerRegistration[] };

type KeyOwner = { fingerprint: string; path: string; xpub: string; position: number };

/** Same rules as `device_name` in Rust: printable ASCII, trimmed, ≤ 64 bytes, non-empty. */
export function deviceName(walletName: string): string {
  let s = Array.from(walletName).filter((c) => c >= " " && c <= "~").join("").trim();
  if (s.length > MAX_NAME_LEN) s = s.slice(0, MAX_NAME_LEN).trimEnd();
  return s || "BTC Safe";
}

/** The policy the browser expects, rebuilt from the owners so a server can't swap it. */
export function expectedPolicy(walletName: string, owners: KeyOwner[], threshold: number): LedgerPolicyJson {
  const sorted = [...owners].sort((a, b) => a.position - b.position);
  const keys = sorted.map((o) => {
    const path = o.path.replace(/^m\/?/, "").replace(/h/g, "'");
    return `[${path ? `${o.fingerprint}/${path}` : o.fingerprint}]${o.xpub}`;
  });
  return {
    name: deviceName(walletName),
    descriptor_template: `wsh(sortedmulti(${threshold},${sorted.map((_, i) => `@${i}/**`).join(",")}))`,
    keys,
  };
}

export function samePolicy(a: LedgerPolicyJson, b: LedgerPolicyJson): boolean {
  return a.name === b.name && a.descriptor_template === b.descriptor_template && a.keys.length === b.keys.length && a.keys.every((k, i) => k === b.keys[i]);
}

export type PartialSig = { inputIndex: number; pubkey: Uint8Array; signature: Uint8Array };

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/**
 * Add the device's signatures to the PSBT. Every signature must be for a key that the input's
 * own bip32_derivation lists, and must verify against the input's sighash here, before
 * anything is uploaded. The server re-validates everything regardless.
 */
export function mergePartialSigs(psbtB64: string, sigs: PartialSig[]): { psbt: string; added: number } {
  const psbt = Psbt.fromBase64(psbtB64);
  let added = 0;
  for (const s of sigs) {
    const input = psbt.data.inputs[s.inputIndex];
    if (!input) throw new Error(`device signed input ${s.inputIndex}, which this PSBT doesn't have`);
    const pk = hex(s.pubkey);
    if (!(input.bip32Derivation ?? []).some((d) => hex(d.pubkey) === pk)) {
      throw new Error(`device signed input ${s.inputIndex} with a key that isn't one of this wallet's (${pk})`);
    }
    if ((input.partialSig ?? []).some((p) => hex(p.pubkey) === pk)) continue;
    psbt.updateInput(s.inputIndex, { partialSig: [{ pubkey: s.pubkey, signature: s.signature }] });
    const ok = psbt.validateSignaturesOfInput(s.inputIndex, (pubkey, msghash, signature) => ecc.verify(msghash, pubkey, signature), s.pubkey);
    if (!ok) throw new Error(`signature for input ${s.inputIndex} doesn't verify`);
    added++;
  }
  return { psbt: psbt.toBase64(), added };
}

export type DeviceState =
  | "unsupported" // no WebHID in this browser
  | "not_connected" // no device picked, unplugged, or busy in another tab/app
  | "locked"
  | "wrong_app" // dashboard, mainnet Bitcoin app, or another coin's app
  | "old_app"
  | "not_registered"
  | "rejected" // user pressed Reject on the device
  | "bad_hmac" // device doesn't recognise our registration (other seed, or reset)
  | "error";

export type DeviceProblem = { state: DeviceState; message: string };

/** Map ledger transport/app errors to something a person can act on. */
export function classifyLedgerError(e: unknown): DeviceProblem {
  const err = e as { name?: string; statusCode?: number; message?: string };
  const msg = err?.message ?? String(e);
  const sc = err?.statusCode;
  if (err?.name === "TransportOpenUserCancelled" || err?.name === "NotFoundError" || /no device selected/i.test(msg))
    return { state: "not_connected", message: "No Ledger selected. Plug it in, unlock it, and pick it in the browser prompt." };
  if (err?.name === "DisconnectedDevice" || err?.name === "DisconnectedDeviceDuringOperation" || /disconnected/i.test(msg))
    return { state: "not_connected", message: "The Ledger disconnected. Reconnect it and try again." };
  if (err?.name === "TransportInterfaceNotAvailable" || /unable to claim interface|already open|InvalidStateError/i.test(msg))
    return { state: "not_connected", message: "The Ledger is busy in another tab or app (Ledger Live?). Close it and retry." };
  if (err?.name === "LockedDeviceError" || sc === 0x5515)
    return { state: "locked", message: "The Ledger is locked. Enter your PIN on the device." };
  if (sc === 0x6985) return { state: "rejected", message: "Rejected on the device." };
  if (sc === 0x6e00 || sc === 0x6e01 || sc === 0x6d00 || sc === 0x6d02 || sc === 0x6511)
    return { state: "wrong_app", message: "Open the Bitcoin Test app on the Ledger." };
  // app-bitcoin-new answers SW_SIGNATURE_FAIL (0xB008) when the policy HMAC doesn't check out
  // (seen on Speculos, app 2.5.1).
  if (sc === 0xb008 || /Invalid HMAC/i.test(msg))
    return { state: "bad_hmac", message: "The Ledger didn't accept this wallet's registration. Register the wallet on this device again." };
  return { state: "error", message: `Ledger error${sc ? ` 0x${sc.toString(16)}` : ""}: ${msg}` };
}

function versionAtLeast(v: string, min: string): boolean {
  const a = v.split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const b = min.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((a[i] ?? 0) !== b[i]) return (a[i] ?? 0) > b[i];
  return true;
}

/** Problem with the app that's open, or null when it's the right one for `network`. */
export function checkApp(name: string, version: string, network: string): DeviceProblem | null {
  const want = network === "mainnet" || network === "bitcoin" ? "Bitcoin" : "Bitcoin Test";
  if (name === "BOLOS") return { state: "wrong_app", message: `No app is open. Open the ${want} app on the Ledger.` };
  if (name !== want) return { state: "wrong_app", message: `The ${name} app is open. This wallet is on ${network}: open the ${want} app.` };
  if (!versionAtLeast(version, MIN_APP_VERSION))
    return { state: "old_app", message: `${name} ${version} is too old. Update it to ${MIN_APP_VERSION} or later in Ledger Live.` };
  return null;
}
