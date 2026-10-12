// Ledger over WebHID (Chrome/Edge desktop). The device holds the key; the browser only
// relays: it reads the owner xpub, registers the wallet policy, and asks the device to sign.
// Logic that doesn't need the device lives in ./ledger-core.ts (tested in node + Speculos).

import { api } from "./api";
import {
  OWNER_PATH,
  checkApp,
  classifyLedgerError,
  expectedPolicy,
  mergePartialSigs,
  samePolicy,
  type DeviceProblem,
  type LedgerInfo,
  type LedgerPolicyJson,
} from "./ledger-core";

export * from "./ledger-core";

type LB = typeof import("ledger-bitcoin");
type AppClient = InstanceType<LB["AppClient"]>;

export const UNSUPPORTED_MESSAGE =
  "Ledger over USB needs WebHID, which only Chrome and Edge (desktop) have. In this browser, sign with a QR code or a PSBT file instead.";

export function webHidSupported(): boolean {
  if (devBridge()) return true;
  return typeof navigator !== "undefined" && "hid" in navigator;
}

export class LedgerError extends Error {
  problem: DeviceProblem;
  constructor(problem: DeviceProblem) {
    super(problem.message);
    this.problem = problem;
  }
}

type DevBridge = (apduHex: string) => Promise<string>;

/**
 * Dev builds only: a test driver (e2e/ledger-browser.mjs) can set `__btcSafeLedgerBridge` to
 * relay APDUs to the Speculos emulator, replacing only the USB hop. Compiled out of
 * production builds (`next build` inlines NODE_ENV).
 */
function devBridge(): DevBridge | undefined {
  if (process.env.NODE_ENV === "production") return undefined;
  return (globalThis as { __btcSafeLedgerBridge?: DevBridge }).__btcSafeLedgerBridge;
}

async function load() {
  // ledger-bitcoin uses node's Buffer.
  const { Buffer } = await import("buffer");
  (globalThis as { Buffer?: unknown }).Buffer ??= Buffer;
  const [hid, lb] = await Promise.all([import("@ledgerhq/hw-transport-webhid"), import("ledger-bitcoin")]);
  const bridge = devBridge();
  if (bridge) {
    const { default: Transport } = await import("@ledgerhq/hw-transport");
    class BridgeTransport extends Transport {
      async exchange(apdu: Buffer): Promise<Buffer> {
        return Buffer.from(await bridge!(apdu.toString("hex")), "hex");
      }
    }
    return { TransportWebHID: { create: async () => new BridgeTransport() as unknown as Awaited<ReturnType<typeof hid.default.create>> }, lb };
  }
  return { TransportWebHID: hid.default, lb };
}

/**
 * Open the device (the browser shows its picker the first time), check that the right
 * Bitcoin app is open, run `fn`, close. Every failure comes out as a LedgerError.
 */
export async function withLedger<T>(network: string, fn: (app: AppClient, lb: LB, fingerprint: string) => Promise<T>): Promise<T> {
  if (!webHidSupported()) throw new LedgerError({ state: "unsupported", message: UNSUPPORTED_MESSAGE });
  const { TransportWebHID, lb } = await load();
  let transport: Awaited<ReturnType<typeof TransportWebHID.create>>;
  try {
    transport = await TransportWebHID.create();
  } catch (e) {
    throw new LedgerError(classifyLedgerError(e));
  }
  try {
    const app = new lb.AppClient(transport);
    const info = await app.getAppAndVersion();
    const bad = checkApp(info.name, info.version, network);
    if (bad) throw new LedgerError(bad);
    const fingerprint = await app.getMasterFingerprint();
    return await fn(app, lb, fingerprint);
  } catch (e) {
    throw e instanceof LedgerError ? e : new LedgerError(classifyLedgerError(e));
  } finally {
    await transport.close().catch(() => undefined);
  }
}

/** Owner key for the create wizard: master fingerprint + BIP-48 P2WSH account xpub. */
export async function readOwnerKey(network: string): Promise<{ fingerprint: string; path: string; xpub: string }> {
  return withLedger(network, async (app, _lb, fingerprint) => ({ fingerprint, path: OWNER_PATH, xpub: await app.getExtendedPubkey(OWNER_PATH) }));
}

type WalletLike = { id: string; name: string; network: string; threshold: number; owners: { id: string; fingerprint: string; path: string; xpub: string; position: number }[] };

/** Policy info from the server, refused if it isn't the policy we'd build from the owners. */
export async function ledgerInfo(w: WalletLike): Promise<LedgerInfo> {
  const info = await api<LedgerInfo>(`/wallets/${w.id}/ledger`);
  if (!samePolicy(info.policy, expectedPolicy(w.name, w.owners, w.threshold))) {
    throw new Error("The server's Ledger policy doesn't match this wallet's owners. Not registering it.");
  }
  return info;
}

function ownerFor(w: WalletLike, fingerprint: string) {
  const o = w.owners.find((x) => x.fingerprint.toLowerCase() === fingerprint.toLowerCase());
  if (!o) {
    throw new LedgerError({
      state: "error",
      message: `This Ledger (fingerprint ${fingerprint}) isn't an owner of this wallet. Connect the owner's device, or check the passphrase.`,
    });
  }
  return o;
}

/**
 * Register the wallet on the connected Ledger. The user reviews the name, policy and every
 * key on the device. The returned HMAC goes to the server, filed under whichever owner this
 * device's fingerprint belongs to.
 */
export async function registerOnLedger(w: WalletLike, onPrompt?: () => void): Promise<{ ownerId: string; fingerprint: string }> {
  const info = await ledgerInfo(w);
  return withLedger(w.network, async (app, lb, fingerprint) => {
    const owner = ownerFor(w, fingerprint);
    const policy = new lb.WalletPolicy(info.policy.name, info.policy.descriptor_template, info.policy.keys);
    if (policy.getId().toString("hex") !== info.policy_id) throw new Error("policy id mismatch between browser and server");
    onPrompt?.();
    const [id, hmac] = await app.registerWallet(policy);
    if (id.toString("hex") !== info.policy_id) throw new Error("the device registered a different policy");
    await api(`/wallets/${w.id}/ledger/owners/${owner.id}`, {
      method: "PUT",
      body: { policy: info.policy, policy_id: info.policy_id, hmac: hmac.toString("hex") },
    });
    return { ownerId: owner.id, fingerprint };
  });
}

/**
 * Sign a proposal on the Ledger. The device shows every output and the fee; the returned
 * partial signatures are checked and merged here, then uploaded to the same endpoint as
 * any other signed PSBT, where the server validates them again.
 */
export async function signOnLedger(
  w: WalletLike,
  proposalId: number,
  psbtB64: string,
  onPrompt?: () => void,
): Promise<{ psbt: string; added: number; fingerprint: string }> {
  const info = await ledgerInfo(w);
  return withLedger(w.network, async (app, lb, fingerprint) => {
    const owner = ownerFor(w, fingerprint);
    const reg = info.registrations.find((r) => r.owner_id === owner.id);
    if (!reg) {
      throw new LedgerError({ state: "not_registered", message: "This wallet isn't registered on this Ledger yet. Register it first (you'll review it on the device)." });
    }
    const policy = policyOf(lb, reg.policy, info.policy);
    onPrompt?.();
    const sigs = await app.signPsbt(psbtB64, policy, Buffer.from(reg.hmac, "hex"));
    if (sigs.length === 0) throw new Error("the Ledger returned no signatures (none of the inputs are its key?)");
    const merged = mergePartialSigs(
      psbtB64,
      sigs.map(([inputIndex, ps]) => ({ inputIndex, pubkey: ps.pubkey, signature: ps.signature })),
    );
    return { ...merged, fingerprint };
  });
}

/** Show a receive/change address on the device; returns what the device derived. */
export async function showOnLedger(w: WalletLike, chain: 0 | 1, index: number, onPrompt?: () => void): Promise<string> {
  const info = await ledgerInfo(w);
  return withLedger(w.network, async (app, lb, fingerprint) => {
    const owner = ownerFor(w, fingerprint);
    const reg = info.registrations.find((r) => r.owner_id === owner.id);
    if (!reg) throw new LedgerError({ state: "not_registered", message: "Register this wallet on this Ledger first (Settings → Ledger)." });
    onPrompt?.();
    return app.getWalletAddress(policyOf(lb, reg.policy, info.policy), Buffer.from(reg.hmac, "hex"), chain, index, true);
  });
}

/** A stored registration's policy, refused unless its template and keys are this wallet's
 *  (the name may be an older wallet name; the device's HMAC covers whatever was registered). */
function policyOf(lb: LB, p: LedgerPolicyJson, want: LedgerPolicyJson) {
  if (!samePolicy({ ...p, name: want.name }, want)) throw new Error("The stored Ledger registration isn't for this wallet's keys. Register again.");
  return new lb.WalletPolicy(p.name, p.descriptor_template, p.keys);
}
