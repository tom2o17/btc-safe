// Shared shape for signing devices (file, QR, Ledger, Trezor, …). An adapter exports an owner's
// xpub and adds its signatures to a PSBT. Watch-only: no adapter ever sees a private key; the
// device keeps it, and the signed PSBT goes to POST /proposals/:id/signatures like any other.

import type { KeyOwner } from "../bitcoin";

export type XpubResult = {
  /** Base58 extended public key in the wallet network's version (tpub on signet/testnet). */
  xpub: string;
  /** Master key fingerprint, 8 lowercase hex chars. */
  fingerprint: string;
  /** Origin path, e.g. m/48'/1'/0'/2'. */
  path: string;
};

export type SignContext = {
  /** All owners, in wallet position order. */
  owners: KeyOwner[];
  threshold: number;
  /** Wallet network name from the API ("signet", "testnet", "bitcoin", …). */
  network: string;
  /** Server's change hints (vout → change index); every hint is re-derived before it's used. */
  changeIndex?: Map<number, number>;
};

export type SignResult = {
  /** The PSBT with this device's partial signatures merged in (base64). */
  psbt: string;
  /** The owner the device turned out to be. */
  signer: KeyOwner;
  inputsSigned: number;
};

export type SignerErrorCode =
  | "not_connected" // no device, transport or host app reachable
  | "cancelled" // the user said no (device, popup or permission prompt)
  | "wrong_network" // device or host can't use the wallet's network, or returned another network's key
  | "wrong_device" // connected device isn't any of this wallet's owners (or the wrong passphrase)
  | "busy" // device in use by another app or call
  | "unsupported" // firmware or feature too old
  | "failed";

export class SignerError extends Error {
  code: SignerErrorCode;
  constructor(code: SignerErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export interface SignerAdapter {
  id: string;
  label: string;
  getXpub(path: string, network: string): Promise<XpubResult>;
  signPsbt(psbtB64: string, ctx: SignContext): Promise<SignResult>;
}
