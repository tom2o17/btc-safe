import { test } from "node:test";
import assert from "node:assert/strict";
import { sniffWalletFile, walletFileName } from "../lib/import-sniff.ts";

const caravan = JSON.stringify({
  name: "Signet test 2-of-3",
  addressType: "P2WSH",
  network: "signet",
  quorum: { requiredSigners: 2, totalSigners: 3 },
  extendedPublicKeys: [{ name: "Carol", bip32Path: "m/48'/1'/0'/2'", xpub: "tpubX", xfp: "af3378c2" }],
}, null, 2);

test("Caravan JSON is a wallet file, and its name is read", () => {
  assert.equal(sniffWalletFile(caravan), "caravan");
  assert.equal(sniffWalletFile("﻿" + caravan + "\n"), "caravan");
  assert.equal(walletFileName(caravan), "Signet test 2-of-3");
  assert.equal(walletFileName(JSON.stringify({ name: "   ", quorum: {} })), null);
  assert.equal(walletFileName(JSON.stringify({ name: "x".repeat(300), quorum: {} })).length, 100);
});

test("BSMS and descriptors are wallet files without a name", () => {
  const bsms = "BSMS 1.0\nwsh(sortedmulti(2,[af3378c2/48'/1'/0'/2']tpubA/**,[48863ae8/48'/1'/0'/2']tpubB/**))#abcd\n/0/*,/1/*\ntb1q…\n";
  assert.equal(sniffWalletFile(bsms), "bsms");
  assert.equal(walletFileName(bsms), null);
  assert.equal(sniffWalletFile("# Sparrow export\nwsh(sortedmulti(2,[af3378c2/48h/1h/0h/2h]tpubA/<0;1>/*,[48863ae8/48h/1h/0h/2h]tpubB/<0;1>/*))#x"), "descriptor");
});

test("an owners array (what 'Paste all owners' wants) is not a wallet file", () => {
  assert.equal(sniffWalletFile('[{"name":"A","xpub":"tpub","fingerprint":"00000000","path":"m/48\'/1\'/0\'/2\'"}]'), null);
  assert.equal(sniffWalletFile('{"foo":1}'), null);
  assert.equal(sniffWalletFile("not json"), null);
  assert.equal(sniffWalletFile(""), null);
});
