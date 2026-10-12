// Ledger e2e against Speculos (app-bitcoin-new "Bitcoin Test" on an emulated Nano S Plus).
// Same calls and the same web/lib/ledger-core.ts code the browser uses; only the transport
// differs (TCP to Speculos instead of WebHID).
//
// Needs: Speculos on 127.0.0.1:9999/5000 (.speculos-vm/START.md), the API on :8080 with
// CHAIN=memory and a dev account (e2e/reset-dev.sh), and the testsigner example built.
// Flow: Ledger xpub → 2-of-3 wallet (Ledger + 2 test keys) → register policy on the device →
// HMAC stored → device address == server address → reject on device → bad HMAC →
// sign on device → merge → upload (server validates) → second signer → execute → confirmed.
import { browserLogin, devAuth } from "./session.mjs";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AppClient, WalletPolicy } from "ledger-bitcoin";
import { openTransport, drive } from "./speculos.mjs";
import { OWNER_PATH, checkApp, classifyLedgerError, expectedPolicy, mergePartialSigs, samePolicy } from "../lib/ledger-core.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SIGNER = path.join(ROOT, "target/debug/examples/testsigner");
const API = process.env.API ?? "http://127.0.0.1:8080";
const AUTH = await devAuth(API);
const RCPT = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

async function call(method, p, body) {
  const r = await fetch(`${API}${p}`, {
    method,
    headers: { ...AUTH, ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  return { status: r.status, body: text ? JSON.parse(text) : null };
}
async function ok(method, p, body) {
  const r = await call(method, p, body);
  assert.ok(r.status < 300, `${method} ${p} -> ${r.status} ${JSON.stringify(r.body)}`);
  return r.body;
}
const step = (s) => console.log(`✓ ${s}`);
const toPolicy = (p) => new WalletPolicy(p.name, p.descriptor_template, p.keys);
const fromHex = (h) => Buffer.from(h, "hex");

const transport = await openTransport();
const app = new AppClient(transport);
try {
  const info = await app.getAppAndVersion();
  assert.equal(checkApp(info.name, info.version, "signet"), null);
  assert.equal(checkApp(info.name, info.version, "mainnet")?.state, "wrong_app");
  step(`device app ${info.name} ${info.version}`);

  // 1. Add owner from Ledger.
  const fingerprint = await app.getMasterFingerprint();
  const xpub = await app.getExtendedPubkey(OWNER_PATH);
  const others = JSON.parse(execFileSync(SIGNER, ["owners"]).toString());
  const owners = [{ name: "Ledger", xpub, fingerprint, path: OWNER_PATH }, others[1], others[2]];
  const created = await ok("POST", "/wallets", { name: "Ledger e2e", network: "signet", threshold: 2, owners });
  const wid = created.id;
  const wallet = await ok("GET", `/wallets/${wid}`);
  const ledgerOwner = wallet.owners.find((o) => o.fingerprint === fingerprint);
  step(`wallet ${wid} with Ledger owner ${fingerprint}`);

  // 2. Register the policy. The browser rebuilds it and requires the server's to match.
  const li = await ok("GET", `/wallets/${wid}/ledger`);
  assert.ok(samePolicy(li.policy, expectedPolicy(wallet.name, wallet.owners, wallet.threshold)), "server policy == browser policy");
  assert.equal(li.registrations.length, 0);
  const policy = toPolicy(li.policy);
  assert.equal(policy.getId().toString("hex"), li.policy_id, "Rust policy id == ledger-bitcoin's");

  // 2a. Reject the registration on the device.
  let pending = app.registerWallet(policy);
  await drive(pending, /^Reject/i);
  await pending.then(() => assert.fail("registration should have been rejected"), (e) => assert.equal(classifyLedgerError(e).state, "rejected"));
  step("registration rejected on device -> 'rejected'");

  pending = app.registerWallet(policy);
  const regScreens = await drive(pending, /^Register account/i);
  const [policyId, hmac] = await pending;
  assert.equal(policyId.toString("hex"), li.policy_id);
  assert.ok(regScreens.some((s) => s.includes("Ledger e2e")), "device showed the wallet name");
  assert.ok(regScreens.some((s) => /2 of 3|@0, @1 and @2|2.*3/.test(s)), `device showed the threshold: ${regScreens.join(" / ")}`);
  await ok("PUT", `/wallets/${wid}/ledger/owners/${ledgerOwner.id}`, { policy: li.policy, policy_id: li.policy_id, hmac: hmac.toString("hex") });
  const li2 = await ok("GET", `/wallets/${wid}/ledger`);
  assert.equal(li2.registrations[0].hmac, hmac.toString("hex"));
  step(`policy registered on device, HMAC stored (screens: ${regScreens.length})`);

  // 2b. The device derives the same addresses as the server.
  for (const [chain, idx] of [[0, 0], [0, 1], [1, 0]]) {
    const devAddr = await app.getWalletAddress(policy, hmac, chain, idx, false);
    const srv = chain === 0 ? created.first_addresses[idx] : null;
    if (srv) assert.equal(devAddr, typeof srv === "string" ? srv : srv.address, `receive #${idx}`);
  }
  pending = app.getWalletAddress(policy, hmac, 0, 0, true);
  const addrScreens = await drive(pending, /^(Confirm|Approve|Verify|Done|Accept)/i);
  await pending;
  step(`device addresses == server addresses; shown on screen (${addrScreens.length} screens)`);

  // 3. Fund 2 inputs, propose.
  for (let i = 0; i < 2; i++) {
    const a = await ok("GET", `/wallets/${wid}/addresses?kind=receive&next=true`);
    await ok("POST", "/dev/fund", { address: a.address, amount_sats: 60_000 });
  }
  await ok("POST", "/dev/mine", { blocks: 1 });
  await ok("POST", `/wallets/${wid}/sync`);
  const prop = await ok("POST", `/wallets/${wid}/proposals`, { outputs: [{ address: RCPT, amount_sats: 90_000 }], fee_rate_sat_vb: 2.0 });
  const pid = prop.id;
  const { psbt: psbtB64 } = await ok("GET", `/proposals/${pid}`);
  step(`proposal #${pid}`);

  // 3a. User rejects the signature on the device.
  pending = app.signPsbt(psbtB64, policy, hmac);
  await drive(pending, /^Reject/i, { max: 120 });
  await pending.then(() => assert.fail("signing should have been rejected"), (e) => assert.equal(classifyLedgerError(e).state, "rejected"));
  step("signing rejected on device -> 'rejected'");

  // 3b. A wrong HMAC is refused by the device.
  const bad = Buffer.alloc(32, 7);
  await app.signPsbt(psbtB64, policy, bad).then(
    () => assert.fail("bad HMAC accepted"),
    (e) => {
      const c = classifyLedgerError(e);
      console.log(`  bad HMAC -> 0x${e.statusCode?.toString(16)} ${c.state}`);
      assert.equal(c.state, "bad_hmac");
    },
  );
  step("bad HMAC -> 'bad_hmac'");

  // 3c. Sign for real.
  pending = app.signPsbt(psbtB64, policy, hmac);
  const signScreens = await drive(pending, /^(Sign transaction|Accept|Hold to sign|Approve|Sign)/i, { max: 120 });
  const sigs = await pending;
  assert.equal(sigs.length, 2, "one signature per input");
  assert.ok(signScreens.some((s) => s.includes(RCPT.slice(0, 10))), `device showed the recipient: ${signScreens.join(" / ")}`);
  const merged = mergePartialSigs(psbtB64, sigs.map(([inputIndex, ps]) => ({ inputIndex, pubkey: ps.pubkey, signature: ps.signature })));
  assert.equal(merged.added, 2);
  assert.equal(mergePartialSigs(merged.psbt, sigs.map(([inputIndex, ps]) => ({ inputIndex, pubkey: ps.pubkey, signature: ps.signature }))).added, 0, "re-merge is a no-op");
  // Swapped inputs or a flipped bit are caught before upload.
  const asSigs = (xs) => xs.map(([inputIndex, ps]) => ({ inputIndex, pubkey: ps.pubkey, signature: ps.signature }));
  const swapped = asSigs(sigs).map((s) => ({ ...s, inputIndex: 1 - s.inputIndex }));
  assert.throws(() => mergePartialSigs(psbtB64, swapped));
  const flipped = asSigs(sigs);
  flipped[0] = { ...flipped[0], signature: Uint8Array.from(flipped[0].signature, (x, i) => (i === 10 ? x ^ 1 : x)) };
  assert.throws(() => mergePartialSigs(psbtB64, flipped));
  let r = await ok("POST", `/proposals/${pid}/signatures`, { psbt: merged.psbt });
  const mine = r.confirmations.owners.find((o) => o.fingerprint === fingerprint);
  assert.ok(mine?.signed, `server counted the Ledger signature: ${JSON.stringify(r.confirmations)}`);
  assert.equal(r.confirmations.count, 1);
  step(`Ledger signature accepted by the server (${signScreens.length} review screens)`);

  // 4. Second signer, execute, confirm.
  const second = execFileSync(SIGNER, ["sign", "1", r.psbt ?? psbtB64], { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  r = await ok("POST", `/proposals/${pid}/signatures`, { psbt: second });
  assert.equal(r.confirmations.ready, true);
  await ok("POST", `/proposals/${pid}/execute`);
  await ok("POST", "/dev/mine", { blocks: 2 });
  await ok("POST", `/wallets/${wid}/sync`);
  const fin = await ok("GET", `/proposals/${pid}`);
  assert.equal(fin.status, "confirmed");
  step(`executed and confirmed: ${fin.broadcast_txid ?? fin.txid}`);
  console.log("LEDGER SPECULOS E2E PASSED");
} finally {
  await transport.close();
}
