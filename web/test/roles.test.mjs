import { test } from "node:test";
import assert from "node:assert/strict";
import { can, canDeleteProposal, parseRole } from "../lib/roles.ts";

test("role table", () => {
  const all = ["propose", "sign", "execute", "label", "ledger", "settings", "members", "delete_wallet"];
  const allowed = (r) => all.filter((a) => can(r, a));
  assert.deepEqual(allowed("viewer"), []);
  assert.deepEqual(allowed("proposer"), ["propose", "sign", "execute", "label", "ledger"]);
  assert.deepEqual(allowed("admin"), all);
  assert.deepEqual(allowed(undefined), [], "missing role is least access");
  assert.deepEqual(allowed("owner"), [], "unknown role is least access");
  assert.equal(parseRole("admin"), "admin");
});

test("proposal deletion: admins any, proposers their own, viewers none", () => {
  assert.equal(canDeleteProposal("admin", "someone@x", "me@x"), true);
  assert.equal(canDeleteProposal("admin", null, "me@x"), true);
  assert.equal(canDeleteProposal("proposer", "Me@X ", "me@x"), true);
  assert.equal(canDeleteProposal("proposer", "someone@x", "me@x"), false);
  assert.equal(canDeleteProposal("proposer", null, "me@x"), false);
  assert.equal(canDeleteProposal("viewer", "me@x", "me@x"), false);
});
