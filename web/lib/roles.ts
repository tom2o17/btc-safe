// Per-wallet roles. The API enforces every rule here (403 {error:"forbidden"}); the UI uses the
// same table only to avoid offering buttons that would fail. Import-free for node:test.

export type Role = "admin" | "proposer" | "viewer";
export const ROLES: readonly Role[] = ["viewer", "proposer", "admin"];

export type Action =
  | "propose" // create proposals (Send)
  | "sign" // upload signatures (file, Ledger, Trezor)
  | "execute"
  | "label" // address labels and the address book
  | "allocate" // allocate a new receive address (moves the wallet's index)
  | "ledger" // register / forget Ledger wallet policies
  | "settings" // ordering mode etc.
  | "members" // share, change roles, remove
  | "delete_wallet";

const RANK: Record<Role, number> = { viewer: 0, proposer: 1, admin: 2 };
const NEEDS: Record<Action, Role> = {
  propose: "proposer",
  sign: "proposer",
  execute: "proposer",
  label: "proposer",
  allocate: "proposer",
  ledger: "proposer",
  settings: "admin",
  members: "admin",
  delete_wallet: "admin",
};

/** Unknown or missing roles get the least access (the server decides anyway). */
export function parseRole(r: unknown): Role {
  return r === "admin" || r === "proposer" ? r : "viewer";
}

export function can(role: Role | null | undefined, action: Action): boolean {
  return RANK[parseRole(role)] >= RANK[NEEDS[action]];
}

/** Admins delete any proposal; proposers only the ones they created. */
export function canDeleteProposal(role: Role | null | undefined, createdBy: string | null | undefined, myEmail: string | null | undefined): boolean {
  const r = parseRole(role);
  if (r === "admin") return true;
  if (r !== "proposer" || !createdBy || !myEmail) return false;
  return createdBy.trim().toLowerCase() === myEmail.trim().toLowerCase();
}

export const ROLE_LABEL: Record<Role, string> = { viewer: "Viewer", proposer: "Proposer", admin: "Admin" };

export const ROLE_HELP: Record<Role, string> = {
  viewer: "sees balances, history and addresses.",
  proposer: "everything a viewer can, plus propose, sign and execute transactions, delete their own proposals, and edit labels and the address book.",
  admin: "everything a proposer can, plus change settings, delete any proposal, delete the account and manage who it's shared with.",
};
