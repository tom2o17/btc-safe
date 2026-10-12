"use client";

import { useEffect, useState } from "react";
import { useMe } from "@/components/auth";
import { ErrorBox } from "@/components/ui";
import { useWalletMaybe } from "@/components/wallet-context";
import { api, ApiError, type Member } from "@/lib/api";
import { can, parseRole, ROLE_HELP, ROLE_LABEL, ROLES, type Role } from "@/lib/roles";

const LAST_ADMIN = "An account needs at least one admin. Make someone else an admin first.";

function explain(e: unknown): unknown {
  if (e instanceof ApiError && e.code === "last_admin") return new Error(LAST_ADMIN);
  if (e instanceof ApiError && e.code === "forbidden") return new Error("Only an admin of this account can change who it's shared with.");
  return e;
}

/**
 * Who can use this account in BTC Safe, and with which role. Separate from owners: owners hold
 * keys, members log in. Admins edit; everyone else sees the list read-only.
 */
export function Members({ walletId, role }: { walletId: string; role: Role | undefined }) {
  const me = useMe();
  const refreshWallet = useWalletMaybe()?.refresh;
  const manage = can(role, "members");
  const [members, setMembers] = useState<Member[] | null>(null);
  const [email, setEmail] = useState("");
  const [newRole, setNewRole] = useState<Role>("viewer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const load = () => api<Member[]>(`/wallets/${walletId}/members`).then(setMembers, (e) => setError(explain(e)));
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [walletId]);

  async function run(f: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await f();
    } catch (e) {
      setError(explain(e));
    } finally {
      setBusy(false);
      await load();
      await refreshWallet?.(); // my own role may have changed
    }
  }

  const add = () =>
    run(async () => {
      const body = { email: email.trim(), role: newRole };
      try {
        await api(`/wallets/${walletId}/members`, { body });
      } catch (e) {
        // Self-registered accounts: the email was never verified, so anyone could own it.
        if (!(e instanceof ApiError && e.code === "unverified_account")) throw e;
        if (!confirm(`${e.message}\n\nShare anyway?`)) return;
        await api(`/wallets/${walletId}/members`, { body: { ...body, confirm_unverified: true } });
      }
      setEmail("");
      setNewRole("viewer");
    });

  const change = (m: Member, r: Role) => run(() => api(`/wallets/${walletId}/members/${m.user_id}`, { method: "PATCH", body: { role: r } }));

  const remove = (m: Member) => {
    if (!confirm(`Stop sharing this account with ${m.email}? They lose access in BTC Safe; their keys are unaffected.`)) return;
    return run(() => api(`/wallets/${walletId}/members/${m.user_id}`, { method: "DELETE" }));
  };

  return (
    <div className="card stack" data-testid="members">
      <h2>Sharing</h2>
      <p className="small muted">
        People who can log in and use this account. Being a member is not the same as being an owner: signing still needs the owners&apos; keys. They need a
        BTC Safe account first.
      </p>
      <ul className="small muted" style={{ margin: 0, paddingLeft: 18 }}>
        {ROLES.map((r) => (
          <li key={r}>
            <b>{ROLE_LABEL[r]}</b>: {ROLE_HELP[r]}
          </li>
        ))}
      </ul>
      <ErrorBox error={error} />
      <table className="list">
        <thead>
          <tr>
            <th>Email</th>
            <th>Role</th>
            <th>Since</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {members?.map((m) => (
            <tr key={m.user_id} data-testid={`member-${m.email}`}>
              <td>
                {m.email}
                {me && m.email.toLowerCase() === me.email.toLowerCase() ? <span className="muted"> (you)</span> : null}
                {m.self_signup ? (
                  <span className="tag" title="Signed itself up; the email address was never verified" style={{ marginLeft: 6 }}>
                    self-registered
                  </span>
                ) : null}
              </td>
              <td>
                {manage ? (
                  <select value={parseRole(m.role)} onChange={(e) => void change(m, e.target.value as Role)} disabled={busy} aria-label={`Role of ${m.email}`}>
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {ROLE_LABEL[r]}
                      </option>
                    ))}
                  </select>
                ) : (
                  <span className="tag">{ROLE_LABEL[parseRole(m.role)]}</span>
                )}
              </td>
              <td className="small muted">{new Date(m.added_at).toLocaleDateString()}</td>
              <td style={{ textAlign: "right" }}>
                {manage ? (
                  <button className="btn secondary small" onClick={() => void remove(m)} disabled={busy}>
                    Remove
                  </button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {manage ? (
        <div className="row">
          <input type="email" placeholder="email of an existing user" value={email} onChange={(e) => setEmail(e.target.value)} aria-label="Share with (email)" />
          <select value={newRole} onChange={(e) => setNewRole(e.target.value as Role)} aria-label="Role" style={{ maxWidth: 160 }}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </select>
          <button className="btn" onClick={() => void add()} disabled={busy || !email.includes("@")}>
            Share
          </button>
        </div>
      ) : (
        <p className="small muted">Your role is {parseRole(role)}. Only an admin of this account can change who it&apos;s shared with.</p>
      )}
    </div>
  );
}
