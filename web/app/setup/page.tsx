"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { TopBar } from "@/components/shell";
import { ErrorBox } from "@/components/ui";
import { ApiError, setSession, type Me } from "@/lib/api";

const MIN = 12;

function SetupForm() {
  const [token, setToken] = useState<string | null>(null);
  const [checked, setChecked] = useState(false);
  const started = useRef(false);
  const [email, setEmail] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    // Read the token once, then drop it from the address bar and history. (Next syncs
    // replaceState into useSearchParams, so this must not re-run on the cleared URL.)
    if (started.current) return; // StrictMode's second run would see the cleared URL
    started.current = true;
    const t = new URLSearchParams(window.location.search).get("token");
    if (!t) return setChecked(true);
    setToken(t);
    window.history.replaceState(null, "", "/setup");
    fetch(`/api/auth/setup?token=${encodeURIComponent(t)}`, { cache: "no-store" })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new ApiError(r.status, j.error ?? String(r.status), j.message ?? "setup link is invalid, used or expired");
        setEmail(j.email);
      })
      .catch(setError)
      .finally(() => setChecked(true));
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) return setError(new Error("passwords don't match"));
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token, password }),
        cache: "no-store",
      });
      const j = await res.json().catch(() => ({}));
      if (!res.ok) throw new ApiError(res.status, j.error ?? String(res.status), j.message ?? `setup failed (${res.status})`);
      setSession(j as Me);
      window.location.assign("/");
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  return (
    <div className="card auth-wrap">
      <h1>Set your password</h1>
      {email ? <p>Account: <b>{email}</b></p> : null}
      {checked && !token ? <p className="muted">This page needs the setup link you were sent.</p> : null}
      <form onSubmit={submit}>
        <input type="email" autoComplete="username" value={email ?? ""} readOnly hidden aria-hidden />
        <input
          type="password"
          autoComplete="new-password"
          placeholder={`New password (at least ${MIN} characters)`}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-label="New password"
          minLength={MIN}
          required
        />
        <input
          type="password"
          autoComplete="new-password"
          placeholder="Repeat password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          aria-label="Repeat password"
          required
        />
        <ErrorBox error={error} />
        <button className="btn" type="submit" disabled={busy || !email || password.length < MIN}>
          {busy ? "Saving…" : "Set password and log in"}
        </button>
      </form>
      <p className="small muted" style={{ marginTop: 16 }}>The link works once. Setting a password logs out any other sessions of this account.</p>
    </div>
  );
}

export default function Setup() {
  return (
    <>
      <TopBar />
      <main className="main full">
        <Suspense>
          <SetupForm />
        </Suspense>
      </main>
    </>
  );
}
