"use client";

import Link from "next/link";
import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { TopBar } from "@/components/shell";
import { ErrorBox } from "@/components/ui";
import { ApiError, authCall, setSession, type LoginResult, type Session } from "@/lib/api";

/** Only same-site relative paths are allowed as the post-login target. */
function safeNext(n: string | null): string {
  return n && n.startsWith("/") && !n.startsWith("//") && !n.startsWith("/\\") ? n : "/";
}

function LoginForm() {
  const params = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // Second step: the server accepted the password and wants a TOTP or recovery code.
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [useRecovery, setUseRecovery] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  function done(s: Session) {
    setSession(s);
    window.location.assign(safeNext(params.get("next")));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await authCall<LoginResult>("/auth/login", { email, password });
      if ("mfa_required" in r && r.mfa_required) {
        setMfaToken(r.mfa_token);
        setPassword("");
        setCode("");
        setBusy(false);
        return;
      }
      done(r as Session);
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  async function verify(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const c = code.trim();
      const body = useRecovery ? { mfa_token: mfaToken, recovery_code: c.toLowerCase() } : { mfa_token: mfaToken, code: c.replace(/\s+/g, "") };
      done(await authCall<Session>("/auth/login/mfa", body));
    } catch (err) {
      if (err instanceof ApiError && err.code === "mfa_expired") {
        setMfaToken(null);
        setError(new Error("That took too long. Enter your password again."));
      } else if (err instanceof ApiError && err.code === "bad_code") {
        setError(new Error(useRecovery ? "That recovery code isn't valid (each one works once)." : "Wrong code. Check your authenticator's clock and try the current code."));
      } else {
        setError(err);
      }
      setBusy(false);
    }
  }

  if (mfaToken) {
    return (
      <div className="card auth-wrap">
        <h1>Two-factor check</h1>
        <p className="small muted">
          Logging in as <b>{email}</b>.{" "}
          {useRecovery ? "Enter one of your saved recovery codes. It stops working once used." : "Enter the 6-digit code from your authenticator app."}
        </p>
        <form onSubmit={verify}>
          {useRecovery ? (
            <input
              type="text"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              placeholder="abcd-efgh-ijkl-mnop"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              aria-label="Recovery code"
              required
              autoFocus
            />
          ) : (
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9 ]{6,7}"
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              aria-label="Authenticator code"
              required
              autoFocus
            />
          )}
          <ErrorBox error={error} />
          <button className="btn" type="submit" disabled={busy}>
            {busy ? "Checking…" : "Verify"}
          </button>
        </form>
        <div className="row between small" style={{ marginTop: 16 }}>
          <button
            type="button"
            className="linkbtn"
            onClick={() => {
              setUseRecovery(!useRecovery);
              setCode("");
              setError(null);
            }}
          >
            {useRecovery ? "Use an authenticator code instead" : "Use a recovery code instead"}
          </button>
          <button
            type="button"
            className="linkbtn"
            onClick={() => {
              setMfaToken(null);
              setError(null);
            }}
          >
            Start over
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="card auth-wrap">
      <h1>Log in</h1>
      <form onSubmit={submit}>
        <input type="email" autoComplete="username" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} aria-label="Email" required />
        <input
          type="password"
          autoComplete="current-password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-label="Password"
          required
        />
        <ErrorBox error={error} />
        <button className="btn" type="submit" disabled={busy}>
          {busy ? "Logging in…" : "Log in"}
        </button>
      </form>
      <p className="small muted" style={{ marginTop: 16 }}>
        No account? <Link href="/signup">Sign up</Link>. Invited? Open the setup link you were given to choose a password.
      </p>
    </div>
  );
}

export default function Login() {
  return (
    <>
      <TopBar />
      <main className="main full">
        <Suspense>
          <LoginForm />
        </Suspense>
      </main>
    </>
  );
}
