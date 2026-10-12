"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { TopBar } from "@/components/shell";
import { ErrorBox } from "@/components/ui";
import { ApiError, authCall, setSession, type Session, type SignupInfo } from "@/lib/api";
import { solvePow } from "@/lib/pow";

const ERRORS: Record<string, string> = {
  signup_closed: "Sign-up is invite-only on this server. Ask an admin for a setup link.",
  email_taken: "There's already an account with that email. Log in instead.",
  user_cap: "This server has reached its account limit. Ask an admin.",
};

function SignupForm() {
  const [info, setInfo] = useState<SignupInfo | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [website, setWebsite] = useState(""); // honeypot: people never see or fill it
  const [phase, setPhase] = useState<null | "pow" | "saving">(null);
  const [error, setError] = useState<unknown>(null);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => {
    authCall<SignupInfo>("/auth/signup").then(setInfo, setError);
    return () => abort.current?.abort();
  }, []);

  const min = info?.min_password ?? 12;

  async function attempt(retry: boolean): Promise<Session> {
    // Each challenge is single-use and short-lived, so fetch a fresh one per attempt.
    const fresh = await authCall<SignupInfo>("/auth/signup");
    setInfo(fresh);
    if (!fresh.open) throw new ApiError(404, "signup_closed", ERRORS.signup_closed);
    let nonce = "";
    if (fresh.pow) {
      setPhase("pow");
      abort.current = new AbortController();
      nonce = await solvePow(fresh.pow.challenge, fresh.pow.bits, { signal: abort.current.signal });
    }
    setPhase("saving");
    try {
      return await authCall<Session>("/auth/signup", {
        email: email.trim(),
        password,
        website,
        pow_challenge: fresh.pow?.challenge ?? "",
        pow_nonce: nonce,
      });
    } catch (e) {
      if (!retry && e instanceof ApiError && e.code === "bad_pow") return attempt(true);
      throw e;
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) return setError(new Error("passwords don't match"));
    setError(null);
    try {
      setSession(await attempt(false));
      window.location.assign("/");
    } catch (err) {
      setError(err instanceof ApiError && ERRORS[err.code] ? new Error(ERRORS[err.code]) : err);
      setPhase(null);
    }
  }

  const busy = phase !== null;

  return (
    <div className="card auth-wrap">
      <h1>Create an account</h1>
      <div className="alert info small" style={{ marginBottom: 14 }}>
        There is no email verification: your email is only your username. We never send email. If you lose your password and your recovery codes, only an
        admin can reset your account.
      </div>
      {info && !info.open ? (
        <p className="muted">Sign-up is invite-only on this server. If you were invited, open the setup link you were given.</p>
      ) : (
        <form onSubmit={submit}>
          <input type="email" autoComplete="username" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} aria-label="Email" required />
          <input
            type="password"
            autoComplete="new-password"
            placeholder={`Password (at least ${min} characters)`}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-label="Password"
            minLength={min}
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
          {/* Bots fill every field; people never see this one. */}
          <div className="hp" aria-hidden="true">
            <label>
              Website
              <input type="text" name="website" tabIndex={-1} autoComplete="off" value={website} onChange={(e) => setWebsite(e.target.value)} />
            </label>
          </div>
          <ErrorBox error={error} />
          {phase === "pow" ? <div className="small muted">Checking you&apos;re not a bot… (a few seconds)</div> : null}
          <button className="btn" type="submit" disabled={busy || !info || password.length < min}>
            {phase === "pow" ? "Checking…" : phase === "saving" ? "Creating account…" : "Create account"}
          </button>
        </form>
      )}
      <p className="small muted" style={{ marginTop: 16 }}>
        Already have an account? <Link href="/login">Log in</Link>.
      </p>
    </div>
  );
}

export default function Signup() {
  return (
    <>
      <TopBar />
      <main className="main full">
        <SignupForm />
      </main>
    </>
  );
}
