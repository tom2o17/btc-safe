"use client";

import { useEffect, useState } from "react";
import { logoutAll } from "@/components/auth";
import { TopBar } from "@/components/shell";
import { CopyButton, ErrorBox, Qr } from "@/components/ui";
import { api, ApiError, fetchMe, type Me, type SignupInfo, type TotpSetup } from "@/lib/api";
import { download } from "@/lib/format";

function duration(secs: number): string {
  if (secs % 3600 === 0) return `${secs / 3600} hour${secs === 3600 ? "" : "s"}`;
  if (secs % 60 === 0) return `${secs / 60} minutes`;
  return `${secs} seconds`;
}

function friendly(e: unknown): unknown {
  if (e instanceof ApiError && e.code === "bad_code") return new Error("That code isn't valid. Use the current code from your authenticator.");
  if (e instanceof ApiError && e.code === "bad_password") return new Error("Wrong password.");
  return e;
}

export default function Account() {
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<unknown>(null);
  const reload = () => fetchMe().then(setMe, setError);
  useEffect(() => {
    void reload();
  }, []);

  return (
    <>
      <TopBar />
      <main className="main full" style={{ maxWidth: 820 }}>
        <h1>Your account</h1>
        <ErrorBox error={error} />
        {me ? (
          <div className="stack">
            <SessionCard me={me} />
            <PasswordCard />
            <TwoFactorCard me={me} onChange={() => void reload()} />
          </div>
        ) : null}
      </main>
    </>
  );
}

function SessionCard({ me }: { me: Me }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  return (
    <div className="card stack" data-testid="session">
      <h2>Session</h2>
      <div className="kv">
        <span className="k">Email (username)</span>
        <span>{me.email}</span>
        <span className="k">Server admin</span>
        <span>{me.is_admin ? "yes" : "no"}</span>
        <span className="k">This session ends</span>
        <span data-testid="session-expires">{me.session_expires_at ? new Date(me.session_expires_at).toLocaleString() : "—"}</span>
        <span className="k">Idle timeout</span>
        <span data-testid="idle-timeout">{me.idle_timeout_secs ? `${duration(me.idle_timeout_secs)} without activity logs you out` : "—"}</span>
      </div>
      <ErrorBox error={error} />
      <div className="row between wrap">
        <span className="small muted">Ends every session of this account, in every browser, including this one.</span>
        <button
          className="btn danger"
          disabled={busy}
          onClick={async () => {
            if (!confirm("Log out of BTC Safe in every browser?")) return;
            setBusy(true);
            try {
              await logoutAll();
            } catch (e) {
              setError(e);
              setBusy(false);
            }
          }}
        >
          Log out everywhere
        </button>
      </div>
    </div>
  );
}

function PasswordCard() {
  const [min, setMin] = useState(12);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);
  useEffect(() => {
    fetch("/api/auth/signup", { cache: "no-store" })
      .then((r) => (r.ok ? (r.json() as Promise<SignupInfo>) : null))
      .then((i) => i?.min_password && setMin(i.min_password), () => undefined);
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (next !== repeat) return setError(new Error("new passwords don't match"));
    setBusy(true);
    setError(null);
    setDone(false);
    try {
      // The response rotates the session (new cookie + csrf_token; api() adopts the token).
      await api("/auth/password", { body: { current_password: current, new_password: next } });
      setCurrent("");
      setNext("");
      setRepeat("");
      setDone(true);
    } catch (err) {
      setError(friendly(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card stack" data-testid="password">
      <h2>Change password</h2>
      <form className="stack" onSubmit={submit}>
        <input type="email" autoComplete="username" hidden readOnly aria-hidden />
        <input type="password" autoComplete="current-password" placeholder="Current password" value={current} onChange={(e) => setCurrent(e.target.value)} aria-label="Current password" required />
        <input
          type="password"
          autoComplete="new-password"
          placeholder={`New password (at least ${min} characters)`}
          value={next}
          onChange={(e) => setNext(e.target.value)}
          aria-label="New password"
          minLength={min}
          required
        />
        <input type="password" autoComplete="new-password" placeholder="Repeat new password" value={repeat} onChange={(e) => setRepeat(e.target.value)} aria-label="Repeat new password" required />
        <ErrorBox error={error} />
        {done ? <div className="alert ok">Password changed. Every other session of this account was logged out.</div> : null}
        <div>
          <button className="btn" type="submit" disabled={busy || !current || next.length < min}>
            {busy ? "Saving…" : "Change password"}
          </button>
        </div>
      </form>
    </div>
  );
}

function RecoveryCodes({ codes, email }: { codes: string[]; email: string }) {
  const text = `BTC Safe recovery codes for ${email}\nEach code works once. Keep them somewhere safe and offline.\n\n${codes.join("\n")}\n`;
  return (
    <div className="stack" data-testid="recovery-codes">
      <div className="alert warn">
        <strong>Save these now.</strong> They are the only way back in if you lose your authenticator — there is no email reset. Each works once. They
        won&apos;t be shown again.
      </div>
      <pre className="mono card" style={{ padding: 12, columns: 2, margin: 0 }}>
        {codes.join("\n")}
      </pre>
      <div className="row">
        <CopyButton text={codes.join("\n")} label="Copy codes" />
        <button className="btn secondary small" onClick={() => download("btc-safe-recovery-codes.txt", text, "text/plain")}>
          ⇩ Download .txt
        </button>
      </div>
    </div>
  );
}

type TfaMode = null | "setup-password" | "setup-scan" | "disable" | "regenerate";

function TwoFactorCard({ me, onChange }: { me: Me; onChange: () => void }) {
  const [mode, setMode] = useState<TfaMode>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  function start(m: TfaMode) {
    setMode(m);
    setPassword("");
    setCode("");
    setUseRecovery(false);
    setError(null);
    setCodes(null);
  }

  async function run(f: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await f();
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(false);
    }
  }

  const beginSetup = () =>
    run(async () => {
      setSetup(await api<TotpSetup>("/auth/totp/setup", { body: { password } }));
      setPassword("");
      setCode("");
      setMode("setup-scan");
    });

  const enable = () =>
    run(async () => {
      const r = await api<{ recovery_codes: string[] }>("/auth/totp/enable", { body: { code: code.replace(/\s+/g, "") } });
      setCodes(r.recovery_codes);
      setSetup(null);
      setMode(null);
      onChange();
    });

  const disable = () =>
    run(async () => {
      const c = code.trim();
      await api("/auth/totp/disable", { body: useRecovery ? { password, recovery_code: c.toLowerCase() } : { password, code: c.replace(/\s+/g, "") } });
      setMode(null);
      onChange();
    });

  const regenerate = () =>
    run(async () => {
      const r = await api<{ recovery_codes: string[] }>("/auth/recovery-codes", { body: { password, code: code.replace(/\s+/g, "") } });
      setCodes(r.recovery_codes);
      setMode(null);
      onChange();
    });

  const pw = (
    <input type="password" autoComplete="current-password" placeholder="Your password" value={password} onChange={(e) => setPassword(e.target.value)} aria-label="Confirm with your password" />
  );
  const otp = (
    <input
      type="text"
      inputMode="numeric"
      autoComplete="one-time-code"
      placeholder="123456"
      value={code}
      onChange={(e) => setCode(e.target.value)}
      aria-label="Authenticator code"
      style={{ maxWidth: 200 }}
    />
  );

  return (
    <div className="card stack" data-testid="two-factor">
      <h2>Two-factor authentication</h2>
      {codes ? <RecoveryCodes codes={codes} email={me.email} /> : null}
      {me.totp_enabled ? (
        <>
          <div className="row between wrap">
            <span>
              <span className="tag ok">On</span> Logging in needs a code from your authenticator app.
            </span>
            <span className="small" data-testid="recovery-left">
              {me.recovery_codes_left ?? "?"} recovery code{me.recovery_codes_left === 1 ? "" : "s"} left
            </span>
          </div>
          {mode === null ? (
            <div className="row">
              <button className="btn secondary" onClick={() => start("regenerate")}>
                New recovery codes
              </button>
              <button className="btn secondary" onClick={() => start("disable")}>
                Turn off two-factor
              </button>
            </div>
          ) : null}
          {mode === "regenerate" ? (
            <form className="stack" onSubmit={(e) => (e.preventDefault(), void regenerate())}>
              <p className="small muted">Makes 10 new recovery codes. The old ones stop working.</p>
              {pw}
              {otp}
              <div className="row">
                <button className="btn" type="submit" disabled={busy || !password || !code.trim()}>
                  Make new codes
                </button>
                <button className="btn secondary" type="button" onClick={() => start(null)}>
                  Cancel
                </button>
              </div>
            </form>
          ) : null}
          {mode === "disable" ? (
            <form className="stack" onSubmit={(e) => (e.preventDefault(), void disable())}>
              <p className="small muted">Turning it off means your password alone gets into this account.</p>
              {pw}
              {useRecovery ? (
                <input type="text" autoComplete="off" spellCheck={false} placeholder="abcd-efgh-ijkl-mnop" value={code} onChange={(e) => setCode(e.target.value)} aria-label="Recovery code" />
              ) : (
                otp
              )}
              <button type="button" className="linkbtn small" style={{ alignSelf: "flex-start" }} onClick={() => (setUseRecovery(!useRecovery), setCode(""))}>
                {useRecovery ? "Use an authenticator code instead" : "Use a recovery code instead"}
              </button>
              <div className="row">
                <button className="btn danger" type="submit" disabled={busy || !password || !code.trim()}>
                  Turn off two-factor
                </button>
                <button className="btn secondary" type="button" onClick={() => start(null)}>
                  Cancel
                </button>
              </div>
            </form>
          ) : null}
        </>
      ) : (
        <>
          <p className="small muted">
            Adds a 6-digit code from an authenticator app (any TOTP app) to every login. Strongly recommended: there is no email reset, so your password is
            otherwise the only thing protecting this account.
          </p>
          {mode === null ? (
            <div>
              <button className="btn" onClick={() => start("setup-password")}>
                Set up two-factor
              </button>
            </div>
          ) : null}
          {mode === "setup-password" ? (
            <form className="stack" onSubmit={(e) => (e.preventDefault(), void beginSetup())}>
              {pw}
              <div className="row">
                <button className="btn" type="submit" disabled={busy || !password}>
                  Continue
                </button>
                <button className="btn secondary" type="button" onClick={() => start(null)}>
                  Cancel
                </button>
              </div>
            </form>
          ) : null}
          {mode === "setup-scan" && setup ? (
            <form className="stack" onSubmit={(e) => (e.preventDefault(), void enable())}>
              <p>1. Scan this with your authenticator app, or type the key in.</p>
              <div className="row wrap" style={{ alignItems: "flex-start", gap: 20 }}>
                <div className="qrbox">
                  <Qr value={setup.otpauth_uri} size={200} />
                </div>
                <div className="stack" style={{ minWidth: 0 }}>
                  <span className="small muted">Key</span>
                  <span className="mono break" data-testid="totp-secret">
                    {setup.secret}
                  </span>
                  <CopyButton text={setup.secret} label="Copy key" />
                </div>
              </div>
              <p>2. Enter the code it shows to turn two-factor on.</p>
              {otp}
              <div className="row">
                <button className="btn" type="submit" disabled={busy || code.replace(/\s+/g, "").length < 6}>
                  Turn on two-factor
                </button>
                <button className="btn secondary" type="button" onClick={() => (start(null), setSetup(null))}>
                  Cancel
                </button>
              </div>
            </form>
          ) : null}
        </>
      )}
      <ErrorBox error={error} />
    </div>
  );
}
