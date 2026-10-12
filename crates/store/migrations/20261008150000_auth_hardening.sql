-- Auth hardening (crates/api/src/auth.rs, mfa.rs, ratelimit.rs): roles per wallet, login
-- backoff, idle sessions, TOTP + recovery codes, Postgres-backed rate limits, signup.

-- Roles. Everyone who was a member before roles existed could do everything, so they become admins.
ALTER TABLE wallet_members ADD COLUMN role text NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'proposer', 'viewer'));
ALTER TABLE wallet_members ALTER COLUMN role SET DEFAULT 'viewer';

-- Who created a wallet, for the per-user wallet cap. NULL for wallets made before this column.
ALTER TABLE wallets ADD COLUMN created_by uuid REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX wallets_created_by ON wallets(created_by);

-- Login backoff: consecutive failures and the time before which password checks are refused.
-- totp_*: the enrolled secret (raw bytes), a pending secret during enrolment, and the last
-- accepted 30-second step (a code is only accepted for a later step: no replay).
ALTER TABLE users
    ADD COLUMN failed_logins       int NOT NULL DEFAULT 0,
    ADD COLUMN locked_until        timestamptz,
    ADD COLUMN totp_secret         bytea,
    ADD COLUMN totp_pending        bytea,
    ADD COLUMN totp_pending_until  timestamptz,
    ADD COLUMN totp_last_step      bigint,
    -- Created through public signup: the email was typed by whoever signed up and never
    -- verified. Shown when sharing a wallet; such accounts can't be promoted by an invite.
    ADD COLUMN self_signup         boolean NOT NULL DEFAULT false;

-- Idle timeout: last request on this session. reauth_failures: wrong passwords/codes typed on
-- account pages in this session (a few end the session; they don't touch the account backoff).
ALTER TABLE sessions
    ADD COLUMN last_seen_at    timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN reauth_failures int NOT NULL DEFAULT 0;

-- One-time recovery codes, SHA-256(user id || code). 80 random bits each.
CREATE TABLE recovery_codes (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL CHECK (length(code_hash) = 32),
    used_at    timestamptz,
    PRIMARY KEY (user_id, code_hash)
);

-- Password accepted, second factor pending. A challenge is not a session: it can only be
-- exchanged for one at /auth/login/mfa, within a few minutes and a few attempts.
CREATE TABLE login_challenges (
    token_hash  bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attempts    int NOT NULL DEFAULT 0,
    expires_at  timestamptz NOT NULL
);

-- Browsers that have logged in to an account before. A login carrying one is not held back by
-- that account's failure backoff, so an attacker can't lock the owner out.
CREATE TABLE known_devices (
    token_hash    bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX known_devices_user ON known_devices(user_id);

-- Token buckets shared by every API process.
CREATE TABLE rate_limits (
    key      text PRIMARY KEY,
    tokens   double precision NOT NULL,
    at       timestamptz NOT NULL,
    last_ok  boolean NOT NULL
);

-- Signup proof-of-work challenges that have been spent.
CREATE TABLE pow_spent (
    challenge_hash  bytea PRIMARY KEY CHECK (length(challenge_hash) = 32),
    at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_action_at ON audit_log (action, at);
