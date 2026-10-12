-- Per-user accounts (replaces the shared API_TOKEN). Invite-only: a user row is created by an
-- admin invite or by the ADMIN_EMAIL bootstrap, with no password; the invitee sets one through a
-- one-time setup token. Tokens (session and setup) are stored as SHA-256 hashes, never raw.
CREATE TABLE users (
    id            uuid PRIMARY KEY,
    email         text NOT NULL UNIQUE CHECK (email = lower(email) AND position('@' in email) > 1),
    password_hash text,                 -- argon2id PHC string; NULL until setup completes
    is_admin      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash  bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);

-- One-time password-setup tokens (invites and password resets). used_at set on redemption.
CREATE TABLE setup_tokens (
    token_hash  bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);

-- Who can see a wallet. The creator is added on create/import; members can add other users.
CREATE TABLE wallet_members (
    wallet_id  uuid NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (wallet_id, user_id)
);
CREATE INDEX wallet_members_user ON wallet_members(user_id);
