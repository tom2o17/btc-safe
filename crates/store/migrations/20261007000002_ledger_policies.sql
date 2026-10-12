-- Ledger wallet-policy registrations (crates/core/src/ledger.rs). One row per (wallet, owner):
-- the device that holds that owner's key registered this wallet's policy and returned `hmac`.
-- The HMAC is not key material, but it lets its holder skip the on-device policy review, so it
-- stays server-side, scoped to the wallet, behind the API token. Re-registering overwrites.
CREATE TABLE ledger_policies (
    wallet_id           uuid  NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    owner_id            uuid  NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    name                text  NOT NULL,
    descriptor_template text  NOT NULL,
    keys                jsonb NOT NULL,
    policy_id           bytea NOT NULL CHECK (length(policy_id) = 32),
    hmac                bytea NOT NULL CHECK (length(hmac) = 32),
    registered_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (wallet_id, owner_id)
);
