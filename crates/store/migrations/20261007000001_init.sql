-- btc-safe schema v1 (DESIGN.md §5.3). Coordination state only: losing it loses the queue
-- and labels, never funds.

CREATE EXTENSION IF NOT EXISTS btree_gist;

CREATE TABLE wallets (
    id               uuid PRIMARY KEY,
    name             text NOT NULL,
    network          text NOT NULL CHECK (network IN ('signet', 'testnet', 'testnet4', 'regtest')),
    descriptor_ext   text NOT NULL,
    descriptor_int   text NOT NULL,
    threshold        int  NOT NULL CHECK (threshold >= 1),
    policy_kind      text NOT NULL DEFAULT 'sortedmulti_p2wsh',
    ordering_mode    text NOT NULL DEFAULT 'parallel' CHECK (ordering_mode IN ('parallel', 'strict')),
    next_receive_idx int  NOT NULL DEFAULT 0 CHECK (next_receive_idx >= 0),
    next_change_idx  int  NOT NULL DEFAULT 0 CHECK (next_change_idx >= 0),
    -- Persisted bdk_wallet ChangeSet (chain + tx graph + indexer state).
    bdk_changeset    jsonb,
    tip_height       int,
    last_synced_at   timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE owners (
    id          uuid PRIMARY KEY,
    wallet_id   uuid NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    name        text NOT NULL,
    xpub        text NOT NULL,
    fingerprint char(8) NOT NULL,
    path        text NOT NULL,
    kind        text NOT NULL DEFAULT 'hardware' CHECK (kind IN ('hardware', 'sparrow', 'metamask_btc', 'cosigner')),
    position    int  NOT NULL,
    UNIQUE (wallet_id, fingerprint),
    UNIQUE (wallet_id, xpub),
    UNIQUE (wallet_id, position)
);

CREATE TABLE proposals (
    id                      bigserial PRIMARY KEY,
    wallet_id               uuid NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    created_by              text NOT NULL,
    status                  text NOT NULL CHECK (status IN
                              ('pending','signing','ready','broadcast','confirmed','deleted','invalidated','conflicted')),
    status_reason           text,
    psbt                    bytea NOT NULL,          -- latest combined (canonical + verified sigs)
    unsigned_tx             bytea NOT NULL,          -- consensus-serialized, the byte-equality reference
    unsigned_txid           char(64) NOT NULL,
    fee_sats                bigint NOT NULL,
    fee_rate_sat_kwu        bigint NOT NULL,
    est_vsize               int NOT NULL,
    sent_sats               bigint NOT NULL,
    rbf                     boolean NOT NULL,
    fee_override            boolean NOT NULL DEFAULT false,
    group_id                bigint,                  -- replacement group root (self id if none)
    replaces_proposal_id    bigint REFERENCES proposals(id),
    predecessor_proposal_id bigint REFERENCES proposals(id),   -- strict-order chain
    broadcast_txid          char(64),
    invalidated_by_txid     char(64),
    confirmed_height        int,
    final_tx                bytea,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX proposals_wallet_status ON proposals (wallet_id, status);
CREATE UNIQUE INDEX proposals_active_txid ON proposals (wallet_id, unsigned_txid)
    WHERE status IN ('pending','signing','ready','broadcast');

CREATE TABLE proposal_inputs (
    proposal_id  bigint NOT NULL REFERENCES proposals(id) ON DELETE CASCADE,
    wallet_id    uuid NOT NULL,
    idx          int NOT NULL,
    outpoint     text NOT NULL,
    amount_sats  bigint NOT NULL,
    keychain     text NOT NULL CHECK (keychain IN ('external', 'internal')),
    deriv_index  int NOT NULL,
    group_id     bigint NOT NULL,
    active       boolean NOT NULL DEFAULT true,
    PRIMARY KEY (proposal_id, idx),
    -- Input reservation (DESIGN.md §2 rule 1): an outpoint can be held by at most one
    -- replacement group among active proposals of a wallet. Replacements share by design.
    EXCLUDE USING gist (wallet_id WITH =, outpoint WITH =, group_id WITH <>) WHERE (active)
);

CREATE TABLE proposal_outputs (
    proposal_id   bigint NOT NULL REFERENCES proposals(id) ON DELETE CASCADE,
    vout          int NOT NULL,
    script_pubkey bytea NOT NULL,
    address       text NOT NULL,
    amount_sats   bigint NOT NULL,
    is_change     boolean NOT NULL,
    change_index  int,
    PRIMARY KEY (proposal_id, vout),
    CHECK (is_change = (change_index IS NOT NULL))
);

CREATE TABLE signatures (
    proposal_id bigint NOT NULL REFERENCES proposals(id) ON DELETE CASCADE,
    owner_id    uuid NOT NULL REFERENCES owners(id),
    input_idx   int NOT NULL,
    pubkey      bytea NOT NULL,
    sig         bytea NOT NULL,
    added_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (proposal_id, owner_id, input_idx)
);

CREATE TABLE address_labels (
    wallet_id   uuid NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    keychain    text NOT NULL CHECK (keychain IN ('external', 'internal')),
    deriv_index int NOT NULL,
    label       text NOT NULL,
    PRIMARY KEY (wallet_id, keychain, deriv_index)
);

CREATE TABLE address_book (
    id         uuid PRIMARY KEY,
    wallet_id  uuid NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    label      text NOT NULL,
    address    text NOT NULL,
    network    text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (wallet_id, address)
);

CREATE TABLE audit_log (
    id        bigserial PRIMARY KEY,
    wallet_id uuid,
    actor     text NOT NULL,
    action    text NOT NULL,
    payload   jsonb NOT NULL DEFAULT '{}'::jsonb,
    at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_wallet ON audit_log (wallet_id, at);
