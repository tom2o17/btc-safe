-- Soft vs final confirmations (reorg handling).
--
-- New status 'soft_confirmed': in a block but fewer than CONFIRMATIONS_FINAL deep. It is active:
-- it keeps its input reservations, stays in the queue, and the watcher re-checks it every tick.
-- 'confirmed' now means final (>= CONFIRMATIONS_FINAL deep) and is never re-checked.

ALTER TABLE proposals DROP CONSTRAINT proposals_status_check;
ALTER TABLE proposals ADD CONSTRAINT proposals_status_check CHECK (status IN
    ('pending','signing','ready','broadcast','soft_confirmed','confirmed','deleted','invalidated','conflicted'));

DROP INDEX proposals_active_txid;
CREATE UNIQUE INDEX proposals_active_txid ON proposals (wallet_id, unsigned_txid)
    WHERE status IN ('pending','signing','ready','broadcast','soft_confirmed');

-- Existing 'confirmed' rows were marked at 1 confirmation and never re-checked, so their depth
-- is unknown. Demote them to soft: the watcher re-verifies each on its next tick and promotes it
-- to final if it is deep enough (typical for old rows), or rolls it back if it was reorged out.
-- Nothing is lost: a still-valid row is final again within one tick.
UPDATE proposals SET status = 'soft_confirmed', updated_at = now() WHERE status = 'confirmed';

-- Soft rows hold their reservations. Re-take them, but only where no other active replacement
-- group holds the same coin now (the EXCLUDE constraint would otherwise abort the migration).
-- Those coins were spent on chain, so in practice nothing else can hold them.
UPDATE proposal_inputs pi SET active = true
FROM proposals p
WHERE pi.proposal_id = p.id AND p.status = 'soft_confirmed' AND NOT pi.active
  AND NOT EXISTS (
    SELECT 1 FROM proposal_inputs o
    WHERE o.active AND o.wallet_id = pi.wallet_id AND o.outpoint = pi.outpoint AND o.group_id <> pi.group_id
  );

INSERT INTO audit_log (wallet_id, actor, action, payload)
SELECT wallet_id, 'migration', 'proposal_status',
       jsonb_build_object('proposal', id, 'from', 'confirmed', 'to', 'soft_confirmed', 'reason', 'reverify_after_upgrade')
FROM proposals WHERE status = 'soft_confirmed';
