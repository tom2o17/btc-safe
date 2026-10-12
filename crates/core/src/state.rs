//! Proposal lifecycle (DESIGN.md §5.4). Pure transition function; the store applies a
//! transition with a compare-and-swap on the previous status.
//!
//! ```text
//!   PENDING ──sig──▶ SIGNING ──sigs ≥ M──▶ READY ──execute──▶ BROADCAST
//!   BROADCAST ──1..N-1 confs──▶ SOFT_CONFIRMED ──≥ N confs──▶ CONFIRMED (final)
//!   BROADCAST ──≥ N confs──▶ CONFIRMED (first seen already deep)
//!   SOFT_CONFIRMED ──reorged out (back in mempool, or gone)──▶ BROADCAST
//!   PENDING/SIGNING/READY ──delete──▶ DELETED
//!   any active ──input spent by a non-sibling tx──▶ INVALIDATED
//!   any active ──sibling replacement confirmed──▶ CONFLICTED
//!   any active ──predecessor gone (strict-order)──▶ INVALIDATED
//!   BROADCAST ──dropped from mempool, inputs unspent──▶ READY
//! ```
//!
//! N is `CONFIRMATIONS_FINAL` (watcher config, default 2). SOFT_CONFIRMED is still active: it
//! keeps its coin reservations and the watcher re-checks it every tick, because a reorg can
//! undo it. CONFIRMED is final and never re-checked.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Signing,
    Ready,
    Broadcast,
    /// In a block, but fewer than `CONFIRMATIONS_FINAL` deep. Can still be reorged out.
    SoftConfirmed,
    /// Final: at least `CONFIRMATIONS_FINAL` deep. Never re-checked.
    Confirmed,
    Deleted,
    Invalidated,
    Conflicted,
}

impl Status {
    pub const ALL: [Status; 9] = [
        Status::Pending,
        Status::Signing,
        Status::Ready,
        Status::Broadcast,
        Status::SoftConfirmed,
        Status::Confirmed,
        Status::Deleted,
        Status::Invalidated,
        Status::Conflicted,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Signing => "signing",
            Status::Ready => "ready",
            Status::Broadcast => "broadcast",
            Status::SoftConfirmed => "soft_confirmed",
            Status::Confirmed => "confirmed",
            Status::Deleted => "deleted",
            Status::Invalidated => "invalidated",
            Status::Conflicted => "conflicted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Status::ALL.into_iter().find(|x| x.as_str() == s)
    }

    /// Active proposals reserve their inputs, appear in the queue, and are re-checked by the
    /// watcher. SOFT_CONFIRMED is active: a reorg can still undo it.
    pub fn is_active(self) -> bool {
        matches!(self, Status::Pending | Status::Signing | Status::Ready | Status::Broadcast | Status::SoftConfirmed)
    }

    /// SQL list of the active statuses, for `status IN (...)` clauses. Must match `is_active`
    /// (a unit test checks it).
    pub const ACTIVE_SQL: &'static str = "('pending','signing','ready','broadcast','soft_confirmed')";

    /// The tx is out (in the mempool or a block, not yet final). Can't be deleted or rebuilt.
    pub fn is_in_flight(self) -> bool {
        matches!(self, Status::Broadcast | Status::SoftConfirmed)
    }

    pub fn is_terminal(self) -> bool {
        !self.is_active()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// New valid signatures were merged; `ready` = every input has ≥ M signatures.
    SignaturesAdded { ready: bool },
    Delete,
    /// The tx was accepted by the chain source (by us, or seen in the mempool after someone
    /// else broadcast the same tx).
    Broadcast,
    /// Seen in a block. `hard` = at least `CONFIRMATIONS_FINAL` deep.
    Confirmed { hard: bool },
    /// A soft-confirmed tx is no longer in the best chain (back in the mempool, or gone).
    Reorged,
    /// An input was spent by a tx that is not this proposal's tx.
    InputSpentElsewhere { by_sibling_replacement: bool, confirmed: bool },
    /// Broadcast tx vanished from the mempool and its inputs are unspent again.
    Dropped,
    /// Strict-order: the predecessor was deleted, invalidated, conflicted, or replaced.
    PredecessorGone,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("transition {event:?} not allowed from {from:?}")]
pub struct TransitionError {
    pub from: Status,
    pub event: Event,
}

pub fn transition(from: Status, event: Event) -> Result<Status, TransitionError> {
    use Status::*;
    let err = Err(TransitionError { from, event });
    match (from, event) {
        (Pending | Signing, Event::SignaturesAdded { ready }) => Ok(if ready { Ready } else { Signing }),
        // More signatures on a ready proposal are harmless.
        (Ready, Event::SignaturesAdded { .. }) => Ok(Ready),
        (Pending | Signing | Ready, Event::Delete) => Ok(Deleted),
        // Someone else may broadcast the fully signed tx before we do; we accept seeing it
        // from any active pre-broadcast state.
        (Pending | Signing | Ready, Event::Broadcast) => Ok(Broadcast),
        (Broadcast, Event::Broadcast) => Ok(Broadcast),
        (Pending | Signing | Ready | Broadcast | SoftConfirmed, Event::Confirmed { hard }) => Ok(if hard { Confirmed } else { SoftConfirmed }),
        (SoftConfirmed, Event::Reorged) => Ok(Broadcast),
        (Pending | Signing | Ready | Broadcast | SoftConfirmed, Event::InputSpentElsewhere { by_sibling_replacement, confirmed }) => {
            if by_sibling_replacement {
                // Replacements of each other: only final once the sibling confirms.
                if confirmed {
                    Ok(Conflicted)
                } else {
                    Ok(from)
                }
            } else {
                Ok(Invalidated)
            }
        }
        (Broadcast, Event::Dropped) => Ok(Ready),
        (Pending | Signing | Ready | Broadcast | SoftConfirmed, Event::PredecessorGone) => Ok(Invalidated),
        _ => err,
    }
}
