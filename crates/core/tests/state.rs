use btc_safe_core::state::{transition, Event, Status};
use proptest::prelude::*;

fn event() -> impl Strategy<Value = Event> {
    prop_oneof![
        any::<bool>().prop_map(|ready| Event::SignaturesAdded { ready }),
        Just(Event::Delete),
        Just(Event::Broadcast),
        any::<bool>().prop_map(|hard| Event::Confirmed { hard }),
        Just(Event::Reorged),
        (any::<bool>(), any::<bool>()).prop_map(|(s, c)| Event::InputSpentElsewhere { by_sibling_replacement: s, confirmed: c }),
        Just(Event::Dropped),
        Just(Event::PredecessorGone),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4000, .. ProptestConfig::default() })]

    /// Over any event sequence: terminal states never change, a broadcast proposal can't be
    /// deleted, and Confirmed is only reachable via an active state.
    #[test]
    fn invariants(events in prop::collection::vec(event(), 0..20)) {
        let mut s = Status::Pending;
        for e in events {
            match transition(s, e) {
                Ok(next) => {
                    prop_assert!(s.is_active(), "terminal {:?} moved to {:?} on {:?}", s, next, e);
                    if e == Event::Delete { prop_assert!(!s.is_in_flight()); }
                    // Only a soft confirmation can be undone, and only back to BROADCAST.
                    if s == Status::SoftConfirmed && next.is_active() {
                        prop_assert!(matches!(next, Status::SoftConfirmed | Status::Broadcast), "{:?} -> {:?}", s, next);
                    }
                    if next == Status::Ready && s != Status::Ready {
                        let ok = matches!(e, Event::SignaturesAdded { .. } | Event::Dropped);
                        prop_assert!(ok);
                    }
                    s = next;
                }
                Err(err) => prop_assert_eq!(err.from, s),
            }
        }
    }
}

#[test]
fn table() {
    use Status::*;
    assert_eq!(transition(Pending, Event::SignaturesAdded { ready: false }), Ok(Signing));
    assert_eq!(transition(Signing, Event::SignaturesAdded { ready: true }), Ok(Ready));
    assert_eq!(transition(Ready, Event::Broadcast), Ok(Broadcast));
    assert_eq!(transition(Broadcast, Event::Confirmed { hard: false }), Ok(SoftConfirmed));
    assert_eq!(transition(Broadcast, Event::Confirmed { hard: true }), Ok(Confirmed));
    assert_eq!(transition(SoftConfirmed, Event::Confirmed { hard: true }), Ok(Confirmed));
    assert_eq!(transition(SoftConfirmed, Event::Confirmed { hard: false }), Ok(SoftConfirmed));
    assert_eq!(transition(SoftConfirmed, Event::Reorged), Ok(Broadcast));
    assert!(transition(Broadcast, Event::Reorged).is_err());
    assert!(transition(Confirmed, Event::Reorged).is_err());
    assert!(transition(Confirmed, Event::Confirmed { hard: false }).is_err());
    assert!(transition(SoftConfirmed, Event::Delete).is_err());
    assert!(transition(SoftConfirmed, Event::Dropped).is_err());
    assert_eq!(transition(SoftConfirmed, Event::InputSpentElsewhere { by_sibling_replacement: false, confirmed: true }), Ok(Invalidated));
    assert_eq!(transition(SoftConfirmed, Event::InputSpentElsewhere { by_sibling_replacement: true, confirmed: true }), Ok(Conflicted));
    assert!(transition(Broadcast, Event::Delete).is_err());
    assert!(transition(Confirmed, Event::Delete).is_err());
    assert!(transition(Deleted, Event::SignaturesAdded { ready: true }).is_err());
    assert_eq!(transition(Broadcast, Event::Dropped), Ok(Ready));
    assert!(transition(Ready, Event::Dropped).is_err());
    assert_eq!(transition(Ready, Event::InputSpentElsewhere { by_sibling_replacement: false, confirmed: false }), Ok(Invalidated));
    assert_eq!(transition(Ready, Event::InputSpentElsewhere { by_sibling_replacement: true, confirmed: false }), Ok(Ready));
    assert_eq!(transition(Broadcast, Event::InputSpentElsewhere { by_sibling_replacement: true, confirmed: true }), Ok(Conflicted));
    assert_eq!(transition(Signing, Event::PredecessorGone), Ok(Invalidated));
    for s in Status::ALL {
        assert_eq!(Status::parse(s.as_str()), Some(s));
        // The SQL list used by the store matches `is_active`.
        assert_eq!(Status::ACTIVE_SQL.contains(&format!("'{}'", s.as_str())), s.is_active(), "{s:?}");
    }
}
