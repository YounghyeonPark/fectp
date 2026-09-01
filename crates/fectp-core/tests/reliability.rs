//! Reliability layer behaviour.
//!
//! Time is an input everywhere, so these run to completion instantly and
//! deterministically. A retransmission test that slept would be slow and
//! flaky, and would not be able to probe the exact millisecond a deadline
//! falls on.

use fectp_core::reliability::{
    Ack, DedupWindow, Due, MessageId, RetransmitQueue, Rto, ACK_BLOCK_LEN, ACK_WINDOW,
    INITIAL_RTO_MS, MAX_IN_FLIGHT, MAX_RETRIES, MAX_RTO_MS,
};
use fectp_core::Error;

// ------------------------------------------------------------------ ack ---

#[test]
fn ack_round_trips() {
    let ack = Ack {
        highest: 0x1234_5678,
        bitmap: 0xDEAD_BEEF_CAFE_F00D,
    };
    let mut buf = [0u8; ACK_BLOCK_LEN];
    ack.encode(&mut buf).expect("encode");
    assert_eq!(Ack::decode(&buf).expect("decode"), ack);
}

#[test]
fn ack_coverage() {
    let ack = Ack {
        highest: 100,
        bitmap: 0b1010,
    };
    assert!(ack.covers(100), "the highest is always covered");
    assert!(!ack.covers(99), "bit 0 clear");
    assert!(ack.covers(98), "bit 1 set");
    assert!(!ack.covers(97), "bit 2 clear");
    assert!(ack.covers(96), "bit 3 set");

    assert!(!ack.covers(101), "nothing above the highest is covered");
    assert!(
        !ack.covers(100 - ACK_WINDOW - 1),
        "beyond the window, unreported means unacknowledged, not delivered"
    );
}

#[test]
fn truncated_ack_is_rejected() {
    assert_eq!(Ack::decode(&[0u8; 4]), Err(Error::MessageTooShort));
}

// -------------------------------------------------------------- dedup ---

#[test]
fn duplicates_are_suppressed() {
    let mut window = DedupWindow::new();
    assert!(window.accept(0), "first message is new");
    assert!(!window.accept(0), "the same message again is a duplicate");

    assert!(window.accept(1));
    assert!(!window.accept(1));
    assert!(!window.accept(0), "still remembered");
}

#[test]
fn out_of_order_arrivals_are_all_delivered_once() {
    let mut window = DedupWindow::new();
    for id in [5u32, 3, 4, 1, 2, 0] {
        assert!(window.accept(id), "{id} arrived out of order but is new");
    }
    for id in 0..=5u32 {
        assert!(!window.accept(id), "{id} must not be delivered twice");
    }
}

#[test]
fn the_dedup_window_slides() {
    let mut window = DedupWindow::new();
    assert!(window.accept(0));

    // Jump far ahead. Everything in between is now outside the window.
    assert!(window.accept(1000));
    assert!(!window.accept(1000));
    assert!(
        !window.accept(500),
        "an id older than the window is assumed already delivered, because \
         handing the application a duplicate is the worse failure"
    );
    assert!(window.accept(999), "still inside the window");
    assert!(window.accept(1000 - ACK_WINDOW), "the far edge is inside");
    assert!(
        !window.accept(1000 - ACK_WINDOW - 1),
        "one past the edge is outside"
    );
}

#[test]
fn sliding_exactly_one_window_keeps_the_previous_highest() {
    // The boundary that a naive shift-by-64 would get wrong.
    let mut window = DedupWindow::new();
    assert!(window.accept(10));
    assert!(window.accept(10 + ACK_WINDOW));
    assert!(
        !window.accept(10),
        "the previous highest must still be remembered at the window edge"
    );
}

#[test]
fn dedup_window_produces_a_matching_ack() {
    let mut window = DedupWindow::new();
    for id in [0u32, 1, 3] {
        window.accept(id);
    }
    let ack = window.to_ack();
    assert_eq!(ack.highest, 3);
    assert!(ack.covers(3));
    assert!(!ack.covers(2), "2 was never received");
    assert!(ack.covers(1));
    assert!(ack.covers(0));
}

// ---------------------------------------------------------------- rto ---

#[test]
fn rto_starts_at_the_initial_value_and_converges() {
    let mut rto = Rto::new();
    assert_eq!(rto.current(), INITIAL_RTO_MS);

    // A steady 40 ms path should settle near 40 ms plus variation margin, and
    // well below the initial guess.
    for _ in 0..20 {
        rto.sample(40);
    }
    let settled = rto.current();
    assert!(
        (40..INITIAL_RTO_MS).contains(&settled),
        "expected the estimate to converge below the initial guess, got {settled}"
    );
}

#[test]
fn rto_backoff_is_exponential_and_bounded() {
    let rto = Rto::new();
    let base = rto.current();
    assert_eq!(rto.with_backoff(0), base);
    assert_eq!(rto.with_backoff(1), base * 2);
    assert_eq!(rto.with_backoff(2), base * 4);
    assert!(
        rto.with_backoff(MAX_RETRIES) <= MAX_RTO_MS,
        "backoff must stay bounded"
    );
}

// -------------------------------------------------------------- queue ---

fn drain(queue: &mut RetransmitQueue, now: u64) -> Vec<Due> {
    let mut out = [Due::Retransmit(0); MAX_IN_FLIGHT];
    let n = queue.poll(now, &mut out);
    out[..n].to_vec()
}

fn acked(queue: &mut RetransmitQueue, ack: &Ack, now: u64) -> Vec<MessageId> {
    let mut out = [0u32; MAX_IN_FLIGHT];
    let n = queue.on_ack(ack, now, &mut out);
    out[..n].to_vec()
}

#[test]
fn an_acknowledged_message_is_never_retransmitted() {
    let mut queue = RetransmitQueue::new();
    let id = queue.register(0).expect("register");
    assert_eq!(queue.in_flight(), 1);

    let ack = Ack {
        highest: id,
        bitmap: 0,
    };
    assert_eq!(acked(&mut queue, &ack, 30), vec![id]);
    assert_eq!(queue.in_flight(), 0);

    assert!(
        drain(&mut queue, 10_000).is_empty(),
        "nothing is outstanding, so nothing can time out"
    );
}

#[test]
fn an_unacknowledged_message_is_retransmitted_after_the_timeout() {
    let mut queue = RetransmitQueue::new();
    let id = queue.register(0).expect("register");

    assert!(
        drain(&mut queue, u64::from(INITIAL_RTO_MS) - 1).is_empty(),
        "must not fire before the deadline"
    );
    assert_eq!(
        drain(&mut queue, u64::from(INITIAL_RTO_MS)),
        vec![Due::Retransmit(id)],
        "must fire exactly at the deadline"
    );
    assert!(
        drain(&mut queue, u64::from(INITIAL_RTO_MS)).is_empty(),
        "the deadline must move out after firing, not fire repeatedly"
    );
}

#[test]
fn retransmission_backs_off_and_eventually_gives_up() {
    let mut queue = RetransmitQueue::new();
    let id = queue.register(0).expect("register");

    let mut now = 0u64;
    let mut retransmits = 0;
    // Step far enough each time to clear any backoff.
    for _ in 0..MAX_RETRIES + 1 {
        now += u64::from(MAX_RTO_MS) + 1;
        match drain(&mut queue, now).as_slice() {
            [Due::Retransmit(got)] => {
                assert_eq!(*got, id);
                retransmits += 1;
            }
            [Due::GaveUp(got)] => {
                assert_eq!(*got, id);
                assert_eq!(
                    retransmits, MAX_RETRIES,
                    "must give up only after exhausting the retry budget"
                );
                assert_eq!(queue.in_flight(), 0, "an abandoned message is dropped");
                return;
            }
            other => panic!("unexpected poll result: {other:?}"),
        }
    }
    panic!("the queue never gave up");
}

#[test]
fn only_the_lost_message_is_resent() {
    // Selective repeat: a gap must not drag its neighbours back onto the wire.
    let mut queue = RetransmitQueue::new();
    let a = queue.register(0).expect("register");
    let b = queue.register(0).expect("register");
    let c = queue.register(0).expect("register");

    // Everything but `b` is acknowledged.
    let mut window = DedupWindow::new();
    window.accept(a);
    window.accept(c);
    let outstanding = acked(&mut queue, &window.to_ack(), 10);
    assert_eq!(outstanding.len(), 2);
    assert!(outstanding.contains(&a) && outstanding.contains(&c));

    assert_eq!(
        drain(&mut queue, u64::from(INITIAL_RTO_MS) + 1),
        vec![Due::Retransmit(b)],
        "only the missing message goes back on the wire"
    );
}

#[test]
fn the_window_is_bounded() {
    let mut queue = RetransmitQueue::new();

    // Two bounds apply, and the congestion window is the tighter of them until
    // acknowledgements widen it. Nothing is acknowledged here, so it stays
    // where it opened.
    let opened = queue.congestion_window();
    assert!(opened <= MAX_IN_FLIGHT);
    for _ in 0..opened {
        queue.register(0).expect("register");
    }
    assert_eq!(
        queue.register(0),
        Err(Error::WindowFull),
        "the window must bound sending, not grow without limit"
    );
}

#[test]
fn the_congestion_window_opens_on_delivery_and_collapses_on_loss() {
    let mut queue = RetransmitQueue::new();
    let opened = queue.congestion_window();

    // Acknowledging what is in flight widens the window, so a path that is
    // carrying everything offered gets more offered to it.
    for _ in 0..opened {
        queue.register(0).expect("register");
    }
    for id in 0..opened as u32 {
        acked(
            &mut queue,
            &Ack {
                highest: id,
                bitmap: 0,
            },
            1,
        );
    }
    let widened = queue.congestion_window();
    assert!(
        widened > opened,
        "delivery must widen the window: {opened} -> {widened}"
    );

    // A retransmission timer firing is the only loss signal there is, and it
    // is the severe one — there are no duplicate acknowledgements to read,
    // because an acknowledgement reports the whole receive window rather than
    // repeating the last in-order identifier.
    queue.register(0).expect("register");
    drain(&mut queue, u64::from(INITIAL_RTO_MS) * 4);
    assert!(
        queue.congestion_window() < widened,
        "a timeout must narrow the window"
    );
}

#[test]
fn the_congestion_window_never_exceeds_the_memory_bound() {
    let mut queue = RetransmitQueue::new();

    // Acknowledge far more than the slots hold. The window may open as wide as
    // the path allows, but the slots are the memory it is allowed to use.
    for round in 0..64u32 {
        let room = queue.congestion_window() - queue.in_flight();
        for _ in 0..room {
            queue.register(u64::from(round)).expect("register");
        }
        for id in 0..MAX_IN_FLIGHT as u32 * 2 {
            acked(
                &mut queue,
                &Ack {
                    highest: id,
                    bitmap: 0,
                },
                u64::from(round) + 1,
            );
        }
        assert!(
            queue.congestion_window() <= MAX_IN_FLIGHT,
            "window {} exceeded the {MAX_IN_FLIGHT}-slot bound",
            queue.congestion_window()
        );
    }
}

#[test]
fn round_trips_are_only_sampled_from_untouched_messages() {
    // Karn's algorithm. An acknowledgement for a retransmitted message is
    // ambiguous — it might answer either transmission — so sampling it would
    // corrupt the estimate.
    let mut queue = RetransmitQueue::new();
    let id = queue.register(0).expect("register");
    assert_eq!(queue.rto_ms(), INITIAL_RTO_MS);

    // Force a retransmission, then acknowledge a long time later.
    drain(&mut queue, u64::from(INITIAL_RTO_MS));
    acked(
        &mut queue,
        &Ack {
            highest: id,
            bitmap: 0,
        },
        4_000,
    );
    assert_eq!(
        queue.rto_ms(),
        INITIAL_RTO_MS,
        "the ambiguous sample must be discarded, leaving the estimate untouched"
    );

    // A clean exchange does move it.
    let id = queue.register(5_000).expect("register");
    acked(
        &mut queue,
        &Ack {
            highest: id,
            bitmap: 0,
        },
        5_030,
    );
    assert_ne!(queue.rto_ms(), INITIAL_RTO_MS, "a clean sample must count");
}

#[test]
fn next_deadline_bounds_how_long_a_caller_may_block() {
    let mut queue = RetransmitQueue::new();
    assert_eq!(queue.next_deadline_ms(), None, "nothing outstanding");

    queue.register(1_000).expect("register");
    queue.register(1_500).expect("register");
    assert_eq!(
        queue.next_deadline_ms(),
        Some(1_000 + u64::from(INITIAL_RTO_MS)),
        "a caller waiting on a socket must wake for the earliest deadline"
    );
}

/// Identifiers wrap, and both sides of the reliability layer have to agree that
/// they do.
///
/// The sender already did: `register` bounds its distance with `wrapping_sub`,
/// and `next_id` wraps. The receiver compared numerically, so at the boundary a
/// brand-new identifier looked older than everything and was refused as already
/// delivered — which stops a session delivering reliable messages at all,
/// permanently, after 2^32 of them in one direction.
///
/// Found by writing the acknowledgement rule out of SPEC.md §5.7 and comparing:
/// "bit `i` set means `highest - 1 - i`" is wrapping arithmetic on a u32, so
/// the document and the code disagreed at exactly one point.
#[test]
fn identifiers_are_compared_the_way_they_wrap() {
    // An acknowledgement whose highest has just wrapped past the end.
    let ack = Ack {
        highest: 0,
        bitmap: 0b1,
    };
    assert!(
        ack.covers(u32::MAX),
        "bit 0 means `highest - 1`, which wraps to u32::MAX"
    );
    assert!(ack.covers(0), "the highest is always covered");
    assert!(!ack.covers(u32::MAX - 1), "bit 1 is clear");

    let ack = Ack {
        highest: 2,
        bitmap: 0b111,
    };
    for id in [2u32, 1, 0, u32::MAX] {
        assert!(ack.covers(id), "{id} is within three of a highest of 2");
    }
    assert!(!ack.covers(u32::MAX - 1), "four below, and only three bits are set");

    // And the receive window, which decides what reaches the application.
    let mut window = DedupWindow::new();
    assert!(window.accept(u32::MAX - 2), "first message, whatever its value");
    assert!(window.accept(u32::MAX - 1));
    assert!(window.accept(u32::MAX));
    assert!(
        window.accept(0),
        "the identifier after u32::MAX is new, not ancient"
    );
    assert!(window.accept(1));
    assert!(!window.accept(0), "and it is a duplicate the second time");
    assert!(
        !window.accept(u32::MAX),
        "so is one from before the wrap, still inside the window"
    );

    // The acknowledgement it produces has to name what it accepted.
    let ack = window.to_ack();
    for id in [1u32, 0, u32::MAX, u32::MAX - 1, u32::MAX - 2] {
        assert!(ack.covers(id), "accepted {id} but the acknowledgement omits it");
    }
}
