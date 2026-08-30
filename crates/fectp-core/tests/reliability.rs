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
    for _ in 0..MAX_IN_FLIGHT {
        queue.register(0).expect("register");
    }
    assert!(queue.is_full());
    assert_eq!(
        queue.register(0),
        Err(Error::WindowFull),
        "the window must bound memory, not grow without limit"
    );
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
