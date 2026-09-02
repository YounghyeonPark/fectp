//! The round-trip estimator, which decides when a message is presumed lost.
//!
//! The last of the state-keeping layers to get a model. It was left until last
//! deliberately: a wrong timeout is a slow connection rather than an incorrect
//! one, so it costs throughput and not correctness.
//!
//! Except where the arithmetic overflows, which is what this found.

use fectp_core::reliability::{
    Ack, MessageId, RetransmitQueue, Rto, INITIAL_RTO_MS, MAX_IN_FLIGHT, MAX_RTO_MS, MIN_RTO_MS,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Any sequence of measurements leaves a usable timeout.
    ///
    /// `sample` takes a `u32` of milliseconds and the queue hands it whatever
    /// the clock produced, clamped to `u32::MAX`. A clock that steps forward —
    /// NTP, a suspend, a caller passing wall-clock time — produces a very large
    /// one, and there is no arrangement of samples for which the estimator may
    /// stop returning a number in range.
    #[test]
    fn any_measurements_leave_a_timeout_in_range(
        samples in prop::collection::vec(any::<u32>(), 1..40),
    ) {
        let mut rto = Rto::new();
        prop_assert_eq!(rto.current(), INITIAL_RTO_MS, "before any measurement");

        for sample in samples {
            rto.sample(sample);
            let current = rto.current();
            prop_assert!(
                (MIN_RTO_MS..=MAX_RTO_MS).contains(&current),
                "a sample of {} left the timeout at {}, outside {}..={}",
                sample,
                current,
                MIN_RTO_MS,
                MAX_RTO_MS
            );
        }
    }

    /// Backing off never shortens the timeout, and never passes the ceiling.
    ///
    /// The point of backoff is that a peer which is not answering is asked
    /// less often, not more.
    #[test]
    fn backoff_only_lengthens_and_stops_at_the_ceiling(
        samples in prop::collection::vec(0u32..10_000, 0..8),
    ) {
        let mut rto = Rto::new();
        for sample in samples {
            rto.sample(sample);
        }

        let mut previous = rto.current();
        for retries in 0..=8u8 {
            let backed_off = rto.with_backoff(retries);
            prop_assert!(
                backed_off >= previous || previous == MAX_RTO_MS,
                "backoff {} gave {} after {}",
                retries,
                backed_off,
                previous
            );
            prop_assert!(
                backed_off <= MAX_RTO_MS,
                "backoff {} gave {}, past the ceiling of {}",
                retries,
                backed_off,
                MAX_RTO_MS
            );
            previous = backed_off;
        }
    }

    /// A steady path converges on that path.
    ///
    /// Not a precise claim — the estimator is a filter, and RFC 6298 adds four
    /// variances on top. What must hold is that repeated identical
    /// measurements pull the timeout towards them rather than away.
    #[test]
    fn repeated_measurements_converge_towards_them(rtt in 30u32..1_000) {
        let mut rto = Rto::new();
        for _ in 0..40 {
            rto.sample(rtt);
        }
        let settled = rto.current();
        prop_assert!(
            settled >= rtt.max(MIN_RTO_MS),
            "settled at {} for a path of {}: below the measurement itself",
            settled,
            rtt
        );
        prop_assert!(
            settled < rtt.saturating_mul(2).max(MIN_RTO_MS * 2),
            "settled at {} for a path of {}: nowhere near it",
            settled,
            rtt
        );
    }
}

/// The measurement that overflowed.
///
/// `current` computes `srtt + 4 * variation`. The addition saturates and the
/// multiplication did not, so one very large sample — which `on_ack` will hand
/// over, since it clamps the clock difference to `u32::MAX` rather than
/// discarding it — panicked the debug build and wrapped in release.
///
/// Reaching it needs a clock that steps: NTP correcting, a device resuming, or
/// a caller supplying wall-clock milliseconds instead of a monotonic counter.
/// None of those is exotic, and the consequence in debug is a panic in the loop
/// that serves every peer.
#[test]
fn an_enormous_measurement_does_not_overflow() {
    for sample in [u32::MAX, u32::MAX / 2, u32::MAX / 4 + 1, 1 << 30] {
        let mut rto = Rto::new();
        rto.sample(sample);
        let current = rto.current();
        assert!(
            (MIN_RTO_MS..=MAX_RTO_MS).contains(&current),
            "a sample of {sample} left the timeout at {current}"
        );

        // And again, because the second sample takes the other branch.
        rto.sample(sample);
        let current = rto.current();
        assert!((MIN_RTO_MS..=MAX_RTO_MS).contains(&current));

        // And backing off from there.
        for retries in 0..=5u8 {
            assert!(rto.with_backoff(retries) <= MAX_RTO_MS);
        }
    }
}

/// Karn's algorithm: a retransmitted message tells you nothing about the path.
///
/// The acknowledgement could be answering either transmission, and choosing
/// wrong skews the estimate — downwards if it was the second, which produces
/// more spurious retransmissions, which produce more bad samples.
#[test]
fn a_retransmitted_message_is_not_measured() {
    use fectp_core::reliability::Due;

    let mut queue = RetransmitQueue::new();
    let mut now = 0u64;

    // One message, acknowledged promptly: this one is measurable.
    let id = queue.register(now).expect("register");
    now += 40;
    let mut acked = [0 as MessageId; MAX_IN_FLIGHT];
    queue.on_ack(&Ack { highest: id, bitmap: u64::MAX }, now, &mut acked);
    let after_clean_sample = queue.rto_ms();
    assert!(
        after_clean_sample < INITIAL_RTO_MS,
        "a 40 ms round trip should have brought the timeout below {INITIAL_RTO_MS}, \
         got {after_clean_sample}"
    );

    // Now one that times out and is resent, then acknowledged a long time
    // later. If that interval were sampled it would drag the estimate up.
    let id = queue.register(now).expect("register");
    now += 10_000;
    let mut due = [Due::Retransmit(0); MAX_IN_FLIGHT];
    let n = queue.poll(now, &mut due);
    assert!(n > 0, "it should have timed out by now");
    assert!(
        matches!(due[0], Due::Retransmit(retried) if retried == id),
        "and been marked for retransmission"
    );

    now += 10_000;
    let before = queue.rto_ms();
    queue.on_ack(&Ack { highest: id, bitmap: u64::MAX }, now, &mut acked);
    assert_eq!(
        queue.rto_ms(),
        before,
        "the acknowledgement of a retransmitted message must not be measured: \
         it is ambiguous which transmission it answers"
    );
}
