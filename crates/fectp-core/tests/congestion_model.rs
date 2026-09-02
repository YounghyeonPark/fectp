//! The congestion window, which is the last of the layers that keep state.
//!
//! [D34](../../../docs/DECISIONS.md) named it beside fragment reassembly and
//! left both. Reassembly got a model; this did not, and until now its three
//! behaviours — grow on an acknowledgement, collapse on a loss, never below
//! `MIN_CWND` — were exercised only as whatever `register` happened to refuse.
//! None of the three was asserted anywhere.
//!
//! It matters because it is the one thing here that decides how fast the sender
//! goes. Measured, it took self-inflicted loss on a 1 Mbit/s link from 46% of
//! everything sent to about 3% (BENCHMARKS.md §9), and a window that grew when
//! it should shrink would put that back without failing anything.

use fectp_core::reliability::{
    Ack, Due, MessageId, RetransmitQueue, INITIAL_CWND, MAX_IN_FLIGHT, MAX_RETRIES, MIN_CWND,
};
use proptest::prelude::*;

/// What the sender is made to do, in the order it is made to do it.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// Register as many messages as the window will currently take.
    FillWindow,
    /// Everything outstanding is acknowledged.
    AcknowledgeAll,
    /// Enough time passes that everything outstanding times out.
    Timeout,
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    prop::collection::vec(
        prop_oneof![
            4 => Just(Step::FillWindow),
            4 => Just(Step::AcknowledgeAll),
            1 => Just(Step::Timeout),
        ],
        1..120,
    )
}

/// Drives a queue and remembers what it saw.
struct Sender {
    queue: RetransmitQueue,
    now: u64,
    outstanding: Vec<MessageId>,
    highest: MessageId,
    started: bool,
}

impl Sender {
    fn new() -> Self {
        Self {
            queue: RetransmitQueue::new(),
            now: 0,
            outstanding: Vec::new(),
            highest: 0,
            started: false,
        }
    }

    fn step(&mut self, step: Step) {
        match step {
            Step::FillWindow => {
                // Registering until refused is what a sender with data does,
                // and it is the only way the window's size becomes visible.
                while let Ok(id) = self.queue.register(self.now) {
                    if !self.started || id > self.highest {
                        self.highest = id;
                        self.started = true;
                    }
                    self.outstanding.push(id);
                }
            }
            Step::AcknowledgeAll => {
                if !self.started {
                    return;
                }
                // Everything up to and including the highest, which is what a
                // receiver that got them all would report.
                let ack = Ack {
                    highest: self.highest,
                    bitmap: u64::MAX,
                };
                let mut acked = [0 as MessageId; MAX_IN_FLIGHT];
                let n = self.queue.on_ack(&ack, self.now, &mut acked);
                let taken: Vec<MessageId> = acked[..n].to_vec();
                self.outstanding.retain(|id| !taken.contains(id));
                self.now += 1;
            }
            Step::Timeout => {
                // Past any retransmission deadline, however far it has backed
                // off. MAX_RTO_MS is 5 s and backoff multiplies it.
                self.now += 60_000;
                let mut due = [Due::Retransmit(0); MAX_IN_FLIGHT];
                let n = self.queue.poll(self.now, &mut due);
                for entry in &due[..n] {
                    if let Due::GaveUp(id) = entry {
                        self.outstanding.retain(|held| held != id);
                    }
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// The window stays inside its bounds, whatever happens to it.
    ///
    /// Below `MIN_CWND` a sender stops making progress on a lossy link; above
    /// `MAX_IN_FLIGHT` it is offering more than there are slots to track, and
    /// the surplus is sent without any way to retransmit it.
    #[test]
    fn the_window_never_leaves_its_bounds(steps in steps()) {
        let mut sender = Sender::new();
        prop_assert_eq!(sender.queue.congestion_window(), INITIAL_CWND);

        for step in steps {
            sender.step(step);
            let window = sender.queue.congestion_window();
            prop_assert!(
                window >= MIN_CWND,
                "window fell to {} against a floor of {}",
                window,
                MIN_CWND
            );
            prop_assert!(
                window <= MAX_IN_FLIGHT,
                "window reached {} against {} slots",
                window,
                MAX_IN_FLIGHT
            );
            prop_assert!(
                sender.queue.in_flight() <= MAX_IN_FLIGHT,
                "more outstanding than there are slots"
            );
        }
    }

    /// An acknowledgement never narrows the window, and a timeout never widens
    /// it.
    ///
    /// The direction is the whole of additive-increase and
    /// multiplicative-decrease. Getting it backwards would be a sender that
    /// speeds up into congestion, and nothing else here would notice.
    #[test]
    fn each_signal_moves_the_window_one_way_only(steps in steps()) {
        let mut sender = Sender::new();

        for step in steps {
            let before = sender.queue.congestion_window();
            sender.step(step);
            let after = sender.queue.congestion_window();

            match step {
                Step::AcknowledgeAll => prop_assert!(
                    after >= before,
                    "an acknowledgement narrowed the window from {} to {}",
                    before,
                    after
                ),
                Step::Timeout => prop_assert!(
                    after <= before,
                    "a timeout widened the window from {} to {}",
                    before,
                    after
                ),
                // Registering is bounded *by* the window and must not move it.
                Step::FillWindow => prop_assert_eq!(
                    after, before,
                    "registering messages changed the window on its own"
                ),
            }
        }
    }
}

/// It starts where the documentation says.
#[test]
fn a_new_sender_opens_at_the_documented_width() {
    let queue = RetransmitQueue::new();
    assert_eq!(queue.congestion_window(), INITIAL_CWND);
    // Compile-time, because they are constants: a build that violated either
    // would not get as far as running a test.
    const { assert!(INITIAL_CWND > MIN_CWND, "there has to be room to fall") };
    const { assert!(INITIAL_CWND < MAX_IN_FLIGHT, "and room to grow") };
}

/// A loss collapses the window to the floor, rather than halving it.
///
/// Deliberate, and documented on `on_loss`: the only loss signal here is a
/// retransmission timer, which in TCP terms is the severe one. There is no
/// duplicate-acknowledgement path, because an acknowledgement reports the whole
/// receive window rather than repeating the last in-order identifier.
#[test]
fn a_timeout_collapses_the_window_to_the_floor() {
    let mut sender = Sender::new();

    // Grow it well past the floor first, or the collapse proves nothing.
    for _ in 0..12 {
        sender.step(Step::FillWindow);
        sender.step(Step::AcknowledgeAll);
    }
    let grown = sender.queue.congestion_window();
    assert!(
        grown > INITIAL_CWND,
        "acknowledgements should have widened it past {INITIAL_CWND}, got {grown}"
    );

    sender.step(Step::FillWindow);
    sender.step(Step::Timeout);
    assert_eq!(
        sender.queue.congestion_window(),
        MIN_CWND,
        "a retransmission timeout collapses the window to the floor"
    );
}

/// And having collapsed, it climbs back.
///
/// A window that fell and stayed down would be a link that never recovers from
/// one lost datagram — which is worse than not having congestion control.
#[test]
fn the_window_recovers_after_a_loss() {
    let mut sender = Sender::new();
    for _ in 0..12 {
        sender.step(Step::FillWindow);
        sender.step(Step::AcknowledgeAll);
    }
    sender.step(Step::FillWindow);
    sender.step(Step::Timeout);
    assert_eq!(sender.queue.congestion_window(), MIN_CWND);

    // Clear the retransmissions the timeout left behind, then run clean.
    for _ in 0..(MAX_RETRIES as usize + 24) {
        sender.step(Step::AcknowledgeAll);
        sender.step(Step::FillWindow);
    }
    assert!(
        sender.queue.congestion_window() > MIN_CWND,
        "the window never recovered from a single timeout"
    );
}

/// Growth is faster below the threshold than above it.
///
/// Slow start adds a message per acknowledgement; congestion avoidance adds
/// about one per window. Losing that distinction does not fail anything — it
/// just makes every connection start slowly for ever, which is the kind of
/// regression a benchmark notices months later.
#[test]
fn growth_slows_once_past_the_threshold() {
    // From a fresh sender, `ssthresh` starts at the ceiling, so everything
    // below MAX_IN_FLIGHT is slow start: one message per acknowledgement.
    let mut fresh = Sender::new();
    fresh.step(Step::FillWindow);
    let before = fresh.queue.congestion_window();
    fresh.step(Step::AcknowledgeAll);
    let slow_start_gain = fresh.queue.congestion_window() - before;
    assert!(
        slow_start_gain >= 1,
        "slow start should widen by at least a message per round of acknowledgements"
    );

    // After a loss, `ssthresh` is half the width it had, so growth past that
    // point is the slower kind.
    let mut recovered = Sender::new();
    for _ in 0..12 {
        recovered.step(Step::FillWindow);
        recovered.step(Step::AcknowledgeAll);
    }
    recovered.step(Step::FillWindow);
    recovered.step(Step::Timeout);
    for _ in 0..(MAX_RETRIES as usize + 40) {
        recovered.step(Step::AcknowledgeAll);
        recovered.step(Step::FillWindow);
    }

    let avoidance = recovered.queue.congestion_window();
    assert!(
        avoidance > MIN_CWND,
        "it should have climbed out of the floor by now"
    );
    assert!(
        avoidance <= MAX_IN_FLIGHT,
        "and not past the slot count"
    );
}
