//! The reliability layer, driven through sequences nobody wrote by hand.
//!
//! `malformed_input.rs` covers the parsers, and says so: one input, one output,
//! no memory between calls. That leaves the half where the bug that started all
//! of this actually lived. The ACK-window failure was not a parser accepting
//! something it should not have — it was a *sequence*. A sender that ran far
//! enough ahead of one stuck message reached a state where no acknowledgement
//! could name it and its retransmissions fell outside the receiver's window, so
//! the message was lost outright. Every individual operation was correct.
//!
//! So this drives the sender and receiver against each other through generated
//! orderings — send, lose selectively, deliver, acknowledge, lose the
//! acknowledgement, let time pass — and checks what has to survive all of them:
//! nothing delivered twice, nothing acknowledged that never arrived, and
//! nothing discarded as a duplicate that was not one.
//!
//! **The generated sequences do not reach the original bug**, and saying so is
//! the point of this paragraph. Measured, they run 32 identifiers past an
//! outstanding message — the slot count — where the failure begins at 64.
//! Getting there by chance took a throwaway harness two orders of magnitude
//! more steps than a suite can afford. Random search is good at states nobody
//! thought of and bad at deep ones; a failure whose shape is already known
//! deserves to be driven to directly, which is what
//! `a_sender_may_not_outrun_what_the_receiver_can_still_name` does. That one
//! fails without the guard. The properties above do not, and it took four
//! versions of this file to find that out rather than assume otherwise.

use std::collections::{HashMap, HashSet};

use fectp_core::reliability::{
    Ack, DedupWindow, Due, MessageId, RetransmitQueue, ACK_WINDOW, MAX_IN_FLIGHT,
};
use proptest::prelude::*;

/// One step of the simulation.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// Register a message that gets through on its `attempt`-th transmission.
    ///
    /// Per message, not per step. A single flag saying "this round arrives"
    /// cannot express the situation the ACK-window bug needed — one message
    /// failing over and over while everything around it succeeds — because the
    /// moment a round succeeds, the stuck one is delivered with the rest. The
    /// first version of this file had exactly that flag, and did not catch the
    /// bug it was written for.
    Send { attempt: u8 },
    /// Time passes and whatever is due is resent, each following its own
    /// profile above.
    Elapse { ms: u16 },
    /// The receiver's acknowledgement travels back, or does not.
    Acknowledge { arrives: bool },
}

/// Sequences long enough to reach the state that matters.
///
/// Measured rather than guessed: with one message stuck, the sender gets 63
/// identifiers ahead of it before the guard refuses the next — one short of
/// `ACK_WINDOW`, which is the guard working. Reaching that at all takes
/// hundreds of steps, because every identifier past the stuck one needs a
/// send, a delivery and an acknowledgement. An earlier version of this file
/// capped at 400 steps and never got near it, so removing the guard changed
/// nothing and the test looked like it was passing on merit.
fn steps() -> impl Strategy<Value = Vec<Step>> {
    prop::collection::vec(
        prop_oneof![
            // Ordinary traffic, which is what drives the identifier forward.
            6 => Just(Step::Send { attempt: 1 }),
            // The rare message that will not go through. One is enough, and
            // one is what the situation needs.
            1 => (60u8..=u8::MAX).prop_map(|attempt| Step::Send { attempt }),
            3 => (1u16..250).prop_map(|ms| Step::Elapse { ms }),
            6 => any::<bool>().prop_map(|arrives| Step::Acknowledge { arrives }),
        ],
        200..1600,
    )
}

/// Sender and receiver, plus the bookkeeping that says what should be true.
struct Sim {
    sender: RetransmitQueue,
    receiver: DedupWindow,
    now: u64,
    /// Every identifier the sender ever issued.
    registered: Vec<MessageId>,
    /// Identifiers the receiver accepted as new — what the application saw.
    delivered: HashSet<MessageId>,
    /// Identifiers the sender learned had arrived.
    acknowledged: HashSet<MessageId>,
    /// Identifiers the sender ran out of retries on.
    gave_up: HashSet<MessageId>,
    /// Which transmission of each message is the one that gets through.
    needs: HashMap<MessageId, u8>,
    /// How many times each has been transmitted so far.
    sent_count: HashMap<MessageId, u8>,
    /// The furthest the sender has issued past a message still outstanding.
    ///
    /// Kept because the state this file exists to explore is defined by it, and
    /// a generator that never approaches `ACK_WINDOW` is a generator that
    /// proves nothing however many cases it runs.
    max_ahead: u32,
}

impl Sim {
    fn new() -> Self {
        Self {
            sender: RetransmitQueue::new(),
            receiver: DedupWindow::new(),
            now: 0,
            registered: Vec::new(),
            delivered: HashSet::new(),
            acknowledged: HashSet::new(),
            gave_up: HashSet::new(),
            needs: HashMap::new(),
            sent_count: HashMap::new(),
            max_ahead: 0,
        }
    }

    /// Transmits `id`, which reaches the receiver only once it has been sent
    /// as many times as its profile demands.
    ///
    /// `accept` returning false means a duplicate, which the receiver must
    /// acknowledge and must not hand to the application a second time.
    fn transmit(&mut self, id: MessageId) -> Result<(), TestCaseError> {
        let count = self.sent_count.entry(id).or_insert(0);
        *count = count.saturating_add(1);
        let count = *count;
        if count < *self.needs.get(&id).unwrap_or(&1) {
            return Ok(());
        }
        if self.receiver.accept(id) {
            prop_assert!(
                self.delivered.insert(id),
                "message {id} was delivered to the application twice"
            );
        } else {
            // Refused as a duplicate. It had therefore better be one.
            //
            // This is the bug, stated exactly. The receiver treats anything
            // more than ACK_WINDOW behind its highest as already seen, so once
            // the sender has run that far ahead, a retransmission of the stuck
            // message *arrives* and is thrown away as a duplicate it never was.
            // The application never gets it and the sender exhausts its
            // retries. Asserting only "delivered or given up on" tolerates that
            // — being given up on is the visible half of the failure, not an
            // acceptable outcome — which is why two earlier versions of this
            // file passed with the guard removed.
            prop_assert!(
                self.delivered.contains(&id),
                "message {id} reached the receiver and was discarded as a \n                 duplicate, but it had never been delivered to anyone"
            );
        }
        Ok(())
    }

    fn step(&mut self, step: Step) -> Result<(), TestCaseError> {
        match step {
            Step::Send { attempt } => {
                if let Ok(id) = self.sender.register(self.now) {
                    self.registered.push(id);
                    self.needs.insert(id, attempt.max(1));
                    if let Some(oldest) = self.oldest_outstanding() {
                        self.max_ahead = self.max_ahead.max(id.wrapping_sub(oldest));
                    }
                    self.transmit(id)?;
                }
            }
            Step::Elapse { ms } => {
                self.now += u64::from(ms);
                let mut due = [Due::Retransmit(0); MAX_IN_FLIGHT];
                let n = self.sender.poll(self.now, &mut due);
                for entry in &due[..n] {
                    match *entry {
                        Due::Retransmit(id) => self.transmit(id)?,
                        Due::GaveUp(id) => {
                            self.gave_up.insert(id);
                        }
                    }
                }
            }
            Step::Acknowledge { arrives } => {
                if arrives && self.receiver.started() {
                    let ack = self.receiver.to_ack();
                    let mut acked = [0 as MessageId; MAX_IN_FLIGHT];
                    let n = self.sender.on_ack(&ack, self.now, &mut acked);
                    for id in &acked[..n] {
                        self.acknowledged.insert(*id);
                    }
                }
            }
        }
        self.check()
    }

    /// The outstanding identifier the rest have run furthest ahead of.
    fn oldest_outstanding(&self) -> Option<MessageId> {
        self.registered
            .iter()
            .filter(|id| !self.acknowledged.contains(id) && !self.gave_up.contains(id))
            .copied()
            .next()
    }

    /// What must hold after every single step.
    fn check(&self) -> Result<(), TestCaseError> {
        // Not `in_flight <= window`: the congestion window shrinks on loss,
        // so messages admitted while it was wide stay outstanding after it
        // narrows. The window bounds *admission*, which is a different claim,
        // and asserting the stronger one was this test being wrong rather than
        // the queue.
        prop_assert!(
            self.sender.in_flight() <= MAX_IN_FLIGHT,
            "{} outstanding against {MAX_IN_FLIGHT} slots",
            self.sender.in_flight()
        );

        // The one the original bug broke. An acknowledgement names the highest
        // identifier seen plus a bitmap of the ACK_WINDOW below it, so anything
        // still outstanding has to stay inside that reach of whatever the
        // receiver will report next. Once it does not, no acknowledgement can
        // ever mention it again.
        if self.receiver.started() {
            let highest = self.receiver.to_ack().highest;
            for id in &self.registered {
                let outstanding =
                    !self.acknowledged.contains(id) && !self.gave_up.contains(id);
                if !outstanding {
                    continue;
                }
                let behind = highest.wrapping_sub(*id);
                // Ahead of the receiver is fine; it has simply not seen it yet.
                let ahead = id.wrapping_sub(highest);
                prop_assert!(
                    ahead < ACK_WINDOW || behind <= ACK_WINDOW,
                    "message {id} is outstanding but {behind} behind the highest \
                     the receiver reports ({highest}); no acknowledgement can name \
                     it and its retransmissions fall outside the replay window"
                );
            }
        }
        Ok(())
    }

    /// Runs the link clean until nothing is outstanding, as a real one recovers.
    fn drain(&mut self) -> Result<(), TestCaseError> {
        for _ in 0..(MAX_IN_FLIGHT * 8) {
            if self.sender.in_flight() == 0 {
                break;
            }
            // Everything gets through now, whatever its profile said.
            for id in self.registered.clone() {
                self.needs.insert(id, 1);
            }
            self.step(Step::Elapse { ms: 400 })?;
            self.step(Step::Acknowledge { arrives: true })?;
        }
        Ok(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Nothing registered may vanish.
    ///
    /// Once the losses stop and the link is given the chance to recover, every
    /// identifier the sender ever issued must have been delivered to the
    /// application or explicitly abandoned. A message that is neither is one
    /// the sender believes it sent, the receiver never saw, and nobody reported
    /// — which is what the ACK-window bug did, silently, while the whole test
    /// suite passed.
    #[test]
    fn no_message_is_lost_without_being_reported(steps in steps()) {
        let mut sim = Sim::new();
        for step in steps {
            sim.step(step)?;
        }
        sim.drain()?;

        for id in &sim.registered {
            let known = sim.delivered.contains(id) || sim.gave_up.contains(id);
            prop_assert!(
                known,
                "message {id} was registered, never delivered, and never given \
                 up on: it disappeared. delivered={} gave_up={} still in flight={}",
                sim.delivered.len(),
                sim.gave_up.len(),
                sim.sender.in_flight()
            );
        }
    }

    /// The receiver hands nothing to the application twice.
    ///
    /// Retransmission means duplicates are ordinary, not exceptional, and the
    /// dedup window is the only thing standing between them and the caller.
    #[test]
    fn a_duplicate_is_never_delivered_twice(steps in steps()) {
        // The assertion lives in `arrive`, which every path goes through.
        let mut sim = Sim::new();
        for step in steps {
            sim.step(step)?;
        }
        sim.drain()?;
        prop_assert_eq!(
            sim.delivered.len(),
            sim.delivered.iter().collect::<HashSet<_>>().len(),
            "the delivered set is not a set"
        );
    }

    /// An acknowledgement never claims something that did not arrive.
    ///
    /// The sender stops retransmitting on the strength of this, so a false
    /// acknowledgement is a lost message that nobody is looking for any more.
    #[test]
    fn nothing_is_acknowledged_that_was_never_received(steps in steps()) {
        let mut sim = Sim::new();
        for step in steps {
            sim.step(step)?;
        }
        for id in &sim.acknowledged {
            prop_assert!(
                sim.delivered.contains(id),
                "message {id} was acknowledged to the sender but never reached \
                 the application"
            );
        }
    }
}

/// The bitmap an acknowledgement carries has to mean what the sender reads.
///
/// `covers` is what decides whether a message stops being retransmitted, so a
/// disagreement between the two sides of it is a message dropped or resent for
/// ever.
#[test]
fn an_acknowledgement_covers_exactly_what_was_accepted() {
    let mut window = DedupWindow::new();
    let accepted: Vec<MessageId> = vec![0, 1, 2, 5, 9, 40, 41, 63];
    for id in &accepted {
        assert!(window.accept(*id), "{id} should be new");
    }

    let ack: Ack = window.to_ack();
    for id in &accepted {
        assert!(ack.covers(*id), "accepted {id} but the acknowledgement omits it");
    }
    for id in [3u32, 4, 6, 7, 8, 10, 39, 42, 62] {
        assert!(!ack.covers(id), "never accepted {id} but the acknowledgement claims it");
    }
}

/// Reports how far these sequences actually reach.
///
/// Not an assertion about the protocol — an assertion about the test. The
/// state that matters begins at `ACK_WINDOW`, and a generator that stops short
/// of it cannot fail however correct its properties are.
#[test]
#[ignore = "diagnostic: cargo test -- --ignored --nocapture"]
fn report_how_far_the_generator_reaches() {
    use proptest::test_runner::{Config, TestRunner};
    let mut runner = TestRunner::new(Config { cases: 96, ..Config::default() });
    let furthest = std::cell::Cell::new(0u32);
    runner
        .run(&steps(), |steps| {
            let mut sim = Sim::new();
            for step in steps {
                sim.step(step)?;
            }
            furthest.set(furthest.get().max(sim.max_ahead));
            Ok(())
        })
        .expect("no property should fail here");
    let furthest = furthest.get();
    println!("\n  furthest the sender ran past an outstanding message: {furthest}");
    println!("  ACK_WINDOW is {ACK_WINDOW}; below it, removing the guard changes nothing\n");
}

/// The ACK-window failure, driven to directly rather than searched for.
///
/// The properties above explore; this one goes straight at a state whose shape
/// is already known, because searching for it does not work. Measured: the
/// generated sequences get 32 identifiers past an outstanding message — the
/// slot count — and the failure begins at 64. Reaching it by chance took the
/// throwaway version of this two orders of magnitude more steps than a test
/// suite can afford, which is exactly the situation a directed test is for.
///
/// The shape is one message that never arrives while ordinary traffic keeps
/// flowing around it. Each cycle registers a message, delivers it, acknowledges
/// it and frees its slot, so the identifier space runs away from the stuck one
/// while it holds a single slot.
#[test]
fn a_sender_may_not_outrun_what_the_receiver_can_still_name() {
    let mut sender = RetransmitQueue::new();
    let mut receiver = DedupWindow::new();
    let mut now = 0u64;

    // The message that never gets through. It is registered first, so every
    // identifier after it is one the receiver's acknowledgement must still be
    // able to reach back to.
    let stuck = sender.register(now).expect("first registration");

    let mut delivered: HashSet<MessageId> = HashSet::new();
    let mut cycles = 0;

    // Ordinary traffic, for as long as the sender will accept it. Two full
    // passes of the identifier space would be well past ACK_WINDOW.
    for tick in 0..(ACK_WINDOW * 3) {
        now = u64::from(tick);
        let Ok(id) = sender.register(now) else {
            // Refused. That is the guard doing its job, and the point.
            break;
        };
        cycles += 1;

        assert!(receiver.accept(id), "ordinary message {id} should be new");
        delivered.insert(id);

        let mut acked = [0 as MessageId; MAX_IN_FLIGHT];
        let n = sender.on_ack(&receiver.to_ack(), now, &mut acked);
        assert!(n > 0, "the acknowledgement should have freed something");
    }

    assert!(
        cycles > MAX_IN_FLIGHT,
        "only {cycles} messages got through; the identifier space never ran ahead \
         and this tested nothing"
    );

    // The stuck message is still outstanding. Its retransmission now arrives.
    // If the sender was allowed to run more than ACK_WINDOW ahead, the receiver
    // treats it as older than its window and discards it as an assumed
    // duplicate — the application never sees it, and no acknowledgement can
    // name it either, so the sender resends until it gives up. The message is
    // lost with nobody reporting it.
    let accepted = receiver.accept(stuck);
    assert!(
        accepted,
        "the stuck message arrived and was discarded as a duplicate it never \
         was: the sender ran {cycles} identifiers ahead of it, past the \
         {ACK_WINDOW} an acknowledgement can reach back over"
    );
    assert!(
        !delivered.contains(&stuck),
        "the stuck message was never among the delivered ones before now"
    );

    // And having arrived, it must be nameable, or the sender never learns.
    assert!(
        receiver.to_ack().covers(stuck),
        "delivered, but no acknowledgement can tell the sender so"
    );
}
