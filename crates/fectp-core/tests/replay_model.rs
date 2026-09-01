//! The replay window, driven through orderings nobody wrote by hand.
//!
//! [D34](../../../docs/DECISIONS.md) modelled the retransmit queue and said
//! what it left out: padding, the replay window and fragment reassembly are
//! behaviour over time and had only example tests. This is the first of those.
//!
//! The window decides what an attacker can make a session accept twice, and it
//! is consulted **before** authentication — a forged sequence number reaches
//! `check` on every datagram anyone sends to the port. So the two properties
//! that matter are that it never accepts the same number twice, and that
//! looking does not change anything.

use std::collections::HashSet;

use fectp_core::error::Error;
use fectp_core::session::{ReplayWindow, REPLAY_WINDOW};
use proptest::prelude::*;

/// What the window is asked to do, in the order it is asked.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// A frame arrives. `authentic` says whether it then commits — a frame that
    /// fails the AEAD is checked and never recorded, which is the whole reason
    /// the two are separate calls.
    Arrive { seq: u64, authentic: bool },
}

/// Sequence numbers that stay near each other, because that is where the
/// window's arithmetic lives. A uniform `u64` would spend every case far
/// outside it, testing one branch over and over.
fn steps() -> impl Strategy<Value = Vec<Step>> {
    prop::collection::vec(
        (0u64..300, any::<bool>()).prop_map(|(seq, authentic)| Step::Arrive { seq, authentic }),
        1..400,
    )
}

/// The window as the documentation describes it, kept beside the real one.
#[derive(Default)]
struct Model {
    started: bool,
    highest: u64,
    /// Every sequence number ever committed. The real window remembers only
    /// `REPLAY_WINDOW` of them; this remembers all, so the test can tell
    /// "refused because it is a duplicate" from "refused because it is old".
    committed: HashSet<u64>,
}

impl Model {
    /// Whether `check` should say yes.
    fn accepts(&self, seq: u64) -> bool {
        if !self.started {
            return true;
        }
        if seq > self.highest {
            return true;
        }
        if self.highest - seq >= REPLAY_WINDOW {
            return false;
        }
        !self.committed.contains(&seq)
    }

    fn commit(&mut self, seq: u64) {
        self.started = true;
        self.highest = self.highest.max(seq);
        self.committed.insert(seq);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// The window agrees with the rule it is meant to implement, at every step.
    #[test]
    fn the_window_accepts_exactly_what_it_should(steps in steps()) {
        let mut window = ReplayWindow::new();
        let mut model = Model::default();

        for Step::Arrive { seq, authentic } in steps {
            let real = window.check(seq).is_ok();
            prop_assert_eq!(
                real,
                model.accepts(seq),
                "check({}) disagreed: highest={}, committed={}",
                seq,
                model.highest,
                model.committed.len()
            );

            // Looking must not change anything. It runs before authentication,
            // so anyone can make it happen as often as they like.
            prop_assert_eq!(window.check(seq).is_ok(), real, "check({}) is not pure", seq);

            if authentic && real {
                window.commit(seq);
                model.commit(seq);
            }
        }
    }

    /// Nothing is ever accepted twice while it is still in the window.
    ///
    /// The property the whole thing exists for. A frame that gets past this
    /// twice is a message the application sees twice, or a replayed command.
    #[test]
    fn nothing_inside_the_window_is_accepted_twice(steps in steps()) {
        let mut window = ReplayWindow::new();
        let mut accepted: HashSet<u64> = HashSet::new();
        let mut highest = 0u64;
        let mut started = false;

        for Step::Arrive { seq, authentic } in steps {
            if !(authentic && window.check(seq).is_ok()) {
                continue;
            }
            if started && highest.saturating_sub(seq) < REPLAY_WINDOW {
                prop_assert!(
                    accepted.insert(seq),
                    "sequence {seq} was accepted twice, {} behind a highest of {highest}",
                    highest - seq
                );
            } else {
                accepted.insert(seq);
            }
            window.commit(seq);
            highest = highest.max(seq);
            started = true;
        }
    }

    /// A forged sequence number cannot make the window forget anything.
    ///
    /// `check` is called before the AEAD, so an off-path attacker can put any
    /// number in front of it on every datagram. If that could move the window,
    /// they could slide it past a real frame and have it refused.
    #[test]
    fn checking_a_forged_number_cannot_move_the_window(
        real in prop::collection::vec(0u64..200, 1..80),
        forged in prop::collection::vec(any::<u64>(), 1..80),
    ) {
        let mut honest = ReplayWindow::new();
        let mut attacked = ReplayWindow::new();

        for (i, seq) in real.iter().enumerate() {
            // The attacked window is asked about every forged number too, and
            // commits none of them, because none would authenticate.
            for f in forged.iter().skip(i).take(3) {
                let _ = attacked.check(*f);
            }
            if honest.check(*seq).is_ok() {
                honest.commit(*seq);
            }
            if attacked.check(*seq).is_ok() {
                attacked.commit(*seq);
            }
        }

        // Both must now answer identically about everything.
        for seq in 0u64..400 {
            prop_assert_eq!(
                honest.check(seq).is_ok(),
                attacked.check(seq).is_ok(),
                "forged numbers changed what the window says about {}",
                seq
            );
        }
    }
}

/// The boundary, pinned by hand because it is where the arithmetic lives.
#[test]
fn the_window_edge_is_where_the_document_puts_it() {
    let mut window = ReplayWindow::new();
    window.commit(1000);

    // "Number of sequence numbers below the newest that remain acceptable."
    assert!(window.check(1000 - (REPLAY_WINDOW - 1)).is_ok(), "the last one inside");
    assert!(
        matches!(window.check(1000 - REPLAY_WINDOW), Err(Error::Replay)),
        "one past the edge is a replay"
    );
    assert!(matches!(window.check(1000), Err(Error::Replay)), "the highest itself");
    assert!(window.check(1001).is_ok(), "anything newer");

    // A jump clean past the window leaves nothing behind it acceptable.
    window.commit(1000 + REPLAY_WINDOW * 2);
    assert!(
        matches!(window.check(1001), Err(Error::Replay)),
        "everything before the jump has fallen out"
    );
    assert!(window.check(1000 + REPLAY_WINDOW * 2 + 1).is_ok());
}

/// An empty window accepts anything, once.
#[test]
fn the_first_frame_is_always_new() {
    for first in [0u64, 1, REPLAY_WINDOW, u64::MAX / 2, u64::MAX - 1] {
        let mut window = ReplayWindow::new();
        assert!(window.check(first).is_ok(), "nothing has been seen yet");
        window.commit(first);
        assert!(
            matches!(window.check(first), Err(Error::Replay)),
            "and immediately afterwards it is a duplicate"
        );
    }
}
