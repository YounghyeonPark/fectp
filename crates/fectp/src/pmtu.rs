//! Path MTU discovery: what size of frame one session's path carries.
//!
//! A probe is a path challenge padded to the size under test (SPEC §5.8.7),
//! and its answer proves a frame that large arrived. This module decides which
//! sizes to try and when, and what to conclude; it sends nothing itself, so it
//! can be driven by a clock the tests control.
//!
//! **What an answer proves depends on the platform.** On Linux, Android and
//! Apple platforms the socket forbids fragmenting while discovery is on
//! ([`forbid_fragmentation`](crate::udp::forbid_fragmentation), D89), so a
//! probe too large for the path is dropped and an answer proves the size
//! crosses whole. On Windows nothing safe can set the bit, a probe may be
//! split on the way and its pieces answered, and an answer proves only that
//! it arrived (D85).
//!
//! The search sends every candidate size at once, each with its own token, and
//! keeps the largest that is answered: one round trip in the usual case, where
//! a binary search over 1200 to 1472 would take nine. The candidates are the
//! sizes paths actually have — IPv6's minimum, ethernet under IPv6 and under
//! IPv4, common tunnels — and the ceiling itself.

use std::time::{Duration, Instant};

use fectp_core::session::PATH_TOKEN_LEN;
use rand_core::{OsRng, RngCore};

use crate::udp::BASE_DATAGRAM;

/// Sizes worth trying between the base and the ceiling, in bytes of UDP
/// payload: 1280 is the least an IPv6 link may carry; 1452 is ethernet's 1500
/// less 40 of IPv6 and 8 of UDP; 1472 is the same under IPv4's 20; 1400 sits
/// below most tunnel overheads.
const LADDER: [usize; 4] = [1280, 1400, 1452, 1472];

/// How many times one probe is sent before its size is given up on.
const PROBE_TRIES: u8 = 3;

/// The least time between tries of one probe, whatever the round trip says.
const MIN_PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// How long a settled size stands before it is checked again, and larger
/// sizes tried again: RFC 8899's raise timer.
pub(crate) const RESEARCH_INTERVAL: Duration = Duration::from_secs(600);

/// How long after falling back to the base before searching again. Shorter
/// than the raise timer: a fall-back is often a path that has changed, and a
/// changed path is worth measuring soon.
pub(crate) const AFTER_FALLBACK: Duration = Duration::from_secs(60);

/// A probe in flight.
#[derive(Debug, Clone, Copy)]
struct Probe {
    size: usize,
    token: [u8; PATH_TOKEN_LEN],
    tries: u8,
    last: Instant,
}

/// A probe to send now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Send {
    pub size: usize,
    pub token: [u8; PATH_TOKEN_LEN],
}

/// One session's knowledge of its path's frame size.
#[derive(Debug)]
pub(crate) struct Pmtu {
    /// The largest frame this session sends: confirmed, or the base.
    current: usize,
    /// The most it may ever be: the peer's advertised receive limit or this
    /// side's ceiling, whichever is smaller.
    cap: usize,
    /// The search in progress, if one is.
    probes: Vec<Probe>,
    /// Whether the search in progress is checking `current` itself, and so
    /// falls back to the base if nothing it sent is answered.
    validating: bool,
    /// When the next search begins, if one is planned.
    next_search: Option<Instant>,
}

impl Pmtu {
    /// Starts at the base, with a search due at `now`.
    pub fn new(cap: usize, now: Instant) -> Self {
        let mut pmtu = Self {
            current: BASE_DATAGRAM,
            cap,
            probes: Vec::new(),
            validating: false,
            next_search: None,
        };
        pmtu.reset(now);
        pmtu
    }

    /// The largest frame to send now.
    pub fn current(&self) -> usize {
        self.current
    }

    /// Forgets the path: back to the base, and search again from `now`.
    ///
    /// For a session that has moved to a new address. What was learned was
    /// learned about the old path, the reasoning SPEC §5.8.4 applies to timing
    /// and capacity.
    pub fn reset(&mut self, now: Instant) {
        self.current = BASE_DATAGRAM.min(self.cap);
        self.probes.clear();
        self.validating = false;
        self.next_search = (self.cap > self.current).then_some(now);
    }

    /// When something next falls due.
    pub fn next_deadline(&self, retry: Duration) -> Option<Instant> {
        let interval = retry.max(MIN_PROBE_INTERVAL);
        let probe = self.probes.iter().map(|p| p.last + interval).min();
        [probe, self.next_search].into_iter().flatten().min()
    }

    /// The probes to send at `now`, if any.
    ///
    /// `retry` is how long to wait for an answer before sending a probe again;
    /// a round-trip estimate is what it should be.
    pub fn due(&mut self, now: Instant, retry: Duration) -> Vec<Send> {
        if self.probes.is_empty() && self.next_search.is_some_and(|at| now >= at) {
            self.next_search = None;
            // Checking what is in use is part of every search after the first:
            // a path can shrink, and a size confirmed ten minutes ago is not
            // confirmed now.
            self.validating = self.current > BASE_DATAGRAM;
            let floor = if self.validating {
                self.current - 1
            } else {
                self.current
            };
            let mut sizes: Vec<usize> = LADDER
                .into_iter()
                .chain([self.cap])
                .chain(self.validating.then_some(self.current))
                .filter(|&size| size > floor && size <= self.cap)
                .collect();
            sizes.sort_unstable();
            sizes.dedup();
            self.probes = sizes
                .into_iter()
                .map(|size| {
                    let mut token = [0u8; PATH_TOKEN_LEN];
                    OsRng.fill_bytes(&mut token);
                    Probe {
                        size,
                        token,
                        // Never sent, so due at once whatever `last` says.
                        tries: 0,
                        last: now,
                    }
                })
                .collect();
        }

        let interval = retry.max(MIN_PROBE_INTERVAL);
        let mut sends = Vec::new();
        self.probes.retain_mut(|probe| {
            if probe.tries > 0 && now < probe.last + interval {
                return true;
            }
            if probe.tries >= PROBE_TRIES {
                // Given up on: this size does not cross the path, or every
                // try of it was lost, which a search cannot tell apart.
                return false;
            }
            probe.tries += 1;
            probe.last = now;
            sends.push(Send {
                size: probe.size,
                token: probe.token,
            });
            true
        });
        if self.probes.is_empty() && self.next_search.is_none() {
            self.finish(now);
        }
        sends
    }

    /// Takes an answer. Returns whether the size in use changed.
    pub fn answered(&mut self, token: &[u8; PATH_TOKEN_LEN], now: Instant) -> bool {
        let Some(size) = self
            .probes
            .iter()
            .find(|p| &p.token == token)
            .map(|p| p.size)
        else {
            // A keep-alive's answer, or a probe's that already settled.
            return false;
        };
        let before = self.current;
        if size >= self.current {
            self.current = size;
            // `current` is confirmed, so this search can no longer fall back.
            self.validating = false;
        }
        // Anything no larger is answered by implication.
        self.probes.retain(|p| p.size > size);
        if self.probes.is_empty() {
            self.finish(now);
        }
        self.current != before
    }

    /// Says a frame larger than the base had to be sent again.
    ///
    /// One resend is ordinary loss. It is also what a path that has stopped
    /// carrying large frames looks like, and the way to tell the two apart is
    /// to ask: if no search is running, this starts one that checks the size
    /// in use, and falls back to the base if nothing it sends is answered.
    pub fn suspect(&mut self, now: Instant) {
        if self.current > BASE_DATAGRAM && self.probes.is_empty() {
            self.next_search = Some(now);
        }
    }

    /// A search has run out of probes.
    fn finish(&mut self, now: Instant) {
        let fell_back = self.validating;
        if fell_back {
            // Nothing was answered, including the size in use.
            self.current = BASE_DATAGRAM.min(self.cap);
        }
        self.validating = false;
        self.next_search = (self.cap > BASE_DATAGRAM).then_some(
            now + if fell_back {
                AFTER_FALLBACK
            } else {
                RESEARCH_INTERVAL
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTT: Duration = Duration::from_millis(50);

    fn sizes(sends: &[Send]) -> Vec<usize> {
        sends.iter().map(|s| s.size).collect()
    }

    fn answer(pmtu: &mut Pmtu, sends: &[Send], size: usize, now: Instant) -> bool {
        let send = sends.iter().find(|s| s.size == size).expect("probed");
        pmtu.answered(&send.token, now)
    }

    #[test]
    fn a_ceiling_at_the_base_never_searches() {
        let now = Instant::now();
        let mut pmtu = Pmtu::new(1200, now);
        assert_eq!(pmtu.current(), 1200);
        assert!(pmtu.due(now, RTT).is_empty());
        assert_eq!(pmtu.next_deadline(RTT), None);

        let mut small = Pmtu::new(600, now);
        assert_eq!(small.current(), 600, "never above what the peer can take");
        assert!(small.due(now, RTT).is_empty());
    }

    #[test]
    fn every_size_up_to_the_cap_is_tried_at_once() {
        let now = Instant::now();
        let mut pmtu = Pmtu::new(1472, now);
        assert_eq!(pmtu.current(), 1200, "nothing is assumed before an answer");
        let sends = pmtu.due(now, RTT);
        assert_eq!(sizes(&sends), [1280, 1400, 1452, 1472]);

        let mut odd = Pmtu::new(1420, now);
        assert_eq!(sizes(&odd.due(now, RTT)), [1280, 1400, 1420]);

        let mut jumbo = Pmtu::new(9000, now);
        assert_eq!(sizes(&jumbo.due(now, RTT)), [1280, 1400, 1452, 1472, 9000]);
    }

    #[test]
    fn the_largest_answer_is_kept_and_settles_the_smaller() {
        let now = Instant::now();
        let mut pmtu = Pmtu::new(1472, now);
        let sends = pmtu.due(now, RTT);

        assert!(answer(&mut pmtu, &sends, 1400, now));
        assert_eq!(pmtu.current(), 1400);
        // An answer for a smaller size, arriving late, changes nothing.
        assert!(!answer(&mut pmtu, &sends, 1280, now));
        assert_eq!(pmtu.current(), 1400);

        // Only the larger sizes are still being asked about.
        let later = now + MIN_PROBE_INTERVAL;
        assert_eq!(sizes(&pmtu.due(later, RTT)), [1452, 1472]);
    }

    #[test]
    fn an_unanswered_size_is_tried_three_times_then_given_up() {
        let start = Instant::now();
        let mut pmtu = Pmtu::new(1472, start);
        let sends = pmtu.due(start, RTT);
        answer(&mut pmtu, &sends, 1452, start);

        let mut now = start;
        let mut tries = 1;
        loop {
            now += MIN_PROBE_INTERVAL;
            let sends = pmtu.due(now, RTT);
            if sends.is_empty() {
                break;
            }
            assert_eq!(sizes(&sends), [1472]);
            tries += 1;
        }
        assert_eq!(tries, PROBE_TRIES);
        assert_eq!(
            pmtu.current(),
            1452,
            "a lost larger size does not undo a smaller one"
        );
        assert_eq!(
            pmtu.next_deadline(RTT),
            Some(now + RESEARCH_INTERVAL),
            "and the next search is the raise timer away"
        );
    }

    #[test]
    fn a_later_search_checks_the_size_in_use_and_falls_back_without_an_answer() {
        let start = Instant::now();
        let mut pmtu = Pmtu::new(1472, start);
        let sends = pmtu.due(start, RTT);
        answer(&mut pmtu, &sends, 1472, start);
        assert_eq!(pmtu.current(), 1472);
        assert!(pmtu.due(start, RTT).is_empty(), "the search is over");

        // Ten minutes on, the path carries nothing large any more.
        let mut now = start + RESEARCH_INTERVAL;
        let sends = pmtu.due(now, RTT);
        assert_eq!(sizes(&sends), [1472], "the size in use is what is checked");
        assert_eq!(pmtu.current(), 1472, "still in use while it is checked");
        while !pmtu.probes.is_empty() {
            now += MIN_PROBE_INTERVAL;
            pmtu.due(now, RTT);
        }
        assert_eq!(pmtu.current(), 1200, "back to what needs no proof");
        assert_eq!(pmtu.next_deadline(RTT), Some(now + AFTER_FALLBACK));
    }

    #[test]
    fn an_answer_to_the_check_keeps_the_size() {
        let start = Instant::now();
        let mut pmtu = Pmtu::new(1472, start);
        let sends = pmtu.due(start, RTT);
        answer(&mut pmtu, &sends, 1452, start);
        // 1472 goes unanswered until the first search gives it up.
        let mut ended = start;
        while !pmtu.probes.is_empty() {
            ended += MIN_PROBE_INTERVAL;
            pmtu.due(ended, RTT);
        }

        let now = ended + RESEARCH_INTERVAL;
        let sends = pmtu.due(now, RTT);
        assert_eq!(sizes(&sends), [1452, 1472]);
        answer(&mut pmtu, &sends, 1452, now);
        assert_eq!(pmtu.current(), 1452);

        // 1472 still goes unanswered; that is not a reason to fall back.
        let mut later = now;
        while !pmtu.probes.is_empty() {
            later += MIN_PROBE_INTERVAL;
            pmtu.due(later, RTT);
        }
        assert_eq!(pmtu.current(), 1452);
    }

    #[test]
    fn a_suspected_blackhole_is_checked_at_once() {
        let start = Instant::now();
        let mut pmtu = Pmtu::new(1472, start);
        let sends = pmtu.due(start, RTT);
        answer(&mut pmtu, &sends, 1472, start);

        let now = start + Duration::from_secs(5);
        assert!(pmtu.due(now, RTT).is_empty());
        pmtu.suspect(now);
        assert_eq!(sizes(&pmtu.due(now, RTT)), [1472]);
    }

    #[test]
    fn suspicion_at_the_base_asks_nothing() {
        let start = Instant::now();
        let mut pmtu = Pmtu::new(1472, start);
        pmtu.due(start, RTT);
        // Nothing answered: the search gives up and the base stands.
        let mut now = start;
        while !pmtu.probes.is_empty() {
            now += MIN_PROBE_INTERVAL;
            pmtu.due(now, RTT);
        }
        assert_eq!(pmtu.current(), 1200);
        pmtu.suspect(now);
        assert!(pmtu.due(now, RTT).is_empty());
    }

    #[test]
    fn a_reset_starts_again_from_the_base() {
        let start = Instant::now();
        let mut pmtu = Pmtu::new(1472, start);
        let sends = pmtu.due(start, RTT);
        answer(&mut pmtu, &sends, 1472, start);

        let moved = start + Duration::from_secs(1);
        pmtu.reset(moved);
        assert_eq!(pmtu.current(), 1200);
        // A token from the old path settles nothing.
        assert!(!answer(&mut pmtu, &sends, 1472, moved));
        assert_eq!(sizes(&pmtu.due(moved, RTT)), [1280, 1400, 1452, 1472]);
    }

    #[test]
    fn a_slow_path_waits_its_round_trip_before_trying_again() {
        let start = Instant::now();
        let mut pmtu = Pmtu::new(1472, start);
        let slow = Duration::from_secs(2);
        assert_eq!(pmtu.due(start, slow).len(), 4);
        assert!(pmtu.due(start + Duration::from_secs(1), slow).is_empty());
        assert_eq!(pmtu.due(start + slow, slow).len(), 4);
    }
}
