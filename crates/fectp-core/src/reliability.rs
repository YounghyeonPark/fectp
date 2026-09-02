//! Selective-repeat ARQ, at message granularity and without ordering.
//!
//! ## Reliable, but still unordered
//!
//! A lost message is retransmitted until acknowledged. A message that arrives
//! is delivered immediately, even if an earlier one is still missing.
//!
//! Ordering is deliberately not provided. Guaranteeing it would mean holding
//! arrived messages back until their predecessors turn up, which is
//! head-of-line blocking — the exact cost this protocol is built to avoid.
//! An application that needs ordering can sequence its own payloads; one that
//! does not should not pay for it.
//!
//! ## Why messages carry their own identifier
//!
//! A retransmission cannot reuse the frame sequence number, because that is
//! the AEAD nonce and reusing it would be catastrophic. So a retransmitted
//! message goes out under a fresh sequence number, and the receiver cannot
//! tell from the header that it has seen the content before — the replay
//! window would let it through as a new frame.
//!
//! Reliable messages therefore carry a `MessageId` inside their encrypted
//! plaintext. Acknowledgements reference it, and the receiver deduplicates on
//! it.
//!
//! ## No clock
//!
//! Nothing here reads the time. Every entry point takes `now_ms` from the
//! caller. That keeps the module usable on a microcontroller with no clock
//! abstraction, and it makes the retransmission logic testable without a
//! single sleep.

use crate::error::{Error, Result};

/// Identifies one reliable message within a session.
///
/// Assigned by the sender, starting at 0 and increasing by one. A session must
/// be re-established before 2^32 reliable messages; the frame sequence number
/// imposes a far larger limit, so this is the binding one.
pub type MessageId = u32;

/// Size of the acknowledgement block carried by an `Ack` frame.
pub const ACK_BLOCK_LEN: usize = 12;

/// Size of the message identifier prefixed to a reliable plaintext.
pub const MESSAGE_ID_LEN: usize = 4;

/// How many messages may be unacknowledged at once.
///
/// Fixed so that the queue needs no allocator. It also bounds how far ahead of
/// the peer a sender may run, which is a crude but real form of flow control.
pub const MAX_IN_FLIGHT: usize = 32;

/// Retransmissions attempted before a message is abandoned.
pub const MAX_RETRIES: u8 = 5;

/// Messages an acknowledgement can report below its highest.
pub const ACK_WINDOW: u32 = 64;

/// An acknowledgement: the highest message seen, plus a bitmap of the 64 below.
///
/// Selective rather than cumulative, so a single gap does not stall everything
/// behind it — the same reason the delivery is unordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    /// Highest message identifier received so far.
    pub highest: MessageId,
    /// Bit `i` set means `highest - 1 - i` was also received.
    pub bitmap: u64,
}

impl Ack {
    /// Serialises into the first [`ACK_BLOCK_LEN`] bytes of `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < ACK_BLOCK_LEN {
            return Err(Error::BufferTooSmall);
        }
        out[..4].copy_from_slice(&self.highest.to_le_bytes());
        out[4..ACK_BLOCK_LEN].copy_from_slice(&self.bitmap.to_le_bytes());
        Ok(())
    }

    /// Parses an acknowledgement block.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < ACK_BLOCK_LEN {
            return Err(Error::MessageTooShort);
        }
        let mut highest = [0u8; 4];
        highest.copy_from_slice(&input[..4]);
        let mut bitmap = [0u8; 8];
        bitmap.copy_from_slice(&input[4..ACK_BLOCK_LEN]);
        Ok(Self {
            highest: MessageId::from_le_bytes(highest),
            bitmap: u64::from_le_bytes(bitmap),
        })
    }

    /// Whether this acknowledgement covers `id`.
    pub fn covers(&self, id: MessageId) -> bool {
        if id == self.highest {
            return true;
        }
        // Distance the way round the circle that identifiers actually travel.
        // Comparing numerically was wrong at exactly one point — a `highest`
        // that had just wrapped made every new identifier look ancient — and
        // the sender had used wrapping arithmetic all along.
        let distance = self.highest.wrapping_sub(id);
        if distance > ACK_WINDOW {
            // Too old to be reported, or ahead of the highest and not yet
            // seen. Either way unacknowledged rather than assumed delivered.
            return false;
        }
        self.bitmap & (1u64 << (distance - 1)) != 0
    }
}

/// Whether `id` is later than `than`, given that identifiers wrap.
///
/// Serial-number comparison: the shorter way round the circle wins, so an
/// identifier just past the end of the space is newer than one just before it
/// rather than four billion older. The sender has always measured distance
/// this way — `register` bounds `next_id.wrapping_sub(oldest)` — and the
/// receiver used to compare numerically, which disagreed at the wrap and
/// nowhere else.
fn is_newer(id: MessageId, than: MessageId) -> bool {
    id != than && id.wrapping_sub(than) < 0x8000_0000
}

/// Tracks which message identifiers have already been delivered.
///
/// Retransmissions arrive as fresh frames with valid sequence numbers, so the
/// replay window cannot catch them. This is what stops the application seeing
/// a message twice.
#[derive(Debug, Clone, Copy, Default)]
pub struct DedupWindow {
    highest: MessageId,
    bitmap: u64,
    started: bool,
}

impl DedupWindow {
    /// Creates an empty window.
    pub const fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            started: false,
        }
    }

    /// Records `id` and reports whether it is new.
    ///
    /// Returns `false` for a duplicate, which the caller must acknowledge but
    /// must not deliver to the application.
    pub fn accept(&mut self, id: MessageId) -> bool {
        if !self.started {
            self.started = true;
            self.highest = id;
            return true;
        }
        if is_newer(id, self.highest) {
            let shift = id.wrapping_sub(self.highest);
            // As the window slides, the previous highest becomes a set bit at
            // distance `shift`, which is bit `shift - 1`.
            self.bitmap = if shift > ACK_WINDOW {
                0
            } else if shift == ACK_WINDOW {
                // Everything else has fallen out; only the old highest is left,
                // at the far edge. Shifting by 64 would overflow, so this case
                // is written out.
                1u64 << (ACK_WINDOW - 1)
            } else {
                (self.bitmap << shift) | (1u64 << (shift - 1))
            };
            self.highest = id;
            return true;
        }
        if id == self.highest {
            return false;
        }
        let distance = self.highest.wrapping_sub(id);
        if distance > ACK_WINDOW {
            // Older than the window. Assume already delivered rather than risk
            // handing the application a duplicate.
            return false;
        }
        let bit = 1u64 << (distance - 1);
        if self.bitmap & bit != 0 {
            return false;
        }
        self.bitmap |= bit;
        true
    }

    /// The acknowledgement describing everything received so far.
    pub fn to_ack(&self) -> Ack {
        Ack {
            highest: self.highest,
            bitmap: self.bitmap,
        }
    }

    /// Whether any message has been recorded.
    pub fn started(&self) -> bool {
        self.started
    }
}

/// Retransmission timeout estimator, following RFC 6298.
///
/// The initial timeout is far shorter than TCP's one second: this protocol
/// exists for low-latency exchanges, and a second of silence after a dropped
/// datagram would undo that.
#[derive(Debug, Clone, Copy)]
pub struct Rto {
    smoothed_ms: Option<u32>,
    variation_ms: u32,
}

/// Timeout used before any round trip has been measured.
pub const INITIAL_RTO_MS: u32 = 200;
/// Floor on the computed timeout, guarding against spurious retransmission.
pub const MIN_RTO_MS: u32 = 20;
/// Ceiling on the computed timeout, backoff included.
pub const MAX_RTO_MS: u32 = 5_000;

impl Rto {
    /// Creates an estimator with no measurements yet.
    pub const fn new() -> Self {
        Self {
            smoothed_ms: None,
            variation_ms: 0,
        }
    }

    /// The current retransmission timeout in milliseconds.
    pub fn current(&self) -> u32 {
        match self.smoothed_ms {
            None => INITIAL_RTO_MS,
            Some(srtt) => srtt
                .saturating_add(self.variation_ms.saturating_mul(4))
                .clamp(MIN_RTO_MS, MAX_RTO_MS),
        }
    }

    /// Folds in a round-trip measurement.
    ///
    /// Samples from retransmitted messages must not be supplied: it is
    /// ambiguous which transmission the acknowledgement answers, and taking
    /// the wrong one skews the estimate. That is Karn's algorithm, and the
    /// queue enforces it by refusing to sample retransmitted entries.
    pub fn sample(&mut self, rtt_ms: u32) {
        match self.smoothed_ms {
            None => {
                self.smoothed_ms = Some(rtt_ms);
                self.variation_ms = rtt_ms / 2;
            }
            Some(srtt) => {
                let delta = srtt.abs_diff(rtt_ms);
                // RFC 6298: rttvar = 3/4 rttvar + 1/4 delta,
                //           srtt   = 7/8 srtt   + 1/8 sample
                //
                // In 64 bits, because `3 * variation` and `7 * srtt` overflow a
                // u32 for measurements this is handed in practice — `on_ack`
                // clamps a clock difference to `u32::MAX` rather than
                // discarding it, so a clock that steps produces one. Both
                // results are weighted averages of values that fit a u32, so
                // they fit one too, and the narrowing loses nothing.
                let variation = (u64::from(self.variation_ms) * 3 + u64::from(delta)) / 4;
                let smoothed = (u64::from(srtt) * 7 + u64::from(rtt_ms)) / 8;
                self.variation_ms = variation as u32;
                self.smoothed_ms = Some(smoothed as u32);
            }
        }
    }

    /// The timeout for a message that has already been retransmitted `retries`
    /// times, with exponential backoff applied.
    pub fn with_backoff(&self, retries: u8) -> u32 {
        let shift = retries.min(5) as u32;
        self.current().saturating_mul(1 << shift).min(MAX_RTO_MS)
    }
}

impl Default for Rto {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
struct InFlight {
    id: MessageId,
    /// When this message next needs retransmitting.
    deadline_ms: u64,
    /// When the current transmission left, for the round-trip sample.
    sent_at_ms: u64,
    retries: u8,
}

/// What polling the queue turned up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    /// This message timed out and should be sent again.
    Retransmit(MessageId),
    /// This message exhausted [`MAX_RETRIES`] and has been abandoned.
    GaveUp(MessageId),
}

/// Fixed-point scale for the congestion window.
///
/// The window grows by a fraction of a message per acknowledgement during
/// congestion avoidance, which needs sub-integer resolution; floating point in
/// a `no_std` core that targets microcontrollers without an FPU is not worth
/// the trouble for one counter.
const CWND_SCALE: u32 = 256;

/// Messages the window starts at.
///
/// Small on purpose: a sender that opens at its memory bound puts a full burst
/// into a path it knows nothing about, which is exactly what BENCHMARKS.md §10
/// measured filling a bottleneck queue.
pub const INITIAL_CWND: usize = 4;

/// Messages the window will not shrink below.
///
/// Below two there is nothing left to halve and the sender stalls waiting for
/// a timer on every message.
pub const MIN_CWND: usize = 2;

/// The sender's window of unacknowledged messages.
///
/// Holds only metadata. The message bytes stay with the caller, which is what
/// lets this be a fixed-size structure with no allocator.
///
/// Two limits apply to what may be outstanding. The slot count bounds memory
/// and never moves. The congestion window bounds what the *path* is willing to
/// carry, opens small, and is the tighter of the two until acknowledgements
/// widen it.
pub struct RetransmitQueue {
    slots: [Option<InFlight>; MAX_IN_FLIGHT],
    rto: Rto,
    next_id: MessageId,
    /// Congestion window in messages, scaled by [`CWND_SCALE`].
    cwnd: u32,
    /// Where slow start ends and congestion avoidance begins, same scale.
    ssthresh: u32,
}

impl RetransmitQueue {
    /// Creates an empty queue.
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_IN_FLIGHT],
            rto: Rto::new(),
            next_id: 0,
            cwnd: INITIAL_CWND as u32 * CWND_SCALE,
            ssthresh: MAX_IN_FLIGHT as u32 * CWND_SCALE,
        }
    }

    /// How many messages may be outstanding right now.
    ///
    /// The smaller of the congestion window and the slot count. The slots bound
    /// memory and never move; the window is what the path is telling us it can
    /// take.
    pub fn window(&self) -> usize {
        let messages = (self.cwnd / CWND_SCALE) as usize;
        messages.clamp(1, MAX_IN_FLIGHT)
    }

    /// Widens the window by one acknowledgement's worth.
    ///
    /// Doubling per round trip while below the threshold, then one message per
    /// round trip above it — the standard shape, with the round trip implicit
    /// in how many acknowledgements arrive during one.
    fn on_delivery(&mut self) {
        let ceiling = MAX_IN_FLIGHT as u32 * CWND_SCALE;
        self.cwnd = if self.cwnd < self.ssthresh {
            self.cwnd.saturating_add(CWND_SCALE)
        } else {
            // += 1/cwnd, in the same fixed point.
            let step = (CWND_SCALE * CWND_SCALE / self.cwnd.max(1)).max(1);
            self.cwnd.saturating_add(step)
        }
        .min(ceiling);
    }

    /// Halves the window, because something was lost.
    ///
    /// The only loss signal here is a retransmission timer, which in TCP terms
    /// is the severe one — there is no duplicate-acknowledgement path, because
    /// an acknowledgement reports the whole receive window rather than
    /// repeating the last in-order identifier. So this collapses the window
    /// rather than merely halving it, and `ssthresh` remembers where to stop
    /// growing quickly next time.
    fn on_loss(&mut self) {
        let floor = MIN_CWND as u32 * CWND_SCALE;
        self.ssthresh = (self.cwnd / 2).max(floor);
        self.cwnd = floor;
    }

    /// The congestion window in messages, for tests and for reporting.
    pub fn congestion_window(&self) -> usize {
        self.window()
    }

    /// Number of messages awaiting acknowledgement.
    pub fn in_flight(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Whether the window is full.
    ///
    /// A full window must not be pushed to; the caller either waits or sends
    /// the message unreliably.
    pub fn is_full(&self) -> bool {
        self.in_flight() >= MAX_IN_FLIGHT
    }

    /// The current retransmission timeout estimate, in milliseconds.
    pub fn rto_ms(&self) -> u32 {
        self.rto.current()
    }

    /// Registers a newly sent message and returns its identifier.
    ///
    /// Fails with [`Error::WindowFull`] when [`MAX_IN_FLIGHT`] messages are
    /// already outstanding.
    pub fn register(&mut self, now_ms: u64) -> Result<MessageId> {
        // A free slot is not enough. The receiver reports what it has seen as a
        // highest identifier plus a bitmap of the `ACK_WINDOW` below it, so once
        // the sender has run further ahead than that, an older outstanding
        // message can no longer be *named* by any acknowledgement — and its
        // retransmission now falls outside the receiver's replay window too, so
        // it is discarded rather than delivered. The message is then lost for
        // good, however many retries remain.
        //
        // Slot count does not prevent this and it is tempting to think it does:
        // one stuck message holds a single slot while the other thirty-one keep
        // cycling, and the identifier space runs away from it. The bound has to
        // be on the identifier distance, not on how many are outstanding.
        if let Some(oldest) = self.oldest_unacked() {
            if self.next_id.wrapping_sub(oldest) >= ACK_WINDOW {
                return Err(Error::WindowFull);
            }
        }

        // The congestion window bounds this before the slots do. Without it a
        // sender offers a full burst to a path it knows nothing about, and
        // whatever the bottleneck cannot buffer it drops — measured at 46% of
        // everything sent on a 1 Mbit/s link with an 8 KiB queue.
        if self.in_flight() >= self.window() {
            return Err(Error::WindowFull);
        }

        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::WindowFull)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        *slot = Some(InFlight {
            id,
            // `current` already answers INITIAL_RTO_MS while no round trip has
            // been measured, so taking a maximum with it only pins the first
            // timeout at 200 ms for the life of the session — which would make
            // MIN_RTO_MS unreachable exactly where it matters, on the first
            // transmission, and leave a loss on a fast path costing ten times
            // what the measured round trip justifies.
            deadline_ms: now_ms.saturating_add(u64::from(self.rto.current())),
            sent_at_ms: now_ms,
            retries: 0,
        });
        Ok(id)
    }

    /// The outstanding identifier the rest have run furthest ahead of.
    ///
    /// Identifiers wrap, so "oldest" is measured as distance behind the next
    /// one to be issued rather than by numeric order.
    fn oldest_unacked(&self) -> Option<MessageId> {
        self.slots
            .iter()
            .flatten()
            .map(|entry| entry.id)
            .max_by_key(|id| self.next_id.wrapping_sub(*id))
    }

    /// Applies an acknowledgement, writing the newly acknowledged identifiers
    /// into `acked` and returning how many there were.
    ///
    /// A round-trip sample is taken only from messages that were never
    /// retransmitted (Karn's algorithm).
    pub fn on_ack(&mut self, ack: &Ack, now_ms: u64, acked: &mut [MessageId]) -> usize {
        let mut count = 0;
        let mut delivered = 0usize;
        for slot in self.slots.iter_mut() {
            let Some(entry) = slot else { continue };
            if !ack.covers(entry.id) {
                continue;
            }
            if entry.retries == 0 {
                let rtt = now_ms.saturating_sub(entry.sent_at_ms);
                self.rto.sample(rtt.min(u64::from(u32::MAX)) as u32);
            }
            if count < acked.len() {
                acked[count] = entry.id;
            }
            count += 1;
            *slot = None;
            delivered += 1;
        }
        // Outside the loop over `slots`, which holds a borrow of `self`.
        for _ in 0..delivered {
            self.on_delivery();
        }
        count.min(acked.len())
    }

    /// Reports messages whose deadline has passed, writing them into `out`.
    ///
    /// Entries reported as [`Due::Retransmit`] have had their retry count
    /// incremented and their deadline pushed out with exponential backoff, so
    /// the caller should resend them. Entries reported as [`Due::GaveUp`] have
    /// been removed.
    pub fn poll(&mut self, now_ms: u64, out: &mut [Due]) -> usize {
        let mut count = 0;
        let mut lost = false;
        for slot in self.slots.iter_mut() {
            let Some(entry) = slot else { continue };
            if entry.deadline_ms > now_ms {
                continue;
            }
            if count >= out.len() {
                break;
            }
            if entry.retries >= MAX_RETRIES {
                out[count] = Due::GaveUp(entry.id);
                *slot = None;
            } else {
                entry.retries += 1;
                entry.sent_at_ms = now_ms;
                entry.deadline_ms =
                    now_ms.saturating_add(u64::from(self.rto.with_backoff(entry.retries)));
                out[count] = Due::Retransmit(entry.id);
                lost = true;
            }
            count += 1;
        }
        if lost {
            self.on_loss();
        }
        count
    }

    /// The earliest deadline among outstanding messages.
    ///
    /// A caller waiting on a socket should not block past this, or a lost
    /// message goes unnoticed until the next unrelated event.
    pub fn next_deadline_ms(&self) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .map(|entry| entry.deadline_ms)
            .min()
    }
}

impl Default for RetransmitQueue {
    fn default() -> Self {
        Self::new()
    }
}
