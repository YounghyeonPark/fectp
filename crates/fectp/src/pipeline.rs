//! The per-frame work that is the same whoever owns the socket.
//!
//! A client connection and one peer of a multi-client server run identical
//! coding, sealing, and reliability logic; only the transport around them
//! differs. This module holds that shared middle so the two cannot drift
//! apart.

use std::collections::VecDeque;

use fectp_core::codec::{CodecHeader, CODEC_HEADER_LEN};
use fectp_core::fragment::{
    fragments_needed, Fragment, FRAGMENT_LEN, MAX_FRAGMENTS, MAX_MESSAGE_LEN,
};
use fectp_core::frame::{FrameType, FLAG_COMPRESSED, HEADER_LEN};
use fectp_core::reliability::{
    Ack, DedupWindow, Due, MessageId, RetransmitQueue, MAX_IN_FLIGHT, MESSAGE_ID_LEN,
};
use fectp_core::session::{Opened, ResumptionTicket, TICKET_ID_LEN};
use fectp_core::PublicKey;

use crate::compress::{self, PayloadType};
use crate::link::Link;
use crate::{Error, Result};


/// Messages a peer may have part-sent at once.
///
/// Each holds its payload until acknowledged, so this bounds what one peer can
/// make the sender keep.
pub const MAX_QUEUED: usize = 4;

/// A message being fed out one fragment at a time.
///
/// A payload larger than a frame cannot be handed to the kernel in one go: the
/// congestion window is measured in a handful of messages, so most of it has to
/// wait for acknowledgements. Keeping it here rather than blocking the caller
/// is what lets `send_reliable` accept any size and still return promptly.
pub(crate) struct Queued {
    message: u32,
    payload_type: PayloadType,
    data: Vec<u8>,
    per_fragment: usize,
    count: u16,
    /// Next fragment to hand to the window.
    next: u16,
    /// Fragments sent but not yet acknowledged.
    outstanding: Vec<MessageId>,
    /// Set when a fragment was given up on, which loses the whole message.
    lost: bool,
}

/// What a pass over the outgoing queue finished.
pub(crate) struct Finished {
    /// Whether the peer acknowledged every fragment.
    pub delivered: bool,
}

/// A reliable message awaiting acknowledgement, kept so it can be resent.
pub(crate) struct Pending {
    pub id: MessageId,
    pub payload_type: PayloadType,
    pub data: Vec<u8>,
    /// Present when this is one piece of a larger message.
    ///
    /// A retransmission re-seals from scratch, so without this a resent
    /// fragment would go out looking like a whole message and be delivered as
    /// one.
    pub fragment: Option<Fragment>,
}

/// Messages a receiver will reassemble at once.
///
/// Each one holds up to [`MAX_MESSAGE_LEN`] of half-finished work, so the two
/// bounds multiply: this is the memory a peer can make a receiver hold.
pub const MAX_REASSEMBLIES: usize = 4;

/// One message being put back together.
///
/// Every fragment but the last is the same length (SPEC §5.6), so the body can
/// be one buffer indexed by fragment number and only the tail needs its own.
/// That keeps reassembly to a single allocation per message rather than one
/// per fragment.
struct Partial {
    message: u32,
    count: u16,
    /// Length of a non-final fragment, learned from the first one that is not
    /// the tail. A message of one fragment never learns it and never needs to.
    stride: Option<usize>,
    /// Fragments `0..count-1`, each at `index * stride`.
    body: Vec<u8>,
    /// The final fragment, whose length is whatever is left over.
    tail: Vec<u8>,
    have: Vec<bool>,
    received: u16,
}

impl Partial {
    fn new(message: u32, count: u16) -> Self {
        Self {
            message,
            count,
            stride: None,
            body: Vec::new(),
            tail: Vec::new(),
            have: vec![false; count as usize],
            received: 0,
        }
    }

    /// Bytes currently held, for the memory bound.
    fn held(&self) -> usize {
        self.body.len() + self.tail.len()
    }

    /// Records one fragment, returning the whole message once it is complete.
    fn insert(&mut self, fragment: Fragment, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let index = fragment.index as usize;
        if self.have[index] {
            // A retransmission the dedup window let through, or a duplicate
            // path. Either way the bytes are already here.
            return Ok(None);
        }

        if fragment.is_last() {
            self.tail = data.to_vec();
        } else {
            let stride = *self.stride.get_or_insert(data.len());
            if data.len() != stride {
                // SPEC §5.6 requires equal-length fragments before the last.
                // Without that a fragment's offset cannot be derived from its
                // index, so this is unplaceable rather than merely odd.
                return Err(Error::Protocol(fectp_core::Error::BadHeader));
            }
            let end = stride
                .checked_mul(self.count as usize - 1)
                .ok_or(Error::Protocol(fectp_core::Error::PayloadTooLarge))?;
            if end > MAX_MESSAGE_LEN {
                return Err(Error::Protocol(fectp_core::Error::PayloadTooLarge));
            }
            if self.body.len() < end {
                self.body.resize(end, 0);
            }
            self.body[index * stride..(index + 1) * stride].copy_from_slice(data);
        }

        self.have[index] = true;
        self.received += 1;
        if self.received != self.count {
            return Ok(None);
        }

        let mut whole = core::mem::take(&mut self.body);
        whole.extend_from_slice(&self.tail);
        Ok(Some(whole))
    }
}

/// Partial messages, bounded in both count and bytes.
///
/// A peer that starts many messages and finishes none would otherwise pin
/// memory indefinitely. Both limits are enforced here rather than trusted from
/// the descriptor, which is a peer's claim about what it intends to send.
pub(crate) struct Reassembly {
    partials: Vec<Partial>,
}

impl Reassembly {
    pub fn new() -> Self {
        Self {
            partials: Vec::new(),
        }
    }

    /// Folds one fragment in, returning the message once every piece has come.
    pub fn accept(&mut self, fragment: Fragment, data: &[u8]) -> Result<Option<Vec<u8>>> {
        if fragment.count > MAX_FRAGMENTS {
            return Err(Error::Protocol(fectp_core::Error::BadHeader));
        }

        let slot = self
            .partials
            .iter()
            .position(|p| p.message == fragment.message);

        let slot = match slot {
            Some(slot) => {
                if self.partials[slot].count != fragment.count {
                    // The same message cannot have been cut two ways. One of
                    // the two is wrong and there is no way to tell which, so
                    // neither is trusted.
                    self.partials.remove(slot);
                    return Err(Error::Protocol(fectp_core::Error::BadHeader));
                }
                slot
            }
            None => {
                if self.partials.len() >= MAX_REASSEMBLIES {
                    // Drop the oldest rather than refuse the newest: a stalled
                    // message should not block every later one.
                    self.partials.remove(0);
                }
                self.partials
                    .push(Partial::new(fragment.message, fragment.count));
                self.partials.len() - 1
            }
        };

        match self.partials[slot].insert(fragment, data) {
            Ok(Some(whole)) => {
                self.partials.remove(slot);
                Ok(Some(whole))
            }
            Ok(None) => {
                if self.partials[slot].held() > MAX_MESSAGE_LEN {
                    self.partials.remove(slot);
                    return Err(Error::Protocol(fectp_core::Error::PayloadTooLarge));
                }
                Ok(None)
            }
            Err(e) => {
                self.partials.remove(slot);
                Err(e)
            }
        }
    }

    /// Messages currently half-assembled.
    pub fn in_progress(&self) -> usize {
        self.partials.len()
    }
}

/// What an inbound frame turned out to be.
pub(crate) enum Ingested {
    /// Nothing for the application: an acknowledgement, a duplicate, or noise.
    Nothing,
    /// Application data, at `frame[HEADER_LEN..][..len]`.
    Data {
        /// Plaintext length within the frame buffer.
        len: usize,
        /// Whether a codec header precedes it.
        compressed: bool,
    },
    /// A fragmented message, complete and already decoded.
    ///
    /// Fragments are coded individually, so this has been through the codec
    /// already and does not live in the frame buffer — it was assembled from
    /// several.
    Message(Vec<u8>),
}

/// One peer's protocol state, independent of how bytes reach it.
pub(crate) struct Peer {
    pub session: Link,

    /// Sender side of the reliability layer.
    pub retransmit: RetransmitQueue,
    pub pending: Vec<Pending>,
    /// Receiver side: identifiers already delivered.
    pub dedup: DedupWindow,
    /// Reliable messages abandoned after exhausting their retries.
    ///
    /// Identifiers rather than a count, because a caller feeding a large
    /// message out fragment by fragment has to know *which* piece was given up
    /// to know that the message is beyond saving.
    pub abandoned: Vec<MessageId>,

    /// Partly-arrived fragmented messages.
    pub reassembly: Reassembly,
    /// Identifier for the next fragmented message this side sends.
    pub next_message: u32,
    /// Messages being fed out fragment by fragment.
    pub queue: VecDeque<Queued>,

    /// Coding scratch space, grown on demand.
    pub primary: Vec<u8>,
    pub secondary: Vec<u8>,
    /// Consecutive coding attempts that did not shrink the payload.
    coding_misses: u8,
    /// Sends still to be skipped before coding is attempted again.
    coding_skips: u8,
    /// The shape the miss counter was accumulated for. A caller that changes
    /// shape is describing different data, which deserves a fresh attempt.
    coding_shape: PayloadType,
}

/// Misses in a row before coding is assumed not to pay for this stream.
const CODING_MISS_LIMIT: u8 = 4;

/// Sends skipped after that, before trying once more.
///
/// Compression is attempted again periodically because a stream's content can
/// change — an opaque channel carrying encrypted blobs may later carry text.
/// At 32 this costs about 3% of one attempt per send while it is not paying.
const CODING_PROBE_INTERVAL: u8 = 32;

impl Peer {
    pub fn new(session: Link, buffer_hint: usize) -> Self {
        Self {
            session,
            retransmit: RetransmitQueue::new(),
            pending: Vec::new(),
            dedup: DedupWindow::new(),
            abandoned: Vec::new(),
            reassembly: Reassembly::new(),
            next_message: 0,
            queue: VecDeque::new(),
            primary: vec![0u8; buffer_hint],
            secondary: vec![0u8; buffer_hint],
            coding_misses: 0,
            coding_skips: 0,
            coding_shape: PayloadType::Opaque,
        }
    }

    /// Whether coding is worth attempting for this send.
    fn should_code(&mut self, payload_type: PayloadType) -> bool {
        if payload_type != self.coding_shape {
            self.coding_shape = payload_type;
            self.coding_misses = 0;
            self.coding_skips = 0;
            return true;
        }
        if self.coding_skips > 0 {
            self.coding_skips -= 1;
            return false;
        }
        true
    }

    /// Folds one coding outcome into the decision for the next send.
    fn record_coding(&mut self, paid: bool) {
        if paid {
            self.coding_misses = 0;
            self.coding_skips = 0;
        } else if self.coding_misses + 1 >= CODING_MISS_LIMIT {
            self.coding_misses = 0;
            self.coding_skips = CODING_PROBE_INTERVAL;
        } else {
            self.coding_misses += 1;
        }
    }

    /// The peer's authenticated static public key.
    pub fn remote_static(&self) -> &PublicKey {
        self.session.remote_static()
    }

    /// Largest uncompressed payload that fits in one frame.
    pub fn max_payload(&self, datagram_limit: usize) -> usize {
        self.session
            .max_payload()
            .min(datagram_limit.saturating_sub(self.session.data_overhead()))
    }

    /// Largest payload that fits once the optional plaintext parts are paid
    /// for.
    ///
    /// `max_payload` counts neither the message identifier nor the fragment
    /// descriptor, because an unreliable whole message carries neither. Every
    /// other combination has less room, and the difference has to come off
    /// here rather than surface later as a buffer that would not fit.
    pub fn payload_room(&self, datagram_limit: usize, reliable: bool, fragmented: bool) -> usize {
        let mut room = self.max_payload(datagram_limit);
        if reliable {
            room = room.saturating_sub(MESSAGE_ID_LEN);
        }
        if fragmented {
            room = room.saturating_sub(FRAGMENT_LEN);
        }
        room
    }

    /// Largest slice of a fragmented message that fits in one frame.
    pub fn max_fragment_payload(&self, datagram_limit: usize) -> usize {
        self.payload_room(datagram_limit, true, true)
    }

    /// Codes if it pays, then seals into `tx`, returning the frame length.
    ///
    /// The size limit applies to what actually goes on the wire, so a payload
    /// too large in its raw form may still be sent if it codes down far enough.
    pub fn seal(
        &mut self,
        data: &[u8],
        payload_type: PayloadType,
        message_id: Option<MessageId>,
        fragment: Option<Fragment>,
        datagram_limit: usize,
        tx: &mut [u8],
    ) -> Result<usize> {
        let limit =
            self.payload_room(datagram_limit, message_id.is_some(), fragment.is_some());
        let peer_caps = self.session.peer_capabilities();

        let mut primary = core::mem::take(&mut self.primary);
        let mut secondary = core::mem::take(&mut self.secondary);

        // Coding costs a couple of microseconds per send whether or not it
        // pays, which on a protocol whose whole claim is latency is worth not
        // spending on a stream that has already shown it cannot be shrunk.
        // Skipping is always safe: an uncompressed frame is a valid frame, and
        // the receiver is told which it got by a flag.
        //
        // The exception is a payload too large to send raw. There, coding is
        // the only thing that can get it under the limit, so it is always
        // attempted regardless of what the stream has done so far.
        let must_try = data.len() > limit;
        let coded = if self.should_code(payload_type) || must_try {
            let attempt = compress::encode_payload(
                data,
                payload_type,
                peer_caps,
                &mut primary,
                &mut secondary,
            );
            if !must_try {
                self.record_coding(attempt.is_some());
            }
            attempt
        } else {
            None
        };

        let result = match coded {
            Some((header, len)) if CODEC_HEADER_LEN + len <= limit => {
                let total = CODEC_HEADER_LEN + len;
                if secondary.len() < total {
                    secondary.resize(total, 0);
                }
                header
                    .encode(&mut secondary)
                    .map_err(Error::Protocol)
                    .and_then(|()| {
                        secondary[CODEC_HEADER_LEN..total].copy_from_slice(&primary[..len]);
                        match (message_id, fragment) {
                            (Some(id), Some(f)) => self.session.seal_fragment(
                                &secondary[..total],
                                id,
                                f,
                                FLAG_COMPRESSED,
                                tx,
                            ),
                            (Some(id), None) => self.session.seal_reliable(
                                &secondary[..total],
                                id,
                                FLAG_COMPRESSED,
                                tx,
                            ),
                            (None, _) => {
                                self.session.seal(&secondary[..total], FLAG_COMPRESSED, tx)
                            }
                        }
                        .map_err(Error::Protocol)
                    })
            }
            _ if data.len() > limit => Err(Error::PayloadTooLarge {
                len: data.len(),
                limit,
            }),
            _ => match (message_id, fragment) {
                (Some(id), Some(f)) => self.session.seal_fragment(data, id, f, 0, tx),
                (Some(id), None) => self.session.seal_reliable(data, id, 0, tx),
                (None, _) => self.session.seal(data, 0, tx),
            }
            .map_err(Error::Protocol),
        };

        self.primary = primary;
        self.secondary = secondary;
        result
    }


    /// Splits `data` across frames and queues it.
    ///
    /// Returns without sending anything; [`drive_queue`](Self::drive_queue)
    /// does that as the congestion window allows.
    pub fn queue_message(
        &mut self,
        data: &[u8],
        payload_type: PayloadType,
        datagram_limit: usize,
    ) -> Result<()> {
        if !self.session.peer_capabilities().supports_reliable() {
            return Err(Error::ReliabilityUnsupported);
        }
        if self.queue.len() >= MAX_QUEUED {
            return Err(Error::Protocol(fectp_core::Error::WindowFull));
        }

        let per_fragment = self.max_fragment_payload(datagram_limit);
        let count = fragments_needed(data.len(), per_fragment).ok_or(Error::PayloadTooLarge {
            len: data.len(),
            limit: MAX_MESSAGE_LEN,
        })?;

        let message = self.next_message;
        self.next_message = self.next_message.wrapping_add(1);
        self.queue.push_back(Queued {
            message,
            payload_type,
            data: data.to_vec(),
            per_fragment,
            count,
            next: 0,
            outstanding: Vec::new(),
            lost: false,
        });
        Ok(())
    }

    /// Feeds queued fragments into whatever send window is free.
    ///
    /// Returns the outcome of a message that finished during this pass, if one
    /// did. Only the front message is fed, so a stalled one does not let a
    /// later one overtake it and confuse which fragments belong to what.
    pub fn drive_queue<F>(
        &mut self,
        now_ms: u64,
        datagram_limit: usize,
        tx: &mut [u8],
        mut send: F,
    ) -> Result<Option<Finished>>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        // Drained whether or not anything is queued: nothing else reads this,
        // so leaving it would grow for the life of a peer that loses messages.
        let lost = core::mem::take(&mut self.abandoned);
        if self.queue.is_empty() {
            return Ok(None);
        }

        {
            let job = self.queue.front_mut().expect("checked");
            // Anything given up on takes the whole message with it: the
            // receiver cannot use the fragments that did arrive.
            if !lost.is_empty() {
                if job.outstanding.iter().any(|f| lost.contains(f)) {
                    job.lost = true;
                }
                job.outstanding.retain(|f| !lost.contains(f));
            }
        }

        loop {
            let job = self.queue.front().expect("checked");
            if job.lost || job.next >= job.count {
                break;
            }
            let id = match self.retransmit.register(now_ms) {
                Ok(id) => id,
                // The window is full. Whatever frees it — an acknowledgement,
                // or a retransmission giving up — brings us back here.
                Err(fectp_core::Error::WindowFull) => break,
                Err(e) => return Err(Error::Protocol(e)),
            };

            let job = self.queue.front().expect("checked");
            let start = job.next as usize * job.per_fragment;
            let end = (start + job.per_fragment).min(job.data.len());
            let chunk = job.data[start..end].to_vec();
            let payload_type = job.payload_type;
            let fragment = Fragment {
                message: job.message,
                index: job.next,
                count: job.count,
            };

            let n = self.seal(&chunk, payload_type, Some(id), Some(fragment), datagram_limit, tx)?;
            send(&tx[..n])?;
            self.pending.push(Pending {
                id,
                payload_type,
                data: chunk,
                fragment: Some(fragment),
            });

            let job = self.queue.front_mut().expect("checked");
            job.outstanding.push(id);
            job.next += 1;
        }

        // A fragment leaves `pending` when it is acknowledged; the abandoned
        // ones were taken out above, so what is left is still in flight.
        let pending = &self.pending;
        let job = self.queue.front_mut().expect("checked");
        job.outstanding
            .retain(|f| pending.iter().any(|p| p.id == *f));

        let done = job.lost || (job.next == job.count && job.outstanding.is_empty());
        if !done {
            return Ok(None);
        }
        let delivered = !job.lost;
        self.queue.pop_front();
        Ok(Some(Finished { delivered }))
    }

    /// Whether anything is still waiting to be fed out.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Authenticates a frame and works out what it means.
    ///
    /// When the frame is a reliable message, an acknowledgement is written to
    /// `ack` and its length returned in `ack_len`; the caller sends it. That
    /// keeps this function free of any transport.
    ///
    /// `now_ms` is supplied rather than read, matching the core reliability
    /// layer: an acknowledgement arriving here is what produces a round-trip
    /// sample, so a wrong timestamp would corrupt the retransmission estimate.
    pub fn ingest(
        &mut self,
        frame: &mut [u8],
        now_ms: u64,
        ack: &mut [u8],
        ack_len: &mut usize,
    ) -> Result<Ingested> {
        *ack_len = 0;

        let opened: Opened = match self.session.open(frame) {
            Ok(v) => v,
            // Forged, replayed, or misdirected. Anyone can send bytes to a UDP
            // port; treating that as an error would hand an off-path attacker
            // a denial of service.
            Err(_) => return Ok(Ingested::Nothing),
        };

        if matches!(
            opened.header.frame_type,
            FrameType::Ack | FrameType::PlainAck
        ) {
            if let Ok(parsed) = Ack::decode(&frame[HEADER_LEN..HEADER_LEN + opened.len]) {
                self.apply_ack(&parsed, now_ms);
            }
            return Ok(Ingested::Nothing);
        }

        if let Some(id) = opened.message_id {
            // Acknowledge first, duplicates included: the peer is resending
            // precisely because it has not heard from us.
            let is_new = self.dedup.accept(id);
            let reply = self.dedup.to_ack();
            *ack_len = self.session.seal_ack(&reply, ack)?;
            if !is_new {
                return Ok(Ingested::Nothing);
            }
        }

        let compressed = opened.header.is_compressed();

        // A fragment is only part of a message, so it cannot be handed up as
        // one. Coding is per-fragment, so it is undone here before the pieces
        // are joined.
        if let Some(fragment) = opened.fragment {
            let body = &frame[HEADER_LEN..HEADER_LEN + opened.len];
            let mut piece = vec![0u8; decoded_capacity(body, compressed)];
            let mut scratch = core::mem::take(&mut self.secondary);
            let written = deliver(body, compressed, &mut scratch, &mut piece);
            self.secondary = scratch;
            piece.truncate(written?);

            return match self.reassembly.accept(fragment, &piece) {
                Ok(Some(whole)) => Ok(Ingested::Message(whole)),
                Ok(None) => Ok(Ingested::Nothing),
                // A descriptor that cannot be reconciled with what has already
                // arrived. The partial is dropped; treating it as a connection
                // error would let one bad frame end a session.
                Err(_) => Ok(Ingested::Nothing),
            };
        }

        Ok(Ingested::Data {
            len: opened.len,
            compressed,
        })
    }

    /// Applies an acknowledgement, dropping the messages it covers.
    pub fn apply_ack(&mut self, ack: &Ack, now_ms: u64) {
        let mut acked = [0 as MessageId; MAX_IN_FLIGHT];
        let count = self.retransmit.on_ack(ack, now_ms, &mut acked);
        for id in acked.into_iter().take(count) {
            self.pending.retain(|p| p.id != id);
        }
    }

    /// Collects the messages due for retransmission, resealing each into
    /// `tx` and handing it to `send`.
    pub fn drive_retransmits<F>(
        &mut self,
        now_ms: u64,
        datagram_limit: usize,
        tx: &mut [u8],
        mut send: F,
    ) -> Result<()>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        let mut due = [Due::Retransmit(0); MAX_IN_FLIGHT];
        let count = self.retransmit.poll(now_ms, &mut due);

        for item in due.into_iter().take(count) {
            match item {
                Due::Retransmit(id) => {
                    let Some(index) = self.pending.iter().position(|p| p.id == id) else {
                        continue;
                    };
                    // Re-seal rather than resend the bytes: the frame needs a
                    // fresh sequence number, because that is the AEAD nonce.
                    // The message identifier inside stays the same, which is
                    // how the peer recognises the duplicate.
                    let data = core::mem::take(&mut self.pending[index].data);
                    let payload_type = self.pending[index].payload_type;
                    let fragment = self.pending[index].fragment;
                    let sealed =
                        self.seal(&data, payload_type, Some(id), fragment, datagram_limit, tx);
                    self.pending[index].data = data;
                    send(&tx[..sealed?])?;
                }
                Due::GaveUp(id) => {
                    self.pending.retain(|p| p.id != id);
                    self.abandoned.push(id);
                }
            }
        }
        Ok(())
    }
}

/// How large a buffer `deliver` needs for this frame.
///
/// A coded frame states its decoded length in the codec header, so this is
/// exact. Guessing a multiple of the coded size instead — the obvious shortcut
/// — fails on exactly the payloads compression helps most with, and the
/// failure looks like a lost message rather than a bug.
pub(crate) fn decoded_capacity(body: &[u8], compressed: bool) -> usize {
    if !compressed {
        return body.len();
    }
    match CodecHeader::decode(body) {
        Ok(header) => usize::from(header.original_len),
        // Malformed; `deliver` will reject it, and a small buffer is enough
        // for it to do so.
        Err(_) => body.len(),
    }
}

/// Copies a plaintext out of a frame buffer, decoding it if it was coded.
pub(crate) fn deliver(
    body: &[u8],
    compressed: bool,
    scratch: &mut Vec<u8>,
    out: &mut [u8],
) -> Result<usize> {
    if compressed {
        return compress::decode_payload(body, scratch, out);
    }
    if out.len() < body.len() {
        return Err(Error::PayloadTooLarge {
            len: body.len(),
            limit: out.len(),
        });
    }
    out[..body.len()].copy_from_slice(body);
    Ok(body.len())
}

/// How many resumption tickets a server remembers.
///
/// Bounded, oldest evicted first: an unbounded store would let any peer that
/// completes handshakes grow the server's memory without limit. Eviction
/// simply costs the affected peer a full handshake.
pub const MAX_TICKETS: usize = 256;

/// Resumption tickets a server will honour.
#[derive(Default)]
pub(crate) struct TicketStore {
    by_id: std::collections::HashMap<[u8; TICKET_ID_LEN], (ResumptionTicket, PublicKey)>,
    order: std::collections::VecDeque<[u8; TICKET_ID_LEN]>,
}

impl TicketStore {
    pub fn insert(&mut self, ticket: ResumptionTicket, peer: PublicKey) {
        let id = *ticket.id();
        if self.by_id.insert(id, (ticket, peer)).is_none() {
            self.order.push_back(id);
        }
        while self.order.len() > MAX_TICKETS {
            if let Some(oldest) = self.order.pop_front() {
                self.by_id.remove(&oldest);
            }
        }
    }

    /// Takes a ticket, removing it.
    ///
    /// Tickets are single use. Letting one be redeemed twice would let an
    /// attacker replay a captured resumption request.
    pub fn take(&mut self, id: &[u8; TICKET_ID_LEN]) -> Option<(ResumptionTicket, PublicKey)> {
        let found = self.by_id.remove(id)?;
        self.order.retain(|queued| queued != id);
        Some(found)
    }

    /// How many tickets are outstanding.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }
}

#[cfg(test)]
mod reassembly_tests {
    //! Fragment reassembly, driven through orderings nobody wrote by hand.
    //!
    //! Named as a gap by D34 and again by D35: it is behaviour over time, so
    //! the layout cross-check does not reach it and the retransmit model does
    //! not either. It is also where attacker-chosen indices meet buffer
    //! arithmetic, which is the combination worth being careful about.
    //!
    //! In-crate because `Reassembly` is `pub(crate)`: an integration test would
    //! have to go through a socket and could not choose the arrival order,
    //! which is the whole subject.

    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    /// Splits `data` the way a sender must: equal fragments, a possibly shorter
    /// last one (SPEC §5.6).
    fn fragment(message: u32, data: &[u8], stride: usize) -> Vec<(Fragment, Vec<u8>)> {
        let count = data.len().div_ceil(stride).max(1);
        (0..count)
            .map(|i| {
                let at = i * stride;
                let end = (at + stride).min(data.len());
                (
                    Fragment {
                        message,
                        index: i as u16,
                        count: count as u16,
                    },
                    data[at..end].to_vec(),
                )
            })
            .collect()
    }

    /// A shuffle driven by a seed, so a failing case can be replayed.
    fn shuffle<T>(items: &mut [T], seed: u64) {
        let mut state = seed | 1;
        for i in (1..items.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            items.swap(i, (state % (i as u64 + 1)) as usize);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        /// Order does not matter, and neither does duplication.
        ///
        /// Both are ordinary here: datagrams reorder, and every fragment is
        /// reliable, so a retransmission arrives as a duplicate.
        #[test]
        fn a_message_survives_any_order_and_any_duplication(
            len in 1usize..2000,
            stride in 1usize..300,
            seed in any::<u64>(),
            duplicates in 0usize..4,
        ) {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            let mut pieces = fragment(1, &data, stride);
            shuffle(&mut pieces, seed);

            // Duplicates go *before* the last arrival, never after it. The
            // layer holds no memory of a message it has finished — see
            // `a_duplicate_after_completion_starts_the_message_again` — and it
            // does not need one, because the dedup window runs first and a
            // repeated fragment never gets this far.
            let last = pieces.pop().expect("at least one fragment");
            for n in 0..duplicates {
                if pieces.is_empty() {
                    break;
                }
                let at = (seed as usize).wrapping_add(n) % pieces.len();
                let dup = pieces[at].clone();
                pieces.insert(at, dup);
            }
            pieces.push(last);

            let mut reassembly = Reassembly::new();
            let mut delivered = 0;
            for (fragment, bytes) in pieces {
                if let Ok(Some(whole)) = reassembly.accept(fragment, &bytes) {
                    delivered += 1;
                    prop_assert_eq!(&whole, &data, "reassembled to the wrong bytes");
                }
            }
            prop_assert_eq!(delivered, 1, "a message must be delivered exactly once");
            prop_assert_eq!(reassembly.in_progress(), 0, "nothing left half-built");
        }

        /// Several messages at once, their fragments interleaved.
        #[test]
        fn interleaved_messages_do_not_contaminate_each_other(
            lengths in prop::collection::vec(1usize..600, 1..4),
            stride in 1usize..200,
            seed in any::<u64>(),
        ) {
            let messages: Vec<Vec<u8>> = lengths
                .iter()
                .enumerate()
                .map(|(m, len)| (0..*len).map(|i| ((i + m * 97) % 251) as u8).collect())
                .collect();

            let mut all: Vec<(usize, Fragment, Vec<u8>)> = Vec::new();
            for (m, data) in messages.iter().enumerate() {
                for (f, bytes) in fragment(m as u32, data, stride) {
                    all.push((m, f, bytes));
                }
            }
            shuffle(&mut all, seed);

            let mut reassembly = Reassembly::new();
            let mut seen: HashSet<usize> = HashSet::new();
            for (m, f, bytes) in all {
                if let Ok(Some(whole)) = reassembly.accept(f, &bytes) {
                    prop_assert_eq!(
                        &whole,
                        &messages[m],
                        "message {} came back carrying another message's bytes",
                        m
                    );
                    prop_assert!(seen.insert(m), "message {} was delivered twice", m);
                }
            }
            prop_assert_eq!(seen.len(), messages.len(), "not every message arrived");
        }

        /// More half-built messages than there is room for.
        ///
        /// The bound is what stops a peer parking memory by starting messages
        /// it never finishes. Exceeding it must cost the oldest, never the
        /// correctness of what remains.
        #[test]
        fn exceeding_the_bound_drops_rather_than_corrupts(
            extra in 1usize..6,
            stride in 8usize..64,
        ) {
            let mut reassembly = Reassembly::new();
            let total = MAX_REASSEMBLIES + extra;

            let mut started = Vec::new();
            for m in 0..total {
                let bytes: Vec<u8> = (0..stride * 3).map(|i| ((i + m) % 251) as u8).collect();
                let pieces = fragment(m as u32, &bytes, stride);
                prop_assert!(pieces.len() > 1, "this needs a genuinely split message");
                let _ = reassembly.accept(pieces[0].0, &pieces[0].1);
                started.push((bytes, pieces));
            }
            prop_assert!(
                reassembly.in_progress() <= MAX_REASSEMBLIES,
                "{} half-built against a bound of {}",
                reassembly.in_progress(),
                MAX_REASSEMBLIES
            );

            // Eviction may lose a message. It may not garble one.
            let (bytes, pieces) = started.last().expect("at least one");
            for (f, chunk) in pieces.iter().skip(1) {
                if let Ok(Some(whole)) = reassembly.accept(*f, chunk) {
                    prop_assert_eq!(&whole, bytes, "the surviving message was corrupted");
                }
            }
        }
    }

    /// The layer keeps no memory of a message it has finished.
    ///
    /// A fragment of a completed message starts it again, and completing it a
    /// second time delivers it a second time. That is not a defect here and it
    /// is not defence in depth either — it is a contract, and it holds because
    /// `ingest` consults the dedup window *before* reaching reassembly: a
    /// repeated fragment carries the message identifier it carried the first
    /// time, is recognised there, and returns `Ingested::Nothing`.
    ///
    /// Written down because the first version of the property test above fed
    /// duplicates straight in, saw a message delivered twice, and looked like a
    /// bug. Remembering finished messages would mean unbounded state chosen by
    /// the peer, which is the thing every other bound here exists to avoid.
    #[test]
    fn a_duplicate_after_completion_starts_the_message_again() {
        let mut reassembly = Reassembly::new();
        let only = Fragment { message: 1, index: 0, count: 1 };

        let first = reassembly.accept(only, b"whole").expect("accept");
        assert_eq!(first.as_deref(), Some(&b"whole"[..]));
        assert_eq!(reassembly.in_progress(), 0, "and it is no longer held");

        let again = reassembly.accept(only, b"whole").expect("accept");
        assert_eq!(
            again.as_deref(),
            Some(&b"whole"[..]),
            "nothing here remembers the message just delivered; the dedup              window is what stops this arriving"
        );
    }

    /// A message that claims two shapes is refused, not guessed at.
    #[test]
    fn a_count_that_changes_mid_message_is_refused() {
        let mut reassembly = Reassembly::new();
        let first = Fragment { message: 9, index: 0, count: 4 };
        assert!(reassembly.accept(first, &[1, 2, 3, 4]).is_ok());

        let contradiction = Fragment { message: 9, index: 1, count: 7 };
        assert!(
            reassembly.accept(contradiction, &[5, 6, 7, 8]).is_err(),
            "the same message cannot have been cut two ways"
        );
        assert_eq!(
            reassembly.in_progress(),
            0,
            "and neither version is kept, because nothing says which is the lie"
        );
    }

    /// SPEC §5.6: every fragment but the last is the same length.
    ///
    /// Without that a fragment's offset cannot be derived from its index, so an
    /// odd length is unplaceable rather than merely unusual.
    #[test]
    fn unequal_fragments_before_the_last_are_refused() {
        let mut reassembly = Reassembly::new();
        let at = |index| Fragment { message: 3, index, count: 3 };
        assert!(reassembly.accept(at(0), &[0u8; 100]).is_ok());
        assert!(
            reassembly.accept(at(1), &[0u8; 60]).is_err(),
            "a short fragment that is not the last cannot be placed"
        );
    }
}
