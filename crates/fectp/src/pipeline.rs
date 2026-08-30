//! The per-frame work that is the same whoever owns the socket.
//!
//! A client connection and one peer of a multi-client server run identical
//! coding, sealing, and reliability logic; only the transport around them
//! differs. This module holds that shared middle so the two cannot drift
//! apart.

use fectp_core::codec::{CodecHeader, CODEC_HEADER_LEN};
use fectp_core::frame::{FrameType, FLAG_COMPRESSED, HEADER_LEN};
use fectp_core::reliability::{
    Ack, DedupWindow, Due, MessageId, RetransmitQueue, MAX_IN_FLIGHT,
};
use fectp_core::session::{Opened, ResumptionTicket, TICKET_ID_LEN};
use fectp_core::PublicKey;

use crate::compress::{self, PayloadType};
use crate::link::Link;
use crate::{Error, Result};

/// A reliable message awaiting acknowledgement, kept so it can be resent.
pub(crate) struct Pending {
    pub id: MessageId,
    pub payload_type: PayloadType,
    pub data: Vec<u8>,
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
}

/// One peer's protocol state, independent of how bytes reach it.
pub(crate) struct Peer {
    pub session: Link,
    pub default_payload_type: PayloadType,

    /// Sender side of the reliability layer.
    pub retransmit: RetransmitQueue,
    pub pending: Vec<Pending>,
    /// Receiver side: identifiers already delivered.
    pub dedup: DedupWindow,
    /// Reliable messages abandoned after exhausting their retries.
    pub abandoned: usize,

    /// Coding scratch space, grown on demand.
    pub primary: Vec<u8>,
    pub secondary: Vec<u8>,
}

impl Peer {
    pub fn new(session: Link, buffer_hint: usize) -> Self {
        Self {
            session,
            default_payload_type: PayloadType::Opaque,
            retransmit: RetransmitQueue::new(),
            pending: Vec::new(),
            dedup: DedupWindow::new(),
            abandoned: 0,
            primary: vec![0u8; buffer_hint],
            secondary: vec![0u8; buffer_hint],
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

    /// Codes if it pays, then seals into `tx`, returning the frame length.
    ///
    /// The size limit applies to what actually goes on the wire, so a payload
    /// too large in its raw form may still be sent if it codes down far enough.
    pub fn seal(
        &mut self,
        data: &[u8],
        payload_type: PayloadType,
        message_id: Option<MessageId>,
        datagram_limit: usize,
        tx: &mut [u8],
    ) -> Result<usize> {
        let limit = self.max_payload(datagram_limit);
        let peer_caps = self.session.peer_capabilities();

        let mut primary = core::mem::take(&mut self.primary);
        let mut secondary = core::mem::take(&mut self.secondary);

        let coded =
            compress::encode_payload(data, payload_type, peer_caps, &mut primary, &mut secondary);

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
                        match message_id {
                            Some(id) => self.session.seal_reliable(
                                &secondary[..total],
                                id,
                                FLAG_COMPRESSED,
                                tx,
                            ),
                            None => self.session.seal(&secondary[..total], FLAG_COMPRESSED, tx),
                        }
                        .map_err(Error::Protocol)
                    })
            }
            _ if data.len() > limit => Err(Error::PayloadTooLarge {
                len: data.len(),
                limit,
            }),
            _ => match message_id {
                Some(id) => self.session.seal_reliable(data, id, 0, tx),
                None => self.session.seal(data, 0, tx),
            }
            .map_err(Error::Protocol),
        };

        self.primary = primary;
        self.secondary = secondary;
        result
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

        Ok(Ingested::Data {
            len: opened.len,
            compressed: opened.header.is_compressed(),
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
                    let sealed = self.seal(&data, payload_type, Some(id), datagram_limit, tx);
                    self.pending[index].data = data;
                    send(&tx[..sealed?])?;
                }
                Due::GaveUp(id) => {
                    self.pending.retain(|p| p.id != id);
                    self.abandoned += 1;
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
