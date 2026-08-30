//! Capability negotiation, the handshake driver, and the established session.

use rand_core::{CryptoRng, RngCore};

use crate::error::{Error, Result};
use crate::frame::{FrameType, Header, FLAG_PADDED, FLAG_RELIABLE, HEADER_LEN};
use crate::keys::{Keypair, PublicKey};
use crate::reliability::{Ack, MessageId, ACK_BLOCK_LEN, MESSAGE_ID_LEN};
use crate::noise::{
    hash, CipherState, HandshakeState, ResumeHandshake, MSG1_OVERHEAD, MSG1_PAYLOAD_OFFSET,
    MSG2_OVERHEAD, MSG2_PAYLOAD_OFFSET, PSK_LEN, RESUME_MSG_OVERHEAD, RESUME_PAYLOAD_OFFSET,
    TAGLEN,
};

/// Size of the capability block that prefixes every handshake payload.
pub const CAPS_LEN: usize = 8;

/// Capability flag: this peer can decompress Zstandard payloads.
pub const CAP_ZSTD: u8 = 0b0000_0001;

/// Capability flag: this peer implements the reliability layer.
pub const CAP_RELIABLE: u8 = 0b0000_0010;

/// What a peer can do, exchanged inside the encrypted handshake payload.
///
/// This is the fix for the interoperability gap in the original design. The
/// per-frame compression flag says whether *this* frame is compressed, but a
/// sender also has to know whether the receiver can decompress at all: a
/// microcontroller has no room for a Zstandard decoder, so a server must never
/// compress towards it. Advertising capabilities here rather than in the
/// header means an attacker cannot force a downgrade, because the block is
/// encrypted and authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Bitwise OR of the `CAP_*` flags.
    pub flags: u8,
    /// Largest frame this peer is willing to receive, in bytes.
    ///
    /// Set by available RAM on constrained targets, not by the path MTU.
    pub max_frame_size: u16,
    /// Bitwise OR of the `CODEC_*` bits this peer can decode.
    ///
    /// A sender must never use a codec the receiver has not advertised: the
    /// receiver would have no way to reverse it. The core's transforms need no
    /// allocator, so even a constrained peer can advertise
    /// [`CODECS_CORE`](crate::codec::CODECS_CORE) while omitting
    /// [`CODEC_ZSTD`](crate::codec::CODEC_ZSTD).
    pub codecs: u16,
}

impl Capabilities {
    /// Capabilities of a constrained peer: small frames, core transforms only.
    pub const fn minimal(max_frame_size: u16) -> Self {
        Self {
            flags: 0,
            max_frame_size,
            codecs: crate::codec::CODECS_CORE,
        }
    }

    /// Whether this peer can decompress Zstandard payloads.
    pub fn accepts_compression(&self) -> bool {
        self.flags & CAP_ZSTD != 0
    }

    /// Whether this peer implements the reliability layer.
    ///
    /// A sender must check this before sending reliably: a peer that never
    /// acknowledges would have every message retransmitted until it was
    /// abandoned.
    pub fn supports_reliable(&self) -> bool {
        self.flags & CAP_RELIABLE != 0
    }

    /// Whether this peer advertised every bit in `codecs`.
    pub fn supports_codecs(&self, codecs: u16) -> bool {
        self.codecs & codecs == codecs
    }

    /// Serialises into the first [`CAPS_LEN`] bytes of `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<()> {
        self.encode(out)
    }

    /// Parses a capability block.
    pub fn decode_from(input: &[u8]) -> Result<Self> {
        Self::decode(input)
    }

    fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < CAPS_LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.flags;
        out[1] = 0;
        out[2..4].copy_from_slice(&self.max_frame_size.to_le_bytes());
        out[4..6].copy_from_slice(&self.codecs.to_le_bytes());
        out[6..CAPS_LEN].fill(0);
        Ok(())
    }

    fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < CAPS_LEN {
            return Err(Error::MessageTooShort);
        }
        let mut size = [0u8; 2];
        size.copy_from_slice(&input[2..4]);
        let mut codecs = [0u8; 2];
        codecs.copy_from_slice(&input[4..6]);
        Ok(Self {
            flags: input[0],
            max_frame_size: u16::from_le_bytes(size),
            codecs: u16::from_le_bytes(codecs),
        })
    }
}

/// Tracks which sequence numbers have already been accepted.
///
/// A datagram transport reorders and duplicates, so a strictly increasing
/// counter is not usable. This is the standard sliding bitmap: `highest` is
/// the newest accepted sequence number and `bitmap` records the 64 slots
/// below it.
#[derive(Debug, Clone, Copy)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: u64,
    started: bool,
}

/// Number of sequence numbers below the newest that remain acceptable.
pub const REPLAY_WINDOW: u64 = 64;

impl ReplayWindow {
    /// Creates an empty window.
    pub const fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            started: false,
        }
    }

    /// Checks `seq` without recording it.
    ///
    /// Called before authentication so that obviously stale frames cost
    /// nothing. The window is only *updated* after the frame authenticates,
    /// so a forged sequence number cannot poison it.
    pub fn check(&self, seq: u64) -> Result<()> {
        if !self.started {
            return Ok(());
        }
        if seq > self.highest {
            return Ok(());
        }
        let diff = self.highest - seq;
        if diff >= REPLAY_WINDOW {
            return Err(Error::Replay);
        }
        if self.bitmap & (1u64 << diff) != 0 {
            return Err(Error::Replay);
        }
        Ok(())
    }

    /// Records `seq` as accepted. Call only after the frame authenticates.
    pub fn commit(&mut self, seq: u64) {
        if !self.started {
            self.started = true;
            self.highest = seq;
            self.bitmap = 1;
            return;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= REPLAY_WINDOW {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = seq;
        } else {
            let diff = self.highest - seq;
            if diff < REPLAY_WINDOW {
                self.bitmap |= 1u64 << diff;
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Bytes a data frame adds on top of its payload: header plus AEAD tag.
pub const DATA_OVERHEAD: usize = HEADER_LEN + TAGLEN;

/// Boundary that padded plaintexts are rounded up to.
pub const PAD_BLOCK: usize = 64;

/// Bytes of length prefix inside a padded plaintext.
const LEN_PREFIX: usize = 2;

/// What [`Session::open`] recovered from a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    /// The frame's parsed header.
    pub header: Header,
    /// Plaintext length. The plaintext occupies `frame[HEADER_LEN..][..len]`.
    pub len: usize,
    /// The reliable message identifier, when the frame carried one.
    pub message_id: Option<MessageId>,
}

/// An established FECTP session.
///
/// Holds only the two transport ciphers and the sequencing state; it owns no
/// buffers, so the caller controls all memory.
pub struct Session {
    send: CipherState,
    recv: CipherState,
    session_id: u32,
    send_seq: u64,
    replay: ReplayWindow,
    peer_caps: Capabilities,
    remote_static: PublicKey,
    padding: bool,
    resumption_key: [u8; PSK_LEN],
}

impl Session {
    fn new(
        send: CipherState,
        recv: CipherState,
        session_id: u32,
        peer_caps: Capabilities,
        remote_static: PublicKey,
        resumption_key: [u8; PSK_LEN],
    ) -> Self {
        Self {
            send,
            recv,
            session_id,
            send_seq: 0,
            replay: ReplayWindow::new(),
            peer_caps,
            remote_static,
            padding: false,
            resumption_key,
        }
    }

    /// The ticket that lets a later connection skip most of the handshake.
    ///
    /// Both peers derive the same value. Persisting it — to flash on a
    /// constrained device — is what turns a four-Diffie-Hellman reconnect into
    /// a one-Diffie-Hellman one.
    pub fn resumption_ticket(&self) -> ResumptionTicket {
        ResumptionTicket::from_key(self.resumption_key)
    }

    /// Enables or disables length-masking padding on outgoing frames.
    ///
    /// With padding on, each plaintext is length-prefixed and rounded up to a
    /// [`PAD_BLOCK`]-byte boundary, so the frame size reveals only which
    /// 64-byte bucket the payload fell into rather than its exact length. The
    /// receiver follows the per-frame flag, so this can be changed at any time
    /// and need not match on both sides.
    ///
    /// It is off by default because the cost is severe for the small messages
    /// this protocol is built around: a 10-byte payload becomes a 64-byte one.
    /// Turn it on when payload lengths are themselves sensitive.
    ///
    /// This narrows length leakage; it does not by itself defeat CRIME- or
    /// BREACH-style attacks. Those work by having the attacker influence
    /// plaintext that is compressed together with a secret, and observing the
    /// *change* in compressed size across many probes. Rounding to 64 bytes
    /// raises the number of probes needed but does not remove the signal. The
    /// actual defence is not to compress attacker-influenced data together
    /// with secrets; see the notes in `docs/DECISIONS.md`.
    pub fn set_padding(&mut self, enabled: bool) {
        self.padding = enabled;
    }

    /// Whether outgoing frames are padded.
    pub fn padding(&self) -> bool {
        self.padding
    }

    /// The peer's advertised capabilities.
    ///
    /// Consult this before compressing: a peer without [`CAP_ZSTD`] cannot
    /// decode a compressed frame.
    pub fn peer_capabilities(&self) -> Capabilities {
        self.peer_caps
    }

    /// The peer's authenticated static public key.
    pub fn remote_static(&self) -> &PublicKey {
        &self.remote_static
    }

    /// This session's identifier, as it appears in frame headers.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Largest payload that fits in one frame given the peer's frame limit.
    pub fn max_payload(&self) -> usize {
        (self.peer_caps.max_frame_size as usize).saturating_sub(DATA_OVERHEAD)
    }

    /// Encrypts `payload` into a complete data frame in `out`.
    ///
    /// `out` must be at least `payload.len() + DATA_OVERHEAD` bytes. Returns
    /// the frame length. `flags` carries per-frame markers such as
    /// [`FLAG_COMPRESSED`](crate::frame::FLAG_COMPRESSED); the caller sets it
    /// after deciding, against [`peer_capabilities`](Self::peer_capabilities),
    /// whether compression is permitted and worthwhile.
    ///
    /// The whole header is the AEAD's associated data, so a modified header
    /// fails authentication rather than being silently accepted.
    pub fn seal(&mut self, payload: &[u8], flags: u8, out: &mut [u8]) -> Result<usize> {
        self.seal_frame(FrameType::Data, payload, None, flags, out)
    }

    /// Encrypts `payload` as a reliable data frame carrying `message_id`.
    ///
    /// The identifier travels inside the encrypted plaintext, not the header.
    /// It has to: a retransmission cannot reuse the frame sequence number,
    /// because that is the AEAD nonce, so the receiver could not otherwise
    /// recognise a resent message.
    pub fn seal_reliable(
        &mut self,
        payload: &[u8],
        message_id: MessageId,
        flags: u8,
        out: &mut [u8],
    ) -> Result<usize> {
        self.seal_frame(FrameType::Data, payload, Some(message_id), flags, out)
    }

    /// Encrypts an acknowledgement frame.
    ///
    /// Acknowledgements are never themselves acknowledged. Each one reports the
    /// whole receive window, so a lost acknowledgement is repaired by the next
    /// one rather than by retransmitting it.
    pub fn seal_ack(&mut self, ack: &Ack, out: &mut [u8]) -> Result<usize> {
        let mut block = [0u8; ACK_BLOCK_LEN];
        ack.encode(&mut block)?;
        self.seal_frame(FrameType::Ack, &block, None, 0, out)
    }

    /// Builds any outgoing frame.
    ///
    /// The plaintext is assembled as `[pad_len]? [message_id]? payload
    /// [zeros]?`, each part present only when its header flag is set. Padding
    /// is outermost because it hides the total length, so its length field
    /// covers the message identifier too.
    fn seal_frame(
        &mut self,
        frame_type: FrameType,
        payload: &[u8],
        message_id: Option<MessageId>,
        flags: u8,
        out: &mut [u8],
    ) -> Result<usize> {
        if self.send_seq == u64::MAX {
            return Err(Error::NonceExhausted);
        }

        let mut flags = flags;
        let id_len = if message_id.is_some() {
            flags |= FLAG_RELIABLE;
            MESSAGE_ID_LEN
        } else {
            0
        };
        let inner_len = id_len
            .checked_add(payload.len())
            .ok_or(Error::PayloadTooLarge)?;

        // With padding on, the plaintext is rounded up to a block boundary so
        // the frame size no longer reveals the exact payload length.
        let plaintext_len = if self.padding {
            if inner_len > u16::MAX as usize {
                return Err(Error::PayloadTooLarge);
            }
            flags |= FLAG_PADDED;
            LEN_PREFIX
                .checked_add(inner_len)
                .ok_or(Error::PayloadTooLarge)?
                .next_multiple_of(PAD_BLOCK)
        } else {
            inner_len
        };

        let total = plaintext_len
            .checked_add(DATA_OVERHEAD)
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        let mut header = Header::new(frame_type, self.session_id);
        header.flags = flags;
        header.sequence = self.send_seq;
        header.encode(out)?;

        let (hdr, body) = out[..total].split_at_mut(HEADER_LEN);
        let mut at = 0;
        if self.padding {
            body[..LEN_PREFIX].copy_from_slice(&(inner_len as u16).to_le_bytes());
            at = LEN_PREFIX;
        }
        if let Some(id) = message_id {
            body[at..at + MESSAGE_ID_LEN].copy_from_slice(&id.to_le_bytes());
            at += MESSAGE_ID_LEN;
        }
        body[at..at + payload.len()].copy_from_slice(payload);
        body[at + payload.len()..plaintext_len].fill(0);

        self.send.encrypt_at(hdr, self.send_seq, body, plaintext_len)?;
        self.send_seq += 1;
        Ok(total)
    }

    /// Authenticates and decrypts a data frame in place.
    ///
    /// On success the plaintext occupies `frame[HEADER_LEN..][..len]` and the
    /// parsed header is returned alongside `len`.
    pub fn open(&mut self, frame: &mut [u8]) -> Result<Opened> {
        let header = Header::decode(frame)?;
        if !matches!(
            header.frame_type,
            FrameType::Data | FrameType::Close | FrameType::Ack
        ) {
            return Err(Error::BadHeader);
        }
        if header.session_id != self.session_id {
            return Err(Error::BadHeader);
        }
        if frame.len() < HEADER_LEN + TAGLEN {
            return Err(Error::MessageTooShort);
        }
        // Cheap pre-filter; the window is only updated once the frame proves
        // authentic, so a forged sequence number cannot advance it.
        self.replay.check(header.sequence)?;

        let (hdr, body) = frame.split_at_mut(HEADER_LEN);
        let pt_len = self.recv.decrypt_at(hdr, header.sequence, body)?;

        // Peel the prefixes in the order they were written, then shift the
        // payload down so callers always find it at `HEADER_LEN`, whatever the
        // sender wrapped it in.
        let mut at = 0;
        let mut len = pt_len;

        if header.flags & FLAG_PADDED != 0 {
            if pt_len < LEN_PREFIX {
                return Err(Error::BadHeader);
            }
            let mut raw = [0u8; LEN_PREFIX];
            raw.copy_from_slice(&body[..LEN_PREFIX]);
            let inner = usize::from(u16::from_le_bytes(raw));
            if LEN_PREFIX + inner > pt_len {
                return Err(Error::BadHeader);
            }
            at = LEN_PREFIX;
            len = inner;
        }

        let message_id = if header.flags & FLAG_RELIABLE != 0 {
            if len < MESSAGE_ID_LEN {
                return Err(Error::BadHeader);
            }
            let mut raw = [0u8; MESSAGE_ID_LEN];
            raw.copy_from_slice(&body[at..at + MESSAGE_ID_LEN]);
            at += MESSAGE_ID_LEN;
            len -= MESSAGE_ID_LEN;
            Some(MessageId::from_le_bytes(raw))
        } else {
            None
        };

        if at > 0 {
            body.copy_within(at..at + len, 0);
        }

        self.replay.commit(header.sequence);
        Ok(Opened {
            header,
            len,
            message_id,
        })
    }

    /// Parses the acknowledgement carried by an `Ack` frame.
    ///
    /// `plaintext` is what [`open`](Self::open) exposed at `HEADER_LEN`.
    pub fn parse_ack(plaintext: &[u8]) -> Result<Ack> {
        Ack::decode(plaintext)
    }

}

/// The initiator half of the framed handshake.
pub struct Initiator {
    hs: HandshakeState,
    session_id: u32,
    caps: Capabilities,
}

impl Initiator {
    /// Prepares an initiator that will connect to `remote_static`.
    ///
    /// `session_id` should be drawn at random; it demultiplexes sessions that
    /// share one socket.
    pub fn new(
        static_key: Keypair,
        remote_static: PublicKey,
        session_id: u32,
        caps: Capabilities,
    ) -> Result<Self> {
        // The message-1 header is the Noise prologue, so both peers bind the
        // version, frame type, and session id into the transcript. Tampering
        // with those bytes makes the handshake fail to authenticate.
        let mut prologue = [0u8; HEADER_LEN];
        Header::new(FrameType::HandshakeInit, session_id).encode(&mut prologue)?;
        Ok(Self {
            hs: HandshakeState::initiator(static_key, remote_static, &prologue),
            session_id,
            caps,
        })
    }

    /// Bytes that a message-1 frame adds on top of its application payload.
    pub const OVERHEAD: usize = HEADER_LEN + MSG1_OVERHEAD + CAPS_LEN;

    /// Writes the message-1 frame, carrying `app_payload` as 0-RTT data.
    ///
    /// `out` must be at least `Self::OVERHEAD + app_payload.len()` bytes.
    ///
    /// The 0-RTT payload is encrypted, but it is protected only by the
    /// responder's static key: it lacks forward secrecy and can be replayed by
    /// an attacker who captures the frame. Send only data that is safe to
    /// replay, or nothing at all.
    pub fn write_init<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        app_payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let payload_len = CAPS_LEN
            .checked_add(app_payload.len())
            .ok_or(Error::PayloadTooLarge)?;
        let total = Self::OVERHEAD
            .checked_add(app_payload.len())
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        Header::new(FrameType::HandshakeInit, self.session_id).encode(out)?;
        let noise = &mut out[HEADER_LEN..total];

        // Assemble the payload directly where the handshake expects it, so no
        // staging buffer or allocation is needed.
        let payload = &mut noise[MSG1_PAYLOAD_OFFSET..MSG1_PAYLOAD_OFFSET + payload_len];
        self.caps.encode(payload)?;
        payload[CAPS_LEN..].copy_from_slice(app_payload);

        let n = self.hs.write_message_1_in_place(rng, payload_len, noise)?;
        Ok(HEADER_LEN + n)
    }

    /// Consumes the message-2 frame and produces the established session.
    ///
    /// Any application payload the responder sent is written to `out`, and its
    /// length is returned alongside the session.
    pub fn read_response(mut self, frame: &[u8], out: &mut [u8]) -> Result<(Session, usize)> {
        let header = Header::decode(frame)?;
        if header.frame_type != FrameType::HandshakeResponse
            || header.session_id != self.session_id
        {
            return Err(Error::BadHeader);
        }

        // Decrypt into `out`, then split off the capability block.
        let pt_len = self.hs.read_message_2(&frame[HEADER_LEN..], out)?;
        if pt_len < CAPS_LEN {
            return Err(Error::MessageTooShort);
        }
        let peer_caps = Capabilities::decode(&out[..CAPS_LEN])?;
        let app_len = pt_len - CAPS_LEN;
        out.copy_within(CAPS_LEN..pt_len, 0);

        let remote_static = *self.hs.remote_static().ok_or(Error::HandshakeState)?;
        let resumption_key = self.hs.resumption_key();
        let (send, recv) = self.hs.split()?;
        Ok((
            Session::new(
                send,
                recv,
                self.session_id,
                peer_caps,
                remote_static,
                resumption_key,
            ),
            app_len,
        ))
    }
}

/// The responder half of the framed handshake.
pub struct Responder {
    /// Taken when message 1 arrives; the handshake needs the header of that
    /// message as its prologue, so it cannot be built any earlier.
    static_key: Option<Keypair>,
    hs: Option<HandshakeState>,
    static_public: PublicKey,
    session_id: u32,
    caps: Capabilities,
    peer_caps: Option<Capabilities>,
}

impl Responder {
    /// Prepares a responder holding `static_key`.
    pub fn new(static_key: Keypair, caps: Capabilities) -> Self {
        let static_public = *static_key.public();
        Self {
            static_key: Some(static_key),
            hs: None,
            static_public,
            session_id: 0,
            caps,
            peer_caps: None,
        }
    }

    /// Bytes that a message-2 frame adds on top of its application payload.
    pub const OVERHEAD: usize = HEADER_LEN + MSG2_OVERHEAD + CAPS_LEN;

    /// Consumes a message-1 frame, writing any 0-RTT payload into `out`.
    ///
    /// Returns the 0-RTT payload length.
    pub fn read_init(&mut self, frame: &[u8], out: &mut [u8]) -> Result<usize> {
        let header = Header::decode(frame)?;
        if header.frame_type != FrameType::HandshakeInit {
            return Err(Error::BadHeader);
        }
        let static_key = self.static_key.take().ok_or(Error::HandshakeState)?;

        // The received header is the prologue, binding version, frame type,
        // and session id into the transcript.
        let mut hs = HandshakeState::responder(static_key, &frame[..HEADER_LEN]);
        let pt_len = hs.read_message_1(&frame[HEADER_LEN..], out)?;
        if pt_len < CAPS_LEN {
            return Err(Error::MessageTooShort);
        }

        self.peer_caps = Some(Capabilities::decode(&out[..CAPS_LEN])?);
        self.session_id = header.session_id;
        self.hs = Some(hs);

        let app_len = pt_len - CAPS_LEN;
        out.copy_within(CAPS_LEN..pt_len, 0);
        Ok(app_len)
    }

    /// The initiator's authenticated static key, known after `read_init`.
    pub fn remote_static(&self) -> Option<&PublicKey> {
        self.hs.as_ref().and_then(|hs| hs.remote_static())
    }

    /// This responder's own static public key, which initiators must know.
    pub fn static_public(&self) -> &PublicKey {
        &self.static_public
    }

    /// Writes the message-2 frame and produces the established session.
    pub fn write_response<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        app_payload: &[u8],
        out: &mut [u8],
    ) -> Result<(Session, usize)> {
        let peer_caps = self.peer_caps.ok_or(Error::HandshakeState)?;
        let mut hs = self.hs.ok_or(Error::HandshakeState)?;
        let payload_len = CAPS_LEN
            .checked_add(app_payload.len())
            .ok_or(Error::PayloadTooLarge)?;
        let total = Self::OVERHEAD
            .checked_add(app_payload.len())
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        Header::new(FrameType::HandshakeResponse, self.session_id).encode(out)?;
        let noise = &mut out[HEADER_LEN..total];

        let payload = &mut noise[MSG2_PAYLOAD_OFFSET..MSG2_PAYLOAD_OFFSET + payload_len];
        self.caps.encode(payload)?;
        payload[CAPS_LEN..].copy_from_slice(app_payload);

        let n = hs.write_message_2_in_place(rng, payload_len, noise)?;

        let remote_static = *hs.remote_static().ok_or(Error::HandshakeState)?;
        let resumption_key = hs.resumption_key();
        let (send, recv) = hs.split()?;
        Ok((
            Session::new(
                send,
                recv,
                self.session_id,
                peer_caps,
                remote_static,
                resumption_key,
            ),
            HEADER_LEN + n,
        ))
    }
}

/// Domain separator for turning a configured secret into a pre-shared key.
const PSK_LABEL: &[u8] = b"fectp/1 psk";

/// Derives a long-lived pre-shared key from a configured secret.
///
/// The secret may be any length — a passphrase, a device serial, bytes burned
/// in at manufacture. Hashing it with a domain separator gives a uniform
/// 32-byte key that is independent of any resumption key, so the two cannot be
/// confused even though both drive the same handshake pattern.
///
/// The result is a [`ResumptionTicket`] because pre-shared-key mode and
/// resumption are the same handshake; only the provenance of the key differs.
/// A resumption ticket is spent when redeemed, while a configured key is not.
pub fn preshared_key(secret: &[u8]) -> ResumptionTicket {
    ResumptionTicket::from_key(hash(&[PSK_LABEL, secret]))
}

/// Length of the identifier a responder uses to find a stored ticket.
pub const TICKET_ID_LEN: usize = 8;

/// Domain separator for the ticket identifier.
const TICKET_ID_LABEL: &[u8] = b"fectp/1 ticket-id";

/// A resumption ticket: a shared key plus the identifier that names it.
///
/// The identifier is derived from the key rather than assigned, so the two
/// cannot drift apart and a responder needs no separate index. It travels in
/// the clear — a responder has to know which key to try before it can decrypt
/// anything — but it is one-way derived, so it discloses nothing about the key
/// and is bound into the transcript by the prologue.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResumptionTicket {
    id: [u8; TICKET_ID_LEN],
    key: [u8; PSK_LEN],
}

impl ResumptionTicket {
    /// Derives a ticket from a resumption key.
    pub fn from_key(key: [u8; PSK_LEN]) -> Self {
        let digest = hash(&[TICKET_ID_LABEL, &key]);
        let mut id = [0u8; TICKET_ID_LEN];
        id.copy_from_slice(&digest[..TICKET_ID_LEN]);
        Self { id, key }
    }

    /// The public identifier, sent in the clear so the peer can find the key.
    pub fn id(&self) -> &[u8; TICKET_ID_LEN] {
        &self.id
    }

    /// The secret key. Treat it like any other long-term key material.
    pub fn key(&self) -> &[u8; PSK_LEN] {
        &self.key
    }
}

impl core::fmt::Debug for ResumptionTicket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResumptionTicket")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The initiator half of a resumption handshake.
pub struct ResumeInitiator {
    hs: ResumeHandshake,
    session_id: u32,
    ticket: ResumptionTicket,
    caps: Capabilities,
    remote_static: PublicKey,
}

impl ResumeInitiator {
    /// Bytes a resumption message-1 frame adds on top of its payload.
    pub const OVERHEAD: usize = HEADER_LEN + TICKET_ID_LEN + RESUME_MSG_OVERHEAD + CAPS_LEN;

    /// Prepares a resumption using `ticket`.
    ///
    /// `remote_static` is remembered only so the resumed session can report
    /// the peer's identity; it takes no part in the handshake, which is
    /// authenticated entirely by the ticket.
    pub fn new(
        ticket: ResumptionTicket,
        remote_static: PublicKey,
        session_id: u32,
        caps: Capabilities,
    ) -> Result<Self> {
        // The prologue covers both the header and the cleartext ticket
        // identifier, so tampering with either breaks authentication.
        let mut prologue = [0u8; HEADER_LEN + TICKET_ID_LEN];
        Header::new(FrameType::ResumeInit, session_id).encode(&mut prologue)?;
        prologue[HEADER_LEN..].copy_from_slice(ticket.id());
        Ok(Self {
            hs: ResumeHandshake::initiator(ticket.key(), &prologue),
            session_id,
            ticket,
            caps,
            remote_static,
        })
    }

    /// Writes the resumption request, carrying `app_payload` as 0-RTT data.
    pub fn write_init<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        app_payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let payload_len = CAPS_LEN
            .checked_add(app_payload.len())
            .ok_or(Error::PayloadTooLarge)?;
        let total = Self::OVERHEAD
            .checked_add(app_payload.len())
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        Header::new(FrameType::ResumeInit, self.session_id).encode(out)?;
        out[HEADER_LEN..HEADER_LEN + TICKET_ID_LEN].copy_from_slice(self.ticket.id());

        let noise = &mut out[HEADER_LEN + TICKET_ID_LEN..total];
        let payload = &mut noise[RESUME_PAYLOAD_OFFSET..RESUME_PAYLOAD_OFFSET + payload_len];
        self.caps.encode(payload)?;
        payload[CAPS_LEN..].copy_from_slice(app_payload);

        let n = self.hs.write_message_1(rng, payload_len, noise)?;
        Ok(HEADER_LEN + TICKET_ID_LEN + n)
    }

    /// Consumes the response and produces the resumed session.
    pub fn read_response(mut self, frame: &[u8], out: &mut [u8]) -> Result<(Session, usize)> {
        let header = Header::decode(frame)?;
        if header.frame_type != FrameType::ResumeResponse || header.session_id != self.session_id {
            return Err(Error::BadHeader);
        }

        let pt_len = self.hs.read_message_2(&frame[HEADER_LEN..], out)?;
        if pt_len < CAPS_LEN {
            return Err(Error::MessageTooShort);
        }
        let peer_caps = Capabilities::decode(&out[..CAPS_LEN])?;
        let app_len = pt_len - CAPS_LEN;
        out.copy_within(CAPS_LEN..pt_len, 0);

        // A fresh key for next time. Tickets are single use, so reusing this
        // one would fail; the session must carry its replacement.
        let next_key = self.hs.next_resumption_key();
        let (send, recv) = self.hs.split()?;
        Ok((
            Session::new(
                send,
                recv,
                self.session_id,
                peer_caps,
                self.remote_static,
                next_key,
            ),
            app_len,
        ))
    }
}

/// The responder half of a resumption handshake.
pub struct ResumeResponder {
    hs: Option<ResumeHandshake>,
    session_id: u32,
    caps: Capabilities,
    peer_caps: Option<Capabilities>,
    remote_static: PublicKey,
}

impl ResumeResponder {
    /// Bytes a resumption message-2 frame adds on top of its payload.
    pub const OVERHEAD: usize = HEADER_LEN + RESUME_MSG_OVERHEAD + CAPS_LEN;

    /// Reads the ticket identifier a resumption request names.
    ///
    /// A responder calls this first, looks the identifier up in its own store,
    /// and only then has a key to attempt the handshake with.
    pub fn ticket_id(frame: &[u8]) -> Result<[u8; TICKET_ID_LEN]> {
        let header = Header::decode(frame)?;
        if header.frame_type != FrameType::ResumeInit {
            return Err(Error::BadHeader);
        }
        if frame.len() < HEADER_LEN + TICKET_ID_LEN {
            return Err(Error::MessageTooShort);
        }
        let mut id = [0u8; TICKET_ID_LEN];
        id.copy_from_slice(&frame[HEADER_LEN..HEADER_LEN + TICKET_ID_LEN]);
        Ok(id)
    }

    /// Prepares a responder holding a looked-up ticket.
    pub fn new(caps: Capabilities, remote_static: PublicKey) -> Self {
        Self {
            hs: None,
            session_id: 0,
            caps,
            peer_caps: None,
            remote_static,
        }
    }

    /// Consumes a resumption request, writing any 0-RTT payload into `out`.
    ///
    /// `ticket` must be the one named by [`ticket_id`](Self::ticket_id).
    /// Failure here means the ticket was stale or the frame forged; a responder
    /// should discard the frame and let the peer fall back to a full handshake.
    pub fn read_init(
        &mut self,
        ticket: &ResumptionTicket,
        frame: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let header = Header::decode(frame)?;
        if header.frame_type != FrameType::ResumeInit {
            return Err(Error::BadHeader);
        }
        if frame.len() < HEADER_LEN + TICKET_ID_LEN {
            return Err(Error::MessageTooShort);
        }

        let prologue = &frame[..HEADER_LEN + TICKET_ID_LEN];
        let mut hs = ResumeHandshake::responder(ticket.key(), prologue);
        let pt_len = hs.read_message_1(&frame[HEADER_LEN + TICKET_ID_LEN..], out)?;
        if pt_len < CAPS_LEN {
            return Err(Error::MessageTooShort);
        }

        self.peer_caps = Some(Capabilities::decode(&out[..CAPS_LEN])?);
        self.session_id = header.session_id;
        self.hs = Some(hs);

        let app_len = pt_len - CAPS_LEN;
        out.copy_within(CAPS_LEN..pt_len, 0);
        Ok(app_len)
    }

    /// Writes the response and produces the resumed session.
    pub fn write_response<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        app_payload: &[u8],
        out: &mut [u8],
    ) -> Result<(Session, usize)> {
        let peer_caps = self.peer_caps.ok_or(Error::HandshakeState)?;
        let mut hs = self.hs.ok_or(Error::HandshakeState)?;
        let payload_len = CAPS_LEN
            .checked_add(app_payload.len())
            .ok_or(Error::PayloadTooLarge)?;
        let total = Self::OVERHEAD
            .checked_add(app_payload.len())
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        Header::new(FrameType::ResumeResponse, self.session_id).encode(out)?;
        let noise = &mut out[HEADER_LEN..total];
        let payload = &mut noise[RESUME_PAYLOAD_OFFSET..RESUME_PAYLOAD_OFFSET + payload_len];
        self.caps.encode(payload)?;
        payload[CAPS_LEN..].copy_from_slice(app_payload);

        let n = hs.write_message_2(rng, payload_len, noise)?;
        let next_key = hs.next_resumption_key();
        let (send, recv) = hs.split()?;
        Ok((
            Session::new(
                send,
                recv,
                self.session_id,
                peer_caps,
                self.remote_static,
                next_key,
            ),
            HEADER_LEN + n,
        ))
    }
}
