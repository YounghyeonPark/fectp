//! Unencrypted framing, for links where confidentiality is not the point.
//!
//! ## When this is the right choice
//!
//! Two cases, and they are narrow:
//!
//! - **A physically trusted link.** An instrument wired to its host over USB,
//!   RS-485, or a direct cable has no network for an attacker to sit on.
//! - **Development.** Running the framing, codec, and reliability layers with
//!   the crypto out of the way makes packet captures readable and isolates
//!   bugs to one layer.
//!
//! ## When it is not
//!
//! Almost everywhere else. Encrypting a 1200-byte frame costs on the order of
//! a microsecond; what actually costs anything is distributing keys. If the
//! reason for reaching for this module is that key management is awkward, the
//! answer is a pre-shared key — encryption stays on and there is nothing to
//! distribute but one secret.
//!
//! ## The safety property that makes this tolerable
//!
//! **The mode is chosen, never negotiated.** Plaintext uses its own frame
//! types, so an encrypted peer cannot be talked down to plaintext and a
//! plaintext peer cannot be fed encrypted frames. There is no mode field for
//! an attacker to rewrite, because a protocol that negotiates its own security
//! level is a protocol that can be downgraded.
//!
//! Everything above this layer — sequencing, codecs, reliability — behaves
//! exactly as it does over an encrypted session, so an application can switch
//! between them without changing a line.

use crate::error::{Error, Result};
use crate::fragment::{Fragment, FRAGMENT_LEN};
use crate::frame::{FrameType, Header, FLAG_FRAGMENT, FLAG_RELIABLE, HEADER_LEN};
use crate::keys::PublicKey;
use crate::reliability::{Ack, MessageId, ACK_BLOCK_LEN, MESSAGE_ID_LEN};
use crate::session::{Capabilities, Opened, ReplayWindow, CAPS_LEN};

/// Bytes a plaintext data frame adds on top of its payload.
///
/// The header alone: there is no authentication tag, because there is no
/// authentication.
pub const PLAIN_DATA_OVERHEAD: usize = HEADER_LEN;

/// Bytes a plaintext handshake frame occupies beyond its application payload.
pub const PLAIN_HANDSHAKE_OVERHEAD: usize = HEADER_LEN + CAPS_LEN;

/// A public key stand-in for peers that present no identity.
///
/// Plaintext peers are anonymous; this is what `remote_static` reports so that
/// callers do not have to special-case the mode.
pub const ANONYMOUS: PublicKey = [0u8; 32];

/// An established plaintext session.
///
/// Mirrors [`Session`](crate::Session) so that everything layered on top works
/// unchanged, minus every guarantee that comes from cryptography.
pub struct PlainSession {
    session_id: u32,
    send_seq: u64,
    replay: ReplayWindow,
    peer_caps: Capabilities,
}

impl PlainSession {
    fn new(session_id: u32, peer_caps: Capabilities) -> Self {
        Self {
            session_id,
            send_seq: 0,
            replay: ReplayWindow::new(),
            peer_caps,
        }
    }

    /// The peer's advertised capabilities.
    pub fn peer_capabilities(&self) -> Capabilities {
        self.peer_caps
    }

    /// This session's identifier, as it appears in frame headers.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Largest payload that fits in one frame.
    pub fn max_payload(&self) -> usize {
        (self.peer_caps.max_frame_size as usize).saturating_sub(PLAIN_DATA_OVERHEAD)
    }

    /// Writes `payload` as a plaintext data frame.
    pub fn seal(&mut self, payload: &[u8], flags: u8, out: &mut [u8]) -> Result<usize> {
        self.seal_frame(FrameType::PlainData, payload, None, None, flags, out)
    }

    /// Writes `payload` as a plaintext data frame carrying `message_id`.
    pub fn seal_reliable(
        &mut self,
        payload: &[u8],
        message_id: MessageId,
        flags: u8,
        out: &mut [u8],
    ) -> Result<usize> {
        self.seal_frame(FrameType::PlainData, payload, Some(message_id), None, flags, out)
    }

    /// Writes one fragment of a larger message.
    pub fn seal_fragment(
        &mut self,
        payload: &[u8],
        message_id: MessageId,
        fragment: Fragment,
        flags: u8,
        out: &mut [u8],
    ) -> Result<usize> {
        self.seal_frame(
            FrameType::PlainData,
            payload,
            Some(message_id),
            Some(fragment),
            flags,
            out,
        )
    }

    /// Writes an acknowledgement frame.
    pub fn seal_ack(&mut self, ack: &Ack, out: &mut [u8]) -> Result<usize> {
        let mut block = [0u8; ACK_BLOCK_LEN];
        ack.encode(&mut block)?;
        self.seal_frame(FrameType::PlainAck, &block, None, None, 0, out)
    }

    fn seal_frame(
        &mut self,
        frame_type: FrameType,
        payload: &[u8],
        message_id: Option<MessageId>,
        fragment: Option<Fragment>,
        flags: u8,
        out: &mut [u8],
    ) -> Result<usize> {
        let mut flags = flags;
        let id_len = if message_id.is_some() {
            flags |= FLAG_RELIABLE;
            MESSAGE_ID_LEN
        } else {
            0
        };
        let fragment_len = if fragment.is_some() {
            flags |= FLAG_FRAGMENT;
            FRAGMENT_LEN
        } else {
            0
        };
        let total = HEADER_LEN
            .checked_add(id_len)
            .and_then(|n| n.checked_add(fragment_len))
            .and_then(|n| n.checked_add(payload.len()))
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        let mut header = Header::new(frame_type, self.session_id);
        header.flags = flags;
        header.sequence = self.send_seq;
        header.encode(out)?;

        let mut at = HEADER_LEN;
        if let Some(id) = message_id {
            out[at..at + MESSAGE_ID_LEN].copy_from_slice(&id.to_le_bytes());
            at += MESSAGE_ID_LEN;
        }
        if let Some(fragment) = fragment {
            fragment.encode(&mut out[at..])?;
            at += FRAGMENT_LEN;
        }
        out[at..total].copy_from_slice(payload);

        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(total)
    }

    /// Parses a plaintext frame in place.
    ///
    /// On success the payload occupies `frame[HEADER_LEN..][..len]`, matching
    /// the encrypted path so callers need no special case.
    ///
    /// The replay window is applied here as it is for an encrypted session, so
    /// that reordering and duplicate behaviour is identical. It is **not** a
    /// security mechanism in this mode: nothing here is authenticated, so an
    /// attacker on the path can forge any frame it likes. That is the whole
    /// bargain of plaintext mode.
    pub fn open(&mut self, frame: &mut [u8]) -> Result<Opened> {
        let header = Header::decode(frame)?;
        if !matches!(
            header.frame_type,
            FrameType::PlainData | FrameType::PlainAck
        ) {
            return Err(Error::BadHeader);
        }
        if header.session_id != self.session_id {
            return Err(Error::BadHeader);
        }
        self.replay.check(header.sequence)?;

        let body = frame.len() - HEADER_LEN;
        let (message_id, at, len) = if header.flags & FLAG_RELIABLE != 0 {
            if body < MESSAGE_ID_LEN {
                return Err(Error::BadHeader);
            }
            let mut raw = [0u8; MESSAGE_ID_LEN];
            raw.copy_from_slice(&frame[HEADER_LEN..HEADER_LEN + MESSAGE_ID_LEN]);
            (
                Some(MessageId::from_le_bytes(raw)),
                MESSAGE_ID_LEN,
                body - MESSAGE_ID_LEN,
            )
        } else {
            (None, 0, body)
        };

        let (fragment, at, len) = if header.flags & FLAG_FRAGMENT != 0 {
            if len < FRAGMENT_LEN {
                return Err(Error::BadHeader);
            }
            let parsed = Fragment::decode(&frame[HEADER_LEN + at..])?;
            (Some(parsed), at + FRAGMENT_LEN, len - FRAGMENT_LEN)
        } else {
            (None, at, len)
        };

        if at > 0 {
            frame.copy_within(HEADER_LEN + at..HEADER_LEN + at + len, HEADER_LEN);
        }

        self.replay.commit(header.sequence);
        Ok(Opened {
            header,
            len,
            message_id,
            fragment,
        })
    }
}

/// The initiator half of the plaintext handshake.
///
/// There are no keys to agree, so this exchange exists only to swap capability
/// blocks and settle on a session identifier — which keeps codec negotiation
/// and the reliability layer working exactly as they do when encrypted.
pub struct PlainInitiator {
    session_id: u32,
    caps: Capabilities,
}

impl PlainInitiator {
    /// Bytes a plaintext opening frame adds on top of its payload.
    pub const OVERHEAD: usize = PLAIN_HANDSHAKE_OVERHEAD;

    /// Prepares an initiator.
    pub fn new(session_id: u32, caps: Capabilities) -> Self {
        Self { session_id, caps }
    }

    /// Writes the opening frame, carrying `app_payload` alongside.
    pub fn write_init(&mut self, app_payload: &[u8], out: &mut [u8]) -> Result<usize> {
        write_handshake(
            FrameType::PlainInit,
            self.session_id,
            self.caps,
            app_payload,
            out,
        )
    }

    /// Consumes the response and produces the established session.
    pub fn read_response(self, frame: &[u8], out: &mut [u8]) -> Result<(PlainSession, usize)> {
        let (peer_caps, app_len) = read_handshake(
            FrameType::PlainResponse,
            Some(self.session_id),
            frame,
            out,
        )?;
        Ok((PlainSession::new(self.session_id, peer_caps), app_len))
    }
}

/// The responder half of the plaintext handshake.
pub struct PlainResponder {
    caps: Capabilities,
    session_id: u32,
    peer_caps: Option<Capabilities>,
}

impl PlainResponder {
    /// Bytes a plaintext response frame adds on top of its payload.
    pub const OVERHEAD: usize = PLAIN_HANDSHAKE_OVERHEAD;

    /// Prepares a responder advertising `caps`.
    pub fn new(caps: Capabilities) -> Self {
        Self {
            caps,
            session_id: 0,
            peer_caps: None,
        }
    }

    /// Consumes an opening frame, writing any payload into `out`.
    pub fn read_init(&mut self, frame: &[u8], out: &mut [u8]) -> Result<usize> {
        let (peer_caps, app_len) = read_handshake(FrameType::PlainInit, None, frame, out)?;
        self.session_id = Header::decode(frame)?.session_id;
        self.peer_caps = Some(peer_caps);
        Ok(app_len)
    }

    /// Writes the response and produces the established session.
    pub fn write_response(
        self,
        app_payload: &[u8],
        out: &mut [u8],
    ) -> Result<(PlainSession, usize)> {
        let peer_caps = self.peer_caps.ok_or(Error::HandshakeState)?;
        let n = write_handshake(
            FrameType::PlainResponse,
            self.session_id,
            self.caps,
            app_payload,
            out,
        )?;
        Ok((PlainSession::new(self.session_id, peer_caps), n))
    }
}

fn write_handshake(
    frame_type: FrameType,
    session_id: u32,
    caps: Capabilities,
    app_payload: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let total = PLAIN_HANDSHAKE_OVERHEAD
        .checked_add(app_payload.len())
        .ok_or(Error::PayloadTooLarge)?;
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    Header::new(frame_type, session_id).encode(out)?;
    caps.encode_into(&mut out[HEADER_LEN..HEADER_LEN + CAPS_LEN])?;
    out[HEADER_LEN + CAPS_LEN..total].copy_from_slice(app_payload);
    Ok(total)
}

fn read_handshake(
    expected: FrameType,
    expected_session: Option<u32>,
    frame: &[u8],
    out: &mut [u8],
) -> Result<(Capabilities, usize)> {
    let header = Header::decode(frame)?;
    if header.frame_type != expected {
        return Err(Error::BadHeader);
    }
    if expected_session.is_some_and(|id| id != header.session_id) {
        return Err(Error::BadHeader);
    }
    if frame.len() < PLAIN_HANDSHAKE_OVERHEAD {
        return Err(Error::MessageTooShort);
    }
    let caps = Capabilities::decode_from(&frame[HEADER_LEN..HEADER_LEN + CAPS_LEN])?;
    let app = &frame[HEADER_LEN + CAPS_LEN..];
    if out.len() < app.len() {
        return Err(Error::BufferTooSmall);
    }
    out[..app.len()].copy_from_slice(app);
    Ok((caps, app.len()))
}
