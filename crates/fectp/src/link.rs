//! The session, whichever kind it is.
//!
//! Everything above this — sequencing, codecs, reliability, the whole public
//! API — is identical whether a session is encrypted or not. This enum is the
//! one place that difference exists, so adding plaintext mode changed nothing
//! upstream of it.
//!
//! There is deliberately no way to convert one kind into the other, and no
//! wire field that selects between them. The mode is fixed when the session is
//! built.

use fectp_core::plain::{PlainSession, ANONYMOUS, PLAIN_DATA_OVERHEAD};
use fectp_core::reliability::{Ack, MessageId};
use fectp_core::session::{Capabilities, Opened, ResumptionTicket, DATA_OVERHEAD};
use fectp_core::{PublicKey, Result, Session};

/// An established session, encrypted or not.
pub(crate) enum Link {
    /// Authenticated and encrypted.
    Encrypted(Session),
    /// Framed but in the clear. See [`fectp_core::plain`] for when that is
    /// defensible.
    Plain(PlainSession),
}

impl Link {
    /// Whether this session encrypts.
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Link::Encrypted(_))
    }

    /// Bytes a data frame adds on top of its payload.
    ///
    /// Plaintext frames carry no authentication tag, because there is no
    /// authentication — 14 bytes of overhead against 30.
    pub fn data_overhead(&self) -> usize {
        match self {
            Link::Encrypted(_) => DATA_OVERHEAD,
            Link::Plain(_) => PLAIN_DATA_OVERHEAD,
        }
    }

    pub fn peer_capabilities(&self) -> Capabilities {
        match self {
            Link::Encrypted(s) => s.peer_capabilities(),
            Link::Plain(s) => s.peer_capabilities(),
        }
    }

    pub fn session_id(&self) -> u32 {
        match self {
            Link::Encrypted(s) => s.session_id(),
            Link::Plain(s) => s.session_id(),
        }
    }

    pub fn max_payload(&self) -> usize {
        match self {
            Link::Encrypted(s) => s.max_payload(),
            Link::Plain(s) => s.max_payload(),
        }
    }

    /// The peer's authenticated static public key.
    ///
    /// A plaintext peer has no identity to report, so this is
    /// [`ANONYMOUS`]. Callers that care about who they are talking to must
    /// check [`is_encrypted`](Self::is_encrypted) first — an all-zero key is
    /// not an identity.
    pub fn remote_static(&self) -> &PublicKey {
        match self {
            Link::Encrypted(s) => s.remote_static(),
            Link::Plain(_) => &ANONYMOUS,
        }
    }

    /// The ticket for resuming this session, when there is one.
    ///
    /// Plaintext sessions have nothing to resume: there is no key schedule to
    /// carry forward, and the handshake they would skip costs nothing anyway.
    pub fn resumption_ticket(&self) -> Option<ResumptionTicket> {
        match self {
            Link::Encrypted(s) => Some(s.resumption_ticket()),
            Link::Plain(_) => None,
        }
    }

    /// Enables length-masking padding, where that is meaningful.
    ///
    /// Ignored on a plaintext session: padding hides a length from someone who
    /// can see the ciphertext but not the plaintext, and here they can see the
    /// plaintext.
    pub fn set_padding(&mut self, enabled: bool) {
        if let Link::Encrypted(s) = self {
            s.set_padding(enabled);
        }
    }

    pub fn seal(&mut self, payload: &[u8], flags: u8, out: &mut [u8]) -> Result<usize> {
        match self {
            Link::Encrypted(s) => s.seal(payload, flags, out),
            Link::Plain(s) => s.seal(payload, flags, out),
        }
    }

    pub fn seal_reliable(
        &mut self,
        payload: &[u8],
        message_id: MessageId,
        flags: u8,
        out: &mut [u8],
    ) -> Result<usize> {
        match self {
            Link::Encrypted(s) => s.seal_reliable(payload, message_id, flags, out),
            Link::Plain(s) => s.seal_reliable(payload, message_id, flags, out),
        }
    }

    pub fn seal_ack(&mut self, ack: &Ack, out: &mut [u8]) -> Result<usize> {
        match self {
            Link::Encrypted(s) => s.seal_ack(ack, out),
            Link::Plain(s) => s.seal_ack(ack, out),
        }
    }

    pub fn open(&mut self, frame: &mut [u8]) -> Result<Opened> {
        match self {
            Link::Encrypted(s) => s.open(frame),
            Link::Plain(s) => s.open(frame),
        }
    }
}
