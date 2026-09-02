//! The FECTP wire format.
//!
//! Every frame begins with a fixed 14-byte header. The header is fixed-size
//! and has no variable-length fields, so parsing an attacker-controlled frame
//! involves no length arithmetic before authentication. This is deliberate:
//! the pre-authentication parser is the highest-risk code in any transport
//! protocol, and on a microcontroller there is no ASLR, no NX, and no MMU to
//! contain a mistake in it.
//!
//! ```text
//!  0               1               2               3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | ver |  type | flags         | session_id (low 16 bits)        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | session_id (high 16 bits)   | sequence (low 16 bits)          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | sequence (bits 16..48)                                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | sequence (bits 48..64)      |  payload ...                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! For data frames the entire header is the AEAD's associated data, so any
//! tampering with it is a decryption failure.
//!
//! Nothing negotiable lives in the header. Capabilities such as compression
//! support travel inside the *encrypted* handshake payload, which makes
//! downgrade attacks impossible: an attacker who rewrites header bytes can
//! only cause a decryption failure, never a weaker configuration.

use crate::error::{Error, Result};

/// Length of the fixed frame header, in bytes.
pub const HEADER_LEN: usize = 14;

/// The protocol version this implementation speaks.
pub const VERSION: u8 = 1;

/// Frame flag: the payload is Zstandard-compressed.
pub const FLAG_COMPRESSED: u8 = 0b0000_0001;

/// Frame flag: the payload participates in the reliability layer.
pub const FLAG_RELIABLE: u8 = 0b0000_0010;

/// Frame flag: the plaintext is length-prefixed and padded to a block boundary.
pub const FLAG_PADDED: u8 = 0b0000_0100;

/// Frame flag: the plaintext carries a fragment descriptor before its payload.
pub const FLAG_FRAGMENT: u8 = 0b0000_1000;

/// Flag bits that are defined; any other bit set is a malformed frame.
const KNOWN_FLAGS: u8 = FLAG_COMPRESSED | FLAG_RELIABLE | FLAG_PADDED | FLAG_FRAGMENT;

/// What a frame carries.
///
/// The encrypted and plaintext framings use disjoint type numbers precisely so
/// that neither can be mistaken for the other. A protocol that lets peers
/// negotiate their own security level is a protocol that can be downgraded;
/// here the mode is fixed when the session is built and never appears on the
/// wire as a choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Noise IK message 1, with optional 0-RTT payload.
    HandshakeInit,
    /// Noise IK message 2.
    HandshakeResponse,
    /// Post-handshake application data.
    Data,
    /// Orderly shutdown.
    Close,
    /// Acknowledges received reliable messages.
    Ack,
    /// Resumption message 1, redeeming a ticket from an earlier session.
    ResumeInit,
    /// Resumption message 2.
    ResumeResponse,
}

impl FrameType {
    fn to_bits(self) -> u8 {
        match self {
            FrameType::HandshakeInit => 1,
            FrameType::HandshakeResponse => 2,
            FrameType::Data => 3,
            FrameType::Close => 4,
            FrameType::Ack => 5,
            FrameType::ResumeInit => 6,
            FrameType::ResumeResponse => 7,
        }
    }

    fn from_bits(bits: u8) -> Result<Self> {
        match bits {
            1 => Ok(FrameType::HandshakeInit),
            2 => Ok(FrameType::HandshakeResponse),
            3 => Ok(FrameType::Data),
            4 => Ok(FrameType::Close),
            5 => Ok(FrameType::Ack),
            6 => Ok(FrameType::ResumeInit),
            7 => Ok(FrameType::ResumeResponse),
            _ => Err(Error::BadHeader),
        }
    }
}

/// A parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Frame kind.
    pub frame_type: FrameType,
    /// Frame flags; see [`FLAG_COMPRESSED`] and [`FLAG_RELIABLE`].
    pub flags: u8,
    /// Identifies the session on the receiver, for demultiplexing one socket.
    pub session_id: u32,
    /// AEAD nonce counter for data frames; zero for handshake frames.
    pub sequence: u64,
}

impl Header {
    /// Builds a header for the given frame type.
    pub fn new(frame_type: FrameType, session_id: u32) -> Self {
        Self {
            frame_type,
            flags: 0,
            session_id,
            sequence: 0,
        }
    }

    /// Returns whether the payload is marked compressed.
    pub fn is_compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }

    /// Serialises the header into the first [`HEADER_LEN`] bytes of `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < HEADER_LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = (VERSION << 4) | self.frame_type.to_bits();
        out[1] = self.flags;
        out[2..6].copy_from_slice(&self.session_id.to_le_bytes());
        out[6..14].copy_from_slice(&self.sequence.to_le_bytes());
        Ok(())
    }

    /// Parses a header from the first [`HEADER_LEN`] bytes of `input`.
    ///
    /// Rejects unknown versions, unknown frame types, and undefined flag bits.
    /// Rejecting unknown flags now keeps them available for a future version
    /// without ambiguity.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < HEADER_LEN {
            return Err(Error::MessageTooShort);
        }
        let version = input[0] >> 4;
        if version != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let frame_type = FrameType::from_bits(input[0] & 0x0f)?;
        let flags = input[1];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Error::BadHeader);
        }
        let mut id = [0u8; 4];
        id.copy_from_slice(&input[2..6]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&input[6..14]);
        Ok(Self {
            frame_type,
            flags,
            session_id: u32::from_le_bytes(id),
            sequence: u64::from_le_bytes(seq),
        })
    }
}
