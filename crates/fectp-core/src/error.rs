//! Error type shared by every FECTP operation.

/// Convenience alias for fallible FECTP operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong in the FECTP core.
///
/// The variants carry no payload on purpose: an attacker must not be able to
/// learn *why* a frame was rejected, and MCU targets cannot afford formatted
/// error strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The caller-supplied output buffer is too small for the result.
    BufferTooSmall,
    /// The received message is shorter than its format requires.
    MessageTooShort,
    /// AEAD authentication failed: the frame was forged, corrupted, or
    /// encrypted under a different key.
    Decrypt,
    /// The 64-bit nonce counter is exhausted. The session must be rekeyed.
    NonceExhausted,
    /// A handshake method was called out of order.
    HandshakeState,
    /// The frame carries an unrecognised protocol version.
    UnsupportedVersion,
    /// The frame header is structurally invalid.
    BadHeader,
    /// The frame's sequence number was already seen, or is too old to verify.
    Replay,
    /// The session is not yet established.
    NotReady,
    /// The payload exceeds what a single frame can carry.
    PayloadTooLarge,
    /// Too many reliable messages are already awaiting acknowledgement.
    WindowFull,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Error::BufferTooSmall => "output buffer too small",
            Error::MessageTooShort => "message too short",
            Error::Decrypt => "decryption failed",
            Error::NonceExhausted => "nonce counter exhausted",
            Error::HandshakeState => "handshake called out of order",
            Error::UnsupportedVersion => "unsupported protocol version",
            Error::BadHeader => "malformed header",
            Error::Replay => "replayed or too-old sequence number",
            Error::NotReady => "session not established",
            Error::PayloadTooLarge => "payload too large for one frame",
            Error::WindowFull => "too many unacknowledged messages in flight",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
