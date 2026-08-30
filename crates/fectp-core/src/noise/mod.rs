//! The `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake.
//!
//! ## Why BLAKE2s rather than BLAKE2b
//!
//! BLAKE2b operates on 64-bit words and loses a large constant factor on
//! 32-bit microcontrollers. BLAKE2s is the 32-bit variant and is a standard
//! Noise cipher-suite choice. Because both peers must agree on the hash, this
//! is fixed protocol-wide rather than being selected per profile.
//!
//! ## Why IK
//!
//! In IK the initiator already knows the responder's static public key, so it
//! can put real application data in the very first handshake message. That
//! makes first-contact 0-RTT possible without a prior session, which QUIC with
//! TLS 1.3 cannot do.

mod cipher;
mod resume;
mod handshake;
mod hash;
mod symmetric;

pub use cipher::{CipherState, KEYLEN, TAGLEN};
pub use handshake::{
    HandshakeState, Role, MSG1_OVERHEAD, MSG1_PAYLOAD_OFFSET, MSG2_OVERHEAD, MSG2_PAYLOAD_OFFSET,
};
pub use hash::{hash, hkdf2, hkdf3, Hash, HASHLEN};
pub use resume::{ResumeHandshake, PSK_LEN, RESUME_MSG_OVERHEAD, RESUME_PAYLOAD_OFFSET};
pub use symmetric::SymmetricState;

/// The full Noise protocol name for the initial handshake.
pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// The Noise protocol name for resumption.
///
/// `NNpsk0` authenticates from a pre-shared key established by a previous
/// `IK` handshake, so it needs no static-key operations at all: one
/// Diffie-Hellman instead of four. The ephemerals are still fresh, so a
/// resumed session keeps forward secrecy against later compromise of the
/// stored key.
pub const RESUME_PROTOCOL_NAME: &[u8] = b"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
