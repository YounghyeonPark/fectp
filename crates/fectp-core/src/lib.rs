//! # FECTP core
//!
//! `no_std`, allocation-free implementation of the FECTP session layer:
//! the `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake, the framing format,
//! and the datagram [`Transport`] abstraction.
//!
//! This crate deliberately contains no transport implementation and no
//! compression. Both are supplied from the outside so that the same core
//! runs unchanged from a Cortex-M microcontroller to a server.
//!
//! ## Profile support
//!
//! The core is sized for the smallest supported target (32-bit MCU, >=32 KiB
//! RAM). It performs no heap allocation, spawns no threads, and holds no
//! buffers of its own: every operation writes into a caller-provided slice.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod codec;
pub mod error;
pub mod fragment;
pub mod frame;
pub mod keys;
pub mod noise;
pub mod reliability;
pub mod session;
pub mod transport;

pub use codec::{CodecHeader, Entropy, Transform};
pub use error::{Error, Result};
pub use keys::{Keypair, PublicKey, ANONYMOUS, DHLEN};
pub use reliability::{Ack, DedupWindow, Due, MessageId, RetransmitQueue};
pub use session::{
    preshared_key, Capabilities, Initiator, ResumeInitiator, ResumeResponder, Responder,
    ResumptionTicket, Session,
};
pub use transport::Transport;

#[cfg(feature = "std")]
extern crate std;
