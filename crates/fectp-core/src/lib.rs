//! # FECTP core
//!
//! `no_std`, allocation-free implementation of the FECTP session layer:
//! the `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake, the framing format,
//! and the datagram [`Transport`] abstraction.
//!
//! <div class="warning">
//!
//! **This has not been security-audited.** No cryptographer has reviewed the
//! handshake, the key schedule or the replay window, and none is going to:
//! [D74](https://github.com/YounghyeonPark/fectp/blob/main/docs/DECISIONS.md)
//! records that decision and what was done instead. This crate is
//! `#![forbid(unsafe_code)]` and is cross-validated against
//! [`snow`](https://docs.rs/snow) in both handshake roles, but neither of
//! those is a review of whether the construction is right. Use it where being
//! wrong is survivable.
//!
//! </div>
//!
//! This crate deliberately contains no transport implementation and no entropy
//! coder. The typed transforms are here — delta, zigzag, varint, transpose —
//! because they are integer arithmetic with no allocator behind them; what is
//! supplied from outside is the socket and Zstandard, so that the same core
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
pub use keys::{Keypair, PublicKey, StaticKey, ANONYMOUS, DHLEN};
pub use reliability::{Ack, DedupWindow, Due, MessageId, RetransmitQueue};
pub use session::{
    preshared_key, Capabilities, Initiator, Responder, ResumeInitiator, ResumeResponder,
    ResumptionTicket, Session,
};
pub use transport::Transport;

#[cfg(feature = "std")]
extern crate std;
