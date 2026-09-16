//! Arbitrary bytes into `Responder::read_init`.
//!
//! The first thing a stranger reaches. Nothing has authenticated this frame
//! when it arrives: anyone who can address the socket can send anything, and
//! everything the responder does before the AEAD tag verifies — decoding the
//! header, sizing the Noise message, deriving a key from a public key it was
//! handed — happens on bytes it has no reason to trust.
//!
//! `malformed_input.rs` already throws random bytes at the layouts below this
//! one. What that cannot do is *get anywhere*: a random 100 bytes fails the
//! header check and stops, so the states past it are never entered. This is
//! seeded with a real opening frame and mutates from there, which is the only
//! way in.
//!
//! The property is the weak one on purpose — no panic, no hang, no
//! out-of-bounds. A frame that decrypts is not expected and would be a finding
//! of a different kind; a frame that aborts the process is the one a stranger
//! gets to cause.

#![no_main]

use libfuzzer_sys::fuzz_target;

use fectp_core::keys::Keypair;
use fectp_core::session::{Capabilities, Responder};

fuzz_target!(|data: &[u8]| {
    // A fixed identity, so a run is reproducible from its input alone.
    let responder_key = Keypair::from_secret([0x22; 32]);
    let mut responder = Responder::new(responder_key, Capabilities::minimal(1200));

    // Generous, so that a refusal is the parser's decision and not the
    // buffer's. A buffer too small is its own error and is covered by tests.
    let mut out = vec![0u8; data.len() + 4096];
    let _ = responder.read_init(data, &mut out);
});
