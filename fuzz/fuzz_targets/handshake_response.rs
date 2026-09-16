//! Arbitrary bytes into `Initiator::read_response`.
//!
//! The other unauthenticated read, and the one with the shorter reach: an
//! attacker has to guess a 32-bit session identifier *and* have the frame
//! arrive from the address the initiator is talking to. Fuzzed anyway, because
//! "hard to reach" is a statement about the network and not about the parser,
//! and because this read consumes the handshake state either way — a fault
//! here is a fault on a path the caller cannot retry out of.

#![no_main]

use libfuzzer_sys::fuzz_target;

use fectp_core::keys::Keypair;
use fectp_core::session::{Capabilities, Initiator};

fuzz_target!(|data: &[u8]| {
    let initiator_key = Keypair::from_secret([0x11; 32]);
    let responder_public = *Keypair::from_secret([0x22; 32]).public();

    // The session identifier the vectors use, so a seed corpus built from a
    // real exchange lines up with what this initiator expects.
    let Ok(initiator) = Initiator::new(
        initiator_key,
        responder_public,
        0x5eed_face,
        Capabilities::minimal(1200),
    ) else {
        return;
    };

    let mut out = vec![0u8; data.len() + 4096];
    let _ = initiator.read_response(data, &mut out);
});
