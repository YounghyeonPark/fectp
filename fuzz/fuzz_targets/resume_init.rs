//! Arbitrary bytes into `ResumeResponder::read_init`, and into the ticket
//! lookup that precedes it.
//!
//! This is the surface D73 modelled, reached the way an attacker reaches it.
//! `ticket_id` runs on a frame nothing has checked — a responder has to read
//! eight bytes out of a stranger's datagram to know which key to even try —
//! so it is fuzzed here together with the read it selects a key for.

#![no_main]

use libfuzzer_sys::fuzz_target;

use fectp_core::session::{preshared_key, Capabilities, ResumeResponder};
use fectp_core::ANONYMOUS;

fuzz_target!(|data: &[u8]| {
    // The identifier is read before any key is chosen, so it is the first
    // thing an attacker's bytes reach.
    let _ = ResumeResponder::ticket_id(data);

    let ticket = preshared_key(b"a secret both ends were given out of band");
    let mut responder = ResumeResponder::new(Capabilities::minimal(1200), ANONYMOUS);
    let mut out = vec![0u8; data.len() + 4096];
    let _ = responder.read_init(&ticket, data, &mut out);
});
