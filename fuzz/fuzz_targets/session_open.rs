//! Arbitrary bytes into `Session::open`, on an established session.
//!
//! Every datagram that reaches a live session comes through here, and most of
//! them from whoever felt like sending one. `malformed_input.rs` covers this
//! with random bytes and with single-bit mutations of real frames; what it
//! cannot do is follow coverage into the paths a *structured* wrong frame
//! reaches — a plausible header with an implausible sequence, a fragment
//! descriptor that parses and then does not add up, a reliable frame whose
//! identifier is in the plaintext it never gets to read.
//!
//! `open` decrypts in place, so the input is copied first: the fuzzer owns its
//! buffer and a target that scribbled on it would be reporting its own bug.

#![no_main]

use libfuzzer_sys::fuzz_target;

use fectp_core::keys::Keypair;
use fectp_core::session::{Capabilities, Initiator, Responder, INITIATOR_OVERHEAD, RESPONDER_OVERHEAD};
use rand_core::OsRng;

/// A settled pair, built once per input.
///
/// Rebuilding the handshake every time costs two X25519 operations per case
/// and is what makes this the slowest of the four. It buys independence: a
/// session that carried state from the previous input would make a finding
/// depend on the order the fuzzer happened to try things in.
fn pair() -> Option<(fectp_core::Session, fectp_core::Session)> {
    let server_key = Keypair::from_secret([0x22; 32]);
    let server_public = *server_key.public();
    let client_key = Keypair::from_secret([0x11; 32]);

    let mut initiator = Initiator::new(
        client_key,
        server_public,
        0x5eed_face,
        Capabilities::minimal(1200),
    )
    .ok()?;
    let mut responder = Responder::new(server_key, Capabilities::minimal(1200));

    let mut msg1 = vec![0u8; INITIATOR_OVERHEAD + 64];
    let n = initiator.write_init(&mut OsRng, &[], &mut msg1).ok()?;
    let mut staging = vec![0u8; msg1.len()];
    responder.read_init(&msg1[..n], &mut staging).ok()?;

    let mut msg2 = vec![0u8; RESPONDER_OVERHEAD + 64];
    let (server, n2) = responder.write_response(&mut OsRng, &[], &mut msg2).ok()?;
    let mut reply = vec![0u8; msg2.len()];
    let (client, _) = initiator.read_response(&msg2[..n2], &mut reply).ok()?;
    Some((client, server))
}

fuzz_target!(|data: &[u8]| {
    let Some((_client, mut server)) = pair() else {
        return;
    };
    let mut frame = data.to_vec();
    let _ = server.open(&mut frame);
});
