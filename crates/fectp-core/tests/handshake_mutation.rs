//! Real handshake frames, mutated, fed back to the reader that would have
//! accepted the original.
//!
//! `malformed_input.rs` throws arbitrary bytes at these readers already. What
//! it cannot do is get anywhere: a random hundred bytes fails the header check
//! and stops, so every state past that check goes unvisited no matter how many
//! cases run. The way in is to start from a frame that *is* valid and break it.
//!
//! Two properties, and the second is the one worth having:
//!
//! 1. No input panics. A stranger reaches these readers with no authentication
//!    of any kind, so a panic here is a remote abort.
//! 2. **No mutated frame is accepted, except where the bytes are ignored.**
//!    Message 1's header *is* the Noise prologue, so all fourteen of its bytes
//!    are bound into the transcript and changing any of them must make the
//!    frame fail to open. Message 2's header is not: an initiator compares the
//!    frame type and session identifier against what it is expecting, and the
//!    flag byte and the eight sequence bytes are neither compared nor
//!    authenticated. Mutating those is accepted, and this pins that rather than
//!    asserting it away.
//!
//! The second half of (2) is the first thing these tests found, by failing.
//! The property as first written — "every byte is either ciphertext or
//! prologue" — is true of message 1 and false of message 2, and the difference
//! is not an oversight: the responder has no prologue to offer that the
//! initiator does not already have. Those nine bytes are read nowhere on the
//! handshake path; the only code that reads `flags` or `sequence` is
//! `Session::open`, where the whole header is the AEAD's associated data.
//!
//! A coverage-guided fuzzer would do better at (1): it follows the branches it
//! discovers, and this only shakes a known-good frame. `fuzz/` holds targets
//! for one, and `docs/formal/README.md` says where they run.

use proptest::prelude::*;

use fectp_core::keys::Keypair;
use fectp_core::session::{Capabilities, Initiator, ResumeInitiator, ResumeResponder, Responder, INITIATOR_OVERHEAD, RESPONDER_OVERHEAD};
use rand_core::OsRng;

/// Fixed secrets, so a shrunk counterexample is reproducible from its seed.
const INITIATOR_SECRET: [u8; 32] = [0x11; 32];
const RESPONDER_SECRET: [u8; 32] = [0x22; 32];
const SESSION_ID: u32 = 0x5eed_face;
const ZERO_RTT: &[u8] = b"a reading sent with the handshake";

fn caps() -> Capabilities {
    Capabilities::minimal(1200)
}

/// A genuine message 1, and the responder that would accept it.
fn opening_frame() -> Vec<u8> {
    let mut initiator = Initiator::new(
        Keypair::from_secret(INITIATOR_SECRET),
        *Keypair::from_secret(RESPONDER_SECRET).public(),
        SESSION_ID,
        caps(),
    )
    .expect("initiator");
    let mut frame = vec![0u8; INITIATOR_OVERHEAD + ZERO_RTT.len()];
    let n = initiator
        .write_init(&mut OsRng, ZERO_RTT, &mut frame)
        .expect("message 1");
    frame.truncate(n);
    frame
}

/// A genuine message 2, and the initiator that is waiting for it.
fn reply_frame() -> (Initiator, Vec<u8>) {
    let mut initiator = Initiator::new(
        Keypair::from_secret(INITIATOR_SECRET),
        *Keypair::from_secret(RESPONDER_SECRET).public(),
        SESSION_ID,
        caps(),
    )
    .expect("initiator");
    let mut msg1 = vec![0u8; INITIATOR_OVERHEAD + ZERO_RTT.len()];
    let n = initiator
        .write_init(&mut OsRng, ZERO_RTT, &mut msg1)
        .expect("message 1");

    let mut responder = Responder::new(Keypair::from_secret(RESPONDER_SECRET), caps());
    let mut staging = vec![0u8; msg1.len()];
    responder
        .read_init(&msg1[..n], &mut staging)
        .expect("read message 1");

    let mut msg2 = vec![0u8; RESPONDER_OVERHEAD + 32];
    let (_, n2) = responder
        .write_response(&mut OsRng, b"and the reply", &mut msg2)
        .expect("message 2");
    msg2.truncate(n2);
    (initiator, msg2)
}

/// How a frame is broken. Each arm is a different way for bytes to arrive
/// wrong, and the cheap ones are the ones an attacker actually has.
#[derive(Debug, Clone)]
enum Mutation {
    /// One byte replaced. The single-bit case a tampering attacker starts with.
    Set { at: usize, to: u8 },
    /// Cut short. A truncated datagram, or a length field the sender lied about.
    Truncate { to: usize },
    /// Bytes appended. A parser that trusts a length would read them.
    Extend { with: Vec<u8> },
    /// Two bytes exchanged. Catches a parser that sums or sorts where it
    /// should compare in order.
    Swap { a: usize, b: usize },
}

/// Builds one mutation from plain proptest inputs.
///
/// The indices are taken modulo the frame's length rather than generated
/// against it, because the length is not known until the frame is built and a
/// strategy that depended on it would have to be built per case — which
/// defeats shrinking, and shrinking is how a counterexample here becomes
/// readable.
fn mutation(kind: u8, at: usize, to: u8, other: usize, extra: Vec<u8>, len: usize) -> Mutation {
    match kind % 4 {
        0 => Mutation::Set { at: at % len, to },
        1 => Mutation::Truncate { to: at % len },
        2 => Mutation::Extend { with: extra },
        _ => Mutation::Swap {
            a: at % len,
            b: other % len,
        },
    }
}

/// Header bytes a handshake reply neither compares nor authenticates.
///
/// Byte 1 is the flags and bytes 6 through 13 are the sequence number, which a
/// handshake frame leaves at zero. Message 1 has no such bytes — its header is
/// the prologue — so this applies only to the reply.
fn ignored_in_a_reply(index: usize) -> bool {
    index == 1 || (6..14).contains(&index)
}

/// Whether two frames differ only where a reply's header is ignored.
///
/// Comparing the bytes rather than reasoning about the mutation: a swap of two
/// equal bytes changes nothing, and a swap that crosses the boundary changes
/// something. The comparison gets both right without a case for either.
fn only_ignored_bytes_differ(original: &[u8], broken: &[u8]) -> bool {
    original.len() == broken.len()
        && original
            .iter()
            .zip(broken)
            .enumerate()
            .all(|(i, (a, b))| a == b || ignored_in_a_reply(i))
}

fn apply(frame: &[u8], mutation: &Mutation) -> Vec<u8> {
    let mut out = frame.to_vec();
    match mutation {
        Mutation::Set { at, to } => out[*at] = *to,
        Mutation::Truncate { to } => out.truncate(*to),
        Mutation::Extend { with } => out.extend_from_slice(with),
        Mutation::Swap { a, b } => out.swap(*a, *b),
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// A broken message 1 is refused, and refusing it does not panic.
    #[test]
    fn a_mutated_opening_frame_is_never_accepted(
        kind in any::<u8>(),
        at in any::<usize>(),
        to in any::<u8>(),
        other in any::<usize>(),
        extra in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let frame = opening_frame();
        let mutation = mutation(kind, at, to, other, extra, frame.len());
        let broken = apply(&frame, &mutation);

        let mut responder = Responder::new(Keypair::from_secret(RESPONDER_SECRET), caps());
        let mut out = vec![0u8; broken.len() + 256];
        let accepted = responder.read_init(&broken, &mut out).is_ok();

        prop_assert!(
            !accepted || broken == frame,
            "a mutated opening frame was accepted: {mutation:?}"
        );
    }

    /// A broken message 2 is refused by the initiator that was waiting for it.
    #[test]
    fn a_mutated_reply_is_never_accepted(
        kind in any::<u8>(),
        at in any::<usize>(),
        to in any::<u8>(),
        other in any::<usize>(),
        extra in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let (initiator, frame) = reply_frame();
        let mutation = mutation(kind, at, to, other, extra, frame.len());
        let broken = apply(&frame, &mutation);

        let mut out = vec![0u8; broken.len() + 256];
        let accepted = initiator.read_response(&broken, &mut out).is_ok();

        prop_assert!(
            !accepted || only_ignored_bytes_differ(&frame, &broken),
            "a mutated reply was accepted, and the change was not confined to              the flag and sequence bytes an initiator ignores: {mutation:?}"
        );
    }

    /// A broken resumption request is refused.
    ///
    /// The ticket identifier travels in the clear at a fixed offset, so this
    /// reaches a parser that runs on a stranger's bytes before any key has
    /// been chosen — the surface D73 modelled, approached from the other side.
    #[test]
    fn a_mutated_resumption_request_is_never_accepted(
        kind in any::<u8>(),
        at in any::<usize>(),
        to in any::<u8>(),
        other in any::<usize>(),
        extra in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let ticket = fectp_core::session::preshared_key(b"a configured secret");
        let mut initiator =
            ResumeInitiator::new(ticket.clone(), fectp_core::ANONYMOUS, SESSION_ID, caps())
                .expect("resume initiator");
        let mut frame = vec![0u8; ResumeInitiator::OVERHEAD + ZERO_RTT.len()];
        let n = initiator
            .write_init(&mut OsRng, ZERO_RTT, &mut frame)
            .expect("resumption request");
        frame.truncate(n);

        let mutation = mutation(kind, at, to, other, extra, frame.len());
        let broken = apply(&frame, &mutation);

        // Reading the identifier out of unchecked bytes is itself a parse, and
        // it happens first. Its only job here is not to panic.
        let _ = ResumeResponder::ticket_id(&broken);

        let mut responder = ResumeResponder::new(caps(), fectp_core::ANONYMOUS);
        let mut out = vec![0u8; broken.len() + 256];
        let accepted = responder.read_init(&ticket, &broken, &mut out).is_ok();

        prop_assert!(
            !accepted || broken == frame,
            "a mutated resumption request was accepted: {mutation:?}"
        );
    }
}

/// Exactly which header bytes of a reply an initiator does not authenticate.
///
/// Pinned in one place, with the numbers, because an attacker on the path can
/// change these and the handshake still completes. That costs nothing today —
/// nothing on this path reads them — and "nothing reads them" is what this
/// guards. A change that gave the flag byte a meaning during a handshake would
/// make this a real malleability and would fail here first.
///
/// The reply has no prologue of its own: message 1's header is the Noise
/// prologue for both peers, and there is nothing the responder could bind that
/// the initiator does not already hold.
#[test]
fn a_reply_does_not_authenticate_its_sequence_or_its_known_flag_bits() {
    // Flipping every bit of a byte. The session identifier and the version and
    // frame type are compared, so those refuse; the sequence is read nowhere.
    let mut flipped_and_accepted = Vec::new();
    for index in 0..14 {
        let (initiator, frame) = reply_frame();
        let mut broken = frame.clone();
        broken[index] ^= 0xff;
        let mut out = vec![0u8; broken.len() + 256];
        if initiator.read_response(&broken, &mut out).is_ok() {
            flipped_and_accepted.push(index);
        }
    }
    assert_eq!(
        flipped_and_accepted,
        vec![6, 7, 8, 9, 10, 11, 12, 13],
        "the set of header bytes a reply leaves unauthenticated changed"
    );

    // Byte 1 is the flags, and it is absent above only because flipping every
    // bit sets bits `Header::decode` does not know — which it refuses for any
    // frame, handshake or not. Within the known mask it is unauthenticated
    // like the sequence is.
    let known = fectp_core::frame::FLAG_COMPRESSED
        | fectp_core::frame::FLAG_RELIABLE
        | fectp_core::frame::FLAG_PADDED
        | fectp_core::frame::FLAG_FRAGMENT;
    let mut flags_accepted = Vec::new();
    for value in 0..=known {
        if value & !known != 0 {
            continue;
        }
        let (initiator, frame) = reply_frame();
        let mut broken = frame.clone();
        broken[1] = value;
        let mut out = vec![0u8; broken.len() + 256];
        if initiator.read_response(&broken, &mut out).is_ok() {
            flags_accepted.push(value);
        }
    }
    assert_eq!(
        flags_accepted.len(),
        usize::from(known) + 1,
        "every known flag combination should be accepted on a reply, since          nothing on the handshake path reads them; accepted: {flags_accepted:?}"
    );
}
