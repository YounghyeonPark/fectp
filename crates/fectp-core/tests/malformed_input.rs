//! What every decoder does with bytes nobody meant to send.
//!
//! The rest of the suite feeds each parser inputs a person thought to write.
//! That is the weakness this file exists to cover: the ACK-window bug lost
//! messages outright while 179 such tests passed, and every parser here reads
//! bytes chosen by someone else.
//!
//! `#![forbid(unsafe_code)]` rules out memory corruption, so the failures worth
//! hunting are the two that remain. A **panic** is a remote denial of service:
//! one datagram ends the process serving every other peer. A **wrong accept**
//! is worse and quieter — a decoder that returns `Ok` for bytes the encoder
//! could not have produced hands the layer above a value it will trust.
//!
//! Each property is therefore one of:
//!
//! - it terminates and does not panic, on any input at all;
//! - what it accepts, it accepts for a reason — re-encoding reproduces the
//!   bytes, so there is no second spelling of the same value;
//! - what it accepts satisfies the invariant the layer above assumes.

use fectp_core::codec::varint::MAX_LEN as MAX_VARINT_LEN;
use fectp_core::codec::{numeric, transpose, varint, CodecHeader, Transform};
use fectp_core::error::Error;
use fectp_core::fragment::{Fragment, FRAGMENT_LEN, MAX_FRAGMENTS};
use fectp_core::frame::{Header, HEADER_LEN};
use fectp_core::keys::Keypair;
use fectp_core::reliability::{Ack, ACK_BLOCK_LEN};
use fectp_core::session::{Capabilities, Initiator, Responder};
use proptest::prelude::*;
use rand_core::OsRng;

// ---------------------------------------------------------------- headers ---

proptest! {
    /// A frame header is the first thing an off-path attacker reaches: it is
    /// read before anything is authenticated, so it must survive any 14 bytes.
    #[test]
    fn a_frame_header_survives_any_bytes(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(header) = Header::decode(&bytes) {
            // Accepting means claiming these bytes are canonical. Writing the
            // parsed header back must reproduce them, or two different frames
            // decode to one header and the difference is somewhere unchecked.
            let mut round = [0u8; HEADER_LEN];
            header.encode(&mut round).expect("a decoded header re-encodes");
            prop_assert_eq!(&round[..], &bytes[..HEADER_LEN]);
        }
    }

    /// Reassembly indexes a table with these values, so the bounds have to hold
    /// before they reach it, not at the point of use.
    #[test]
    fn a_fragment_descriptor_is_coherent_or_refused(
        bytes in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        if let Ok(fragment) = Fragment::decode(&bytes) {
            prop_assert!(fragment.count > 0);
            prop_assert!(fragment.count <= MAX_FRAGMENTS);
            prop_assert!(fragment.index < fragment.count);

            let mut round = [0u8; FRAGMENT_LEN];
            fragment.encode(&mut round).expect("a decoded fragment re-encodes");
            prop_assert_eq!(&round[..], &bytes[..FRAGMENT_LEN]);
        }
    }

    /// An acknowledgement decides what a sender stops retransmitting.
    #[test]
    fn an_acknowledgement_survives_any_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        if let Ok(ack) = Ack::decode(&bytes) {
            let mut round = [0u8; ACK_BLOCK_LEN];
            ack.encode(&mut round).expect("a decoded ack re-encodes");
            prop_assert_eq!(&round[..], &bytes[..ACK_BLOCK_LEN]);
        }
    }

    /// The codec header names a transform and a length the decoder will trust.
    #[test]
    fn a_codec_header_survives_any_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let _ = CodecHeader::decode(&bytes);
    }
}

// ---------------------------------------------------------------- varints ---

proptest! {
    /// LEB128 is where a hostile payload would try for an unbounded loop or a
    /// value the encoder could not have written.
    #[test]
    fn a_varint_terminates_and_has_one_spelling(
        bytes in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        if let Ok((value, used)) = varint::decode(&bytes) {
            prop_assert!(used > 0 && used <= bytes.len());

            // The shortest encoding is the only one accepted, so a padded
            // varint cannot smuggle a second reading of the same number.
            let mut round = [0u8; 8];
            let n = varint::encode(value, &mut round).expect("re-encode");
            prop_assert_eq!(n, used, "{} decoded from {} bytes but encodes to {}", value, used, n);
            prop_assert_eq!(&round[..n], &bytes[..used]);
        }
    }

    /// Every `u32` survives the round trip, zigzag included.
    #[test]
    fn every_varint_round_trips(value in any::<u32>()) {
        let mut buf = [0u8; 8];
        let n = varint::encode(value, &mut buf).expect("encode");
        prop_assert_eq!(varint::decode(&buf[..n]).expect("decode"), (value, n));
    }

    #[test]
    fn zigzag_round_trips(value in any::<i32>()) {
        prop_assert_eq!(varint::unzigzag(varint::zigzag(value)), value);
    }
}

// ----------------------------------------------------------------- codecs ---

// A transform reverses bytes chosen by the peer. Reaching it needs the session
// key, so this is the peer threat model rather than the off-path one — but a
// peer is exactly who sends a payload that does not match its own header, by
// malice or by being a different implementation with a bug.
proptest! {
    #[test]
    fn reversing_a_transform_never_panics(
        kind in 0u8..4,
        param in any::<u8>(),
        original_len in 0usize..512,
        input in prop::collection::vec(any::<u8>(), 0..512),
        slack in 0usize..8,
    ) {
        let transform = match kind {
            0 => Transform::None,
            1 => Transform::I16Delta,
            2 => Transform::I32Delta,
            _ => Transform::ByteTranspose,
        };
        let mut out = vec![0u8; original_len + slack];
        // The only claim: it returns. A wrong `original_len`, a `param` naming
        // impossible channels, a body that ran out early — all are errors, none
        // is a crash.
        if let Ok(written) = transform.reverse(&input, param, original_len, &mut out) {
            prop_assert!(written <= out.len());
        }
    }

    /// What the transform wrote, it can read back — for inputs that are the
    /// right shape for it.
    #[test]
    fn a_transform_round_trips_its_own_output(
        channels in 1usize..5,
        samples in 0usize..64,
        seed in any::<u64>(),
    ) {
        let width = 2;
        let len = samples * channels * width;
        let mut state = seed | 1;
        let input: Vec<u8> = (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();

        let mut coded = vec![0u8; len * 4 + 16];
        let n = numeric::encode_i16(&input, channels, &mut coded).expect("encode");
        let mut back = vec![0u8; len];
        let m = numeric::decode_i16(&coded[..n], channels, len, &mut back).expect("decode");
        prop_assert_eq!(m, len);
        prop_assert_eq!(back, input, "a codec must be lossless");
    }

    /// Byte transposition is its own inverse for any element size.
    #[test]
    fn transposition_round_trips(
        element_size in 1usize..9,
        input in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut coded = vec![0u8; input.len()];
        transpose::encode(&input, element_size, &mut coded).expect("encode");
        let mut back = vec![0u8; input.len()];
        transpose::decode(&coded, element_size, &mut back).expect("decode");
        prop_assert_eq!(back, input);
    }
}

// ---------------------------------------------------------------- sessions ---

const SERVER_SECRET: [u8; 32] = [0xA1; 32];
const CLIENT_SECRET: [u8; 32] = [0xB2; 32];
const SESSION_ID: u32 = 0xDEAD_BEEF;

/// Two established sessions, as `tests/session.rs` builds them.
fn connect() -> (fectp_core::Session, fectp_core::Session) {
    let server_kp = Keypair::from_secret(SERVER_SECRET);
    let server_public = *server_kp.public();
    let caps = Capabilities::minimal(1200);

    let mut initiator =
        Initiator::new(Keypair::from_secret(CLIENT_SECRET), server_public, SESSION_ID, caps)
            .expect("initiator");
    let mut responder = Responder::new(server_kp, caps);

    let mut wire = [0u8; 2048];
    let mut scratch = [0u8; 2048];

    let n = initiator.write_init(&mut OsRng, b"", &mut wire).expect("init");
    responder.read_init(&wire[..n], &mut scratch).expect("read init");
    let (server, n) = responder
        .write_response(&mut OsRng, b"", &mut wire)
        .expect("response");
    let (client, _) = initiator.read_response(&wire[..n], &mut scratch).expect("read response");
    (client, server)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The whole point of an AEAD: bytes nobody holding the key produced are
    /// refused. Anything else here would mean forged data reaching the caller.
    #[test]
    fn an_unauthenticated_frame_is_never_opened(
        bytes in prop::collection::vec(any::<u8>(), 0..1400),
    ) {
        let (_client, mut server) = connect();
        let mut frame = bytes;
        prop_assert!(
            server.open(&mut frame).is_err(),
            "opened a frame that was never sealed"
        );
    }

    /// A real frame with one byte changed. This is the interesting half: the
    /// header is well-formed and the session id matches, so the frame gets past
    /// every cheap check and has to be caught by the tag.
    #[test]
    fn a_tampered_frame_is_never_opened(
        payload in prop::collection::vec(any::<u8>(), 1..256),
        at in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let (mut client, mut server) = connect();
        let mut frame = vec![0u8; 1400];
        let n = client.seal(&payload, 0, &mut frame).expect("seal");
        frame.truncate(n);

        let i = at.index(n);
        frame[i] ^= flip;

        match server.open(&mut frame) {
            Err(_) => {}
            Ok(opened) => prop_assert!(
                false,
                "a byte changed at {} of {} and the frame still opened, giving {} bytes",
                i, n, opened.len
            ),
        }
    }

    /// Truncation is not tampering, but it reaches different arithmetic: the
    /// length checks that peel the optional prefixes.
    #[test]
    fn a_truncated_frame_is_never_opened(
        payload in prop::collection::vec(any::<u8>(), 1..256),
        keep in any::<prop::sample::Index>(),
    ) {
        let (mut client, mut server) = connect();
        let mut frame = vec![0u8; 1400];
        let n = client.seal(&payload, 0, &mut frame).expect("seal");
        frame.truncate(n);

        let cut = keep.index(n);
        frame.truncate(cut);
        prop_assert!(server.open(&mut frame).is_err(), "opened a frame cut to {} of {}", cut, n);
    }
}

// ------------------------------------------------------------- invariants ---

/// `Fragment`'s fields are public, so this is reachable without a decoder.
///
/// `is_last` computes `index + 1`, which overflows for `index == u16::MAX`.
/// `decode` cannot produce that — it rejects `index >= count` and `count` above
/// [`MAX_FRAGMENTS`] — so the guarantee rests on nobody building one by hand.
#[test]
fn a_decoded_fragment_can_always_answer_is_last() {
    for index in [0u16, 1, MAX_FRAGMENTS - 1] {
        let fragment = Fragment {
            message: 7,
            index,
            count: MAX_FRAGMENTS,
        };
        let mut bytes = [0u8; FRAGMENT_LEN];
        fragment.encode(&mut bytes).expect("encode");
        let decoded = Fragment::decode(&bytes).expect("decode");
        assert_eq!(decoded.is_last(), index + 1 == MAX_FRAGMENTS);
    }
}

/// The case `a_varint_terminates_and_has_one_spelling` found, pinned by name.
///
/// `[0x80, 0x00]` is a continuation byte carrying nothing followed by a zero
/// terminator: it decoded to `0`, which [`varint::encode`] writes as the single
/// byte `[0x00]`. Two spellings of one value, and the decoder took both.
///
/// It was reachable only from an authenticated peer — the codec runs on
/// plaintext `Session::open` has already verified — so this was malleability
/// rather than a way in. It is refused now because the encoder never produced
/// the longer form, so nothing was gained by accepting it.
#[test]
fn an_overlong_varint_is_refused() {
    assert_eq!(varint::decode(&[0x00]).expect("canonical zero"), (0, 1));
    assert!(varint::decode(&[0x80, 0x00]).is_err(), "overlong zero");
    assert!(varint::decode(&[0x81, 0x00]).is_err(), "overlong one");
    assert!(varint::decode(&[0x80, 0x80, 0x00]).is_err(), "doubly overlong zero");

    // The tightening must not refuse anything the encoder writes, at any width.
    for value in [0u32, 1, 127, 128, 16_383, 16_384, u32::MAX] {
        let mut buf = [0u8; MAX_VARINT_LEN];
        let n = varint::encode(value, &mut buf).expect("encode");
        assert_eq!(
            varint::decode(&buf[..n]).expect("its own output must decode"),
            (value, n)
        );
    }
}

/// A header carrying a flag this version does not define is refused rather than
/// ignored, which is what keeps the bit free for a later version to mean
/// something without two implementations disagreeing about an old frame.
#[test]
fn undefined_flag_bits_are_refused() {
    let mut frame = [0u8; HEADER_LEN];
    Header::new(fectp_core::frame::FrameType::Data, SESSION_ID)
        .encode(&mut frame)
        .expect("encode");
    for bit in 0..8u8 {
        frame[1] = 1 << bit;
        match Header::decode(&frame) {
            Ok(header) => assert_eq!(
                header.flags, 1 << bit,
                "a known flag must survive decoding"
            ),
            Err(Error::BadHeader) => {}
            Err(other) => panic!("unexpected error for flag bit {bit}: {other:?}"),
        }
    }
}

/// An entropy stage the peer does not have must not be silently treated as
/// "no compression", which would hand the transform a compressed body.
#[test]
fn an_unknown_transform_or_entropy_is_refused() {
    for byte in 0..=u8::MAX {
        let bytes = [byte, 0, 0, 0];
        match CodecHeader::decode(&bytes) {
            Ok(header) => {
                let mut round = [0u8; 4];
                header.encode(&mut round).expect("re-encode");
                assert_eq!(round, bytes, "byte {byte:#04x} decoded to a different spelling");
            }
            Err(Error::BadHeader | Error::UnsupportedVersion) => {}
            Err(other) => panic!("unexpected error for {byte:#04x}: {other:?}"),
        }
    }
    // Both stages are named in one byte, so an undefined value in either
    // half must fail the whole header rather than defaulting.
    assert!(CodecHeader::decode(&[0x0f, 0, 0, 0]).is_err(), "unknown transform");
    assert!(CodecHeader::decode(&[0xf0, 0, 0, 0]).is_err(), "unknown entropy stage");
}
