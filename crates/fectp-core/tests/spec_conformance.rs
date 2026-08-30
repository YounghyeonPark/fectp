//! Pins the constants and byte layouts that `docs/SPEC.md` states normatively.
//!
//! A specification that drifts from the implementation is worse than none: an
//! independent implementation written against it would fail to interoperate,
//! and nothing would catch it. Every value here is quoted from the spec, so
//! changing the wire format without updating the document breaks this file.
//!
//! Section numbers refer to `docs/SPEC.md`.

use fectp_core::codec::{
    CodecHeader, Entropy, Transform, CODEC_HEADER_LEN, CODEC_I16_DELTA, CODEC_I32_DELTA,
    CODEC_TRANSPOSE, CODEC_ZSTD, MAX_ORIGINAL_LEN,
};
use fectp_core::frame::{
    FrameType, Header, FLAG_COMPRESSED, FLAG_FRAGMENT, FLAG_PADDED, FLAG_RELIABLE, HEADER_LEN, VERSION,
};
use fectp_core::keys::DHLEN;
use fectp_core::plain::{
    PlainInitiator, PlainResponder, PLAIN_DATA_OVERHEAD, PLAIN_HANDSHAKE_OVERHEAD,
};
use fectp_core::reliability::{Ack, ACK_BLOCK_LEN, ACK_WINDOW, MESSAGE_ID_LEN};
use fectp_core::noise::{
    HASHLEN, KEYLEN, MSG1_OVERHEAD, MSG2_OVERHEAD, PROTOCOL_NAME, PSK_LEN,
    RESUME_MSG_OVERHEAD, RESUME_PROTOCOL_NAME, TAGLEN,
};
use fectp_core::session::{
    Capabilities, Initiator, ResumeInitiator, ResumeResponder, Responder, ResumptionTicket,
    CAPS_LEN, CAP_RELIABLE, CAP_ZSTD, DATA_OVERHEAD, PAD_BLOCK, REPLAY_WINDOW, TICKET_ID_LEN,
};

/// SPEC §2 — cipher suite sizes.
#[test]
fn suite_constants() {
    assert_eq!(DHLEN, 32);
    assert_eq!(KEYLEN, 32);
    assert_eq!(HASHLEN, 32);
    assert_eq!(TAGLEN, 16);
}

/// SPEC §2.1 — the protocol name, byte for byte.
#[test]
fn protocol_name_is_exact() {
    assert_eq!(PROTOCOL_NAME, b"Noise_IK_25519_ChaChaPoly_BLAKE2s");
    assert_eq!(
        PROTOCOL_NAME.len(),
        33,
        "the name must exceed HASHLEN so it is hashed rather than zero-padded"
    );
    assert!(PROTOCOL_NAME.len() > HASHLEN);
}

/// SPEC §3 — header layout, field by field.
#[test]
fn header_layout_matches_the_specified_offsets() {
    assert_eq!(HEADER_LEN, 14);
    assert_eq!(VERSION, 1);

    let mut header = Header::new(FrameType::Data, 0x1122_3344);
    header.flags = FLAG_COMPRESSED | FLAG_PADDED;
    header.sequence = 0x8877_6655_4433_2211;

    let mut buf = [0u8; HEADER_LEN];
    header.encode(&mut buf).expect("encode");

    // byte 0: version in the high nibble, type in the low nibble
    assert_eq!(buf[0] >> 4, VERSION);
    assert_eq!(buf[0] & 0x0f, 3, "Data is type 3");
    // byte 1: flags
    assert_eq!(buf[1], 0b0000_0101);
    // bytes 2..6: session_id, little-endian
    assert_eq!(&buf[2..6], &[0x44, 0x33, 0x22, 0x11]);
    // bytes 6..14: sequence, little-endian
    assert_eq!(
        &buf[6..14],
        &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );
}

/// SPEC §3.1 — frame type ids.
#[test]
fn frame_type_ids() {
    for (frame_type, id) in [
        (FrameType::HandshakeInit, 1u8),
        (FrameType::HandshakeResponse, 2),
        (FrameType::Data, 3),
        (FrameType::Close, 4),
        (FrameType::Ack, 5),
        (FrameType::ResumeInit, 6),
        (FrameType::ResumeResponse, 7),
        (FrameType::PlainInit, 10),
        (FrameType::PlainResponse, 11),
        (FrameType::PlainData, 12),
        (FrameType::PlainAck, 13),
    ] {
        let mut buf = [0u8; HEADER_LEN];
        Header::new(frame_type, 0).encode(&mut buf).expect("encode");
        assert_eq!(buf[0] & 0x0f, id, "{frame_type:?}");
        assert_eq!(
            Header::decode(&buf).expect("decode").frame_type,
            frame_type
        );
    }

    // Every id the specification does not define must be rejected. Checking
    // the whole 4-bit space rather than a sample means a new frame type cannot
    // be added without this test — and therefore the specification — noticing.
    const DEFINED: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13];
    for id in 0..16u8 {
        let mut buf = [0u8; HEADER_LEN];
        Header::new(FrameType::Data, 0).encode(&mut buf).expect("encode");
        buf[0] = (VERSION << 4) | id;
        let accepted = Header::decode(&buf).is_ok();
        assert_eq!(
            accepted,
            DEFINED.contains(&id),
            "frame type {id}: implementation and SPEC.md §3.1 disagree"
        );
    }
}

/// SPEC §3.2 — flag bit values, and rejection of the reserved ones.
#[test]
fn flag_bits() {
    assert_eq!(FLAG_COMPRESSED, 0x01);
    assert_eq!(FLAG_RELIABLE, 0x02);
    assert_eq!(FLAG_PADDED, 0x04);
    assert_eq!(FLAG_FRAGMENT, 0x08);

    for reserved in [0x10u8, 0x20, 0x40, 0x80] {
        let mut buf = [0u8; HEADER_LEN];
        Header::new(FrameType::Data, 0).encode(&mut buf).expect("encode");
        buf[1] = reserved;
        assert!(
            Header::decode(&buf).is_err(),
            "reserved flag {reserved:#04x} must be rejected"
        );
    }
}

/// SPEC §4.3 — capability block layout.
#[test]
fn capability_block_layout() {
    assert_eq!(CAPS_LEN, 8);
    assert_eq!(CAP_ZSTD, 0x01);
    assert_eq!(CAP_RELIABLE, 0x02);

    assert_eq!(CODEC_ZSTD, 0x01);
    assert_eq!(CODEC_I16_DELTA, 0x02);
    assert_eq!(CODEC_I32_DELTA, 0x04);
    assert_eq!(CODEC_TRANSPOSE, 0x08);

    assert_eq!(Transform::I16Delta.capability(), CODEC_I16_DELTA);
    assert_eq!(Transform::I32Delta.capability(), CODEC_I32_DELTA);
    assert_eq!(Transform::ByteTranspose.capability(), CODEC_TRANSPOSE);
    assert_eq!(Entropy::Zstd.capability(), CODEC_ZSTD);
}

/// SPEC §4.4, §4.5 — handshake message sizes.
#[test]
fn handshake_frame_sizes() {
    // Noise overheads: e(32) + encrypted s(32+16) + payload tag(16).
    assert_eq!(MSG1_OVERHEAD, 96);
    // e(32) + payload tag(16).
    assert_eq!(MSG2_OVERHEAD, 48);

    // Minimum valid frames include the mandatory capability block.
    assert_eq!(Initiator::OVERHEAD, 118, "14 header + 96 Noise + 8 caps");
    assert_eq!(Responder::OVERHEAD, 70, "14 header + 48 Noise + 8 caps");
    assert_eq!(Initiator::OVERHEAD, HEADER_LEN + MSG1_OVERHEAD + CAPS_LEN);
    assert_eq!(Responder::OVERHEAD, HEADER_LEN + MSG2_OVERHEAD + CAPS_LEN);
}

/// SPEC §5.1, §5.3 — replay window and padding block.
#[test]
fn replay_and_padding_constants() {
    assert_eq!(REPLAY_WINDOW, 64);
    assert_eq!(PAD_BLOCK, 64);
}

/// SPEC §5.6 — the fragment descriptor.
#[test]
fn fragment_descriptor_layout() {
    use fectp_core::fragment::{Fragment, FRAGMENT_LEN, MAX_FRAGMENTS};

    assert_eq!(FRAGMENT_LEN, 8);
    assert_eq!(MAX_FRAGMENTS, 4096);

    let fragment = Fragment {
        message: 0x0403_0201,
        index: 0x0605,
        count: 0x0807,
    };
    let mut buf = [0u8; FRAGMENT_LEN];
    fragment.encode(&mut buf).expect("encode");
    assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8], "little-endian, in field order");

    // A receiver sizes a buffer from `count`, so both bounds are normative.
    let mut absurd = [0u8; FRAGMENT_LEN];
    absurd[6..8].copy_from_slice(&(MAX_FRAGMENTS + 1).to_le_bytes());
    assert!(Fragment::decode(&absurd).is_err());
}

/// SPEC §5.5, §5.7 — reliability constants and the acknowledgement block.
#[test]
fn reliability_constants() {
    assert_eq!(ACK_BLOCK_LEN, 12);
    assert_eq!(MESSAGE_ID_LEN, 4);
    assert_eq!(ACK_WINDOW, 64, "minimum acknowledgement and dedup window");

    let ack = Ack {
        highest: 0x1122_3344,
        bitmap: 0x8899_AABB_CCDD_EEFF,
    };
    let mut buf = [0u8; ACK_BLOCK_LEN];
    ack.encode(&mut buf).expect("encode");
    // bytes 0..4: highest, little-endian
    assert_eq!(&buf[..4], &[0x44, 0x33, 0x22, 0x11]);
    // bytes 4..12: bitmap, little-endian
    assert_eq!(
        &buf[4..12],
        &[0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88]
    );
}

/// SPEC §5.5 — a peer must advertise `CAP_RELIABLE` to be sent reliable data.
#[test]
fn reliability_is_advertised() {
    let silent = Capabilities {
        flags: 0,
        max_frame_size: 1200,
        codecs: 0,
    };
    assert!(!silent.supports_reliable());

    let capable = Capabilities {
        flags: CAP_RELIABLE,
        max_frame_size: 1200,
        codecs: 0,
    };
    assert!(capable.supports_reliable());
}

/// SPEC §4.6, §4.7 — resumption constants and ticket derivation.
#[test]
fn resumption_constants() {
    assert_eq!(TICKET_ID_LEN, 8);
    assert_eq!(PSK_LEN, 32);
    assert_eq!(RESUME_MSG_OVERHEAD, 48, "e(32) + payload tag(16)");
    assert_eq!(
        ResumeInitiator::OVERHEAD,
        78,
        "14 header + 8 ticket id + 48 Noise + 8 caps"
    );
    assert_eq!(
        ResumeResponder::OVERHEAD,
        70,
        "14 header + 48 Noise + 8 caps"
    );
    assert_eq!(
        RESUME_PROTOCOL_NAME,
        b"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"
    );
    assert!(RESUME_PROTOCOL_NAME.len() > HASHLEN, "hashed, not zero-padded");
}

/// SPEC §4.6 — the ticket identifier is derived from the key, not assigned.
#[test]
fn ticket_ids_are_derived_from_their_keys() {
    let key = [0x42u8; PSK_LEN];
    let ticket = ResumptionTicket::from_key(key);
    assert_eq!(
        ticket.id(),
        ResumptionTicket::from_key(key).id(),
        "derivation must be deterministic, or a peer could not find the key"
    );
    assert_ne!(
        ticket.id(),
        ResumptionTicket::from_key([0x43u8; PSK_LEN]).id(),
        "different keys must not collide"
    );
    assert_ne!(
        &ticket.id()[..],
        &key[..TICKET_ID_LEN],
        "the public identifier must not expose key bytes"
    );
}

/// SPEC §1.2 — plaintext framing carries no tag, and reuses nothing.
#[test]
fn plaintext_framing_constants() {
    assert_eq!(PLAIN_DATA_OVERHEAD, HEADER_LEN, "no authentication tag");
    assert_eq!(
        DATA_OVERHEAD - PLAIN_DATA_OVERHEAD,
        TAGLEN,
        "the whole difference is the Poly1305 tag"
    );
    assert_eq!(PLAIN_HANDSHAKE_OVERHEAD, HEADER_LEN + CAPS_LEN);
    assert_eq!(PlainInitiator::OVERHEAD, 22, "14 header + 8 caps");
    assert_eq!(PlainResponder::OVERHEAD, 22);
}

/// SPEC §1.2 — encrypted and plaintext frame types are disjoint.
#[test]
fn the_two_framings_share_no_type_ids() {
    // This is what makes the mode unnegotiable: neither framing can be
    // mistaken for the other, so there is no downgrade to attempt.
    let encrypted: &[FrameType] = &[
        FrameType::HandshakeInit,
        FrameType::HandshakeResponse,
        FrameType::Data,
        FrameType::Close,
        FrameType::Ack,
        FrameType::ResumeInit,
        FrameType::ResumeResponse,
    ];
    let plain: &[FrameType] = &[
        FrameType::PlainInit,
        FrameType::PlainResponse,
        FrameType::PlainData,
        FrameType::PlainAck,
    ];
    for a in encrypted {
        for b in plain {
            assert_ne!(a, b);
        }
    }
}

/// SPEC §6.1 — codec header layout and id assignments.
#[test]
fn codec_header_layout() {
    assert_eq!(CODEC_HEADER_LEN, 4);
    assert_eq!(MAX_ORIGINAL_LEN, 65535);

    let header = CodecHeader {
        transform: Transform::ByteTranspose,
        entropy: Entropy::Zstd,
        param: 0xAB,
        original_len: 0x1234,
    };
    let mut buf = [0u8; CODEC_HEADER_LEN];
    header.encode(&mut buf).expect("encode");

    // byte 0: transform in the low nibble, entropy in the high nibble
    assert_eq!(buf[0] & 0x0f, 3, "ByteTranspose is transform 3");
    assert_eq!(buf[0] >> 4, 1, "Zstd is entropy 1");
    // byte 1: param
    assert_eq!(buf[1], 0xAB);
    // bytes 2..4: original_len, little-endian
    assert_eq!(&buf[2..4], &[0x34, 0x12]);
}

/// SPEC §6.2 — transform id assignments.
#[test]
fn transform_ids() {
    for (transform, id) in [
        (Transform::None, 0u8),
        (Transform::I16Delta, 1),
        (Transform::I32Delta, 2),
        (Transform::ByteTranspose, 3),
    ] {
        let mut buf = [0u8; CODEC_HEADER_LEN];
        CodecHeader {
            transform,
            entropy: Entropy::None,
            param: 0,
            original_len: 0,
        }
        .encode(&mut buf)
        .expect("encode");
        assert_eq!(buf[0] & 0x0f, id, "{transform:?}");
    }
}

/// SPEC §6.4 — a peer advertising no codecs receives uncoded payloads.
#[test]
fn a_peer_advertising_no_codecs_is_representable() {
    let none = Capabilities {
        flags: 0,
        max_frame_size: 1200,
        codecs: 0,
    };
    assert!(!none.accepts_compression());
    assert!(!none.supports_codecs(CODEC_I16_DELTA));

    // The minimal profile advertises the core transforms but not Zstandard,
    // which is what lets a constrained peer still receive coded payloads.
    let minimal = Capabilities::minimal(256);
    assert!(!minimal.accepts_compression());
    assert!(minimal.supports_codecs(CODEC_I16_DELTA | CODEC_I32_DELTA | CODEC_TRANSPOSE));
}
