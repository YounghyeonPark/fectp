//! Session-layer behaviour: framed handshake, capability negotiation, and the
//! guarantees a datagram transport forces on us (reorder tolerance, replay
//! rejection, tamper detection).

use fectp_core::error::Error;
use fectp_core::frame::{FrameType, Header, FLAG_COMPRESSED, FLAG_PADDED, HEADER_LEN};
use fectp_core::keys::Keypair;
use fectp_core::codec::{CODECS_CORE, CODEC_ZSTD};
use fectp_core::session::{
    Capabilities, Initiator, Responder, CAP_RELIABLE, CAP_ZSTD, DATA_OVERHEAD, PAD_BLOCK,
};
use rand_core::OsRng;

const SERVER_SECRET: [u8; 32] = [0xA1; 32];
const CLIENT_SECRET: [u8; 32] = [0xB2; 32];
const SESSION_ID: u32 = 0xDEAD_BEEF;

fn server_caps() -> Capabilities {
    Capabilities {
        flags: CAP_ZSTD | CAP_RELIABLE,
        max_frame_size: 1200,
        codecs: CODECS_CORE | CODEC_ZSTD,
    }
}

/// A constrained peer: no room for a Zstandard decoder, small frames.
fn mcu_caps() -> Capabilities {
    Capabilities::minimal(256)
}

/// Drives a complete handshake and returns both established sessions.
fn connect(
    client_caps: Capabilities,
    server_caps: Capabilities,
    zero_rtt: &[u8],
) -> (fectp_core::Session, fectp_core::Session, Vec<u8>) {
    let server_kp = Keypair::from_secret(SERVER_SECRET);
    let server_public = *server_kp.public();

    let mut initiator = Initiator::new(
        Keypair::from_secret(CLIENT_SECRET),
        server_public,
        SESSION_ID,
        client_caps,
    )
    .expect("initiator");
    let mut responder = Responder::new(server_kp, server_caps);

    let mut wire = [0u8; 2048];
    let mut scratch = [0u8; 2048];

    let n = initiator
        .write_init(&mut OsRng, zero_rtt, &mut wire)
        .expect("write init");
    let len = responder
        .read_init(&wire[..n], &mut scratch)
        .expect("read init");
    let received_zero_rtt = scratch[..len].to_vec();

    // The server authenticates the client from message 1 alone.
    assert_eq!(
        responder.remote_static(),
        Some(Keypair::from_secret(CLIENT_SECRET).public())
    );

    let (server_session, n) = responder
        .write_response(&mut OsRng, b"", &mut wire)
        .expect("write response");
    let (client_session, len) = initiator
        .read_response(&wire[..n], &mut scratch)
        .expect("read response");
    assert_eq!(len, 0);

    (client_session, server_session, received_zero_rtt)
}

#[test]
fn handshake_carries_zero_rtt_data() {
    let (_client, _server, zero_rtt) = connect(server_caps(), server_caps(), b"first reading: 23.5");
    assert_eq!(
        zero_rtt, b"first reading: 23.5",
        "IK must deliver application data in the very first message"
    );
}

#[test]
fn data_flows_in_both_directions() {
    let (mut client, mut server, _) = connect(server_caps(), server_caps(), b"");
    let mut frame = [0u8; 512];

    let n = client.seal(b"client to server", 0, &mut frame).expect("seal");
    let o = server.open(&mut frame[..n]).expect("open");
    let (header, len) = (o.header, o.len);
    assert_eq!(header.frame_type, FrameType::Data);
    assert_eq!(&frame[HEADER_LEN..HEADER_LEN + len], b"client to server");

    let n = server.seal(b"server to client", 0, &mut frame).expect("seal");
    let len = client.open(&mut frame[..n]).expect("open").len;
    assert_eq!(&frame[HEADER_LEN..HEADER_LEN + len], b"server to client");
}

#[test]
fn capabilities_are_negotiated() {
    // A microcontroller connects to a full server.
    let (client, server, _) = connect(mcu_caps(), server_caps(), b"");

    assert!(
        !server.peer_capabilities().accepts_compression(),
        "the server must learn that the MCU cannot decompress, or it would \
         send frames the MCU cannot decode"
    );
    assert_eq!(server.peer_capabilities().max_frame_size, 256);
    assert!(client.peer_capabilities().accepts_compression());

    // The server's outgoing frames are bounded by what the MCU can receive.
    assert_eq!(server.max_payload(), 256 - HEADER_LEN - 16);
}

#[test]
fn every_header_byte_is_authenticated() {
    let (mut client, mut server, _) = connect(server_caps(), server_caps(), b"");
    let mut original = [0u8; 512];
    let n = client.seal(b"payload", 0, &mut original).expect("seal");

    // Flipping any single bit anywhere in the header must be detected, because
    // the whole header is the AEAD's associated data.
    for byte in 0..HEADER_LEN {
        for bit in 0..8 {
            let mut frame = original;
            frame[byte] ^= 1 << bit;

            let mut fresh_server = connect(server_caps(), server_caps(), b"").1;
            let result = fresh_server.open(&mut frame[..n]);
            assert!(
                result.is_err(),
                "tampering with header byte {byte} bit {bit} went undetected"
            );
        }
    }

    // The untampered frame still opens.
    let mut frame = original;
    assert!(server.open(&mut frame[..n]).is_ok());
}

#[test]
fn payload_tampering_is_detected() {
    let (mut client, mut server, _) = connect(server_caps(), server_caps(), b"");
    let mut frame = [0u8; 512];
    let n = client.seal(b"payload", 0, &mut frame).expect("seal");
    frame[HEADER_LEN] ^= 0x01;
    assert_eq!(server.open(&mut frame[..n]), Err(Error::Decrypt));
}

#[test]
fn reordered_datagrams_are_accepted() {
    let (mut client, mut server, _) = connect(server_caps(), server_caps(), b"");

    // Seal three frames, then deliver them out of order, as UDP may.
    let mut frames: Vec<(usize, [u8; 512])> = Vec::new();
    for i in 0..3u8 {
        let mut buf = [0u8; 512];
        let n = client.seal(&[i; 4], 0, &mut buf).expect("seal");
        frames.push((n, buf));
    }

    for idx in [2usize, 0, 1] {
        let (n, mut buf) = frames[idx];
        let o = server.open(&mut buf[..n]).expect("out-of-order frame");
        let (header, len) = (o.header, o.len);
        assert_eq!(header.sequence, idx as u64);
        assert_eq!(&buf[HEADER_LEN..HEADER_LEN + len], &[idx as u8; 4]);
    }
}

#[test]
fn replayed_datagrams_are_rejected() {
    let (mut client, mut server, _) = connect(server_caps(), server_caps(), b"");
    let mut frame = [0u8; 512];
    let n = client.seal(b"once", 0, &mut frame).expect("seal");

    let replay = frame;
    assert!(server.open(&mut frame[..n]).is_ok());

    let mut frame = replay;
    assert_eq!(
        server.open(&mut frame[..n]),
        Err(Error::Replay),
        "a captured frame must not be accepted a second time"
    );
}

#[test]
fn frames_older_than_the_window_are_rejected() {
    let (mut client, mut server, _) = connect(server_caps(), server_caps(), b"");

    let mut first = [0u8; 512];
    let first_len = client.seal(b"old", 0, &mut first).expect("seal");

    // Advance well past the 64-frame replay window.
    for _ in 0..100 {
        let mut buf = [0u8; 512];
        let n = client.seal(b"x", 0, &mut buf).expect("seal");
        server.open(&mut buf[..n]).expect("open");
    }

    assert_eq!(server.open(&mut first[..first_len]), Err(Error::Replay));
}

#[test]
fn frames_from_another_session_are_rejected() {
    let (mut client, _, _) = connect(server_caps(), server_caps(), b"");
    let (_, mut other_server, _) = connect(server_caps(), server_caps(), b"");

    let mut frame = [0u8; 512];
    let n = client.seal(b"payload", 0, &mut frame).expect("seal");

    // Same session id, different keys: authentication must fail.
    assert_eq!(other_server.open(&mut frame[..n]), Err(Error::Decrypt));
}

#[test]
fn unknown_flag_bits_are_rejected() {
    let mut buf = [0u8; HEADER_LEN];
    let mut header = Header::new(FrameType::Data, 1);
    header.flags = FLAG_COMPRESSED;
    header.encode(&mut buf).expect("encode");
    assert!(Header::decode(&buf).is_ok());

    // Reserved bits must not be silently ignored; that keeps them usable by a
    // later protocol version without ambiguity.
    buf[1] |= 0b1000_0000;
    assert_eq!(Header::decode(&buf), Err(Error::BadHeader));
}

#[test]
fn unknown_version_is_rejected() {
    let mut buf = [0u8; HEADER_LEN];
    Header::new(FrameType::Data, 1).encode(&mut buf).expect("encode");
    buf[0] = (9 << 4) | (buf[0] & 0x0f);
    assert_eq!(Header::decode(&buf), Err(Error::UnsupportedVersion));
}

#[test]
fn header_roundtrips() {
    let mut header = Header::new(FrameType::HandshakeInit, 0x1234_5678);
    header.flags = FLAG_COMPRESSED;
    header.sequence = 0x0102_0304_0506_0708;

    let mut buf = [0u8; HEADER_LEN];
    header.encode(&mut buf).expect("encode");
    assert_eq!(Header::decode(&buf).expect("decode"), header);
}

#[test]
fn short_buffers_are_refused_not_truncated() {
    let (mut client, _, _) = connect(server_caps(), server_caps(), b"");
    let mut tiny = [0u8; 8];
    assert_eq!(
        client.seal(b"payload", 0, &mut tiny),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(Header::decode(&tiny[..4]), Err(Error::MessageTooShort));
}

#[test]
fn padding_masks_the_payload_length() {
    let (mut client, mut server, _) = connect(server_caps(), server_caps(), b"");
    client.set_padding(true);

    // Payloads of very different lengths must produce identical frame sizes as
    // long as they fall in the same 64-byte bucket. That is the whole point of
    // length masking.
    let mut sizes = Vec::new();
    for len in [1usize, 10, 30, 61] {
        let mut frame = [0u8; 512];
        let n = client.seal(&vec![0xAB; len], 0, &mut frame).expect("seal");
        sizes.push(n);

        let o = server.open(&mut frame[..n]).expect("open");
        let (header, out_len) = (o.header, o.len);
        assert!(header.flags & FLAG_PADDED != 0);
        assert_eq!(out_len, len, "the real length must survive the padding");
        assert_eq!(&frame[HEADER_LEN..HEADER_LEN + out_len], &vec![0xAB; len][..]);
    }
    assert!(
        sizes.windows(2).all(|w| w[0] == w[1]),
        "payloads of 1 and 61 bytes must be indistinguishable on the wire, got {sizes:?}"
    );
}

#[test]
fn padded_frames_land_on_block_boundaries() {
    let (mut client, _server, _) = connect(server_caps(), server_caps(), b"");
    client.set_padding(true);

    for len in [0usize, 1, 62, 63, 100, 200] {
        let mut frame = [0u8; 1024];
        let n = client.seal(&vec![0x7F; len], 0, &mut frame).expect("seal");
        let plaintext = n - DATA_OVERHEAD;
        assert_eq!(
            plaintext % PAD_BLOCK,
            0,
            "padded plaintext of {len} bytes came to {plaintext}, not a multiple of {PAD_BLOCK}"
        );
    }
}

#[test]
fn padding_is_per_frame_not_per_session() {
    // The receiver follows the flag on each frame, so one side may pad while
    // the other does not, and either may change its mind mid-session.
    let (mut client, mut server, _) = connect(server_caps(), server_caps(), b"");

    for padded in [false, true, false, true] {
        client.set_padding(padded);
        let mut frame = [0u8; 512];
        let n = client.seal(b"mixed", 0, &mut frame).expect("seal");
        let o = server.open(&mut frame[..n]).expect("open");
    let (header, len) = (o.header, o.len);
        assert_eq!(header.flags & FLAG_PADDED != 0, padded);
        assert_eq!(&frame[HEADER_LEN..HEADER_LEN + len], b"mixed");
    }
}

#[test]
fn padding_survives_a_tamper_check() {
    let (mut client, mut server, _) = connect(server_caps(), server_caps(), b"");
    client.set_padding(true);

    let mut frame = [0u8; 512];
    let n = client.seal(b"secret", 0, &mut frame).expect("seal");

    // Clearing the padded flag changes the associated data, so the frame no
    // longer authenticates; an attacker cannot strip padding to learn a length.
    frame[1] &= !FLAG_PADDED;
    assert_eq!(server.open(&mut frame[..n]), Err(Error::Decrypt));
}
