//! End-to-end tests over a real UDP socket pair.

use std::time::Duration;

mod common;

use common::Echo;
use fectp::{Connection, Identity, PayloadType};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Connects a client to `echo`, with a read timeout already set.
fn client(echo: &Echo) -> Connection {
    let conn =
        Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect");
    conn.set_read_timeout(Some(TIMEOUT)).expect("timeout");
    conn
}

#[test]
fn round_trip_over_udp() {
    let echo = Echo::start();
    let client = client(&echo);

    // The client authenticated the server by its static key.
    assert_eq!(client.peer_public_key().expect("connected"), echo.public());

    client.send(b"hello over the wire", PayloadType::Opaque).expect("client send");
    let mut buf = [0u8; 2048];
    let n = client.recv(&mut buf).expect("client recv");
    assert_eq!(&buf[..n], b"hello over the wire");
}

#[test]
fn zero_rtt_data_arrives_with_the_handshake() {
    let echo = Echo::start();
    let _client = Connection::connect_and_send(
        echo.addr(),
        &echo.public(),
        &Identity::generate(),
        b"first reading: 23.5",
    )
    .expect("connect");

    let observed = echo.connections(1, TIMEOUT);
    assert_eq!(
        observed.zero_rtt,
        vec![b"first reading: 23.5".to_vec()],
        "IK delivers application data in the first message, before the \
         handshake completes"
    );
}

#[test]
fn server_learns_the_client_identity() {
    let echo = Echo::start();
    let client_identity = Identity::generate();
    let client_public = *client_identity.public();

    let _client =
        Connection::connect(echo.addr(), &echo.public(), &client_identity).expect("connect");

    assert_eq!(echo.connections(1, TIMEOUT).peers, vec![client_public]);
}

#[test]
fn connecting_to_the_wrong_key_fails() {
    let echo = Echo::start();
    let wrong_public = *Identity::generate().public();

    // The server cannot authenticate the frame, so it drops it and says
    // nothing. The client must time out rather than wait forever.
    let result = Connection::connect(echo.addr(), &wrong_public, &Identity::generate());
    assert!(
        result.is_err(),
        "a handshake aimed at the wrong static key must not succeed"
    );
}

#[test]
fn many_messages_in_sequence() {
    let echo = Echo::collector();
    let client =
        Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect");
    for i in 0..64u32 {
        client.send(&i.to_le_bytes(), PayloadType::Opaque).expect("send");
    }

    let received = echo.messages(64, TIMEOUT);
    assert_eq!(received.len(), 64);
    for (i, msg) in received.iter().enumerate() {
        assert_eq!(msg.as_slice(), &(i as u32).to_le_bytes());
    }
}

#[test]
fn oversized_payload_is_refused() {
    let echo = Echo::start();
    let client = client(&echo);
    let limit = client.max_payload();

    // High-entropy bytes, so compression cannot slip this under the limit.
    // A simple arithmetic pattern would not do: zstd finds the period and
    // compresses it, and the send would legitimately succeed.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let huge: Vec<u8> = (0..limit + 1)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    assert!(
        client.send(&huge, PayloadType::Opaque).is_err(),
        "an incompressible payload above the frame limit must be refused, not \
         silently truncated"
    );
}

#[cfg(feature = "compress")]
mod coding_is_skipped_when_it_stops_paying {
    //! Attempting compression costs a couple of microseconds whether or not it
    //! works, so a stream that has repeatedly failed to compress stops being
    //! asked. That is a pure sender-side optimisation and must stay invisible:
    //! these check it changes nothing a receiver can observe.

    use super::*;

    /// Bytes nothing can compress, from a fixed seed so failures reproduce.
    fn incompressible(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn an_incompressible_stream_arrives_intact() {
        let echo = Echo::collector();
        let client =
            Connection::connect(echo.addr(), &echo.public(), &Identity::generate())
                .expect("connect");

        // Comfortably more than it takes to trip the skip, so most of these
        // are sent with coding switched off.
        let sent: Vec<Vec<u8>> = (0..64).map(|i| incompressible(512, 0x9e37 + i)).collect();
        for message in &sent {
            client.send(message, PayloadType::Opaque).expect("send");
        }

        let received = echo.messages(sent.len(), TIMEOUT);
        assert_eq!(received, sent, "skipping compression must not alter payloads");
    }

    #[test]
    fn a_payload_that_only_fits_when_coded_is_still_coded() {
        let echo = Echo::collector();
        let client =
            Connection::connect(echo.addr(), &echo.public(), &Identity::generate())
                .expect("connect");
        let limit = client.max_payload();

        // Stop coding being attempted at all.
        for i in 0..32 {
            client.send(&incompressible(512, 0x2545 + i), PayloadType::Opaque).expect("send");
        }

        // This is larger than a frame can carry raw, and only goes out if
        // coding is attempted anyway. Skipping is an optimisation, so it must
        // never be the reason a legal send fails.
        let compressible = vec![0xA5u8; limit * 4];
        client
            .send(&compressible, PayloadType::Opaque)
            .expect("a payload that fits once coded must be sent, not refused");

        let received = echo.messages(33, TIMEOUT);
        assert_eq!(
            received.last().expect("the large payload"),
            &compressible,
            "the large payload must round-trip unchanged"
        );
    }

    #[test]
    fn compression_resumes_when_the_data_becomes_compressible_again() {
        let echo = Echo::collector();
        let client =
            Connection::connect(echo.addr(), &echo.public(), &Identity::generate())
                .expect("connect");
        let limit = client.max_payload();

        for i in 0..32 {
            client.send(&incompressible(512, 0x7f4a + i), PayloadType::Opaque).expect("send");
        }

        // A stream's content can change. Once it does, payloads too large to
        // send raw must start succeeding again — which only happens if coding
        // is periodically retried rather than abandoned for good.
        let compressible = vec![0x5Cu8; limit * 2];
        for _ in 0..64 {
            client.send(&compressible, PayloadType::Opaque).expect("send");
        }

        let received = echo.messages(96, TIMEOUT);
        assert_eq!(received.len(), 96);
        assert!(
            received[32..].iter().all(|m| m == &compressible),
            "every compressible payload must arrive unchanged"
        );
    }
}

#[cfg(feature = "compress")]
mod compression {
    use super::*;
    use fectp::compress::{looks_precompressed, should_compress, MIN_COMPRESS_SIZE};
    use fectp::{Capabilities, CAP_ZSTD};

    fn full() -> Capabilities {
        Capabilities {
            flags: CAP_ZSTD,
            max_frame_size: 1200,
            codecs: u16::MAX,
        }
    }

    #[test]
    fn small_payloads_are_never_compressed() {
        let small = vec![b'A'; MIN_COMPRESS_SIZE - 1];
        assert!(
            !should_compress(&small, full()),
            "below the threshold, compression costs CPU and saves nothing"
        );
    }

    #[test]
    fn peers_that_cannot_decompress_are_never_sent_compressed_frames() {
        let big = vec![b'A'; MIN_COMPRESS_SIZE * 4];
        assert!(should_compress(&big, full()));
        assert!(
            !should_compress(&big, Capabilities::minimal(256)),
            "a peer without a decoder could never decode the frame"
        );
    }

    #[test]
    fn already_compressed_formats_are_bypassed() {
        let mut jpeg = vec![0xFF, 0xD8, 0xFF];
        jpeg.resize(MIN_COMPRESS_SIZE * 2, 0x5A);
        assert!(looks_precompressed(&jpeg));
        assert!(!should_compress(&jpeg, full()));

        let mut mp4 = vec![0u8, 0, 0, 0x18];
        mp4.extend_from_slice(b"ftypmp42");
        mp4.resize(MIN_COMPRESS_SIZE * 2, 0x33);
        assert!(looks_precompressed(&mp4));
    }

    #[test]
    fn compressible_payload_round_trips() {
        let echo = Echo::collector();
        let client = client(&echo);

        // Far larger than one frame, but highly compressible, so it fits.
        let payload: Vec<u8> = b"{\"sensor\":\"temp\",\"value\":21.5}\n"
            .iter()
            .cycle()
            .take(8000)
            .copied()
            .collect();
        assert!(payload.len() > client.max_payload());

        client.send(&payload, PayloadType::Opaque).expect("send compressible payload");
        assert_eq!(echo.messages(1, TIMEOUT), vec![payload]);
    }
}

/// Typed payloads: declaring the data's shape selects a transform.
mod typed {
    use super::*;
    use fectp::compress::encode_payload;
    use fectp::{Capabilities, PayloadType, CODEC_OVERHEAD, CORE_CODECS};

    /// A multi-channel sensor block that varies slowly, as real instrument
    /// data does.
    fn sensor_block(samples: usize, channels: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(samples * channels * 2);
        let mut noise = 0x1234_5678u32;
        for s in 0..samples {
            for c in 0..channels {
                noise = noise.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let phase = (s as f64) * 0.001 + (c as f64) * 0.7;
                let value = (phase.sin() * 8000.0) as i16;
                let jitter = ((noise >> 16) % 5) as i16 - 2;
                out.extend_from_slice(&value.wrapping_add(jitter).to_le_bytes());
            }
        }
        out
    }

    /// Bytes that would go on the wire for this payload and declared type.
    fn coded_size(data: &[u8], ty: PayloadType, caps: Capabilities) -> usize {
        let (mut a, mut b) = (Vec::new(), Vec::new());
        match encode_payload(data, ty, caps, &mut a, &mut b) {
            Some((_, len)) => CODEC_OVERHEAD + len,
            None => data.len(),
        }
    }

    fn full_peer() -> Capabilities {
        Capabilities {
            flags: fectp::CAP_ZSTD,
            max_frame_size: 1200,
            codecs: u16::MAX,
        }
    }

    /// A constrained peer: core transforms only, no Zstandard decoder.
    fn mcu_peer() -> Capabilities {
        Capabilities {
            flags: 0,
            max_frame_size: 256,
            codecs: CORE_CODECS,
        }
    }

    #[test]
    fn declaring_the_type_beats_treating_it_as_bytes() {
        let block = sensor_block(512, 4);
        let opaque = coded_size(&block, PayloadType::Opaque, full_peer());
        let typed = coded_size(&block, PayloadType::I16 { channels: 4 }, full_peer());

        println!(
            "i16 x4ch 512 samples ({} bytes): opaque {opaque}, typed {typed}",
            block.len()
        );
        assert!(
            typed < opaque,
            "knowing the payload is 4-channel i16 must beat treating it as \
             bytes: typed {typed} vs opaque {opaque}"
        );
    }

    #[test]
    fn transforms_work_without_a_zstandard_decoder_on_the_far_side() {
        // This is the payoff of splitting transform from entropy stage: a peer
        // with no room for Zstandard still gets real compression, because the
        // transform is pure integer code in the no_std core.
        let block = sensor_block(512, 4);
        let typed = coded_size(&block, PayloadType::I16 { channels: 4 }, mcu_peer());
        println!("towards a peer with no zstd: {} -> {typed} bytes", block.len());
        assert!(
            typed < block.len(),
            "the transform alone must still shrink the block: {typed} vs {}",
            block.len()
        );
    }

    #[test]
    fn a_peer_that_cannot_reverse_the_transform_gets_plain_bytes() {
        let block = sensor_block(512, 4);
        let no_codecs = Capabilities {
            flags: 0,
            max_frame_size: 1200,
            codecs: 0,
        };
        assert_eq!(
            coded_size(&block, PayloadType::I16 { channels: 4 }, no_codecs),
            block.len(),
            "a transform the receiver cannot reverse must never be used"
        );
    }

    #[test]
    fn typed_payloads_round_trip_over_udp() {
        let echo = Echo::collector();
        for (label, payload, ty) in [
            (
                "i16 x4",
                sensor_block(256, 4),
                PayloadType::I16 { channels: 4 },
            ),
            (
                "i32 x2",
                (0..512i32).flat_map(|i| (i * 5).to_le_bytes()).collect(),
                PayloadType::I32 { channels: 2 },
            ),
            (
                "f32 array",
                (0..256)
                    .flat_map(|i| (1.0f32 + i as f32 * 0.001).to_le_bytes())
                    .collect(),
                PayloadType::Elements { size: 4 },
            ),
        ] {
            let client = client(&echo);
            let before = echo.observed().messages.len();
            client.send(&payload, ty).expect("send_typed");
            let received = echo.messages(before + 1, TIMEOUT);
            assert_eq!(received[before], payload, "{label}");
        }
    }

    #[test]
    fn a_wrongly_declared_type_still_round_trips() {
        // Declaring the wrong shape must cost compression, never correctness.
        let echo = Echo::collector();
        let client = client(&echo);
        let text = b"this is plain text, not interleaved samples at all!!".repeat(8);
        client
            .send(&text, PayloadType::I16 { channels: 4 })
            .expect("send_typed");
        assert_eq!(echo.messages(1, TIMEOUT), vec![text]);
    }
}

/// A stream of one shape: bind it once, pass it every time.
#[test]
fn a_stream_of_one_shape_names_it_every_time() {
    let echo = Echo::collector();
    let client = client(&echo);

    // The shape is a local, not a setting on the connection. Changing the
    // channel count means changing one line, and no send can be left behind
    // holding a stale one.
    let shape = PayloadType::I16 { channels: 4 };

    let mut blocks = Vec::new();
    for block in 0..3u16 {
        let payload: Vec<u8> = (0..128 * 4)
            .flat_map(|i| ((block as i16) * 100 + (i as i16 / 4)).to_le_bytes())
            .collect();
        client.send(&payload, shape).expect("send");
        blocks.push(payload);
    }

    assert_eq!(echo.messages(3, TIMEOUT), blocks);
}

/// Shapes may be mixed freely, because nothing is remembered between sends.
#[test]
fn shapes_can_be_mixed_within_one_connection() {
    let echo = Echo::collector();
    let client = client(&echo);

    let samples: Vec<u8> = (0..512i16).flat_map(|i| i.to_le_bytes()).collect();
    let text = b"a status line, not samples".to_vec();

    client
        .send(&samples, PayloadType::I16 { channels: 4 })
        .expect("send samples");
    client
        .send(&text, PayloadType::Opaque)
        .expect("send text");

    // Each line said what it was sending, so neither could be misread as the
    // other — which is what a remembered default made possible.
    assert_eq!(echo.messages(2, TIMEOUT), vec![samples, text]);
}

#[test]
fn data_sent_with_the_handshake_reaches_the_peer() {
    let echo = Echo::collector();
    let first = b"a sensor reading, sent with the handshake";

    // One packet carries the handshake and the data, so the peer has it after
    // a single flight rather than after a round trip and then a send.
    let _conn = Connection::connect_and_send(
        echo.addr(),
        &echo.public(),
        &Identity::generate(),
        first,
    )
    .expect("connect_and_send");

    let seen = echo.connections(1, TIMEOUT);
    assert_eq!(seen.zero_rtt, vec![first.to_vec()]);
}

#[test]
fn a_connection_that_sent_nothing_first_has_nothing_waiting() {
    let echo = Echo::start();
    let conn = client(&echo);
    conn.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");

    // Nothing rode along with the handshake, so `recv` has nothing queued and
    // waits on the socket like any other call.
    //
    // The opposite case — a peer that *does* answer in its handshake reply —
    // has no test, because `Endpoint` cannot produce one: it always answers
    // with an empty payload. The delivery path exists and is exercised by the
    // queue it writes into; what is missing is a peer to exercise it against.
    let mut buf = [0u8; 256];
    assert!(conn.recv(&mut buf).is_err(), "nothing should be waiting");
}
