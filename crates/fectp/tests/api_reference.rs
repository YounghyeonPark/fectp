//! Guards `docs/API.md` against drifting from the code.
//!
//! The reference lists constants with their values and claims a shape for the
//! send methods. Both are the kind of thing that goes stale quietly: nothing
//! breaks, the document just starts lying. This makes it break instead.

use std::time::Duration;

mod common;

use common::Echo;
use fectp::{Connection, Identity, PayloadType};

/// API.md — "Constants worth knowing".
#[test]
fn the_documented_constants_are_the_real_ones() {
    assert_eq!(fectp::MAX_UNACKED, 32, "API.md says 32");
    assert_eq!(fectp::INITIAL_CWND, 4, "API.md says 4");
    assert_eq!(fectp::MIN_CWND, 2, "API.md says 2");
    assert_eq!(fectp::MAX_RETRIES, 5, "API.md says 5");
    assert_eq!(fectp::MAX_MESSAGE_LEN, 1 << 20, "API.md says 1 MiB");
    assert_eq!(fectp::MAX_FRAGMENTS, 4096, "API.md says 4096");
    assert_eq!(fectp::MAX_QUEUED_LARGE, 4, "API.md says 4 per peer");
    assert_eq!(fectp::CODEC_OVERHEAD, 4, "API.md says 4 bytes");
}

/// API.md — "Sending": three kinds, each with a `_typed` twin.
#[test]
fn every_send_has_the_shape_the_reference_claims() {
    let echo = Echo::start();
    let conn =
        Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");

    let shape = PayloadType::I16 { channels: 2 };
    let small = [0x11u8; 64];

    // Fire and forget, and its twin.
    conn.send(&small).expect("send");
    conn.send_typed(&small, shape).expect("send_typed");

    // Reliable, and its twin. Both hand back an identifier.
    let first = conn.send_reliable(&small).expect("send_reliable");
    let second = conn
        .send_reliable_typed(&small, shape)
        .expect("send_reliable_typed");
    assert_ne!(first, second, "each reliable message gets its own identifier");
    conn.flush(Duration::from_secs(5)).expect("flush");

    // Large, and its twin. These are the ones that wait, which is why they
    // take a timeout and the others do not.
    conn.send_large(&small, Duration::from_secs(5))
        .expect("send_large");
    conn.send_large_typed(&small, shape, Duration::from_secs(5))
        .expect("send_large_typed");
}

/// API.md — "Sending": the three payload limits, in the order it claims.
#[test]
fn the_payload_limits_are_ordered_as_documented() {
    let echo = Echo::start();
    let conn =
        Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect");

    assert!(
        conn.max_reliable_payload() < conn.max_payload(),
        "a reliable frame carries a message identifier too"
    );
    assert!(
        conn.max_fragment_payload() < conn.max_reliable_payload(),
        "a fragment carries a descriptor on top of that"
    );
}

/// API.md — "Receiving": one method, and it undoes everything on the way.
#[test]
fn one_receive_method_covers_every_kind_of_message() {
    let echo = Echo::start();
    let conn =
        Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");

    let mut buf = vec![0u8; 8192];

    // Plain, coded, and fragmented all arrive through `recv`, whole.
    conn.send(b"plain").expect("send");
    let n = conn.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], b"plain");

    let samples: Vec<u8> = (0..512i16).flat_map(|i| i.to_le_bytes()).collect();
    conn.send_typed(&samples, PayloadType::I16 { channels: 2 })
        .expect("send_typed");
    let n = conn.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], &samples[..], "coded payloads arrive decoded");

    let big = vec![0x7Eu8; conn.max_payload() * 3];
    conn.send_large(&big, Duration::from_secs(5))
        .expect("send_large");
    let n = conn.recv(&mut buf).expect("recv");
    assert_eq!(n, big.len(), "fragmented messages arrive whole");
}
