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
    assert_eq!(fectp::MAX_QUEUED, 4, "API.md says 4 per peer");
    assert_eq!(fectp::CODEC_OVERHEAD, 4, "API.md says 4 bytes");
    assert_eq!(
        fectp::HANDSHAKE_TIMEOUT,
        Duration::from_secs(5),
        "API.md says 5 s"
    );
}

/// API.md — "Sending": two calls, each naming the payload's shape.
#[test]
fn every_send_has_the_shape_the_reference_claims() {
    let echo = Echo::start();
    let conn =
        Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");

    let shape = PayloadType::I16 { channels: 2 };
    let small = [0x11u8; 64];

    // The shape is named at the call, so a line says what it does without
    // reference to a setting made elsewhere. There is no setter to forget.
    conn.send(&small, PayloadType::Opaque).expect("send");
    conn.send(&small, shape).expect("send, typed");
    conn.send_reliable(&small, PayloadType::Opaque)
        .expect("send_reliable");
    conn.send_reliable(&small, shape)
        .expect("send_reliable, typed");

    // The same reliable call with a payload far past the frame limit: the
    // caller never has to know where the limit is.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let big: Vec<u8> = (0..conn.max_payload() * 5)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    conn.send_reliable(&big, PayloadType::Opaque)
        .expect("a large payload needs no other method");
    conn.flush(Duration::from_secs(10)).expect("flush");

    // Unreliable is still one frame only.
    match conn.send(&big, PayloadType::Opaque) {
        Err(fectp::Error::PayloadTooLarge { .. }) => {}
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
}

/// API.md — "Opening one": four modes, none taking a timeout.
#[test]
fn no_way_of_connecting_takes_a_timeout() {
    use std::net::UdpSocket;

    // Every constructor is called here with the argument list the reference
    // prints. A timeout creeping back onto one of them stops compiling.
    let silent = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = silent.local_addr().expect("addr");
    let key = *Identity::generate().public();
    let id = Identity::generate();

    // All fail — nothing is listening — but the shape is what is being pinned.
    let _ = Connection::connect(addr, &key, &id);
    let _ = Connection::connect_and_send(addr, &key, &id, b"hello");
    let _ = Connection::connect_psk(addr, b"secret");
    let _ = Connection::connect_psk_and_send(addr, b"secret", b"hello");
    let _ = Connection::connect_plain(addr);
}

/// API.md — "Asking": the payload limits, in the order the reference claims.
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
    conn.send(b"plain", PayloadType::Opaque).expect("send");
    let n = conn.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], b"plain");

    let samples: Vec<u8> = (0..512i16).flat_map(|i| i.to_le_bytes()).collect();
    conn.send(&samples, PayloadType::I16 { channels: 2 })
        .expect("send_typed");
    let n = conn.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], &samples[..], "coded payloads arrive decoded");

    let big = vec![0x7Eu8; conn.max_payload() * 3];
    conn.send_reliable(&big, PayloadType::Opaque).and_then(|()| conn.flush(Duration::from_secs(5)))
        .expect("send_reliable");
    let n = conn.recv(&mut buf).expect("recv");
    assert_eq!(n, big.len(), "fragmented messages arrive whole");
}
