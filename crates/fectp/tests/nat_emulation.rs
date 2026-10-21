//! The emulated NATs, checked before anything is tested behind them.
//!
//! The hole-punching tests are only as good as the NATs they punch through: an
//! emulation that let everything in would pass them all without a hole ever
//! being made. So each kind is held to what makes it that kind, with the
//! refusal as well as the admission checked.

mod common;

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use common::nat::{behind, Kind};
use common::Echo;
use fectp::{DatagramSocket, Endpoint, Event, Identity, PayloadType};

/// An endpoint behind `kind` connects out to a public server and is echoed.
fn reaches_a_server(kind: Kind) {
    let echo = Echo::start();
    let (socket, nat) = behind(kind);
    let mut client = Endpoint::bind_socket(socket, Identity::generate()).expect("bind");
    let server = client
        .connect(echo.addr(), Some(&echo.public()))
        .expect("connect");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut sent = false;
    loop {
        assert!(Instant::now() < deadline, "{kind:?}: no echo");
        match client.poll(Some(Duration::from_millis(20))).expect("poll") {
            Event::Connected { peer, .. } if peer == server && !sent => {
                client
                    .send(server, b"through the nat", PayloadType::Opaque)
                    .expect("send");
                sent = true;
            }
            Event::Message { data, .. } => {
                assert_eq!(data, b"through the nat");
                break;
            }
            _ => {}
        }
    }
    // The server saw the mapping, not the host.
    let seen = echo.observed();
    assert_eq!(seen.peers.len(), 1);
    assert_eq!(
        nat.outside().len(),
        1,
        "{kind:?}: one destination, one mapping"
    );
}

#[test]
fn every_kind_lets_a_host_reach_out_and_hear_back() {
    for kind in [Kind::FullCone, Kind::PortRestricted, Kind::Symmetric] {
        reaches_a_server(kind);
    }
}

/// Whether a stranger's datagram to the host's mapping gets in, before and
/// after the host has sent to that stranger.
fn stranger_gets_in(kind: Kind) -> (bool, bool) {
    let (socket, nat) = behind(kind);
    let host = Endpoint::bind_socket(socket, Identity::generate()).expect("bind");
    drop(host);
    // The endpoint is gone but the NAT is the test's; drive it directly.
    let elsewhere = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let stranger = UdpSocket::bind("127.0.0.1:0").expect("bind");
    nat.send_to(b"out", elsewhere.local_addr().expect("addr"))
        .expect("send");
    let mapping = nat.outside()[0];

    let mut buf = [0u8; 64];
    stranger.send_to(b"unasked", mapping).expect("send");
    let before = nat
        .recv_from(&mut buf, Some(Duration::from_millis(300)))
        .is_ok();

    // The host now sends to the stranger. A cone NAT uses the same mapping, so
    // the stranger's reply to it is let in; a symmetric NAT makes a new one
    // for the new destination, and the old mapping still refuses.
    nat.send_to(b"hello", stranger.local_addr().expect("addr"))
        .expect("send");
    stranger.send_to(b"asked", mapping).expect("send");
    let after = nat
        .recv_from(&mut buf, Some(Duration::from_millis(300)))
        .is_ok();
    (before, after)
}

#[test]
fn a_full_cone_lets_anyone_in() {
    assert_eq!(stranger_gets_in(Kind::FullCone), (true, true));
}

#[test]
fn a_port_restricted_cone_lets_in_only_who_was_sent_to() {
    assert_eq!(stranger_gets_in(Kind::PortRestricted), (false, true));
}

#[test]
fn a_symmetric_nat_lets_nobody_in_through_a_mapping_made_for_someone_else() {
    assert_eq!(stranger_gets_in(Kind::Symmetric), (false, false));
}

#[test]
fn a_symmetric_nat_shows_each_destination_a_different_address() {
    let (_, nat) = behind(Kind::Symmetric);
    let a = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let b = UdpSocket::bind("127.0.0.1:0").expect("bind");
    nat.send_to(b"1", a.local_addr().expect("addr"))
        .expect("send");
    nat.send_to(b"2", b.local_addr().expect("addr"))
        .expect("send");
    let mut buf = [0u8; 8];
    let (_, from_a) = a.recv_from(&mut buf).expect("a");
    let (_, from_b) = b.recv_from(&mut buf).expect("b");
    assert_ne!(
        from_a, from_b,
        "what a third party saw is no use to anyone else"
    );

    let (_, cone) = behind(Kind::PortRestricted);
    cone.send_to(b"1", a.local_addr().expect("addr"))
        .expect("send");
    cone.send_to(b"2", b.local_addr().expect("addr"))
        .expect("send");
    let (_, from_a) = a.recv_from(&mut buf).expect("a");
    let (_, from_b) = b.recv_from(&mut buf).expect("b");
    assert_eq!(from_a, from_b, "a cone shows everyone the same address");
}
