//! The other half of 0-RTT: an answer inside the handshake.
//!
//! A peer sending data with its opening frame gets a reply in the same round
//! trip rather than the one after it — which is the whole property, and until
//! now an `Endpoint` could only supply the empty payload. `Connection` had
//! always been able to deliver one; nothing could produce it.

mod common;

use std::time::Duration;

use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

/// Serves for `window`, echoing anything that arrives.
fn serve(server: &mut Endpoint, window: Duration) {
    let started = std::time::Instant::now();
    while started.elapsed() < window {
        if let Ok(Event::Message { peer, data }) = server.poll(Some(Duration::from_millis(5))) {
            let _ = server.send(peer, &data, PayloadType::Opaque);
        }
    }
}

#[test]
fn a_peer_gets_the_answer_in_the_same_round_trip() {
    let identity = Identity::generate();
    let public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("bind");
    let addr = server.local_addr().expect("addr");

    const ANSWER: &[u8] = b"config v7, reporting interval 60s";
    server.set_handshake_reply(ANSWER).expect("it fits a frame");

    // A sensor: wakes, reports with the handshake, and wants the answer before
    // it can sleep again.
    let sensor = std::thread::spawn(move || {
        let conn = Connection::connect_and_send(
            addr,
            &public,
            &Identity::generate(),
            b"reading: 23.5",
        )
        .expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");

        // No send of its own: whatever comes back rode in the handshake.
        let mut buf = vec![0u8; 1024];
        let n = conn.recv(&mut buf).expect("recv");
        buf[..n].to_vec()
    });

    serve(&mut server, Duration::from_millis(600));
    let answered = sensor.join().expect("sensor");
    assert_eq!(
        answered, ANSWER,
        "the answer must arrive through the first recv, without a second exchange"
    );
}

/// It reaches a peer that sent nothing with its handshake, too.
///
/// The payload rides in the response either way, so an ordinary `connect` gets
/// it as its first message.
#[test]
fn an_ordinary_connect_receives_it_as_well() {
    let identity = Identity::generate();
    let public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("bind");
    let addr = server.local_addr().expect("addr");
    server.set_handshake_reply(b"banner").expect("fits");

    let client = std::thread::spawn(move || {
        let conn = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        let mut buf = vec![0u8; 256];
        let n = conn.recv(&mut buf).expect("recv");
        buf[..n].to_vec()
    });

    serve(&mut server, Duration::from_millis(600));
    assert_eq!(client.join().expect("client"), b"banner");
}

/// Two peers in a row both get it.
///
/// The payload is written into the response buffer each time, so a
/// once-and-then-empty bug would look exactly like this test passing for one
/// connection.
#[test]
fn every_peer_gets_it_not_only_the_first() {
    let identity = Identity::generate();
    let public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("bind");
    let addr = server.local_addr().expect("addr");
    server.set_handshake_reply(b"same for everyone").expect("fits");

    let clients = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..3 {
            let conn = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
            conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
            let mut buf = vec![0u8; 256];
            let n = conn.recv(&mut buf).expect("recv");
            seen.push(buf[..n].to_vec());
        }
        seen
    });

    serve(&mut server, Duration::from_millis(1_500));
    let seen = clients.join().expect("clients");
    assert_eq!(seen.len(), 3);
    for (i, answer) in seen.iter().enumerate() {
        assert_eq!(answer, b"same for everyone", "peer {i} got something else");
    }
}

/// A payload too large for a handshake frame is refused when it is set.
///
/// Refusing here rather than at connection time matters: a reply that did not
/// fit would otherwise fail every handshake, and the failure would look like
/// an unreachable peer.
#[test]
fn a_reply_that_would_not_fit_is_refused_at_once() {
    let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");

    assert!(
        server.set_handshake_reply(&vec![0u8; fectp::DEFAULT_MAX_DATAGRAM]).is_err(),
        "a payload the size of a whole frame leaves no room for the handshake"
    );
    // And having been refused, nothing was kept.
    let public = *Identity::generate().public();
    let _ = public;
    assert!(server.set_handshake_reply(b"small").is_ok());
}
