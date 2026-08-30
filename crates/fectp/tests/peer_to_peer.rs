//! Nodes that both accept and start connections, on one socket each.
//!
//! "Initiator" and "responder" are roles a *connection* has, not properties a
//! node has. These tests hold two `Endpoint`s that each do both, and check that
//! once a handshake is done neither side is privileged.

use std::time::{Duration, Instant};

use fectp::{Endpoint, Event, Identity, PayloadType, PeerId};

const TIMEOUT: Duration = Duration::from_secs(5);
const SECRET: &[u8] = b"mesh-secret";

/// Two endpoints, and the identity of each.
struct Pair {
    a: Endpoint,
    b: Endpoint,
    a_public: Option<[u8; 32]>,
    b_public: Option<[u8; 32]>,
}

impl Pair {
    fn public_key() -> Self {
        let (ia, ib) = (Identity::generate(), Identity::generate());
        let (a_public, b_public) = (*ia.public(), *ib.public());
        Self {
            a: Endpoint::bind("127.0.0.1:0", ia).expect("bind"),
            b: Endpoint::bind("127.0.0.1:0", ib).expect("bind"),
            a_public: Some(a_public),
            b_public: Some(b_public),
        }
    }

    fn psk() -> Self {
        Self {
            a: Endpoint::bind_psk("127.0.0.1:0", SECRET).expect("bind"),
            b: Endpoint::bind_psk("127.0.0.1:0", SECRET).expect("bind"),
            a_public: None,
            b_public: None,
        }
    }

    fn plain() -> Self {
        Self {
            a: Endpoint::bind_plain("127.0.0.1:0").expect("bind"),
            b: Endpoint::bind_plain("127.0.0.1:0").expect("bind"),
            a_public: None,
            b_public: None,
        }
    }
}

/// Polls both endpoints until each reports a `Connected`, returning the handles.
///
/// One event loop driving two nodes is exactly how a real mesh node works,
/// minus the other peers.
fn settle(pair: &mut Pair) -> (PeerId, PeerId) {
    let deadline = Instant::now() + TIMEOUT;
    let (mut on_a, mut on_b) = (None, None);

    while (on_a.is_none() || on_b.is_none()) && Instant::now() < deadline {
        if let Ok(Event::Connected { peer, .. }) = pair.a.poll(Some(Duration::from_millis(20))) {
            on_a = Some(peer);
        }
        if let Ok(Event::Connected { peer, .. }) = pair.b.poll(Some(Duration::from_millis(20))) {
            on_b = Some(peer);
        }
    }
    (
        on_a.expect("A never completed its handshake"),
        on_b.expect("B never completed its handshake"),
    )
}

/// Sends from `from` to `to` and returns what arrived.
fn deliver(from: &mut Endpoint, from_peer: PeerId, to: &mut Endpoint, payload: &[u8]) -> Vec<u8> {
    from.send(from_peer, payload, PayloadType::Opaque).expect("send");
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(Event::Message { data, .. }) = to.poll(Some(Duration::from_millis(20))) {
            return data;
        }
    }
    panic!("nothing arrived");
}

#[test]
fn a_node_listens_and_dials_on_the_same_socket() {
    let mut pair = Pair::public_key();
    let b_addr = pair.b.local_addr().expect("addr");
    let a_addr = pair.a.local_addr().expect("addr");

    // A dials B from A's own listening socket.
    let _pending = pair
        .a
        .connect(b_addr, pair.b_public.as_ref())
        .expect("connect");

    let (a_to_b, b_from_a) = settle(&mut pair);

    // The opening frame came from A's bound port, not a fresh ephemeral one.
    // That is the property NAT hole punching depends on.
    assert_eq!(
        pair.b.peer_addr(b_from_a),
        Some(a_addr),
        "the dial must originate from the endpoint's own bound socket"
    );

    // And the session works in both directions.
    assert_eq!(
        deliver(&mut pair.a, a_to_b, &mut pair.b, b"A to B"),
        b"A to B"
    );
    assert_eq!(
        deliver(&mut pair.b, b_from_a, &mut pair.a, b"B to A"),
        b"B to A"
    );
}

#[test]
fn the_session_is_symmetric_once_established() {
    let mut pair = Pair::public_key();
    let b_addr = pair.b.local_addr().expect("addr");
    pair.a
        .connect(b_addr, pair.b_public.as_ref())
        .expect("connect");
    let (a_to_b, b_from_a) = settle(&mut pair);

    // Each side authenticated the other, whichever way the handshake ran.
    assert_eq!(pair.a.peer_public_key(a_to_b), pair.b_public.as_ref());
    assert_eq!(pair.b.peer_public_key(b_from_a), pair.a_public.as_ref());

    // Every capability is available from both ends.
    let samples: Vec<u8> = (0..256i16).flat_map(|i| (i / 4).to_le_bytes()).collect();
    pair.a
        .send(a_to_b, &samples, PayloadType::I16 { channels: 4 })
        .expect("A sends typed");
    pair.b
        .send_reliable(b_from_a, b"B sends reliably", PayloadType::Opaque)
        .expect("B sends reliably");

    let deadline = Instant::now() + TIMEOUT;
    let (mut got_a, mut got_b) = (None, None);
    while (got_a.is_none() || got_b.is_none()) && Instant::now() < deadline {
        if let Ok(Event::Message { data, .. }) = pair.a.poll(Some(Duration::from_millis(20))) {
            got_a = Some(data);
        }
        if let Ok(Event::Message { data, .. }) = pair.b.poll(Some(Duration::from_millis(20))) {
            got_b = Some(data);
        }
    }
    assert_eq!(got_b.expect("B receives"), samples);
    assert_eq!(got_a.expect("A receives"), b"B sends reliably");

    // A sent its acknowledgement while receiving; B needs one more turn of its
    // loop to take it in.
    let deadline = Instant::now() + TIMEOUT;
    while pair.b.unacknowledged(b_from_a) > 0 && Instant::now() < deadline {
        let _ = pair.b.poll(Some(Duration::from_millis(20)));
    }
    assert_eq!(
        pair.b.unacknowledged(b_from_a),
        0,
        "the responder's reliable message was acknowledged by the initiator"
    );
}

#[test]
fn each_side_knows_which_way_the_connection_ran() {
    let mut pair = Pair::public_key();
    let b_addr = pair.b.local_addr().expect("addr");
    pair.a
        .connect(b_addr, pair.b_public.as_ref())
        .expect("connect");

    let deadline = Instant::now() + TIMEOUT;
    let (mut a_initiated, mut b_initiated) = (None, None);
    while (a_initiated.is_none() || b_initiated.is_none()) && Instant::now() < deadline {
        if let Ok(Event::Connected { initiated, .. }) = pair.a.poll(Some(Duration::from_millis(20)))
        {
            a_initiated = Some(initiated);
        }
        if let Ok(Event::Connected { initiated, .. }) = pair.b.poll(Some(Duration::from_millis(20)))
        {
            b_initiated = Some(initiated);
        }
    }
    assert_eq!(a_initiated, Some(true), "A dialled");
    assert_eq!(b_initiated, Some(false), "B was dialled");
}

#[test]
fn nodes_can_dial_each_other_at_once() {
    // Both nodes dial simultaneously, which in a mesh is the normal case. Each
    // ends up with two sessions: one it started, one it accepted. They are
    // distinct connections, not a collision.
    let mut pair = Pair::public_key();
    let (a_addr, b_addr) = (
        pair.a.local_addr().expect("addr"),
        pair.b.local_addr().expect("addr"),
    );

    pair.a
        .connect(b_addr, pair.b_public.as_ref())
        .expect("A dials B");
    pair.b
        .connect(a_addr, pair.a_public.as_ref())
        .expect("B dials A");

    let deadline = Instant::now() + TIMEOUT;
    while (pair.a.peer_count() < 2 || pair.b.peer_count() < 2) && Instant::now() < deadline {
        let _ = pair.a.poll(Some(Duration::from_millis(20)));
        let _ = pair.b.poll(Some(Duration::from_millis(20)));
    }

    assert_eq!(pair.a.peer_count(), 2, "one dialled, one accepted");
    assert_eq!(pair.b.peer_count(), 2);
    assert_eq!(pair.a.connecting(), 0, "both handshakes finished");
    assert_eq!(pair.b.connecting(), 0);
}

#[test]
fn an_unanswered_dial_is_reported() {
    let mut node = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    // Nothing is listening here: bind a socket, learn its address, drop it.
    let nowhere = {
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        dead.local_addr().expect("addr")
    };

    let peer = node
        .connect(nowhere, Some(&[0x11; 32]))
        .expect("the dial itself succeeds; only the reply is missing");
    assert_eq!(node.connecting(), 1);

    let deadline = Instant::now() + TIMEOUT;
    let mut failed = None;
    while failed.is_none() && Instant::now() < deadline {
        if let Ok(Event::ConnectFailed { peer }) = node.poll(Some(Duration::from_millis(50))) {
            failed = Some(peer);
        }
    }
    assert_eq!(
        failed,
        Some(peer),
        "a dial that is never answered must be reported, not left hanging"
    );
    assert_eq!(node.connecting(), 0, "the attempt was abandoned");
}

#[test]
fn public_key_mode_needs_the_peers_key() {
    let mut node = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    assert!(
        matches!(
            node.connect("127.0.0.1:1", None),
            Err(fectp::Error::MissingPeerKey)
        ),
        "public-key mode cannot dial anonymously"
    );
}

#[test]
fn a_psk_mesh_needs_no_keys_at_all() {
    // Every node holds the same secret, so any node can dial any other with
    // nothing else configured. This is the shape a lab network wants.
    let mut pair = Pair::psk();
    let b_addr = pair.b.local_addr().expect("addr");
    pair.a.connect(b_addr, None).expect("dial with no key");

    let (a_to_b, b_from_a) = settle(&mut pair);
    assert_eq!(
        deliver(&mut pair.a, a_to_b, &mut pair.b, b"over the mesh"),
        b"over the mesh"
    );
    assert_eq!(
        deliver(&mut pair.b, b_from_a, &mut pair.a, b"and back"),
        b"and back"
    );
}

#[test]
fn plaintext_nodes_pair_up_too() {
    let mut pair = Pair::plain();
    let b_addr = pair.b.local_addr().expect("addr");
    pair.a.connect(b_addr, None).expect("dial");

    let (a_to_b, b_from_a) = settle(&mut pair);
    assert!(!pair.a.is_encrypted());
    assert_eq!(
        deliver(&mut pair.a, a_to_b, &mut pair.b, b"in the clear"),
        b"in the clear"
    );
    assert_eq!(
        deliver(&mut pair.b, b_from_a, &mut pair.a, b"still clear"),
        b"still clear"
    );
}

#[test]
fn dialling_a_node_in_another_mode_fails() {
    // Modes do not interoperate in either direction.
    let mut encrypted = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let mut plain = Endpoint::bind_plain("127.0.0.1:0").expect("bind");
    let plain_addr = plain.local_addr().expect("addr");

    let peer = encrypted
        .connect(plain_addr, Some(&[0x22; 32]))
        .expect("dial");

    let deadline = Instant::now() + TIMEOUT;
    let mut failed = false;
    while !failed && Instant::now() < deadline {
        let _ = plain.poll(Some(Duration::from_millis(20)));
        if let Ok(Event::ConnectFailed { peer: got }) =
            encrypted.poll(Some(Duration::from_millis(20)))
        {
            assert_eq!(got, peer);
            failed = true;
        }
    }
    assert!(failed, "a plaintext node must not answer an encrypted dial");
    assert_eq!(plain.peer_count(), 0, "and must not record a session");
}

#[test]
fn a_dial_can_carry_zero_rtt_data() {
    let mut pair = Pair::public_key();
    let b_addr = pair.b.local_addr().expect("addr");
    pair.a
        .connect_and_send(b_addr, pair.b_public.as_ref(), b"hello on arrival")
        .expect("connect");

    let deadline = Instant::now() + TIMEOUT;
    let mut seen = None;
    while seen.is_none() && Instant::now() < deadline {
        let _ = pair.a.poll(Some(Duration::from_millis(20)));
        if let Ok(Event::Connected { zero_rtt, .. }) = pair.b.poll(Some(Duration::from_millis(20)))
        {
            seen = Some(zero_rtt);
        }
    }
    assert_eq!(
        seen.expect("B saw the connection"),
        b"hello on arrival",
        "a dial from an endpoint carries 0-RTT data just as a client's does"
    );
}
