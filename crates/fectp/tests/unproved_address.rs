//! What an endpoint will send to an address that has proved nothing.
//!
//! [D57](../../../docs/DECISIONS.md) settled this for keep-alives: "One
//! datagram in must not buy a stream out". Reaching the peer table needs the
//! endpoint's public key — public by design — and one datagram, and the source
//! address on that datagram is whatever the sender wrote. So a session can be
//! filed pointing at an address that never asked for anything, and D57 stopped
//! `drive_keepalives` aiming 38 bytes there on every interval.
//!
//! `Endpoint::send` was not part of that decision, and these measure where it
//! leaves things. Nothing here is a bug report: what a caller sends is the
//! caller's, and an endpoint that refused to answer 0-RTT data until the
//! address answered a challenge would give up the round trip this protocol
//! exists to save. The point is that the property is *measured* and named, so
//! that `docs/THREAT-MODEL.md` can say what is true rather than what reads
//! well.

use std::time::{Duration, Instant};

use fectp::{Endpoint, Event, Identity, PayloadType};

/// A reply to 0-RTT data goes out before the address has proved anything.
///
/// The client completes a handshake carrying 0-RTT and then says nothing more,
/// which is the state a spoofed opening frame leaves behind: a session filed
/// against an address that has sent one datagram and authenticated nothing
/// since. The server answers anyway.
///
/// The size is what makes it worth naming. The handshake reply is 70 bytes and
/// is capped at three resends (D33); the *application's* answer is whatever the
/// application chose, and nothing in this protocol bounds it.
#[test]
fn a_reply_goes_to_an_address_that_has_not_answered() {
    let identity = Identity::generate();
    let key = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("server");
    let addr = server.local_addr().expect("addr");

    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("client");
    client
        .connect_and_send(addr, Some(&key), b"one small datagram")
        .expect("connect");

    // Drive until the server has the session. The client is polled too, because
    // its own handshake has to complete for it to read anything later; what it
    // does not do is send a data frame, so nothing authenticated ever arrives
    // at the server from this address.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = None;
    while Instant::now() < deadline && peer.is_none() {
        if let Ok(Event::Connected { peer: id, zero_rtt, .. }) =
            server.poll(Some(Duration::from_millis(1)))
        {
            assert_eq!(zero_rtt, b"one small datagram");
            peer = Some(id);
        }
        let _ = client.poll(Some(Duration::from_millis(1)));
    }
    let peer = peer.expect("the server must have filed the session");

    // One frame's worth. `send` is capped by what the peer advertised as its
    // largest acceptable frame, which is the first real bound here and is
    // easily missed: a single unreliable send cannot amplify past one datagram.
    let answer = vec![0x5a; 1024];
    server
        .send(peer, &answer, PayloadType::Opaque)
        .expect("the send is accepted");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut arrived = false;
    while Instant::now() < deadline && !arrived {
        let _ = server.poll(Some(Duration::from_millis(1)));
        if let Ok(Event::Message { data, .. }) = client.poll(Some(Duration::from_millis(1))) {
            assert_eq!(data.len(), answer.len());
            arrived = true;
        }
    }

    assert!(
        arrived,
        "the answer never reached the address. If `send` has grown a check on \
         whether the address has proved it can receive, docs/THREAT-MODEL.md \
         says the opposite and needs changing with this test."
    );
}

/// The same session, before it has spoken, is the first thing evicted.
///
/// The counterweight, and the reason this is a bounded exposure rather than an
/// open one: a session that has authenticated nothing is what `make_room` drops
/// first, and `resumption_replay.rs` measures that from the other direction.
/// Here it is measured from this one — the peer filed by an opening frame and
/// nothing else does not survive pressure.
#[test]
fn a_session_that_has_not_spoken_is_evicted_first() {
    let identity = Identity::generate();
    let key = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("server");
    server.set_max_peers(4);
    let addr = server.local_addr().expect("addr");

    // One peer that speaks, and one that only ever completes a handshake.
    let mut talker = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("talker");
    let mut silent = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("silent");

    let connect = |client: &mut Endpoint, server: &mut Endpoint| {
        client.connect(addr, Some(&key)).expect("connect");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut id = None;
        while Instant::now() < deadline && id.is_none() {
            if let Ok(Event::Connected { peer, .. }) = server.poll(Some(Duration::from_millis(1))) {
                id = Some(peer);
            }
            let _ = client.poll(Some(Duration::from_millis(1)));
        }
        id.expect("the server must file the session")
    };

    let talker_peer = connect(&mut talker, &mut server);
    let silent_peer = connect(&mut silent, &mut server);

    // The talker authenticates something, which is the only thing that
    // distinguishes it.
    let talker_id = talker
        .peers()
        .first()
        .copied()
        .expect("the talker has its own peer handle");
    talker
        .send(talker_id, b"hello", PayloadType::Opaque)
        .expect("send");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut heard = false;
    while Instant::now() < deadline && !heard {
        if let Ok(Event::Message { .. }) = server.poll(Some(Duration::from_millis(1))) {
            heard = true;
        }
        let _ = talker.poll(Some(Duration::from_millis(1)));
    }
    assert!(heard, "the talker's frame must arrive");

    // Fill the table past its bound with more never-spoken sessions.
    let mut crowd = Vec::new();
    for _ in 0..6 {
        let mut e = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("crowd");
        connect(&mut e, &mut server);
        crowd.push(e);
    }

    let held = server.peers();
    assert!(
        held.contains(&talker_peer),
        "the peer that authenticated a frame was evicted"
    );
    assert!(
        !held.contains(&silent_peer),
        "the peer that only completed a handshake survived a full table, so \
         eviction is no longer preferring sessions that have never spoken"
    );
}
