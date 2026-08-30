//! Many peers over one socket.
//!
//! The failure this guards against is subtle: with a naive design each
//! connection reads from a shared socket and discards what is not addressed to
//! it, so two concurrent peers silently eat each other's datagrams. These tests
//! run peers genuinely at the same time, not one after another.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use fectp::{Connection, Event, Identity, PayloadType, Endpoint, Ticket};

const TIMEOUT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(200);

/// Runs an echo server until it has echoed `expected` messages.
fn spawn_echo(mut server: Endpoint, expected: usize) -> (mpsc::Receiver<()>, thread::JoinHandle<usize>) {
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        ready_tx.send(()).expect("ready");
        let mut echoed = 0usize;
        let deadline = std::time::Instant::now() + TIMEOUT;
        while echoed < expected && std::time::Instant::now() < deadline {
            match server.poll(Some(POLL)) {
                Ok(Event::Message { peer, data }) => {
                    server.send(peer, &data).expect("echo");
                    echoed += 1;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        echoed
    });
    (ready_rx, handle)
}

fn server() -> (Endpoint, std::net::SocketAddr, [u8; 32]) {
    let identity = Identity::generate();
    let public = *identity.public();
    let server = Endpoint::bind("127.0.0.1:0", identity).expect("bind");
    let addr = server.local_addr().expect("addr");
    (server, addr, public)
}

#[test]
fn concurrent_peers_do_not_steal_each_others_traffic() {
    const PEERS: usize = 8;
    const PER_PEER: usize = 5;

    let (server, addr, public) = server();
    let (ready, handle) = spawn_echo(server, PEERS * PER_PEER);
    ready.recv().expect("server ready");

    // All clients connect first, then all talk, so their traffic genuinely
    // interleaves on the one socket.
    let mut clients: Vec<Connection> = (0..PEERS)
        .map(|_| {
            let mut c = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
            c.set_read_timeout(Some(TIMEOUT)).expect("timeout");
            c
        })
        .collect();

    for round in 0..PER_PEER {
        for (index, client) in clients.iter_mut().enumerate() {
            let message = format!("peer {index} round {round}");
            client.send(message.as_bytes()).expect("send");

            let mut buf = vec![0u8; 4096];
            let n = client.recv(&mut buf).expect("recv");
            assert_eq!(
                &buf[..n],
                message.as_bytes(),
                "peer {index} received another peer's message"
            );
        }
    }

    assert_eq!(handle.join().expect("thread"), PEERS * PER_PEER);
}

#[test]
fn the_server_tracks_each_peer_separately() {
    const PEERS: usize = 4;
    let (mut server, addr, public) = server();

    let identities: Vec<Identity> = (0..PEERS).map(|_| Identity::generate()).collect();
    let publics: Vec<[u8; 32]> = identities.iter().map(|i| *i.public()).collect();

    let handle = thread::spawn(move || {
        let mut clients = Vec::new();
        for identity in &identities {
            clients.push(Connection::connect(addr, &public, identity).expect("connect"));
        }
        // Hold the connections open until the server has seen them all.
        thread::sleep(Duration::from_millis(300));
        clients.len()
    });

    let mut connected = Vec::new();
    while connected.len() < PEERS {
        match server.poll(Some(TIMEOUT)) {
            Ok(Event::Connected { peer, resumed, .. }) => {
                assert!(!resumed, "these are full handshakes");
                connected.push(peer);
            }
            Ok(_) => {}
            Err(e) => panic!("poll failed: {e}"),
        }
    }

    assert_eq!(server.peer_count(), PEERS);
    let mut seen: Vec<[u8; 32]> = connected
        .iter()
        .map(|p| *server.peer_public_key(*p).expect("known peer"))
        .collect();
    seen.sort();
    let mut expected = publics.clone();
    expected.sort();
    assert_eq!(
        seen, expected,
        "each peer must be authenticated and tracked as a distinct identity"
    );

    // Handles are distinct and addressable.
    assert_eq!(server.peers().len(), PEERS);
    handle.join().expect("thread");
}

#[test]
fn a_disconnected_peer_stops_resolving() {
    let (mut server, addr, public) = server();
    let handle = thread::spawn(move || {
        let mut client = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
        client.set_read_timeout(Some(TIMEOUT)).expect("timeout");
        client.send(b"hello").expect("send");
        thread::sleep(Duration::from_millis(300));
    });

    let peer = loop {
        match server.poll(Some(TIMEOUT)).expect("poll") {
            Event::Connected { peer, .. } => break peer,
            _ => continue,
        }
    };

    assert!(server.disconnect(peer));
    assert_eq!(server.peer_count(), 0);
    assert!(!server.disconnect(peer), "a second disconnect is a no-op");
    assert!(server.send(peer, b"gone").is_err());
    assert!(server.peer_public_key(peer).is_none());

    handle.join().expect("thread");
}

#[test]
fn the_server_delivers_reliably_to_a_chosen_peer() {
    const PEERS: usize = 3;
    let (mut server, addr, public) = server();

    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut clients: Vec<Connection> = (0..PEERS)
            .map(|_| {
                let mut c =
                    Connection::connect(addr, &public, &Identity::generate()).expect("connect");
                c.set_read_timeout(Some(TIMEOUT)).expect("timeout");
                c
            })
            .collect();
        tx.send(()).expect("connected");

        // Only the second client should hear anything.
        let mut buf = vec![0u8; 4096];
        let got = clients[1].recv(&mut buf).expect("recv");
        buf[..got].to_vec()
    });

    let mut peers = Vec::new();
    while peers.len() < PEERS {
        if let Ok(Event::Connected { peer, .. }) = server.poll(Some(TIMEOUT)) {
            peers.push(peer);
        }
    }
    rx.recv().expect("clients connected");

    server
        .send_reliable(peers[1], b"only for the second peer")
        .expect("send reliable");
    assert_eq!(server.unacknowledged(peers[1]), 1);

    // Poll until the acknowledgement lands.
    let deadline = std::time::Instant::now() + TIMEOUT;
    while server.unacknowledged(peers[1]) > 0 && std::time::Instant::now() < deadline {
        let _ = server.poll(Some(Duration::from_millis(50)));
    }
    assert_eq!(
        server.unacknowledged(peers[1]),
        0,
        "the peer must have acknowledged"
    );

    assert_eq!(handle.join().expect("thread"), b"only for the second peer");
}

#[test]
fn a_peer_can_resume_against_the_server() {
    let (mut server, addr, public) = server();

    let (ticket_tx, ticket_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let handle = thread::spawn(move || {
        let mut client = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
        client.set_read_timeout(Some(TIMEOUT)).expect("timeout");
        client.send(b"first").expect("send");
        let mut buf = vec![0u8; 4096];
        client.recv(&mut buf).expect("echo");
        let key = *client.resumption_ticket().expect("encrypted session").key();
        drop(client);
        ticket_tx.send(key).expect("ticket");

        go_rx.recv().expect("go");
        let mut resumed = Connection::resume(
            addr,
            &Ticket::from_key(key),
            &public,
            Duration::from_millis(700),
        )
        .expect("resume");
        resumed.set_read_timeout(Some(TIMEOUT)).expect("timeout");
        resumed.send(b"second").expect("send");
        let n = resumed.recv(&mut buf).expect("echo");
        buf[..n].to_vec()
    });

    // Serve the first connection.
    let mut echoed = 0;
    let mut resumed_seen = false;
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut sent_go = false;
    while echoed < 2 && std::time::Instant::now() < deadline {
        match server.poll(Some(Duration::from_millis(100))) {
            Ok(Event::Message { peer, data }) => {
                server.send(peer, &data).expect("echo");
                echoed += 1;
                if !sent_go {
                    // The client has its ticket now; let it reconnect.
                    let _ = ticket_rx.recv_timeout(TIMEOUT);
                    go_tx.send(()).expect("go");
                    sent_go = true;
                }
            }
            Ok(Event::Connected { resumed, .. }) => resumed_seen |= resumed,
            _ => {}
        }
    }

    assert!(resumed_seen, "the server must report the second peer as resumed");
    assert_eq!(handle.join().expect("thread"), b"second");
}

#[test]
fn typed_payloads_work_per_peer() {
    let (mut server, addr, public) = server();

    let handle = thread::spawn(move || {
        let mut client = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
        client.set_read_timeout(Some(TIMEOUT)).expect("timeout");
        client.send(b"ping").expect("send");
        let mut buf = vec![0u8; 64 * 1024];
        let n = client.recv(&mut buf).expect("recv");
        buf[..n].to_vec()
    });

    let samples: Vec<u8> = (0..512i16).flat_map(|i| (i / 4).to_le_bytes()).collect();
    let peer = loop {
        match server.poll(Some(TIMEOUT)).expect("poll") {
            Event::Message { peer, .. } => break peer,
            _ => continue,
        }
    };
    assert!(server.set_default_payload_type(peer, PayloadType::I16 { channels: 4 }));
    server
        .send_typed(peer, &samples, PayloadType::I16 { channels: 4 })
        .expect("send typed");

    assert_eq!(
        handle.join().expect("thread"),
        samples,
        "coding must work through the server path too"
    );
}

#[test]
fn garbage_and_stray_datagrams_are_ignored() {
    use std::net::UdpSocket;

    let (mut server, addr, public) = server();
    let handle = thread::spawn(move || {
        // Noise from an unrelated sender, before and after a real client.
        let stray = UdpSocket::bind("127.0.0.1:0").expect("bind");
        stray.send_to(&[0xFF; 64], addr).expect("noise");
        stray.send_to(b"not a frame", addr).expect("noise");

        let mut client = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
        client.set_read_timeout(Some(TIMEOUT)).expect("timeout");
        stray.send_to(&[0x11; 200], addr).expect("noise");
        client.send(b"real message").expect("send");

        let mut buf = vec![0u8; 4096];
        let n = client.recv(&mut buf).expect("recv");
        buf[..n].to_vec()
    });

    let deadline = std::time::Instant::now() + TIMEOUT;
    while std::time::Instant::now() < deadline {
        match server.poll(Some(Duration::from_millis(100))).expect("poll") {
            Event::Message { peer, data } => {
                assert_eq!(data, b"real message");
                server.send(peer, &data).expect("echo");
                break;
            }
            _ => continue,
        }
    }

    assert_eq!(handle.join().expect("thread"), b"real message");
    assert_eq!(
        server.peer_count(),
        1,
        "noise must not create phantom sessions"
    );
}
