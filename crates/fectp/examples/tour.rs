//! Compiles and runs every snippet in `docs/USAGE.md`.
//!
//! A usage guide whose examples do not compile is worse than none, so this
//! exercises each one against the real API.
//!
//! ```bash
//! cargo run -p fectp --example tour --features compress
//! ```

use std::time::Duration;

use fectp::{Connection, Event, Identity, PayloadType, Endpoint, Ticket};

fn main() -> fectp::Result<()> {
    identities()?;
    modes()?;
    shortest_pair()?;
    timeouts_and_zero_rtt()?;
    reliable_delivery()?;
    duplex()?;
    large_messages()?;
    typed_payloads()?;
    resumption()?;
    many_peers()?;
    peer_to_peer()?;
    length_masking()?;
    println!("\nevery documented snippet compiles and runs");
    Ok(())
}

/// USAGE.md — "Identities and keys"
fn identities() -> fectp::Result<()> {
    let identity = Identity::generate();
    let _public = *identity.public();
    let secret = *identity.secret();
    let restored = Identity::from_secret(secret);
    assert_eq!(identity.public(), restored.public());
    println!("identities: a stored secret restores the same public key");
    Ok(())
}

/// Runs `body` against an echo server already built in some mode.
fn with_server_mode<F, T>(mut server: Endpoint, body: F) -> fectp::Result<T>
where
    F: FnOnce(std::net::SocketAddr, Option<[u8; 32]>) -> fectp::Result<T>,
{
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let addr = server.local_addr()?;
    let public = server.public_key().copied();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            match server.poll(Some(Duration::from_millis(50))) {
                Ok(Event::Message { peer, data }) => {
                    let _ = server.send(peer, &data, PayloadType::Opaque);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    let result = body(addr, public);
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    result
}

/// Runs `body` against an echo server.
///
/// The resumption section reconnects, so this has to keep accepting while an
/// older session is still around.
fn with_server<F, T>(body: F) -> fectp::Result<T>
where
    F: FnOnce(std::net::SocketAddr, [u8; 32]) -> fectp::Result<T>,
{
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let identity = Identity::generate();
    let public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity)?;
    let addr = server.local_addr()?;

    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            match server.poll(Some(Duration::from_millis(50))) {
                Ok(Event::Message { peer, data }) => {
                    let _ = server.send(peer, &data, PayloadType::Opaque);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    let result = body(addr, public);
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    result
}

/// USAGE.md — "Choosing a mode"
fn modes() -> fectp::Result<()> {
    use fectp::Endpoint;
    const SECRET: &[u8] = b"lab-instrument-7";

    // Pre-shared key: encrypted, but nothing to distribute except the secret.
    let psk = with_server_mode(Endpoint::bind_psk("127.0.0.1:0", SECRET)?, |addr, _| {
        let conn = Connection::connect_psk(addr, SECRET)?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;
        conn.send(b"psk", PayloadType::Opaque)?;
        let mut buf = vec![0u8; 2048];
        let n = conn.recv(&mut buf)?;
        assert_eq!(&buf[..n], b"psk");
        Ok(conn.max_payload())
    })?;

    // Modes do not interoperate: nothing to negotiate, nothing to downgrade.
    // A full handshake aimed at a pre-shared-key server carries a frame type
    // that server has no arm for, so it is not answered.
    let refused = with_server_mode(Endpoint::bind_psk("127.0.0.1:0", SECRET)?, |addr, _| {
        let key = *Identity::generate().public();
        Ok(Connection::connect(addr, &key, &Identity::generate()).is_err())
    })?;
    assert!(refused, "a public-key client must not reach a pre-shared-key server");

    println!("modes: psk payload {psk}, mismatched modes refused");
    Ok(())
}

/// USAGE.md — "The shortest working pair"
fn shortest_pair() -> fectp::Result<()> {
    with_server(|addr, server_public| {
        let conn = Connection::connect(addr, &server_public, &Identity::generate())?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;
        conn.send(b"hello", PayloadType::Opaque)?;

        let mut buf = vec![0u8; 2048];
        let n = conn.recv(&mut buf)?;
        assert_eq!(&buf[..n], b"hello");
        println!("shortest pair: echoed {n} bytes, max payload {}", conn.max_payload());
        Ok(())
    })
}

/// USAGE.md — "Timeouts" and "Zero-RTT"
fn timeouts_and_zero_rtt() -> fectp::Result<()> {
    with_server(|addr, server_public| {
        let conn = Connection::connect_and_send(
            addr,
            &server_public,
            &Identity::generate(),
            b"first reading: 23.5",
        )?;
        conn.set_read_timeout(Some(Duration::from_millis(300)))?;

        // Nothing is coming, so this must report a timeout rather than hang.
        let mut buf = vec![0u8; 2048];
        match conn.recv(&mut buf) {
            Err(fectp::Error::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                println!("timeouts: read timed out as expected");
            }
            Ok(n) => println!("timeouts: unexpected {n} bytes"),
            Err(e) => return Err(e),
        }
        Ok(())
    })?;

    // A wrong server key means the server drops the frame; connect must not
    // hang forever.
    with_server(|addr, _real| {
        let wrong = *Identity::generate().public();
        // No timeout to pass: every way of opening a connection uses
        // `HANDSHAKE_TIMEOUT`, so an unreachable peer is reported rather than
        // waited on for ever.
        let outcome = Connection::connect(addr, &wrong, &Identity::generate());
        assert!(outcome.is_err(), "the wrong key must not connect");
        println!("timeouts: connecting with the wrong key fails instead of hanging");
        Ok(())
    })
}

/// USAGE.md — "Reliable delivery"
fn reliable_delivery() -> fectp::Result<()> {
    with_server(|addr, server_public| {
        let conn = Connection::connect(addr, &server_public, &Identity::generate())?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;

        conn.send_reliable(b"this must arrive", PayloadType::Opaque)?;
        assert_eq!(conn.unacknowledged(), 1);
        conn.flush(Duration::from_secs(2))?;
        assert_eq!(conn.unacknowledged(), 0);

        // More than the congestion window opens at, so this exercises the
        // waiting a caller has to be ready for.
        for i in 0..12u32 {
            while conn.send_reliable(&i.to_le_bytes(), PayloadType::Opaque).is_err() {
                conn.flush(Duration::from_secs(2))?;
            }
        }
        conn.flush(Duration::from_secs(2))?;

        println!(
            "reliable: acknowledged, retransmit timeout now {} ms (opens at {}, memory bound {})",
            conn.rto_ms(),
            fectp::INITIAL_CWND,
            fectp::MAX_UNACKED
        );
        Ok(())
    })
}

/// USAGE.md — "Sending and receiving at once"
fn duplex() -> fectp::Result<()> {
    with_server(|addr, server_public| {
        let conn = Connection::connect(addr, &server_public, &Identity::generate())?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;

        // Both directions on one `&Connection`, no wrapper and no conversion.
        std::thread::scope(|s| -> fectp::Result<()> {
            let reader = s.spawn(|| {
                let mut buf = [0u8; 2048];
                conn.recv(&mut buf).map(|n| buf[..n].to_vec())
            });

            std::thread::sleep(Duration::from_millis(20));
            conn.send(b"sent while the other thread is blocked reading", PayloadType::Opaque)?;

            let message = reader.join().expect("reader thread")?;
            assert_eq!(message, b"sent while the other thread is blocked reading");
            println!("duplex: {} bytes received on another thread", message.len());
            Ok(())
        })
    })
}

/// USAGE.md — "Large messages"
fn large_messages() -> fectp::Result<()> {
    with_server(|addr, server_public| {
        let conn = Connection::connect(addr, &server_public, &Identity::generate())?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;

        // Comfortably past what one frame carries, so the outbound trip
        // genuinely fragments. The filler is repetitive on purpose: the echo
        // server is an `Endpoint`, and the reply only
        // gets back because it codes down into a single frame.
        let recording = vec![0x5Au8; conn.max_payload() * 5];
        conn.send_reliable(&recording, PayloadType::Opaque).and_then(|()| conn.flush(Duration::from_secs(10)))?;

        let mut buf = vec![0u8; recording.len()];
        let n = conn.recv(&mut buf)?;
        assert_eq!(&buf[..n], &recording[..], "reassembled, and in one piece");

        println!(
            "large: {} bytes arrived as one message (frame limit {}, reliable {}, ceiling {})",
            n,
            conn.max_payload(),
            conn.max_reliable_payload(),
            fectp::MAX_MESSAGE_LEN
        );
        Ok(())
    })?;

    large_from_an_endpoint()
}

/// USAGE.md — "Large messages", the endpoint half.
fn large_from_an_endpoint() -> fectp::Result<()> {
    let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate())?;
    let addr = server.local_addr()?;
    let server_public = *server.public_key().expect("public-key mode");

    let recording = vec![0x7Eu8; 20_000];
    let expected = recording.clone();

    let worker = std::thread::spawn(move || -> fectp::Result<bool> {
        loop {
            match server.poll(Some(Duration::from_millis(50)))? {
                Event::Connected { peer, .. } => {
                    // Returns at once: an endpoint serving many peers cannot
                    // wait on one of them.
                    server.send_reliable(peer, &recording, PayloadType::Opaque)?;
                }
                Event::Sent { delivered, .. } => return Ok(delivered),
                _ => {}
            }
        }
    });

    let conn = Connection::connect(addr, &server_public, &Identity::generate())?;
    conn.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut buf = vec![0u8; expected.len()];
    let n = conn.recv(&mut buf)?;
    assert_eq!(&buf[..n], &expected[..]);

    let delivered = worker.join().expect("worker thread")?;
    println!(
        "large from endpoint: {n} bytes queued and fed out by poll, delivered {delivered} (queue limit {} per peer)",
        fectp::MAX_QUEUED
    );
    Ok(())
}

/// USAGE.md — "Typed payloads"
fn typed_payloads() -> fectp::Result<()> {
    with_server(|addr, server_public| {
        let conn = Connection::connect(addr, &server_public, &Identity::generate())?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;

        // Four interleaved channels of slowly varying i16.
        let samples: Vec<u8> = (0..512i16).flat_map(|i| (i / 4).to_le_bytes()).collect();
        conn.send(&samples, PayloadType::I16 { channels: 4 })?;

        let mut buf = vec![0u8; 64 * 1024];
        let n = conn.recv(&mut buf)?;
        assert_eq!(&buf[..n], &samples[..]);

        // A shape is named at every call, so bind it once and pass it. There
        // is no setting to make, and none to forget.
        let shape = PayloadType::I16 { channels: 4 };
        conn.send(&samples, shape)?;
        let n = conn.recv(&mut buf)?;
        assert_eq!(&buf[..n], &samples[..]);

        // A message of a different shape says so, on its own line.
        conn.send(b"a status line", PayloadType::Opaque)?;
        let n = conn.recv(&mut buf)?;
        assert_eq!(&buf[..n], b"a status line");

        println!(
            "typed payloads: {} bytes of i16 x4 round-tripped, shape named per send",
            samples.len()
        );
        Ok(())
    })
}

/// USAGE.md — "Resumption"
fn resumption() -> fectp::Result<()> {
    with_server(|addr, server_public| {
        let identity = Identity::generate();
        let conn = Connection::connect(addr, &server_public, &identity)?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;
        conn.send(b"first", PayloadType::Opaque)?;
        let mut buf = vec![0u8; 2048];
        conn.recv(&mut buf)?;

        // Persist the 32-byte key; the identifier is derived from it.
        let key: [u8; 32] = *conn.resumption_ticket().expect("encrypted").key();
        drop(conn);

        // Always keep the full-handshake fallback: a restarted or forgetful
        // server cannot answer a resumption.
        let ticket = Ticket::from_key(key);
        let conn = match Connection::resume(addr, &ticket, &server_public) {
            Ok(conn) => {
                println!("resumption: resumed with one Diffie-Hellman instead of four");
                conn
            }
            Err(_) => {
                println!("resumption: ticket refused, fell back to a full handshake");
                Connection::connect(addr, &server_public, &identity)?
            }
        };

        conn.set_read_timeout(Some(Duration::from_secs(5)))?;
        conn.send(b"second", PayloadType::Opaque)?;
        let n = conn.recv(&mut buf)?;
        assert_eq!(&buf[..n], b"second");

        // The next ticket replaces the spent one.
        assert_ne!(conn.resumption_ticket().expect("encrypted").id(), ticket.id());
        Ok(())
    })
}

/// USAGE.md — "Serving many peers"
fn many_peers() -> fectp::Result<()> {
    const PEERS: usize = 3;

    let identity = Identity::generate();
    let server_public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity)?;
    let addr = server.local_addr()?;

    let clients = std::thread::spawn(move || -> fectp::Result<()> {
        let mut conns: Vec<Connection> = (0..PEERS)
            .map(|_| {
                let c = Connection::connect(addr, &server_public, &Identity::generate())?;
                c.set_read_timeout(Some(Duration::from_secs(5)))?;
                Ok(c)
            })
            .collect::<fectp::Result<_>>()?;

        let mut buf = vec![0u8; 4096];
        for (index, conn) in conns.iter_mut().enumerate() {
            let message = format!("from client {index}");
            conn.send(message.as_bytes(), PayloadType::Opaque)?;
            let n = conn.recv(&mut buf)?;
            assert_eq!(&buf[..n], message.as_bytes(), "crossed wires");
        }
        Ok(())
    });

    let mut echoed = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while echoed < PEERS && std::time::Instant::now() < deadline {
        match server.poll(Some(Duration::from_millis(100)))? {
            Event::Connected {
                peer,
                zero_rtt,
                resumed,
                ..
            } => {
                assert!(zero_rtt.is_empty() && !resumed);
                assert!(server.peer_public_key(peer).is_some());
            }
            Event::Message { peer, data } => {
                server.send(peer, &data, PayloadType::Opaque)?;
                echoed += 1;
            }
            Event::Idle => {}
            // `Event` is non-exhaustive, so a wildcard arm is required.
            _ => {}
        }
    }

    clients.join().expect("client thread")?;
    println!(
        "many peers: {echoed} messages echoed across {} peers on one socket",
        server.peer_count()
    );

    // Handles stop resolving once a peer is dropped.
    if let Some(&peer) = server.peers().first() {
        assert!(server.disconnect(peer));
        assert!(server.send(peer, b"gone", PayloadType::Opaque).is_err());
    }
    Ok(())
}

/// USAGE.md — "Peers, not clients and servers"
fn peer_to_peer() -> fectp::Result<()> {
    // Two nodes, one socket each, both able to dial and to listen.
    let mut a = Endpoint::bind_psk("127.0.0.1:0", b"mesh-secret")?;
    let mut b = Endpoint::bind_psk("127.0.0.1:0", b"mesh-secret")?;
    let b_addr = b.local_addr()?;

    // `connect` returns at once; the handshake finishes during `poll`.
    a.connect(b_addr, None)?;

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let (mut on_a, mut on_b) = (None, None);
    while (on_a.is_none() || on_b.is_none()) && std::time::Instant::now() < deadline {
        if let Ok(Event::Connected { peer, initiated, .. }) = a.poll(Some(Duration::from_millis(20)))
        {
            assert!(initiated, "A dialled");
            on_a = Some(peer);
        }
        if let Ok(Event::Connected { peer, initiated, .. }) = b.poll(Some(Duration::from_millis(20)))
        {
            assert!(!initiated, "B was dialled");
            on_b = Some(peer);
        }
    }
    let (on_a, on_b) = (on_a.expect("A connected"), on_b.expect("B connected"));

    // The responder can send just as freely as the initiator.
    b.send(on_b, b"from the side that was dialled", PayloadType::Opaque)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut heard = None;
    while heard.is_none() && std::time::Instant::now() < deadline {
        if let Ok(Event::Message { data, .. }) = a.poll(Some(Duration::from_millis(20))) {
            heard = Some(data);
        }
    }
    assert_eq!(heard.expect("A hears B"), b"from the side that was dialled");
    let _ = on_a;

    println!("peer to peer: both nodes dial and listen on one socket each");
    Ok(())
}

/// USAGE.md — "Length masking"
fn length_masking() -> fectp::Result<()> {
    with_server(|addr, server_public| {
        let conn = Connection::connect(addr, &server_public, &Identity::generate())?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;
        conn.set_padding(true);

        conn.send(b"short", PayloadType::Opaque)?;
        let mut buf = vec![0u8; 2048];
        let n = conn.recv(&mut buf)?;
        assert_eq!(&buf[..n], b"short");
        println!("length masking: padded frames round-trip unchanged");
        Ok(())
    })
}
