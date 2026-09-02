//! A peer that changes address part-way through a session.
//!
//! A NAT whose mapping expires re-creates it on a different port; a phone
//! moving from Wi-Fi to a cellular network changes address outright. In both
//! cases the peer is the same peer and holds the same keys — nothing about the
//! session has ended except the tuple it was filed under.
//!
//! The property that has to hold alongside the migration is the negative one:
//! **an address that has not proved it can receive must not be sent to.** A
//! session that followed any authentic-looking frame to its source would be a
//! way to point a data stream at a third party who never asked for it.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

const TIMEOUT: Duration = Duration::from_secs(5);

// --------------------------------------------------------------- harness ---

/// An echo server on its own thread, stopped when the guard is dropped.
struct Echo {
    addr: SocketAddr,
    public: [u8; 32],
    stop: Arc<AtomicBool>,
    moves: Arc<Mutex<Vec<(SocketAddr, SocketAddr)>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Echo {
    fn spawn() -> Self {
        Self::spawn_with_migrations(fectp::MAX_MIGRATIONS_PER_SECOND)
    }

    fn spawn_with_migrations(rate: u32) -> Self {
        let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        server.set_max_migrations_per_second(rate);
        let addr = server.local_addr().expect("addr");
        let public = *server.public_key().expect("identity");
        let stop = Arc::new(AtomicBool::new(false));
        let moves = Arc::new(Mutex::new(Vec::new()));
        let flag = Arc::clone(&stop);
        let seen = Arc::clone(&moves);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match server.poll(Some(Duration::from_millis(20))) {
                    Ok(Event::Message { peer, data }) => {
                        let _ = server.send(peer, &data, PayloadType::Opaque);
                    }
                    Ok(Event::PeerMoved { from, to, .. }) => {
                        seen.lock().expect("lock").push((from, to));
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            public,
            stop,
            moves,
            handle: Some(handle),
        }
    }

    fn moves(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.moves.lock().expect("lock").clone()
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A relay that forwards from one source port and then, part-way through,
/// from another — which is what a NAT does when its mapping is re-created.
struct Rebinding {
    addr: SocketAddr,
    forwarded: Arc<AtomicU64>,
    rebound: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl Rebinding {
    /// Forwards the first `after` datagrams from one port, the rest from a
    /// second one.
    fn spawn(server: SocketAddr, after: u64) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
        front
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");
        let addr = front.local_addr().expect("addr");

        let stop = Arc::new(AtomicBool::new(false));
        let forwarded = Arc::new(AtomicU64::new(0));
        let rebound = Arc::new(AtomicBool::new(false));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        let mut ports = Vec::new();
        for _ in 0..2 {
            let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
            back.connect(server).expect("connect back");
            back.set_read_timeout(Some(Duration::from_millis(20)))
                .expect("timeout");
            ports.push(back);
        }

        // Client to server, switching source port after `after` datagrams.
        {
            let front = front.try_clone().expect("clone");
            let out: Vec<UdpSocket> = ports
                .iter()
                .map(|s| s.try_clone().expect("clone"))
                .collect();
            let flag = Arc::clone(&stop);
            let count = Arc::clone(&forwarded);
            let moved = Arc::clone(&rebound);
            let learn = Arc::clone(&client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok((n, from)) = front.recv_from(&mut buf) else {
                        continue;
                    };
                    *learn.lock().expect("lock") = Some(from);
                    let seen = count.fetch_add(1, Ordering::SeqCst) + 1;
                    let which = if seen > after {
                        moved.store(true, Ordering::SeqCst);
                        1
                    } else {
                        0
                    };
                    let _ = out[which].send(&buf[..n]);
                }
            });
        }

        // Server to client, on both back ports.
        for back in ports {
            let front = front.try_clone().expect("clone");
            let flag = Arc::clone(&stop);
            let learn = Arc::clone(&client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok(n) = back.recv(&mut buf) else {
                        continue;
                    };
                    let target = *learn.lock().expect("lock");
                    if let Some(target) = target {
                        let _ = front.send_to(&buf[..n], target);
                    }
                }
            });
        }

        Self {
            addr,
            forwarded,
            rebound,
            stop,
        }
    }

    fn has_rebound(&self) -> bool {
        self.rebound.load(Ordering::SeqCst)
    }

    fn forwarded(&self) -> u64 {
        self.forwarded.load(Ordering::SeqCst)
    }
}

impl Drop for Rebinding {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}


/// A relay that can hand one datagram to the server from a second source port
/// and then say nothing more from it — an on-path attacker forwarding a
/// genuine frame under an address it wants the session pointed at.
///
/// Nothing arriving on that second port is ever passed back to the client, so
/// the address is heard from once and is silent afterwards. Whatever the
/// server sends there is counted instead.
struct Tap {
    addr: SocketAddr,
    steal: Arc<AtomicBool>,
    side_bytes: Arc<AtomicU64>,
    side_datagrams: Arc<AtomicU64>,
    stole: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl Tap {
    fn spawn(server: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
        front
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");
        let addr = front.local_addr().expect("addr");

        let main = UdpSocket::bind("127.0.0.1:0").expect("bind main");
        main.connect(server).expect("connect main");
        main.set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");

        let side = UdpSocket::bind("127.0.0.1:0").expect("bind side");
        side.connect(server).expect("connect side");
        side.set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");

        let stop = Arc::new(AtomicBool::new(false));
        let steal = Arc::new(AtomicBool::new(false));
        let stole = Arc::new(AtomicBool::new(false));
        let side_bytes = Arc::new(AtomicU64::new(0));
        let side_datagrams = Arc::new(AtomicU64::new(0));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        // Client to server, out of one port or the other.
        {
            let front = front.try_clone().expect("clone");
            let main = main.try_clone().expect("clone");
            let side = side.try_clone().expect("clone");
            let flag = Arc::clone(&stop);
            let take = Arc::clone(&steal);
            let took = Arc::clone(&stole);
            let learn = Arc::clone(&client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok((n, from)) = front.recv_from(&mut buf) else {
                        continue;
                    };
                    *learn.lock().expect("lock") = Some(from);
                    if take.swap(false, Ordering::SeqCst) {
                        took.store(true, Ordering::SeqCst);
                        let _ = side.send(&buf[..n]);
                    } else {
                        let _ = main.send(&buf[..n]);
                    }
                }
            });
        }

        // Server to client, on the honest port only.
        {
            let front = front.try_clone().expect("clone");
            let flag = Arc::clone(&stop);
            let learn = Arc::clone(&client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok(n) = main.recv(&mut buf) else {
                        continue;
                    };
                    let target = *learn.lock().expect("lock");
                    if let Some(target) = target {
                        let _ = front.send_to(&buf[..n], target);
                    }
                }
            });
        }

        // Whatever the server sends to the stolen address is counted and
        // dropped. This address never answers anything.
        {
            let flag = Arc::clone(&stop);
            let bytes = Arc::clone(&side_bytes);
            let count = Arc::clone(&side_datagrams);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok(n) = side.recv(&mut buf) else {
                        continue;
                    };
                    bytes.fetch_add(n as u64, Ordering::SeqCst);
                    count.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        Self {
            addr,
            steal,
            side_bytes,
            side_datagrams,
            stole,
            stop,
        }
    }

    /// Hands the next datagram to the server from the second port.
    fn steal_next(&self) {
        self.steal.store(true, Ordering::SeqCst);
    }

    fn stole(&self) -> bool {
        self.stole.load(Ordering::SeqCst)
    }

    fn side_bytes(&self) -> u64 {
        self.side_bytes.load(Ordering::SeqCst)
    }

    fn side_datagrams(&self) -> u64 {
        self.side_datagrams.load(Ordering::SeqCst)
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A plain forwarding relay that keeps a copy of the last datagram it passed
/// from the client, so a test can send it again from elsewhere.
struct Recording {
    addr: SocketAddr,
    last: Arc<Mutex<Option<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
}

impl Recording {
    fn spawn(server: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
        front
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");
        let addr = front.local_addr().expect("addr");

        let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
        back.connect(server).expect("connect back");
        back.set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");

        let stop = Arc::new(AtomicBool::new(false));
        let last = Arc::new(Mutex::new(None));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        {
            let front = front.try_clone().expect("clone");
            let back = back.try_clone().expect("clone");
            let flag = Arc::clone(&stop);
            let seen = Arc::clone(&last);
            let learn = Arc::clone(&client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok((n, from)) = front.recv_from(&mut buf) else {
                        continue;
                    };
                    *learn.lock().expect("lock") = Some(from);
                    *seen.lock().expect("lock") = Some(buf[..n].to_vec());
                    let _ = back.send(&buf[..n]);
                }
            });
        }

        {
            let flag = Arc::clone(&stop);
            let learn = Arc::clone(&client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok(n) = back.recv(&mut buf) else {
                        continue;
                    };
                    let target = *learn.lock().expect("lock");
                    if let Some(target) = target {
                        let _ = front.send_to(&buf[..n], target);
                    }
                }
            });
        }

        Self { addr, last, stop }
    }

    fn last(&self) -> Option<Vec<u8>> {
        self.last.lock().expect("lock").clone()
    }
}

impl Drop for Recording {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Sends `message` once and waits for the echo, returning what came back.
///
/// One datagram out, one back, with no retry: use it where a *failure* is the
/// outcome being measured.
fn exchange(conn: &mut Connection, message: &[u8]) -> fectp::Result<Vec<u8>> {
    exchange_within(conn, message, TIMEOUT)
}

fn exchange_within(
    conn: &mut Connection,
    message: &[u8],
    timeout: Duration,
) -> fectp::Result<Vec<u8>> {
    conn.set_read_timeout(Some(timeout))?;
    conn.send(message, PayloadType::Opaque)?;
    let mut buf = vec![0u8; 8 * 1024];
    let n = conn.recv(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// Sends `message` until the echo comes back, or until `TIMEOUT` has passed.
///
/// These tests run over a relay of their own, on loopback, and a relay is a
/// network: it may drop a datagram. `send` is unreliable by definition, so one
/// lost datagram is one lost message and nothing has gone wrong with the
/// protocol — an application that cannot lose a message asks for
/// `send_reliable`, and one that retries is doing what this does.
///
/// This matters because a single unanswered exchange was reported as a failed
/// migration about once in thirty runs, which is a test asserting that the
/// network is lossless while claiming to assert something else.
fn exchange_retrying(conn: &mut Connection, message: &[u8]) -> fectp::Result<Vec<u8>> {
    let deadline = Instant::now() + TIMEOUT;
    let mut last = None;
    while Instant::now() < deadline {
        match exchange_within(conn, message, Duration::from_millis(400)) {
            Ok(reply) => return Ok(reply),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("the deadline must allow at least one attempt"))
}

// -------------------------------------------------------------- the tests ---

#[test]
fn a_peer_that_changes_address_keeps_its_session() {
    let echo = Echo::spawn();
    // The handshake is two datagrams out of the client; rebinding after four
    // puts the change squarely in the data phase, not in the handshake.
    let relay = Rebinding::spawn(echo.addr, 4);
    let mut conn =
        Connection::connect(relay.addr, &echo.public, &Identity::generate()).expect("connect");

    // Control. If this fails the test proves nothing about migration.
    assert_eq!(
        exchange_retrying(&mut conn, b"before the move").expect("control exchange"),
        b"before the move",
        "the session must work before the address changes"
    );

    // Drive datagrams until the relay has actually switched ports. Asserting
    // afterwards on a rebind that never happened is the way this test lies.
    let deadline = Instant::now() + TIMEOUT;
    while !relay.has_rebound() && Instant::now() < deadline {
        let _ = exchange(&mut conn, b"filler");
    }
    assert!(
        relay.has_rebound(),
        "the relay never switched ports after {} datagrams; nothing was tested",
        relay.forwarded()
    );

    // The peer is the same peer, holding the same keys, arriving from a
    // different port. Its session should survive the change.
    assert_eq!(
        exchange_retrying(&mut conn, b"after the move").expect("exchange after the move"),
        b"after the move",
        "a peer that changed address must keep its session"
    );

    let moves = echo.moves();
    assert_eq!(moves.len(), 1, "exactly one move should be reported");
    assert_ne!(moves[0].0, moves[0].1, "a move goes from one address to another");
}

#[test]
fn an_address_that_never_answers_does_not_get_the_session() {
    // The frame handed over from the second port is genuine: the peer sealed
    // it, it is fresh, and it authenticates. That is exactly the case where
    // moving the session on the strength of authentication alone would be
    // wrong — it proves who sent the bytes, not who is at the address they
    // arrived from.
    let echo = Echo::spawn();
    let tap = Tap::spawn(echo.addr);
    let mut conn =
        Connection::connect(tap.addr, &echo.public, &Identity::generate()).expect("connect");

    assert_eq!(
        exchange_retrying(&mut conn, b"control").expect("control exchange"),
        b"control",
        "the session must work before anything is stolen"
    );

    // A payload large enough that an echo of it could not be mistaken for a
    // challenge, if one were ever sent to the address that never asked.
    let payload = vec![0x5Au8; 512];
    tap.steal_next();
    conn.set_read_timeout(Some(Duration::from_millis(400)))
        .expect("timeout");
    conn.send(&payload, PayloadType::Opaque).expect("send");
    // The echo comes back to the old address, which the client is no longer
    // being relayed from for this one datagram, so nothing is expected here.
    let mut buf = vec![0u8; 8 * 1024];
    let _ = conn.recv(&mut buf);
    assert!(tap.stole(), "the relay never handed a datagram over");

    // Give the server time to send everything it was ever going to send to
    // that address.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        conn.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        let _ = exchange(&mut conn, b"carry on");
    }

    // Nothing but challenges may have gone to the silent address. A challenge
    // is 38 bytes and at most three are sent, so anything approaching the size
    // of the payload means the data stream followed the frame.
    assert!(
        tap.side_bytes() < payload.len() as u64,
        "an address that never answered received {} bytes across {} datagrams; \
         the echo of a {}-byte payload must not have gone there",
        tap.side_bytes(),
        tap.side_datagrams(),
        payload.len()
    );

    assert!(
        echo.moves().is_empty(),
        "no move should be reported for an address that never answered: {:?}",
        echo.moves()
    );

    // And the session is undamaged: it is still where it was.
    assert_eq!(
        exchange_retrying(&mut conn, b"still here").expect("exchange after the attempt"),
        b"still here",
        "a failed probe must leave the session on the path it was on"
    );
}

#[test]
fn a_replayed_frame_cannot_move_a_session() {
    // The weaker attack, and the one an off-path attacker can mount: capture
    // a datagram and send it again from somewhere else. The replay window
    // refuses it before anything else looks at it, so it never reaches the
    // point where an address would be probed.
    let echo = Echo::spawn();
    let relay = Recording::spawn(echo.addr);
    let mut conn =
        Connection::connect(relay.addr, &echo.public, &Identity::generate()).expect("connect");

    assert_eq!(
        exchange_retrying(&mut conn, b"recorded").expect("control exchange"),
        b"recorded",
        "the session must work before anything is replayed"
    );

    let captured = relay.last().expect("a datagram to replay");
    assert!(
        captured.len() > 30,
        "the captured datagram must be a data frame, not an empty one"
    );

    // A socket the session has never heard of, sending a frame it did seal.
    let attacker = UdpSocket::bind("127.0.0.1:0").expect("bind attacker");
    attacker
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    for _ in 0..4 {
        attacker.send_to(&captured, echo.addr).expect("replay");
    }

    let mut buf = [0u8; 65535];
    let answered = attacker.recv_from(&mut buf).is_ok();
    assert!(
        !answered,
        "a replayed frame must not draw a reply to the address that sent it"
    );
    assert!(
        echo.moves().is_empty(),
        "a replay must not move a session: {:?}",
        echo.moves()
    );

    assert_eq!(
        exchange_retrying(&mut conn, b"unmoved").expect("exchange after the replay"),
        b"unmoved",
        "the session must be exactly where it was"
    );
}

#[test]
fn an_endpoint_can_refuse_to_follow_anyone() {
    // Following a peer costs an AEAD verification for every frame that arrives
    // from an address with no session on it, and that is reachable by anyone
    // who guesses a 32-bit identifier. An endpoint whose peers never move can
    // decline to pay it at all.
    let echo = Echo::spawn_with_migrations(0);
    let relay = Rebinding::spawn(echo.addr, 4);
    let mut conn =
        Connection::connect(relay.addr, &echo.public, &Identity::generate()).expect("connect");

    // The control: with the budget at zero, everything that does not involve a
    // change of address must still work exactly as before.
    assert_eq!(
        exchange_retrying(&mut conn, b"before the move").expect("control exchange"),
        b"before the move",
        "refusing to follow peers must not stop a session that stays put"
    );

    let deadline = Instant::now() + TIMEOUT;
    while !relay.has_rebound() && Instant::now() < deadline {
        let _ = exchange(&mut conn, b"filler");
    }
    assert!(
        relay.has_rebound(),
        "the relay never switched ports after {} datagrams; nothing was tested",
        relay.forwarded()
    );

    assert!(
        exchange_retrying(&mut conn, b"after the move").is_err(),
        "an endpoint told not to follow peers must not follow one"
    );
    assert!(
        echo.moves().is_empty(),
        "and must report no move: {:?}",
        echo.moves()
    );
}
