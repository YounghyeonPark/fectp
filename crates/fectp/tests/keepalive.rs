//! Holding a NAT mapping open through an idle period.
//!
//! A NAT maps an inside address to an outside one when something is sent out,
//! and forgets the mapping when nothing has been for a while — RFC 4787 asks
//! for at least two minutes, and plenty of equipment does thirty seconds. Once
//! it is forgotten, **inbound datagrams have nowhere to go**. The session is
//! intact at both ends and the peer is simply unreachable.
//!
//! This costs nothing for a peer that talks: its own traffic refreshes the
//! mapping. It matters for one that connects and then only listens — a device
//! waiting for commands — which is the case with no traffic of its own to keep
//! the door open.
//!
//! Only outbound traffic refreshes a mapping, so the peer behind the NAT is
//! the one that has to send. The relay here models exactly that, and the
//! second test is what proves it models it: with no keep-alive the mapping
//! must actually expire, or the first test is asserting nothing.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

/// How long the modelled NAT keeps a mapping after the last outbound datagram.
const MAPPING: Duration = Duration::from_millis(500);

/// How often the server pushes, so an idle client has something to miss.
const PUSH: Duration = Duration::from_millis(200);

/// Comfortably inside `MAPPING`, and well clear of the scheduling noise a
/// loopback test sees on a busy machine.
const KEEPALIVE: Duration = Duration::from_millis(150);

// --------------------------------------------------------------- harness ---

/// A NAT whose mapping expires when nothing has been sent out through it.
///
/// Datagrams from the client are always forwarded, and each one refreshes the
/// mapping. Datagrams from the server are forwarded only while the mapping is
/// live, and counted when they are not — which is what a real NAT does with a
/// packet it has no translation for.
struct ExpiringNat {
    addr: SocketAddr,
    dropped: Arc<AtomicU64>,
    delivered: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl ExpiringNat {
    fn spawn(server: SocketAddr, mapping: Duration) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
        front
            .set_read_timeout(Some(Duration::from_millis(10)))
            .expect("timeout");
        let addr = front.local_addr().expect("addr");

        let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
        back.connect(server).expect("connect back");
        back.set_read_timeout(Some(Duration::from_millis(10)))
            .expect("timeout");

        let stop = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicU64::new(0));
        let delivered = Arc::new(AtomicU64::new(0));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let refreshed = Arc::new(Mutex::new(Instant::now()));

        // Outbound: always forwarded, and each one renews the mapping.
        {
            let front = front.try_clone().expect("clone");
            let back = back.try_clone().expect("clone");
            let flag = Arc::clone(&stop);
            let learn = Arc::clone(&client);
            let touch = Arc::clone(&refreshed);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok((n, from)) = front.recv_from(&mut buf) else {
                        continue;
                    };
                    *learn.lock().expect("lock") = Some(from);
                    *touch.lock().expect("lock") = Instant::now();
                    let _ = back.send(&buf[..n]);
                }
            });
        }

        // Inbound: only while there is a mapping to translate through.
        {
            let flag = Arc::clone(&stop);
            let learn = Arc::clone(&client);
            let touch = Arc::clone(&refreshed);
            let lost = Arc::clone(&dropped);
            let through = Arc::clone(&delivered);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok(n) = back.recv(&mut buf) else {
                        continue;
                    };
                    let live = touch.lock().expect("lock").elapsed() < mapping;
                    let target = *learn.lock().expect("lock");
                    match (live, target) {
                        (true, Some(target)) => {
                            through.fetch_add(1, Ordering::SeqCst);
                            let _ = front.send_to(&buf[..n], target);
                        }
                        _ => {
                            lost.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            });
        }

        Self {
            addr,
            dropped,
            delivered,
            stop,
        }
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }

    fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::SeqCst)
    }
}

impl Drop for ExpiringNat {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A server that echoes, and also pushes to every peer on its own schedule.
///
/// The pushes are unreliable, so they draw no acknowledgement — otherwise the
/// client would be sending on every one of them and would hold the mapping
/// open without any help from a keep-alive.
struct Pusher {
    addr: SocketAddr,
    public: [u8; 32],
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Pusher {
    fn spawn() -> Self {
        let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        let addr = server.local_addr().expect("addr");
        let public = *server.public_key().expect("identity");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut next = Instant::now() + PUSH;
            while !flag.load(Ordering::Relaxed) {
                match server.poll(Some(Duration::from_millis(20))) {
                    Ok(Event::Message { peer, data }) => {
                        let _ = server.send(peer, &data, PayloadType::Opaque);
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
                if Instant::now() >= next {
                    next = Instant::now() + PUSH;
                    let peers = server.peers();
                    for peer in peers {
                        let _ = server.send(peer, b"push", PayloadType::Opaque);
                    }
                }
            }
        });
        Self {
            addr,
            public,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Pusher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// How many attempts a test gets when the host stalls under it.
///
/// The two tests that assert the NAT dropped *nothing* are statements about
/// wall-clock time: the client must get a datagram out within every mapping
/// lifetime, and one that is not scheduled for that long loses the mapping for
/// a reason that has nothing to do with the protocol. Under
/// `cargo test --workspace` that happens. An attempt that stalled is retried
/// rather than believed, and the last one says so.
///
/// The premise comes from [`ExpiringNat::longest_gap`] — the actual interval
/// between the client's outbound datagrams, read at the point the mapping is
/// refreshed from. It was measured by a watchdog thread first, which was the
/// wrong instrument: the keep-alive leaves from the thread inside `recv`, and
/// a watchdog running beside it reported a 24 ms stall while that thread was
/// being held up for 900 ms — nearly twice `MAPPING`. The test then failed and
/// printed "so this is not the machine", which was false. Verified by stalling
/// `Connection::pump` deliberately.
const ATTEMPTS: usize = 3;

/// The longest this process may go unscheduled and still be judged.
///
/// Not `MAPPING`. A keep-alive goes out every `KEEPALIVE`, so after a stall of
/// `S` the mapping has gone unrefreshed for up to `S + KEEPALIVE` — the stall,
/// plus the wait for the next one to fall due. It survives only while that is
/// under `MAPPING`, which puts the real headroom at `MAPPING - KEEPALIVE`.
/// Filtering at `MAPPING` admitted stalls between 350 and 500 ms that expire
/// the mapping honestly, and then blamed the protocol for them.
const HEADROOM: Duration = Duration::from_millis(
    MAPPING.as_millis() as u64 - KEEPALIVE.as_millis() as u64,
);

/// Counts the pushes that arrive over `window`, sending nothing at all.
fn receive_only(conn: &Connection, window: Duration) -> usize {
    receive_only_watching(conn, window).0
}

/// As [`receive_only`], and also the longest this loop went between passes.
///
/// That gap is the premise of the two tests asserting the NAT dropped nothing.
/// A keep-alive leaves from inside `recv`, on **this** thread, so what decides
/// whether the mapping survives is whether this loop is running — and a loop
/// that is not scheduled for longer than `MAPPING` loses the mapping for a
/// reason the protocol had no part in.
///
/// Two earlier attempts measured the wrong thing. A watchdog on its own thread
/// reported a 24 ms stall while this one was held up for 900 ms. Reading the
/// interval between the client's outbound datagrams at the NAT is exact when
/// it fires, but it only updates when a datagram *arrives*, so a client that
/// goes silent to the end of the window never has that silence measured — it
/// read 41 ms against a keep-alive that had been disabled outright.
///
/// The read timeout is therefore short and fixed rather than the whole
/// remaining window: this loop has to come round often enough to time itself.
/// A timeout is the normal outcome and is not an error.
fn receive_only_watching(conn: &Connection, window: Duration) -> (usize, Duration) {
    /// Short enough that a stall worth catching cannot hide inside one pass.
    const SLICE: Duration = Duration::from_millis(50);

    let deadline = Instant::now() + window;
    let mut buf = vec![0u8; 4096];
    let mut arrived = 0;
    let mut longest = Duration::ZERO;
    let mut last = Instant::now();
    while Instant::now() < deadline {
        longest = longest.max(last.elapsed());
        last = Instant::now();
        let left = deadline.saturating_duration_since(Instant::now()).min(SLICE);
        if conn.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match conn.recv(&mut buf) {
            Ok(_) => arrived += 1,
            // Expected once a slice passes with no push due; anything else
            // ends the loop, as it always has.
            Err(fectp::Error::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    (arrived, longest.max(last.elapsed()))
}

// -------------------------------------------------------------- the tests ---

#[test]
fn without_a_keepalive_an_idle_mapping_expires() {
    // The control for the test below. If the modelled NAT never forgot
    // anything, a keep-alive would have nothing to prove.
    let server = Pusher::spawn();
    let nat = ExpiringNat::spawn(server.addr, MAPPING);
    let conn =
        Connection::connect(nat.addr, &server.public, &Identity::generate()).expect("connect");

    // The path works before the client goes quiet.
    conn.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    conn.send(b"hello", PayloadType::Opaque).expect("send");
    let mut buf = vec![0u8; 4096];
    conn.recv(&mut buf).expect("the path must work first");

    // Wait for the mapping to actually be gone rather than assuming how long
    // it takes: the pushes inside its last lifetime arrive legitimately, and
    // asserting against them would be asserting the timer, not the behaviour.
    let deadline = Instant::now() + Duration::from_secs(10);
    while nat.dropped() == 0 && Instant::now() < deadline {
        let _ = receive_only(&conn, Duration::from_millis(50));
    }
    assert!(
        nat.dropped() > 0,
        "the mapping never expired, so this proves nothing: {} delivered",
        nat.delivered()
    );

    // From here there is no translation for an inbound datagram, and a client
    // that says nothing has no way to make one.
    let after = receive_only(&conn, MAPPING * 3);
    assert_eq!(
        after, 0,
        "once the mapping is gone a silent client must hear nothing, \
         but {after} pushes arrived"
    );
}

#[test]
fn a_keepalive_holds_an_idle_mapping_open() {
    let mut stalls = Vec::new();
    for _ in 0..ATTEMPTS {
        let server = Pusher::spawn();
        let nat = ExpiringNat::spawn(server.addr, MAPPING);
        let conn =
            Connection::connect(nat.addr, &server.public, &Identity::generate()).expect("connect");
        conn.set_keepalive(Some(KEEPALIVE)).expect("keepalive");

        conn.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        conn.send(b"hello", PayloadType::Opaque).expect("send");
        let mut buf = vec![0u8; 4096];
        conn.recv(&mut buf).expect("the path must work first");

        // The same silence, several mapping lifetimes long. The keep-alive is
        // the only thing the client sends in it.
        let window = MAPPING * 6;
        let (arrived, stalled) = receive_only_watching(&conn, window);
        if stalled >= HEADROOM {
            stalls.push(stalled);
            continue;
        }

        assert_eq!(
            nat.dropped(),
            0,
            "a keep-alive must stop the mapping expiring at all, but the NAT \
             dropped {} of {} inbound datagrams (longest stall {stalled:?}, \
             under the {HEADROOM:?} it has to stay inside, so this is \
             not the machine)",
            nat.dropped(),
            nat.dropped() + nat.delivered()
        );

        // And the pushes must have actually been flowing, or an unreachable
        // server would satisfy the assertion above by sending nothing.
        let expected = (window.as_millis() / PUSH.as_millis()) as usize;
        assert!(
            arrived >= expected / 2,
            "{arrived} of about {expected} pushes arrived; the mapping was open \
             but nothing came through it"
        );
        return;
    }
    panic!(
        "every attempt was interrupted for longer than the {MAPPING:?} mapping \
         lifetime, so this could not be evaluated: {stalls:?}"
    );
}

#[test]
fn an_endpoint_that_dialled_out_keeps_its_own_mapping_open() {
    // The same property for the other front end. An `Endpoint` that dialled is
    // the side behind the NAT, so it is the side whose keep-alive matters —
    // and its keep-alives have to survive being driven by `poll` rather than
    // by a blocking `recv`.
    let mut stalls = Vec::new();
    for _ in 0..ATTEMPTS {
        let server = Pusher::spawn();
        let nat = ExpiringNat::spawn(server.addr, MAPPING);

        let mut node = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        node.set_keepalive(Some(KEEPALIVE));
        node.connect(nat.addr, Some(&server.public)).expect("dial");

        // Settle the handshake, and confirm the path works before anything is
        // asserted about silence.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut connected = None;
        while connected.is_none() && Instant::now() < deadline {
            if let Ok(Event::Connected { peer, .. }) = node.poll(Some(Duration::from_millis(20))) {
                connected = Some(peer);
            }
        }
        let peer = connected.expect("the handshake must complete");
        node.send(peer, b"hello", PayloadType::Opaque).expect("send");

        // Now poll without sending anything. Only the keep-alive should be
        // going out, and it is the only thing that can hold the mapping open.
        let window = MAPPING * 6;
        let until = Instant::now() + window;
        let mut arrived = 0;
        // The same self-timing as `receive_only_watching`: this loop is the
        // one the endpoint's keep-alive goes out from.
        let mut stalled = Duration::ZERO;
        let mut last = Instant::now();
        while Instant::now() < until {
            stalled = stalled.max(last.elapsed());
            last = Instant::now();
            if let Ok(Event::Message { .. }) = node.poll(Some(Duration::from_millis(20))) {
                arrived += 1;
            }
        }
        let stalled = stalled.max(last.elapsed());
        if stalled >= HEADROOM {
            stalls.push(stalled);
            continue;
        }

        assert_eq!(
            nat.dropped(),
            0,
            "a keep-alive must stop the mapping expiring at all, but the NAT \
             dropped {} of {} inbound datagrams (longest stall {stalled:?}, \
             under the {HEADROOM:?} it has to stay inside, so this is \
             not the machine)",
            nat.dropped(),
            nat.dropped() + nat.delivered()
        );
        let expected = (window.as_millis() / PUSH.as_millis()) as usize;
        assert!(
            arrived >= expected / 2,
            "{arrived} of about {expected} pushes arrived; the mapping was open \
             but nothing came through it"
        );
        return;
    }
    panic!(
        "every attempt was interrupted for longer than the {MAPPING:?} mapping \
         lifetime, so this could not be evaluated: {stalls:?}"
    );
}
