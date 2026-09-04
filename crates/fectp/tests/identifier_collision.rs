//! What sharing one session identifier costs the endpoint.
//!
//! The identifier is chosen by whoever opens the session, so a peer can put
//! the same value on every session it holds. That is fine for routing —
//! sessions are filed under `(address, identifier)` and the addresses differ —
//! but the *secondary* index that address migration needs is keyed on the
//! identifier alone, and a frame from an unknown address is tried against
//! every session wearing the one it names.
//!
//! So the question is what one datagram can be made to cost. The bound that is
//! meant to answer it, `MAX_MIGRATIONS_PER_SECOND`, counts datagrams; the work
//! is per candidate; and a sequence number forged some generations ahead makes
//! each candidate several times more expensive than one AEAD verification,
//! because the key has to be derived before the tag can be checked.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType};
use fectp_core::keys::Keypair;
use fectp_core::session::{Capabilities, Initiator, Session, REKEY_INTERVAL};
use rand_core::OsRng;

/// Sessions made to share one identifier. Well under the default `MAX_PEERS`.
const COLLIDING: usize = 400;

/// The identifier they all wear.
const SHARED_ID: u32 = 0xDEAD_BEEF;

struct Echo {
    addr: SocketAddr,
    public: [u8; 32],
    messages: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Echo {
    fn spawn() -> Self {
        let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        let addr = server.local_addr().expect("addr");
        let public = *server.public_key().expect("identity");
        let stop = Arc::new(AtomicBool::new(false));
        let messages = Arc::new(AtomicU64::new(0));
        let flag = Arc::clone(&stop);
        let counted = Arc::clone(&messages);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match server.poll(Some(Duration::from_millis(5))) {
                    Ok(Event::Message { peer, data }) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let _ = server.send(peer, &data, PayloadType::Opaque);
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            public,
            messages,
            stop,
            handle: Some(handle),
        }
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

/// Opens one session by hand, so its identifier can be chosen.
///
/// Returns the socket it lives on, which must be kept alive for the session to
/// stay routable, and the opened session.
fn open_with_id(server: SocketAddr, server_public: &[u8; 32], id: u32) -> Option<(UdpSocket, Session)> {
    let sock = UdpSocket::bind("127.0.0.1:0").ok()?;
    sock.connect(server).ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok()?;

    let caps = Capabilities::minimal(1200);
    let mut initiator = Initiator::new(
        Keypair::generate(&mut OsRng),
        *server_public,
        id,
        caps,
    )
    .ok()?;

    let mut wire = vec![0u8; 2048];
    let n = initiator.write_init(&mut OsRng, b"", &mut wire).ok()?;
    sock.send(&wire[..n]).ok()?;
    let n = sock.recv(&mut wire).ok()?;
    let mut scratch = vec![0u8; 2048];
    let (session, _) = initiator.read_response(&wire[..n], &mut scratch).ok()?;
    Some((sock, session))
}

/// The median of a peer's round trips, which is what a flood is felt as.
fn median_round_trip(conn: &Connection, samples: usize) -> Duration {
    let mut times = Vec::with_capacity(samples);
    let mut buf = vec![0u8; 4096];
    for _ in 0..samples {
        conn.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let started = Instant::now();
        if conn.send(b"ping", PayloadType::Opaque).is_err() {
            continue;
        }
        if conn.recv(&mut buf).is_ok() {
            times.push(started.elapsed());
        }
    }
    assert!(!times.is_empty(), "the echo peer never answered at all");
    times.sort();
    times[times.len() / 2]
}

/// Sends frames naming `id` from a fresh port, with a sequence far enough
/// ahead to make the receiver derive keys before it can refuse them.
fn flood(server: SocketAddr, id: u32, stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let mut frame = [0u8; 30];
        frame[0] = (1 << 4) | 3; // version 1, Data
        frame[2..6].copy_from_slice(&id.to_le_bytes());
        // Four generations ahead: the replay window passes anything above the
        // high-water mark, so this is derived towards before it is refused.
        frame[6..14].copy_from_slice(&(4 * REKEY_INTERVAL).to_le_bytes());
        while !stop.load(Ordering::Relaxed) {
            let _ = sock.send_to(&frame, server);
        }
    })
}

/// Sends one sealed frame from a fresh port and reports whether the endpoint
/// delivered it — which it can only do by finding the session through the
/// identifier index, since the address is one it has never seen.
fn arrives_from_a_new_address(server: SocketAddr, session: &mut Session, seen: &Arc<AtomicU64>) -> bool {
    let before = seen.load(Ordering::SeqCst);
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let mut wire = vec![0u8; 2048];
    let n = session.seal(b"from somewhere else", 0, &mut wire).expect("seal");
    sock.send_to(&wire[..n], server).expect("send");

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if seen.load(Ordering::SeqCst) > before {
            return true;
        }
    }
    false
}

#[test]
fn only_the_first_few_sessions_wearing_an_identifier_can_be_found_by_it() {
    // The walk from the identifier index is capped, because without a cap one
    // datagram is worth an authentication attempt for every session wearing
    // the identifier it names — and the identifier is chosen by whoever opens
    // the session. See the measurement below for what that was worth.
    //
    // The cap has a cost, and this pins it: a session filed after the first
    // few cannot be found this way, so it cannot migrate. That is the trade,
    // and it is only reachable when a crowd was already filed under the
    // identifier a newcomer then picks at random.
    let echo = Echo::spawn();

    // Enough to sit either side of the cap without depending on its value.
    let mut sessions = Vec::new();
    for _ in 0..12 {
        if let Some(pair) = open_with_id(echo.addr, &echo.public, SHARED_ID) {
            sessions.push(pair);
        }
    }
    assert!(
        sessions.len() >= 12,
        "needed twelve sessions on one identifier, opened {}",
        sessions.len()
    );

    // The first one filed is inside any sane cap.
    let (_, first) = &mut sessions[0];
    assert!(
        arrives_from_a_new_address(echo.addr, first, &echo.messages),
        "a session filed first under an identifier must still be reachable \
         through it, or migration does not work at all"
    );

    // The twelfth is outside it.
    let (_, last) = &mut sessions[11];
    assert!(
        !arrives_from_a_new_address(echo.addr, last, &echo.messages),
        "a session filed twelfth under one identifier must not be searched \
         for: the walk is what a crowded identifier makes expensive"
    );
}

/// What a crowded identifier was worth before the walk was capped.
///
/// Kept as a measurement rather than a check because it reads a latency under
/// load, which on a busy machine says more about the machine than the change.
/// Run it deliberately:
///
/// ```text
/// cargo test -p fectp --release --test identifier_collision -- --ignored --nocapture
/// ```
///
/// Recorded on one desktop, release build, 400 sessions sharing one
/// identifier, flooded at full rate from one thread with a sequence four
/// generations ahead:
///
/// - before the cap: median round trip **39 µs → 78.5 ms**
/// - after it, against a control holding the peer table equal: no separable
///   difference
#[test]
#[ignore = "measurement, not a pass/fail check: cargo test -- --ignored --nocapture"]
fn measure_what_a_crowded_identifier_costs() {
    let echo = Echo::spawn();
    let conn =
        Connection::connect(echo.addr, &echo.public, &Identity::generate()).expect("connect");

    let mut held = Vec::with_capacity(COLLIDING);
    for _ in 0..COLLIDING {
        if let Some(pair) = open_with_id(echo.addr, &echo.public, SHARED_ID) {
            held.push(pair);
        }
    }

    // The control is the same flood at the same rate against the same table,
    // naming an identifier no session wears. Holding the table equal is the
    // point: the poll loop's per-datagram cost grows with the number of peers,
    // and that is a different finding.
    let stop = Arc::new(AtomicBool::new(false));
    let flooder = flood(echo.addr, 0x0BAD_0BAD, Arc::clone(&stop));
    let control = median_round_trip(&conn, 40);
    stop.store(true, Ordering::Relaxed);
    let _ = flooder.join();

    let stop = Arc::new(AtomicBool::new(false));
    let flooder = flood(echo.addr, SHARED_ID, Arc::clone(&stop));
    let crowded = median_round_trip(&conn, 40);
    stop.store(true, Ordering::Relaxed);
    let _ = flooder.join();

    println!("sessions sharing one identifier: {}", held.len());
    println!("median round trip, identifier nobody wears: {control:?}");
    println!("median round trip, identifier they all wear: {crowded:?}");
}
