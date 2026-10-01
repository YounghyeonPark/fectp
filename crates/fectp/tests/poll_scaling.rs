//! What a burst of rubbish costs, and whether it costs more with more peers.
//!
//! An `Endpoint` is one socket and one loop. Everything time-driven —
//! retransmissions, keep-alives, peer timeouts, and working out when to wake
//! next — used to run on every pass of that loop, and the loop goes round once
//! per datagram received. So the work each arriving datagram cost grew with the
//! number of sessions on file, including datagrams rejected at the version
//! check, which anybody can send.
//!
//! The peer table is reachable: completing a handshake needs the endpoint's
//! public key, which is public by design. An attacker who fills it and then
//! sends rubbish is buying `MAX_PEERS` units of work per datagram.
//!
//! Measured before this was fixed, on one desktop: an established peer's round
//! trip went from 101 µs at a thousand peers to 325 ms once a stranger started
//! sending — a flood that costs 8 µs at zero peers.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

/// Sessions to put on file. Enough to show a per-peer cost, few enough that
/// the handshakes are not the slow part of the test in a debug build.
const PEERS: usize = 64;

/// Datagrams in the burst. Sent and then stopped, rather than sustained: a
/// thread that floods for the length of a test starves the other test binaries
/// `cargo test` runs beside it.
const BURST: usize = 4000;

struct Echo {
    addr: SocketAddr,
    public: [u8; 32],
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Echo {
    fn spawn() -> Self {
        let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        let addr = server.local_addr().expect("addr");
        let public = *server.public_key().expect("identity");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match server.poll(Some(Duration::from_millis(5))) {
                    Ok(Event::Message { peer, data }) => {
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

/// Sends a burst of datagrams that fail at the very first check — a version
/// this protocol does not have. No key, no handshake, no session: the floor of
/// what anybody can send.
fn burst_of_rubbish(server: SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let rubbish = [0u8; 14];
    for _ in 0..BURST {
        let _ = sock.send_to(&rubbish, server);
    }
}

/// Every round trip measured behind a burst of rubbish, in order.
///
/// All of them rather than only one, because one alone cannot tell two very
/// different things apart. The measurement is a round trip queued *behind* the
/// burst; a sample far faster than the rest means the burst had already
/// drained when the clock started, which is this harness racing itself, while
/// five slow samples mean the datagram genuinely costs more. A failure on a machine
/// that cannot be reproduced locally is readable only if the message carries
/// them, and the first one was on a macOS runner.
fn round_trips_behind_a_burst(conn: &Connection, server: SocketAddr) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(5);
    let mut buf = vec![0u8; 4096];
    for _ in 0..5 {
        burst_of_rubbish(server);
        conn.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let started = Instant::now();
        conn.send(b"behind the burst", PayloadType::Opaque)
            .expect("send");
        if conn.recv(&mut buf).is_ok() {
            samples.push(started.elapsed());
        }
    }
    assert!(!samples.is_empty(), "the echo peer never answered");
    samples
}

/// The middle of those samples.
///
/// It was the minimum, on the reasoning that the kindest number for the code
/// under test is the one to hold it to. That is kind on one side of the
/// comparison only: the empty table's minimum is the *harshest* baseline, and a
/// sample where the burst had already drained — the race described above —
/// is exactly a minimum. A macOS runner produced one, [2.04, 6.14, 3.18, 0.39,
/// 3.51] ms against a crowded [5.28, 5.03, 5.29, 7.00, 2.60], and failed at
/// 6.6x on a baseline that had measured no burst at all. Medians put the same
/// run at 1.7x. They lose nothing that matters: measured with the time-driven
/// work put back on every pass, which is the bug this file was written for,
/// both statistics read 390 to 600x against 0.8 to 1.1x correct.
fn median(samples: &[Duration]) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}

#[test]
fn a_burst_of_rubbish_does_not_cost_more_when_more_peers_are_on_file() {
    let echo = Echo::spawn();
    let conn =
        Connection::connect(echo.addr, &echo.public, &Identity::generate()).expect("connect");

    // The control: the same burst, the same measurement, an almost empty peer
    // table. Measured in the same run on the same host, so what is left when
    // the two are compared is the cost of the table.
    let alone = round_trips_behind_a_burst(&conn, echo.addr);

    // Fill the table. These sessions do nothing afterwards; they are on file,
    // which is all the old loop needed to charge for them.
    let mut held = Vec::with_capacity(PEERS);
    for _ in 0..PEERS {
        match Connection::connect(echo.addr, &echo.public, &Identity::generate()) {
            Ok(peer) => held.push(peer),
            Err(_) => break,
        }
    }
    assert!(
        held.len() >= PEERS / 2,
        "only {} of {PEERS} sessions opened; there is no crowded table to test",
        held.len()
    );

    let crowded = round_trips_behind_a_burst(&conn, echo.addr);

    assert!(
        median(&crowded) < median(&alone) * 4,
        "a burst of {BURST} rejected datagrams took a median round trip of \
         {:?} with an almost empty table and {:?} with {} sessions on it. What a \
         datagram costs must not grow with the number of peers, because the \
         table is reachable by anyone holding the endpoint's public key.\n\
         Every sample, so one slow reading can be told from a slow set: an \
         outlier means the burst had drained before the clock started, which \
         is this harness racing itself, while a slow set is the cost itself.\n\
         empty table {alone:?}\n\
         {} sessions {crowded:?}",
        median(&alone),
        median(&crowded),
        held.len(),
        held.len()
    );
}
