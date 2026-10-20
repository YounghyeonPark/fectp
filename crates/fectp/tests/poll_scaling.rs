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
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

/// Sessions to put on file. Enough to show a per-peer cost behind a burst
/// small enough to queue, which is what decided it: at 64, putting the bug back
/// cost about 2x, too close to what a correct build reads on a noisy host. The
/// handshakes are now most of the test's time, about 11 seconds in a debug build
/// on one desktop.
const PEERS: usize = 256;

/// Datagrams in the burst. Sent and then stopped, rather than sustained: a
/// thread that floods for the length of a test starves the other test binaries
/// `cargo test` runs beside it.
///
/// It was 4000, sent while the server was running. The server drained them as
/// they came, so whether the measured round trip waited behind any of them
/// depended on whether the sender outran it — and on a macOS runner it did not:
/// the empty table measured 110 to 140 µs, a bare round trip with no burst in
/// front, against about 2 ms crowded, where 64 live sessions kept the server
/// busy enough to fall behind. The comparison was of who kept up, not of what a
/// datagram costs. Now the server is paused while the burst and the measured
/// message are queued, so the burst is always in front; and the burst has to
/// fit in the socket's receive buffer while it waits. Linux charges that buffer
/// per datagram rather than per byte, so its default holds a few hundred this
/// small, by estimate rather than measurement; 200 is meant to stay under it.
/// A buffer that overflowed would drop the measured message, which was sent
/// last: that sample would be missing, and if all were, the test fails saying
/// the echo peer never answered, rather than passing on a short queue.
const BURST: usize = 200;

struct Echo {
    addr: SocketAddr,
    public: [u8; 32],
    stop: Arc<AtomicBool>,
    /// Set to stop the server polling, so datagrams queue in its socket.
    paused: Arc<AtomicBool>,
    /// Set by the server once it has seen `paused` and is not inside `poll`.
    parked: Arc<AtomicBool>,
    /// How long the server took, from leaving its pause to the next message.
    timed: Arc<Mutex<Option<Duration>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Echo {
    fn spawn() -> Self {
        let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        let addr = server.local_addr().expect("addr");
        let public = *server.public_key().expect("identity");
        let stop = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let parked = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let timed = Arc::new(Mutex::new(None));
        let (hold, holding) = (Arc::clone(&paused), Arc::clone(&parked));
        let clock = Arc::clone(&timed);
        let handle = thread::spawn(move || {
            let mut resumed = None;
            while !flag.load(Ordering::Relaxed) {
                if hold.load(Ordering::SeqCst) {
                    holding.store(true, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                if holding.swap(false, Ordering::SeqCst) {
                    resumed = Some(Instant::now());
                }
                match server.poll(Some(Duration::from_millis(5))) {
                    Ok(Event::Message { peer, data }) => {
                        if let Some(at) = resumed.take() {
                            *clock.lock().expect("clock") = Some(at.elapsed());
                        }
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
            paused,
            parked,
            timed,
            handle: Some(handle),
        }
    }

    /// Stops the server polling, and waits until it is not inside `poll`, so
    /// that whatever is sent from here on queues in its socket untouched.
    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
        while !self.parked.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn resume(&self) {
        *self.timed.lock().expect("clock") = None;
        self.paused.store(false, Ordering::SeqCst);
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

/// How long the server took to reach a message queued behind a burst of
/// rubbish, every time, in order.
///
/// The server is paused while the burst and then the message are sent, so
/// both are queued in its socket, in that order, when it starts again: the
/// message cannot be read before the burst is. The server keeps the clock —
/// from leaving its pause to the message coming out of `poll` — so neither the
/// pause, which sleeps, nor the reply's trip back is in the number; with a
/// burst this small they were larger than the thing being measured.
///
/// All the samples rather than only one, because a failure on a machine that
/// cannot be reproduced locally is readable only if the message carries them,
/// and the first ones were on a macOS runner.
fn time_behind_a_burst(conn: &Connection, echo: &Echo) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(5);
    let mut buf = vec![0u8; 4096];
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    for _ in 0..5 {
        echo.pause();
        burst_of_rubbish(echo.addr);
        conn.send(b"behind the burst", PayloadType::Opaque)
            .expect("send");
        echo.resume();
        if conn.recv(&mut buf).is_ok() {
            samples.extend(*echo.timed.lock().expect("clock"));
        }
    }
    assert!(!samples.is_empty(), "the echo peer never answered");
    samples
}

/// The fastest of those samples.
///
/// It was the median for a while, and the minimum before that. The minimum was
/// dropped because of a race: with the server running while the burst was
/// sent, a sample could start after the burst had drained, and that sample was
/// the minimum — a macOS runner failed at 6.6x on a baseline that had measured
/// no burst at all. The pause closed the race. Every sample now waits behind
/// the whole burst, and whatever else a host does to a sample — a preemption,
/// a slow wake — only adds to it, so the fastest is the best estimate of the
/// cost. The median was not: with five samples, one or two slow ones on the
/// empty side moved it, and a correct debug build here read 4.4x by median and
/// 2.3x by minimum in the same run. Measured with the time-driven work put back
/// on every pass, the bug this file was written for, the minimum read 6 to 24x
/// in a release build and 64 to 79x in debug, on one desktop.
fn fastest(samples: &[Duration]) -> Duration {
    *samples.iter().min().expect("samples")
}

#[test]
fn a_burst_of_rubbish_does_not_cost_more_when_more_peers_are_on_file() {
    let echo = Echo::spawn();
    let conn =
        Connection::connect(echo.addr, &echo.public, &Identity::generate()).expect("connect");

    // The control: the same burst, the same measurement, an almost empty peer
    // table. Measured in the same run on the same host, so what is left when
    // the two are compared is the cost of the table.
    let alone = time_behind_a_burst(&conn, &echo);

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

    let crowded = time_behind_a_burst(&conn, &echo);

    assert!(
        fastest(&crowded) < fastest(&alone) * 4,
        "a burst of {BURST} rejected datagrams kept a message waiting at best \
         {:?} with an almost empty table and {:?} with {} sessions on it. What a \
         datagram costs must not grow with the number of peers, because the \
         table is reachable by anyone holding the endpoint's public key.\n\
         Every sample, so one slow reading can be told from a slow set.\n\
         empty table {alone:?}\n\
         {} sessions {crowded:?}",
        fastest(&alone),
        fastest(&crowded),
        held.len(),
        held.len()
    );
}
