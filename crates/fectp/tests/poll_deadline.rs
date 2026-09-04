//! `poll` must come back when it said it would.
//!
//! The timeout is the application's, not the socket's. An endpoint that keeps
//! going as long as datagrams keep arriving hands control of its caller's
//! event loop to whoever is sending — and the cheapest way to send is to send
//! rubbish, which needs no key, no handshake, and no knowledge of the peer.
//!
//! Everything the caller does between polls stops for the duration: its own
//! timers, its own sockets, its own shutdown. Measured before this was fixed,
//! a `poll(50 ms)` took a mean of 752 ms and a worst case of 2.6 seconds under
//! one flooding thread on loopback.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Endpoint, Identity};

#[test]
fn poll_returns_within_its_timeout_under_a_flood() {
    let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let addr = server.local_addr().expect("addr");

    // Datagrams that fail at the very first check — a version this protocol
    // does not have. No key, no handshake, no session: the floor of what
    // anybody can send.
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let flood = thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let rubbish = [0u8; 14];
        while !flag.load(Ordering::Relaxed) {
            let _ = sock.send_to(&rubbish, addr);
        }
    });

    // Let the flood get going, then time the polls.
    let settle = Instant::now() + Duration::from_millis(100);
    while Instant::now() < settle {
        let _ = server.poll(Some(Duration::from_millis(10)));
    }

    let timeout = Duration::from_millis(50);
    let mut worst = Duration::ZERO;
    for _ in 0..20 {
        let started = Instant::now();
        let _ = server.poll(Some(timeout));
        worst = worst.max(started.elapsed());
    }

    stop.store(true, Ordering::Relaxed);
    let _ = flood.join();

    // Generous: five times what was asked for. The failure this guards against
    // is two orders of magnitude out, not a few percent, and a loopback flood
    // is a hostile environment for a scheduler.
    assert!(
        worst < timeout * 5,
        "poll(50 ms) took up to {worst:?} under a flood; the caller's timeout \
         must bound it whether or not datagrams keep arriving"
    );
}
