//! What an unauthenticated peer can make a server spend.
//!
//! Reaching `accept_full` needs nothing but the server's public key, which is
//! public by design. A stranger completes the handshake — four X25519
//! operations — and is filed in the peer table before the application is told
//! anything, which is the point at which it could have said no.
//!
//! `examples/keys.rs` demonstrates the same path deliberately: its "stranger"
//! connects, and is refused only afterwards.

mod common;

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::Echo;
use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

/// One attacker, ordinary hardware, sixty seconds of nothing but handshakes.
#[test]
#[ignore = "measurement, not a pass/fail check: cargo test -- --ignored --nocapture"]
fn measure_what_a_flood_costs() {
    let identity = Identity::generate();
    let public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("bind");
    let addr = server.local_addr().expect("addr");

    let attacker = std::thread::spawn(move || {
        let started = Instant::now();
        let mut made = 0;
        // Each is a fresh identity: a distinct peer as far as the server knows.
        while started.elapsed() < Duration::from_secs(2) {
            if Connection::connect(addr, &public, &Identity::generate()).is_ok() {
                made += 1;
            }
        }
        (made, started.elapsed())
    });

    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        if server.poll(Some(Duration::from_millis(10))).is_err() {
            break;
        }
    }
    let (made, elapsed) = attacker.join().expect("attacker");

    let peers = server.peer_count();
    let rate = made as f64 / elapsed.as_secs_f64();
    println!("\n  handshakes completed : {made} in {elapsed:?} ({rate:.0}/s)");
    println!("  peers now filed      : {peers}");
    println!("  session state each   : 294 bytes, so {} KiB held", peers * 294 / 1024);
    println!("  none of them ever sent a byte.\n");
}

/// The property that matters: a flood must not stop the peers that belong here.
///
/// An unbounded table is not only memory. It is the established sessions that
/// go with it when the process runs out.
#[test]
fn a_flood_does_not_evict_an_established_peer() {
    let echo = Echo::start();

    // A legitimate client, connected and working before the flood starts.
    let good = Connection::connect(echo.addr(), &echo.public(), &Identity::generate())
        .expect("connect");
    good.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    good.send(b"before", PayloadType::Opaque).expect("send");
    let mut buf = vec![0u8; 1024];
    let n = good.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], b"before");

    // Two hundred strangers, none of which ever sends anything.
    let mut strangers = Vec::new();
    for _ in 0..200 {
        if let Ok(conn) = Connection::connect(echo.addr(), &echo.public(), &Identity::generate()) {
            strangers.push(conn);
        }
    }
    assert!(!strangers.is_empty(), "the flood has to actually connect");

    // The peer that was here first must still work.
    good.send(b"after", PayloadType::Opaque).expect("send after flood");
    let n = good.recv(&mut buf).expect("recv after flood");
    assert_eq!(
        &buf[..n],
        b"after",
        "an established session was lost to peers that never sent anything"
    );
}

/// Garbage costs less than a real opening frame, and should.
///
/// A random datagram fails the first authentication in `read_init`, so it does
/// not reach the two Diffie-Hellman operations of the reply. This pins that:
/// the cheap rejection must stay cheap.
#[test]
fn unparseable_datagrams_do_not_become_peers() {
    let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let addr = server.local_addr().expect("addr");

    let attacker = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let mut state = 0x243F_6A88_85A3_08D3u64;
    for _ in 0..500 {
        let mut junk = [0u8; 96];
        for byte in junk.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state >> 24) as u8;
        }
        let _ = attacker.send_to(&junk, addr);
    }

    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(500) {
        match server.poll(Some(Duration::from_millis(10))) {
            Ok(Event::Idle) | Err(_) => {}
            Ok(_) => panic!("random bytes must not surface as an event"),
        }
    }
    assert_eq!(server.peer_count(), 0, "random bytes must not become sessions");
}

/// The table is bounded, and what it drops to stay bounded is the silent.
///
/// This drives its own `Endpoint` rather than using `Echo`, because the claim
/// is about `peer_count()` and `Echo` owns its server in a thread where nothing
/// can ask. An earlier version of this test used `Echo` and asserted only that
/// an established peer still worked — which was true before the bound existed
/// too, and so proved nothing.
///
/// Slow by nature: the rate limit is what makes filling the table take time,
/// and both halves are the point.
#[test]
fn the_peer_table_is_bounded_and_evicts_the_silent_first() {
    let identity = Identity::generate();
    let public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("bind");
    let addr = server.local_addr().expect("addr");

    // A small bound so the flood can go well past it in seconds. The default is
    // 1024, which at the measured flood rate would take the better part of a
    // minute to exceed — long enough that the temptation is to stop the test at
    // the limit, which is exactly what makes it prove nothing.
    const LIMIT: usize = 32;
    server.set_max_peers(LIMIT);

    let stop = Arc::new(AtomicBool::new(false));

    // An honest peer, established first and talking throughout. It runs in its
    // own thread because `connect` blocks for the reply, and the reply only
    // comes from the `poll` loop below.
    let served = Arc::new(AtomicUsize::new(0));
    let honest = {
        let flag = Arc::clone(&stop);
        let count = Arc::clone(&served);
        thread::spawn(move || {
            let conn = Connection::connect(addr, &public, &Identity::generate())
                .expect("the honest peer must get in before the flood starts");
            conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
            let mut buf = vec![0u8; 256];
            // Returns whether it was still being answered when told to stop.
            // Counting successes is not enough: a peer evicted halfway through
            // still has a healthy count from before it happened, which is how
            // an earlier version of this test passed against plain
            // oldest-first eviction and proved nothing.
            while !flag.load(Ordering::Relaxed) {
                if conn.send(b"still here", PayloadType::Opaque).is_err() {
                    return false;
                }
                match conn.recv(&mut buf) {
                    Ok(n) if &buf[..n] == b"still here" => {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => return false,
                }
                thread::sleep(Duration::from_millis(20));
            }
            true
        })
    };

    // Let it establish before anything competes with it.
    let settled = Instant::now();
    while served.load(Ordering::Relaxed) == 0 && settled.elapsed() < Duration::from_secs(10) {
        // One poll, not two: the first would swallow the very event this is
        // waiting for.
        if let Ok(Event::Message { peer, data }) = server.poll(Some(Duration::from_millis(5))) {
            let _ = server.send(peer, &data, PayloadType::Opaque);
        }
    }
    assert!(
        served.load(Ordering::Relaxed) > 0,
        "the honest peer never connected, which is a different bug"
    );
    let before = served.load(Ordering::Relaxed);

    // Now the flood. Every one of these completes a handshake and says nothing.
    let flag = Arc::clone(&stop);
    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&attempts);
    let flood = thread::spawn(move || {
        let mut held = Vec::new();
        while !flag.load(Ordering::Relaxed) {
            if let Ok(conn) = Connection::connect(addr, &public, &Identity::generate()) {
                counted.fetch_add(1, Ordering::Relaxed);
                held.push(conn);
            }
        }
        held.len()
    });

    let mut highest = 0usize;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(90) {
        if let Ok(Event::Message { peer, data }) = server.poll(Some(Duration::from_millis(5))) {
            let _ = server.send(peer, &data, PayloadType::Opaque);
        }
        highest = highest.max(server.peer_count());
        // Deliberately *not* stopping at the limit: stopping there would make
        // "never exceeded the limit" true by construction. This runs until the
        // flood has attempted several times the limit, so an unbounded table
        // has every chance to show itself.
        if attempts.load(Ordering::Relaxed) > LIMIT * 4 {
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);

    // Keep serving while they wind down. The honest peer checks the flag at the
    // top of its loop, so it may be inside `recv` right now — and if nothing
    // answers that, it times out and reports being evicted when it was only
    // abandoned by this loop. That race made this test fail about one run in
    // six, which is worse than not having it.
    let draining = Instant::now();
    while draining.elapsed() < Duration::from_secs(1) {
        if let Ok(Event::Message { peer, data }) = server.poll(Some(Duration::from_millis(5))) {
            let _ = server.send(peer, &data, PayloadType::Opaque);
        }
    }

    let attempted = flood.join().expect("flood");
    let survived = honest.join().expect("honest peer");

    assert!(
        attempted > LIMIT,
        "only {attempted} handshakes got through against a limit of {LIMIT};          the bound was never actually exceeded and nothing was tested"
    );
    assert!(
        highest <= LIMIT,
        "peer table reached {highest} against a bound of {LIMIT}"
    );
    assert!(
        served.load(Ordering::Relaxed) > before,
        "the honest peer was not served at all while the flood ran"
    );
    // The one that pins the *policy* rather than the bound. Counting successes
    // is not enough on its own: a peer evicted a second into the flood still
    // has a healthy count from before it happened, and an earlier version of
    // this test passed against plain oldest-first eviction for exactly that
    // reason.
    assert!(
        survived,
        "the honest peer was evicted while the flood ran. It had been talking \
         throughout, and everything that displaced it had never sent a byte."
    );
}

/// The limit is on new sessions, not on traffic.
///
/// If a flood could stall an established peer, bounding the work would have
/// traded one denial of service for another.
#[test]
fn a_flood_does_not_slow_an_established_peer() {
    let echo = Echo::start();
    let good = Connection::connect(echo.addr(), &echo.public(), &Identity::generate())
        .expect("connect");
    good.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");

    let addr = echo.addr();
    let public = echo.public();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&stop);
    let flood = std::thread::spawn(move || {
        let mut held = Vec::new();
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(c) = Connection::connect(addr, &public, &Identity::generate()) {
                held.push(c);
            }
        }
    });

    let mut buf = vec![0u8; 1024];
    for round in 0..20 {
        let message = format!("round {round}");
        good.send(message.as_bytes(), PayloadType::Opaque)
            .expect("send during flood");
        let n = good.recv(&mut buf).expect("recv during flood");
        assert_eq!(&buf[..n], message.as_bytes());
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = flood.join();
}
