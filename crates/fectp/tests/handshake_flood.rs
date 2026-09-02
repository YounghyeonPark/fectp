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

use std::net::{SocketAddr, UdpSocket};
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

    // Several clients, because one blocking `connect` at a time measures the
    // client's round trip rather than what the server can be made to do.
    let total = Arc::new(AtomicUsize::new(0));
    let attackers: Vec<_> = (0..8)
        .map(|_| {
            let count = Arc::clone(&total);
            std::thread::spawn(move || {
                let started = Instant::now();
                while started.elapsed() < Duration::from_secs(2) {
                    if Connection::connect(addr, &public, &Identity::generate()).is_ok() {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    let attacker = std::thread::spawn(move || {
        let started = Instant::now();
        for a in attackers {
            let _ = a.join();
        }
        (total.load(Ordering::Relaxed), started.elapsed())
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

// A test named `a_flood_does_not_evict_an_established_peer` used to sit here. It
// connected two hundred strangers and checked that an established peer still
// worked, which it did — and did equally well with the eviction removed, because
// two hundred is under the default `MAX_PEERS` of 1024 and nothing was ever
// evicted at all. It asserted something already true.
//
// `the_peer_table_is_bounded_and_evicts_the_silent_first` below tests the same
// property and fails without the fix, which is the difference.

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
            conn.set_read_timeout(Some(Duration::from_millis(500))).expect("timeout");
            let mut buf = vec![0u8; 256];

            // Returns whether it was still being answered when told to stop.
            // Counting successes is not enough: a peer evicted halfway through
            // still has a healthy count from before it happened, which is how
            // an earlier version of this test passed against plain
            // oldest-first eviction and proved nothing.
            //
            // But one timed-out read is not eviction either. Under load — and
            // this suite runs several second-long tests beside this one — the
            // single poll loop that answers everybody can simply be late. The
            // two are told apart by persistence: an evicted peer has no route
            // on the server and is never answered again, while a starved one
            // gets through eventually. Treating the first timeout as eviction
            // made this fail about one run in three, on a machine doing
            // nothing but running the tests.
            // Best effort while the flood runs: a timed-out read here is as
            // likely to be the single poll loop being late as anything else,
            // and this suite runs several second-long tests beside this one.
            while !flag.load(Ordering::Relaxed) {
                if conn.send(b"still here", PayloadType::Opaque).is_ok() {
                    if let Ok(n) = conn.recv(&mut buf) {
                        if &buf[..n] == b"still here" {
                            count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                thread::sleep(Duration::from_millis(20));
            }

            // The judgement, once the flood has stopped and the loop is
            // draining with nothing else to do. A peer that is still filed gets
            // answered now; one that was evicted has no route on the server and
            // never will, however long it waits.
            //
            // Deciding during the flood does not work in either direction.
            // Treating one timeout as eviction failed about a run in three from
            // starvation alone; tolerating eight in a row stopped catching
            // plain oldest-first eviction, because the test ends before eight
            // have accumulated. Asking afterwards is not a matter of degree.
            conn.set_read_timeout(Some(Duration::from_millis(700)))
                .expect("timeout");
            for _ in 0..3 {
                if conn.send(b"still here", PayloadType::Opaque).is_ok() {
                    if let Ok(n) = conn.recv(&mut buf) {
                        if &buf[..n] == b"still here" {
                            return true;
                        }
                    }
                }
            }
            false
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
    while draining.elapsed() < Duration::from_secs(3) {
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

/// A captured opening frame, sent again.
///
/// This is not the same as the flood above. A replay carries a *specific*
/// peer's session identifier, and the responder files sessions by address and
/// identifier — so answering it afresh replaces the session that pair already
/// had. That turns a captured packet into a way to cut one chosen peer off,
/// which is a good deal more pointed than making a server do arithmetic.
///
/// It is also the ordinary case now that the client retransmits its handshake:
/// a reply lost on the way back means the responder sees message 1 twice.
#[test]
fn a_replayed_opening_frame_does_not_displace_the_session_it_names() {
    let echo = Echo::start();

    // A relay that keeps the first datagram it forwards — the opening frame —
    // and can send it again from the same address it originally came from,
    // which is what makes the responder file it against the same pair.
    let relay = UdpSocket::bind("127.0.0.1:0").expect("relay bind");
    relay.set_read_timeout(Some(Duration::from_millis(25))).expect("timeout");
    let relay_addr = relay.local_addr().expect("addr");
    let server = echo.addr();

    let replay_now = Arc::new(AtomicBool::new(false));
    let replayed = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let trigger = Arc::clone(&replay_now);
    let count = Arc::clone(&replayed);
    let flag = Arc::clone(&stop);
    let pump = thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        let mut client: Option<SocketAddr> = None;
        let mut opening: Option<Vec<u8>> = None;
        while !flag.load(Ordering::Relaxed) {
            if trigger.swap(false, Ordering::Relaxed) {
                if let Some(frame) = &opening {
                    let _ = relay.send_to(frame, server);
                    count.fetch_add(1, Ordering::Relaxed);
                }
            }
            let (n, from) = match relay.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if from == server {
                if let Some(client) = client {
                    let _ = relay.send_to(&buf[..n], client);
                }
            } else {
                client = Some(from);
                if opening.is_none() {
                    opening = Some(buf[..n].to_vec());
                }
                let _ = relay.send_to(&buf[..n], server);
            }
        }
    });

    let conn = Connection::connect(relay_addr, &echo.public(), &Identity::generate())
        .expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");

    let mut buf = vec![0u8; 1024];
    conn.send(b"before the replay", PayloadType::Opaque).expect("send");
    let n = conn.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], b"before the replay");

    // Send the captured opening frame again, from the same address.
    replay_now.store(true, Ordering::Relaxed);
    let waited = Instant::now();
    while replayed.load(Ordering::Relaxed) == 0 && waited.elapsed() < Duration::from_secs(2) {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(replayed.load(Ordering::Relaxed), 1, "the replay must have gone out");
    thread::sleep(Duration::from_millis(200));

    // The session the frame named must still be the one that works.
    conn.send(b"after the replay", PayloadType::Opaque)
        .expect("send after replay");
    let n = conn
        .recv(&mut buf)
        .expect("a replayed opening frame cut off the session it named");
    assert_eq!(&buf[..n], b"after the replay");

    stop.store(true, Ordering::Relaxed);
    let _ = pump.join();
}

/// The rate limit is enforced, and is the operator's to set.
///
/// Without a test the limit is a number in a file. The default is deliberately
/// far above anything a test could drive, so this sets a small one — which also
/// exercises the setter, since a bound nobody can adjust is the reason the
/// first value shipped too low.
#[test]
fn new_handshakes_are_rate_limited() {
    let identity = Identity::generate();
    let public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("bind");
    let addr = server.local_addr().expect("addr");

    const PER_SECOND: u32 = 8;
    server.set_max_handshakes_per_second(PER_SECOND);

    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&attempts);
    let flood: Vec<_> = (0..4)
        .map(|_| {
            let flag = Arc::clone(&flag);
            let counted = Arc::clone(&counted);
            thread::spawn(move || {
                let mut held = Vec::new();
                while !flag.load(Ordering::Relaxed) {
                    if let Ok(conn) = Connection::connect(addr, &public, &Identity::generate()) {
                        counted.fetch_add(1, Ordering::Relaxed);
                        held.push(conn);
                    }
                }
            })
        })
        .collect();

    let started = Instant::now();
    let window = Duration::from_secs(3);
    while started.elapsed() < window {
        let _ = server.poll(Some(Duration::from_millis(5)));
    }
    stop.store(true, Ordering::Relaxed);
    for t in flood {
        let _ = t.join();
    }

    // The bucket starts full, so the ceiling over the window is one burst plus
    // the refill. Generous slop on top: this is checking that a limit exists at
    // all, not measuring it to the packet.
    let accepted = server.peer_count();
    let ceiling = (PER_SECOND as f64 * (1.0 + window.as_secs_f64()) * 2.0) as usize;
    assert!(
        accepted <= ceiling,
        "{accepted} handshakes answered at a limit of {PER_SECOND}/s over {window:?}; \
         expected no more than about {ceiling}"
    );
    assert!(
        attempts.load(Ordering::Relaxed) > 0,
        "nothing connected at all, so the limit was never the thing being tested"
    );
}
