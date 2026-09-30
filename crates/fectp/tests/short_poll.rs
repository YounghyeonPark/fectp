//! Waiting with a short timeout must not cost datagrams.
//!
//! On Windows a read that times out on an unconnected UDP socket can take a
//! datagram with it: one that arrives as the timeout expires is neither
//! returned nor left queued. An `Endpoint` waits by setting a read timeout and
//! reading, every time round `poll`, so an application polling a little faster
//! than its peer sent lost a share of what arrived, on loopback, with nothing
//! on the path to lose it. `udp::recv_from` has the measurements and the fix.
//!
//! Unreliable sends on purpose. Reliable delivery would retransmit whatever the
//! socket lost and hide it, which is how this went unnoticed.
//!
//! Elsewhere than Windows the read never lost anything, so this passes there
//! either way; it guards the Windows path, which CI runs.
//!
//! `UdpTransport::with_peer` reads an unconnected socket through the same
//! function and is not tested separately, because it could not be tested
//! usefully: with the fix removed it lost at most one datagram in 300, so a
//! test of it failed one run in three or four at best. The endpoint loses far
//! more for reasons not pinned down, and its test fails six runs in six.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Endpoint, Event, Identity, PayloadType};

/// How often the sender sends.
const PERIOD: Duration = Duration::from_millis(17);
/// How long the receiver waits each time. Chosen from a grid of five waits
/// against three periods with the fix removed: every cell lost something, and
/// this one lost the most, 19 of 300.
const POLL: Duration = Duration::from_millis(5);
/// Datagrams per run.
const MESSAGES: u32 = 300;

#[test]
fn an_endpoint_polled_briefly_loses_nothing() {
    let identity = Identity::generate();
    let key = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("server bind");
    let addr = server.local_addr().expect("addr");
    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("client bind");
    let peer = client.connect(addr, Some(&key)).expect("connect");

    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut up, mut down) = (false, false);
    while Instant::now() < deadline && !(up && down) {
        if let Ok(Event::Connected { .. }) = server.poll(Some(Duration::from_millis(1))) {
            up = true;
        }
        if let Ok(Event::Connected { .. }) = client.poll(Some(Duration::from_millis(1))) {
            down = true;
        }
    }
    assert!(up && down, "the two endpoints must connect");

    let stop = Arc::new(AtomicBool::new(false));
    let delivered = Arc::new(AtomicUsize::new(0));
    let (halt, count) = (Arc::clone(&stop), Arc::clone(&delivered));
    let receiver = thread::spawn(move || {
        while !halt.load(Ordering::Relaxed) {
            if let Ok(Event::Message { .. }) = server.poll(Some(POLL)) {
                count.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    let started = Instant::now();
    for i in 0..MESSAGES {
        let due = started + PERIOD * i;
        while Instant::now() < due {
            let _ = client.poll(Some(Duration::from_millis(1)));
        }
        client
            .send(peer, &i.to_le_bytes(), PayloadType::Opaque)
            .expect("send");
    }
    let settle = Instant::now() + Duration::from_millis(500);
    while Instant::now() < settle {
        let _ = client.poll(Some(Duration::from_millis(5)));
    }
    stop.store(true, Ordering::Relaxed);
    receiver.join().expect("the receiving thread");

    let got = delivered.load(Ordering::Relaxed);
    assert_eq!(
        got, MESSAGES as usize,
        "an endpoint polled every {POLL:?} delivered {got} of {MESSAGES} \
         datagrams sent every {PERIOD:?} over loopback; waiting must not \
         lose what arrives while it waits"
    );
}
