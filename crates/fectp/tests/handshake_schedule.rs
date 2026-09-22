//! What the handshake does when an opening frame goes missing, and how long it
//! waits before deciding that it did.
//!
//! [D66](../../../docs/DECISIONS.md) doubled the handshake budget and said
//! plainly that doubling a margin is not understanding it: the schedule was a
//! fixed linear backoff that knew nothing about the path. Through the relay
//! here a round trip is about 24 ms, and a lost opening frame cost 288 ms — an
//! order of magnitude more than the path needs, paid on every reconnect by the
//! device this protocol is written for, the one that wakes, reports and
//! sleeps.
//!
//! These tests are about that interval. They put a relay in the path so that a
//! chosen datagram can be thrown away, and they measure what the wait costs.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Endpoint, Event, Identity, PeerId, PeerKey};

/// First byte of a `HandshakeInit` frame: version 1, frame type 1.
///
/// From the header layout in SPEC 3, and pinned by `docs/test-vectors.txt` —
/// so this does not rest on a comment.
const HANDSHAKE_INIT: u8 = 0x11;

/// Forwards datagrams between one client and one server, able to throw away
/// one opening frame on request.
///
/// Armed rather than counted. Naming the *n*th opening frame looked simpler and
/// was wrong: loopback loses datagrams of its own — one warm-up handshake in
/// fifteen runs here lost its opening frame for real — and an adapted schedule
/// occasionally resends one early, so the index drifts and the drop lands on a
/// handshake the test was not measuring. Arming it makes the next opening frame
/// the one that goes, whatever came before.
struct Relay {
    addr: SocketAddr,
    /// Opening frames the relay has seen arrive from the client.
    opens: Arc<AtomicUsize>,
    /// Set to drop the next opening frame, and cleared when it is dropped.
    armed: Arc<AtomicBool>,
    /// Set to stop forwarding anything, turning a working path into a silent
    /// one without changing its address.
    swallow: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Relay {
    fn start(server: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("relay bind");
        socket
            .set_read_timeout(Some(Duration::from_millis(1)))
            .expect("timeout");
        let addr = socket.local_addr().expect("addr");

        let opens = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let swallow = Arc::new(AtomicBool::new(false));
        let armed = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&opens);
        let halt = Arc::clone(&stop);
        let eat = Arc::clone(&swallow);
        let trap = Arc::clone(&armed);

        let handle = thread::spawn(move || {
            let mut buf = vec![0u8; 2048];
            let mut client: Option<SocketAddr> = None;

            while !halt.load(Ordering::Relaxed) {
                let Ok((n, from)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if from == server {
                    if let Some(back) = client {
                        let _ = socket.send_to(&buf[..n], back);
                    }
                    continue;
                }
                client = Some(from);

                if n > 0 && buf[0] == HANDSHAKE_INIT {
                    seen.fetch_add(1, Ordering::Relaxed);
                    if trap.swap(false, Ordering::Relaxed) {
                        continue;
                    }
                }
                if eat.load(Ordering::Relaxed) {
                    continue;
                }
                let _ = socket.send_to(&buf[..n], server);
            }
        });

        Self {
            addr,
            opens,
            armed,
            swallow,
            stop,
            handle: Some(handle),
        }
    }

    fn opening_frames(&self) -> usize {
        self.opens.load(Ordering::Relaxed)
    }

    /// Throws away the next opening frame, once.
    fn arm(&self) {
        self.armed.store(true, Ordering::Relaxed);
    }

    /// Whether the armed drop is still waiting for a frame to land on.
    fn still_armed(&self) -> bool {
        self.armed.load(Ordering::Relaxed)
    }

    /// Stops forwarding, so the same address goes silent.
    fn go_silent(&self) {
        self.swallow.store(true, Ordering::Relaxed);
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A server endpoint on its own thread, answering handshakes until stopped.
struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn start(identity: Identity) -> Self {
        let endpoint = Endpoint::bind("127.0.0.1:0", identity).expect("server bind");
        let addr = endpoint.local_addr().expect("addr");
        let stop = Arc::new(AtomicBool::new(false));
        let halt = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            let mut endpoint = endpoint;
            while !halt.load(Ordering::Relaxed) {
                let _ = endpoint.poll(Some(Duration::from_millis(1)));
            }
        });

        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Connects and waits for the outcome, returning how long it took and the peer.
fn connect_timed(
    client: &mut Endpoint,
    addr: SocketAddr,
    key: &PeerKey,
) -> (Duration, Option<PeerId>) {
    let started = Instant::now();
    client.connect(addr, Some(key)).expect("connect starts");
    let deadline = started + Duration::from_secs(20);
    while Instant::now() < deadline {
        match client.poll(Some(Duration::from_millis(2))) {
            Ok(Event::Connected { peer, .. }) => return (started.elapsed(), Some(peer)),
            Ok(Event::ConnectFailed { .. }) => return (started.elapsed(), None),
            _ => {}
        }
    }
    panic!("the handshake neither completed nor failed inside twenty seconds");
}

/// Connects, insisting it succeeds.
fn connect_ok(client: &mut Endpoint, addr: SocketAddr, key: &PeerKey) -> (Duration, PeerId) {
    let (took, peer) = connect_timed(client, addr, key);
    (took, peer.expect("the handshake must complete"))
}

/// Undisturbed handshakes run before the one under test.
///
/// One sample is not an estimate. RFC 6298 sets the variation term to half the
/// first measurement, so a cold estimate is three times the round trip by
/// construction and comes down only as samples arrive. Measured on this
/// harness: 288 ms cold, 65 ms after one sample, 50 ms after twenty, against a
/// path of about 24 ms. Four is enough for the margin these tests need and
/// cheap enough to run every time.
const WARM_UP: usize = 4;

/// The wait a cold schedule takes before resending an opening frame.
///
/// The discriminator these tests use. Nothing on the fixed schedule recovers
/// from a lost opening frame in less than this, whatever the path, so coming in
/// under it means the estimate was consulted. A host slow enough to break the
/// assertion is slow enough to break it cold as well, which is the honest limit
/// of any wall-clock claim here.
const COLD_WAIT: Duration = Duration::from_millis(250);

/// How many times a trial is repeated when the network interferes with it.
const TRIALS: usize = 8;

/// Runs enough undisturbed handshakes for the estimate to settle, releasing
/// each session as it goes, and returns what the last one took.
fn warm_up(client: &mut Endpoint, addr: SocketAddr, key: &PeerKey) -> Duration {
    let mut last = Duration::ZERO;
    for _ in 0..WARM_UP {
        let (took, peer) = connect_ok(client, addr, key);
        client.disconnect(peer);
        last = took;
    }
    last
}

/// Loses one opening frame on purpose and returns how long recovery took.
///
/// Repeated until the only frame missing is the one asked for. A relay is a
/// network and loopback drops datagrams of its own, which `handshake_loss.rs`
/// says and this file measured: a trial where something else went missing is
/// measuring the loss rather than the schedule. Exactly two opening frames —
/// the one taken and the resend that got through — is what makes a trial
/// countable. The property asserted afterwards is the same either way; only
/// interference is retried.
fn recovery_from_one_lost_frame(client: &mut Endpoint, relay: &Relay, key: &PeerKey) -> Duration {
    for _ in 0..TRIALS {
        let before = relay.opening_frames();
        relay.arm();
        let (took, peer) = connect_ok(client, relay.addr, key);
        client.disconnect(peer);
        let sent = relay.opening_frames() - before;
        if !relay.still_armed() && sent == 2 {
            return took;
        }
    }
    panic!("no trial in {TRIALS} lost exactly the frame it was asked to lose");
}

/// A lost opening frame must not cost a fixed quarter of a second on a path
/// that answers in a fraction of one.
///
/// The warm-up measures the path. The handshake after it loses its opening
/// frame, and the wait before resending is what this asserts on: the fixed
/// schedule cannot come in under [`COLD_WAIT`], and a schedule that has
/// measured this path has no reason to wait anything like it.
#[test]
fn a_lost_opening_frame_costs_the_path_and_not_a_fixed_quarter_second() {
    let identity = Identity::generate();
    let key = *identity.public();
    let server = Server::start(identity);
    let relay = Relay::start(server.addr);

    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("client bind");
    let measured = warm_up(&mut client, relay.addr, &key);

    let recovered = recovery_from_one_lost_frame(&mut client, &relay, &key);
    assert!(
        recovered < COLD_WAIT,
        "recovering from one lost opening frame took {recovered:?} on a path \
         measured at {measured:?}; the fixed schedule waits {COLD_WAIT:?} \
         before resending whatever the path is, so nothing has adapted"
    );
}

/// What one path measures must not be applied to another.
///
/// An endpoint that has learned loopback is fast must not carry that to a peer
/// it has never reached: an estimate belongs to the path it came from. Here the
/// second address answers nothing, and the endpoint must still spend its whole
/// budget before reporting failure rather than giving up at loopback speed.
#[test]
fn a_fast_path_does_not_shorten_the_budget_for_an_unrelated_one() {
    let identity = Identity::generate();
    let key = *identity.public();
    let server = Server::start(identity);

    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("client bind");
    connect_ok(&mut client, server.addr, &key);

    // A bound socket nothing ever reads: datagrams arrive and no answer comes,
    // which is an unreachable peer at an address that is otherwise valid.
    let hole = UdpSocket::bind("127.0.0.1:0").expect("hole bind");
    let hole_addr = hole.local_addr().expect("addr");

    let (elapsed, peer) = connect_timed(&mut client, hole_addr, &key);
    assert!(peer.is_none(), "a black hole must not produce a session");
    assert!(
        elapsed >= Duration::from_millis(1_400),
        "gave up on an unanswered peer after {elapsed:?}; four attempts at 250, \
         500 and 750 ms is the budget, so a measurement from another path has \
         shortened it"
    );
}

/// The estimate has to survive the session it was measured on.
///
/// A device that wakes, reports and sleeps reconnects to the same address over
/// and over, and each reconnect is a fresh handshake. If what the last one
/// measured goes when its session goes, every reconnect pays the cold schedule
/// and the adaptation is worth nothing to the caller it was built for.
#[test]
fn what_a_path_measured_outlives_the_session() {
    let identity = Identity::generate();
    let key = *identity.public();
    let server = Server::start(identity);
    let relay = Relay::start(server.addr);

    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("client bind");
    // `warm_up` releases each session as it goes, which is what a sleeping
    // device's reconnect looks like from here: every peer the measurements came
    // from is gone by the time the handshake under test starts, and only the
    // path is left.
    let measured = warm_up(&mut client, relay.addr, &key);
    assert_eq!(client.connecting(), 0, "no handshake is still outstanding");

    let recovered = recovery_from_one_lost_frame(&mut client, &relay, &key);
    assert!(
        recovered < COLD_WAIT,
        "the reconnect took {recovered:?} after one dropped opening frame on a \
         path measured at {measured:?}, so what those handshakes measured did \
         not outlive the sessions they produced"
    );
}

/// A path that was fast and then went silent must still be given the whole
/// budget before the connect is called off.
///
/// This is what the attempt count alone cannot do. Once an address has been
/// measured at twenty-odd milliseconds, four attempts on that estimate are
/// over in under two tenths of a second — so an endpoint that stopped there
/// would report an unreachable peer more than ten times sooner than it did
/// before any of this, on a path that may simply have stalled. The attempts
/// and the time the cold schedule would have taken both have to be spent.
#[test]
fn a_measured_path_that_goes_silent_still_gets_the_whole_budget() {
    let identity = Identity::generate();
    let key = *identity.public();
    let server = Server::start(identity);
    let relay = Relay::start(server.addr);

    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("client bind");
    let measured = warm_up(&mut client, relay.addr, &key);
    assert!(
        measured < COLD_WAIT,
        "the warm-up handshakes took {measured:?}, so the estimate they left \
         is not the fast one this test needs"
    );

    relay.go_silent();

    let (elapsed, peer) = connect_timed(&mut client, relay.addr, &key);
    assert!(peer.is_none(), "a silent path must not produce a session");
    assert!(
        elapsed >= Duration::from_millis(1_400),
        "gave up on a measured path that went silent after {elapsed:?}; the          cold schedule would have spent about 2.5 s, and nothing may give up          sooner than it did before the estimate existed"
    );
}
