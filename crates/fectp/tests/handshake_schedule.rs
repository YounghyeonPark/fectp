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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Endpoint, Event, Identity, PeerId, PeerKey};

mod common;

/// First byte of a `HandshakeInit` frame: version 1, frame type 1.
///
/// From the header layout in SPEC 3, and pinned by `docs/test-vectors.txt` —
/// so this does not rest on a comment.
const HANDSHAKE_INIT: u8 = 0x11;

/// Forwards datagrams between one client and one server, able to throw away
/// one opening frame on request, go silent, or hold replies back.
///
/// Armed rather than counted. Naming the *n*th opening frame looked simpler and
/// was wrong: loopback loses datagrams of its own — one warm-up handshake in
/// fifteen runs here lost its opening frame for real — and an adapted schedule
/// occasionally resends one early, so the index drifts and the drop lands on a
/// handshake the test was not measuring. Arming it makes the next opening frame
/// the one that goes, whatever came before.
///
/// **Blocking, with no read timeout, and that is load-bearing.** This relay
/// used to read its socket in a loop of short timeouts, and on Windows it lost
/// what it was sent: with nothing behind it but an echo, it received 81 to 98
/// per cent, and 47 to 98 per cent once replies were held back, across read
/// timeouts from 1 to 25 ms. What in that loop lost them was not pinned down —
/// two plain sockets with the same timeouts lost well under one per cent —
/// but blocking reads lost none in 1,800 and this relay, rebuilt to block,
/// none in 720. So it blocks, held replies go out from a second thread that
/// sleeps until each is due, and dropping it wakes the read with a datagram.
///
/// Everything this file used to call loopback losing datagrams went through
/// the old relay. How much of that was loopback is now an open question.
struct Relay {
    addr: SocketAddr,
    /// Opening frames the relay has seen arrive from the client.
    opens: Arc<AtomicUsize>,
    /// Set to drop the next opening frame, and cleared when it is dropped.
    armed: Arc<AtomicBool>,
    /// Set to stop forwarding anything, turning a working path into a silent
    /// one without changing its address.
    swallow: Arc<AtomicBool>,
    /// Milliseconds added to every reply, turning loopback into a slow path.
    delay: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    releaser: Option<thread::JoinHandle<()>>,
}

impl Relay {
    fn start(server: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("relay bind");
        let addr = socket.local_addr().expect("addr");
        let out = socket.try_clone().expect("relay clone");

        let opens = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let swallow = Arc::new(AtomicBool::new(false));
        let armed = Arc::new(AtomicBool::new(false));
        let delay = Arc::new(AtomicU64::new(0));
        let seen = Arc::clone(&opens);
        let halt = Arc::clone(&stop);
        let eat = Arc::clone(&swallow);
        let trap = Arc::clone(&armed);
        let late = Arc::clone(&delay);

        // Every reply is held for the same time, so they fall due in the order
        // they were queued and sleeping until each in turn is exact.
        let (hold, held) = mpsc::channel::<(Instant, Vec<u8>, SocketAddr)>();
        let releaser = thread::spawn(move || {
            while let Ok((due, bytes, to)) = held.recv() {
                let now = Instant::now();
                if due > now {
                    thread::sleep(due - now);
                }
                let _ = out.send_to(&bytes, to);
            }
        });

        let handle = thread::spawn(move || {
            let mut buf = vec![0u8; 2048];
            let mut client: Option<SocketAddr> = None;

            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf) else {
                    if halt.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                };
                if halt.load(Ordering::Relaxed) {
                    break;
                }
                if from == server {
                    if let Some(back) = client {
                        let wait = Duration::from_millis(late.load(Ordering::Relaxed));
                        if wait.is_zero() {
                            let _ = socket.send_to(&buf[..n], back);
                        } else {
                            let _ = hold.send((Instant::now() + wait, buf[..n].to_vec(), back));
                        }
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
            // Dropping `hold` here ends the releaser.
        });

        Self {
            addr,
            opens,
            armed,
            swallow,
            delay,
            stop,
            handle: Some(handle),
            releaser: Some(releaser),
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

    /// Holds every reply back by this much, so the path is that much slower.
    fn slow_by(&self, extra: Duration) {
        self.delay.store(
            u64::try_from(extra.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // The read has no timeout, so something has to arrive for it to see
        // the flag. Sent more than once because this is loopback too.
        if let Ok(waker) = UdpSocket::bind("127.0.0.1:0") {
            for _ in 0..3 {
                let _ = waker.send_to(&[0], self.addr);
            }
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if let Some(releaser) = self.releaser.take() {
            let _ = releaser.join();
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
///
/// For the places where a handshake failing is the test failing. Where it is
/// the host being busy — a warm-up sample, a trial — [`connect_timed`] is used
/// directly and the attempt discarded, because a handshake that spent its
/// whole budget and gave up measures the machine, not the schedule.
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

/// How many attempts a trial may take, counting those the network spoils.
const ATTEMPTS: usize = 8;

/// How many countable trials the assertion is taken over.
///
/// One was enough until it was not. A trial measures the wait before a resend
/// plus whatever the host added, and a host adds in one direction only: the
/// resend is scheduled inside `poll`, so a thread that does not run makes the
/// wait look longer and never shorter. Measured with four copies of this file
/// running at once — the load that first broke the single-trial version — one
/// trial ranged from 63 ms to 298 ms while the best of four stayed inside 64
/// to 78 ms on every run of twelve. The floor is what the schedule chose;
/// everything above it is the machine.
const COUNTABLE: usize = 4;

/// Runs enough undisturbed handshakes for the estimate to settle, releasing
/// each session as it goes, and returns what the last one took.
fn warm_up(client: &mut Endpoint, addr: SocketAddr, key: &PeerKey) -> Duration {
    let mut last = Duration::ZERO;
    let mut samples = 0;
    for _ in 0..ATTEMPTS {
        if samples == WARM_UP {
            break;
        }
        // A handshake that gave up is not a sample. Under load this happens:
        // four copies of this file at once cost one handshake in about a
        // hundred its whole ten-second budget. Insisting here made that a
        // failure of whichever test was warming up, reported as though the
        // schedule were wrong.
        let (took, Some(peer)) = connect_timed(client, addr, key) else {
            continue;
        };
        client.disconnect(peer);
        last = took;
        samples += 1;
    }
    assert_eq!(
        samples, WARM_UP,
        "only {samples} of {WARM_UP} warm-up handshakes completed in {ATTEMPTS} \
         attempts, so there is no estimate to test against"
    );
    last
}

/// Loses one opening frame on purpose and returns the shortest recovery seen.
///
/// Two kinds of noise are filtered here, and they need different treatment.
///
/// A trial where something *other* than the armed frame went missing is not a
/// trial at all — it measures loopback's own loss, which `handshake_loss.rs`
/// says happens and this file has seen. Exactly two opening frames, the one
/// taken and the resend that got through, is what makes a trial countable;
/// anything else is discarded and attempted again.
///
/// A trial that was countable but slow is a different thing: the frames went
/// as intended and the host was busy. That cannot be seen in the frame count,
/// and it cannot be averaged away either, because it is one-sided. So the best
/// of [`COUNTABLE`] trials is what comes back.
fn recovery_from_one_lost_frame(
    client: &mut Endpoint,
    relay: &Relay,
    key: &PeerKey,
) -> (Duration, usize) {
    let mut countable = Vec::new();
    for _ in 0..ATTEMPTS {
        if countable.len() == COUNTABLE {
            break;
        }
        let before = relay.opening_frames();
        relay.arm();
        // Same reason as the warm-up: a handshake that gave up is the host,
        // and the frame count cannot tell that apart from a spoiled drop.
        let (took, Some(peer)) = connect_timed(client, relay.addr, key) else {
            continue;
        };
        client.disconnect(peer);
        let sent = relay.opening_frames() - before;
        if !relay.still_armed() && sent == 2 {
            countable.push(took);
        }
    }
    let best = countable.iter().min().copied().unwrap_or_else(|| {
        panic!("no trial in {ATTEMPTS} lost exactly the frame it was asked to lose")
    });
    (best, countable.len())
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

    let (recovered, trials) = recovery_from_one_lost_frame(&mut client, &relay, &key);
    assert!(
        recovered < COLD_WAIT,
        "the quickest of {trials} recoveries from one lost opening frame took \
         {recovered:?} on a path measured at {measured:?}; the fixed schedule \
         waits {COLD_WAIT:?} before resending whatever the path is, so nothing \
         has adapted. A busy host lengthens a trial and cannot shorten one, so \
         this is the schedule and not the machine"
    );
}

/// A lost opening frame must not poison what the path measured.
///
/// Karn's algorithm, and the only thing in this file that tests it. Once an
/// opening frame has been resent there is nothing in the reply to say which
/// attempt it answers — the frame goes out byte for byte identical — so the
/// round trip measured from the first send includes the wait before the
/// resend. Folding that in tells the endpoint the path is an order of
/// magnitude slower than it is.
///
/// It compounds, which is what makes it worth its own test rather than a note.
/// Measured with the rule removed: the first round of dropped frames still
/// recovers in 74 ms, the second in 527 ms, the third in 5.04 s. With the rule
/// in place the same three rounds are 70, 76 and 76 ms. So the assertion is on
/// the second round — the first is where the bad sample would be taken, not
/// where it would be spent.
#[test]
fn a_lost_opening_frame_does_not_poison_what_the_path_measured() {
    let identity = Identity::generate();
    let key = *identity.public();
    let server = Server::start(identity);
    let relay = Relay::start(server.addr);

    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("client bind");
    let measured = warm_up(&mut client, relay.addr, &key);

    // Every trial in here resends, so every one of them is a sample Karn
    // refuses. Nothing is asserted about this round; it is the poison.
    let (first, _) = recovery_from_one_lost_frame(&mut client, &relay, &key);

    let (second, trials) = recovery_from_one_lost_frame(&mut client, &relay, &key);
    assert!(
        second < COLD_WAIT,
        "the quickest of {trials} recoveries was {first:?} before a round of \
         dropped opening frames and {second:?} after, on a path measured at \
         {measured:?}; a resent handshake has been folded into the estimate, \
         which makes every later loss more expensive than the one before"
    );
}

/// What one path measures must not be applied to another.
///
/// An endpoint that has learned loopback is fast must not carry that to a peer
/// it has never reached: an estimate belongs to the path it came from.
///
/// Asserted on when the attempts went out, not on when the endpoint gave up.
/// Giving up is governed by the budget floor, which spends the cold schedule's
/// wall clock whatever the estimate says — so an endpoint that pooled its
/// measurements would still take the whole budget, and this test used to say
/// so and pass. Measured: with the estimates pooled it gave up after 3.1 s
/// against 2.5 s correct, comfortably past the 1.4 s that was asserted. The
/// floor was answering for the property, and the property had no test.
///
/// The frames themselves cannot be argued with. On an address never reached,
/// the cold schedule puts them 250, 500 and 750 ms apart; pooled with
/// loopback, the same run spaced them 51 to 65 ms. A busy host only ever
/// widens a gap, so the narrowest one is the schedule's own.
#[test]
fn a_fast_path_does_not_shorten_the_budget_for_an_unrelated_one() {
    /// Between [`COLD_WAIT`] and what a loopback estimate would give, with
    /// about four times the room on either side.
    const NARROWEST: Duration = Duration::from_millis(200);

    let identity = Identity::generate();
    let key = *identity.public();
    let server = Server::start(identity);

    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("client bind");
    connect_ok(&mut client, server.addr, &key);

    // A bound socket that answers nothing: an unreachable peer at an address
    // that is otherwise valid. Read here only to time the arrivals, which the
    // sender cannot observe.
    let hole = UdpSocket::bind("127.0.0.1:0").expect("hole bind");
    let hole_addr = hole.local_addr().expect("addr");

    let arrivals = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&arrivals);
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let watcher = thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        // No read timeout: a timestamp missed because the wait swallowed the
        // frame would merge two gaps into one wider one (see `common::wake`).
        loop {
            let got = hole.recv_from(&mut buf);
            if flag.load(Ordering::Relaxed) {
                break;
            }
            if let Ok((n, _)) = got {
                if n > 0 && buf[0] == HANDSHAKE_INIT {
                    record.lock().expect("lock").push(Instant::now());
                }
            }
        }
    });

    let (elapsed, peer) = connect_timed(&mut client, hole_addr, &key);
    stop.store(true, Ordering::Relaxed);
    common::wake(hole_addr);
    watcher.join().expect("the watching thread");

    assert!(peer.is_none(), "a black hole must not produce a session");

    let at = arrivals.lock().expect("lock").clone();
    assert!(
        at.len() >= 2,
        "only {} opening frames reached the black hole, so there is no \
         spacing to judge",
        at.len()
    );
    let narrowest = at
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .min()
        .expect("at least one gap");
    assert!(
        narrowest >= NARROWEST,
        "the closest two of {} attempts on a path never reached were \
         {narrowest:?} apart; the cold schedule leaves {COLD_WAIT:?}, so an \
         estimate from another path has been applied to this one. A busy host \
         widens a gap and cannot narrow one, so this is the schedule",
        at.len()
    );

    // And the budget floor, which is the other half of the name. Held here as
    // well as in `a_measured_path_that_goes_silent_still_gets_the_whole_budget`
    // because this is the path that was never measured at all.
    assert!(
        elapsed >= Duration::from_millis(1_400),
        "gave up on an unanswered peer after {elapsed:?}; four attempts at 250, \
         500 and 750 ms is the budget"
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

    let (recovered, trials) = recovery_from_one_lost_frame(&mut client, &relay, &key);
    assert!(
        recovered < COLD_WAIT,
        "the quickest of {trials} reconnects took {recovered:?} after one \
         dropped opening frame on a path measured at {measured:?}, so what \
         those handshakes measured did not outlive the sessions they produced"
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
        "gave up on a measured path that went silent after {elapsed:?}; the \
         cold schedule would have spent about 2.5 s, and nothing may give up \
         sooner than it did before the estimate existed"
    );
}

/// A path slower than the cold schedule must be learned, not resent to forever.
///
/// D71's residue, stated there as a limit: such a path's handshakes always
/// resend, a resent handshake is never sampled, so the estimate never learns
/// the path is slow and every handshake to it sends its opening frame twice.
/// Measured before the fix, on a path 400 ms slower than loopback: every
/// handshake of seven sent exactly two, in each of six runs.
///
/// Judged by opening frames per handshake rather than by the clock, because a
/// frame is resent or it is not and a busy host cannot change which. Most
/// rather than all of them after learning: a settled estimate occasionally
/// resends a little early, which D71 accepts as the price of a tight one, and
/// that costs one frame without meaning the path went unmeasured. Before the
/// fix the count of single-frame handshakes here was zero.
#[test]
fn a_path_slower_than_the_cold_schedule_is_learned() {
    /// Well past the cold schedule's first wait, well inside its budget.
    const SLOW: Duration = Duration::from_millis(400);
    /// Handshakes allowed to resend before the path must have been learned.
    const LEARNING: usize = 3;
    /// Handshakes after that, of which most must send one opening frame.
    const LEARNED: usize = 4;

    let identity = Identity::generate();
    let key = *identity.public();
    let server = Server::start(identity);
    let relay = Relay::start(server.addr);
    relay.slow_by(SLOW);

    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("client bind");
    let mut frames = Vec::new();
    for _ in 0..LEARNING + LEARNED {
        let before = relay.opening_frames();
        let (_, peer) = connect_timed(&mut client, relay.addr, &key);
        if let Some(peer) = peer {
            client.disconnect(peer);
        }
        frames.push(relay.opening_frames() - before);
    }

    let single = frames[LEARNING..].iter().filter(|&&n| n == 1).count();
    assert!(
        single * 4 >= LEARNED * 3,
        "opening frames per handshake on a path {SLOW:?} slower than loopback \
         were {frames:?}; after {LEARNING} handshakes at least three in four \
         should need only one, and a path that keeps resending is a path that \
         was never measured"
    );
}
