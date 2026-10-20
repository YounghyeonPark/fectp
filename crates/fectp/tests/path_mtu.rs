//! Path MTU discovery, through a relay that drops what is too large.
//!
//! Loopback carries 65535-byte datagrams, so on its own it has no MTU to
//! discover. The relay supplies one: anything over its limit is dropped, in
//! either direction, the way a link with a smaller MTU drops a datagram that
//! has the don't-fragment bit set or that no router will split. The limit can
//! be changed mid-session, which is a path that stops carrying large frames.
//!
//! Its own file because the ceiling is process-wide, and one test at a time
//! within it for the same reason.

mod common;

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType, PeerId};

/// The ceiling for every test here: ethernet under IPv4.
const CEILING: usize = 1472;

static SERIAL: Mutex<()> = Mutex::new(());

fn exclusive() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Bytes that will not compress, so a payload's size is its size on the wire.
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// A relay between one client and one server that drops any datagram larger
/// than its limit.
///
/// It has two ports towards the server and uses one at a time; switching is a
/// NAT rebinding, which the server sees as the client moving.
struct Relay {
    addr: SocketAddr,
    limit: Arc<AtomicUsize>,
    port: Arc<AtomicUsize>,
    dropped: Arc<AtomicU64>,
    /// Datagrams over 1200 bytes seen, in either direction, dropped or not.
    large: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl Relay {
    fn spawn(server: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
        let addr = front.local_addr().expect("addr");
        let limit = Arc::new(AtomicUsize::new(usize::MAX));
        let port = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let large = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        // Connected, so a timed read cannot lose a datagram (D80), and the
        // timeout is only how often these notice `stop`.
        let backs: Vec<UdpSocket> = (0..2)
            .map(|_| {
                let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
                back.connect(server).expect("connect back");
                back.set_read_timeout(Some(Duration::from_millis(20)))
                    .expect("timeout");
                back
            })
            .collect();

        // Client to server, through whichever port is current. The front
        // socket blocks and is woken on drop, as every relay here does.
        {
            let front = front.try_clone().expect("clone");
            let backs: Vec<UdpSocket> = backs
                .iter()
                .map(|b| b.try_clone().expect("clone"))
                .collect();
            let (limit, port, dropped, large, stop, client) = (
                Arc::clone(&limit),
                Arc::clone(&port),
                Arc::clone(&dropped),
                Arc::clone(&large),
                Arc::clone(&stop),
                Arc::clone(&client),
            );
            thread::spawn(move || {
                let mut buf = vec![0u8; 65535];
                loop {
                    let got = front.recv_from(&mut buf);
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok((n, from)) = got else {
                        continue;
                    };
                    *client.lock().expect("lock") = Some(from);
                    if n > 1200 {
                        large.fetch_add(1, Ordering::SeqCst);
                    }
                    if n > limit.load(Ordering::SeqCst) {
                        dropped.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                    let _ = backs[port.load(Ordering::SeqCst)].send(&buf[..n]);
                }
            });
        }

        // Server to client, one thread per port. Only the current port
        // carries anything: a mapping that has been replaced is gone.
        for (which, back) in backs.into_iter().enumerate() {
            let front = front.try_clone().expect("clone");
            let (limit, port, dropped, large, stop, client) = (
                Arc::clone(&limit),
                Arc::clone(&port),
                Arc::clone(&dropped),
                Arc::clone(&large),
                Arc::clone(&stop),
                Arc::clone(&client),
            );
            thread::spawn(move || {
                let mut buf = vec![0u8; 65535];
                while !stop.load(Ordering::Relaxed) {
                    let Ok(n) = back.recv(&mut buf) else {
                        continue;
                    };
                    if port.load(Ordering::SeqCst) != which {
                        continue;
                    }
                    if n > 1200 {
                        large.fetch_add(1, Ordering::SeqCst);
                    }
                    if n > limit.load(Ordering::SeqCst) {
                        dropped.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                    if let Some(to) = *client.lock().expect("lock") {
                        let _ = front.send_to(&buf[..n], to);
                    }
                }
            });
        }

        Self {
            addr,
            limit,
            port,
            dropped,
            large,
            stop,
        }
    }

    fn set_limit(&self, bytes: usize) {
        self.limit.store(bytes, Ordering::SeqCst);
    }

    /// Moves the client to the relay's other port, as a NAT rebinding would.
    fn rebind(&self) {
        self.port.fetch_xor(1, Ordering::SeqCst);
    }

    fn large(&self) -> u64 {
        self.large.load(Ordering::SeqCst)
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        common::wake(self.addr);
    }
}

/// A client and a server endpoint with a relay between them, both driven by
/// the test's own thread.
struct Pair {
    client: Endpoint,
    server: Endpoint,
    relay: Relay,
    /// The server, as the client knows it.
    to_server: PeerId,
    /// The client, as the server knows it.
    to_client: Option<PeerId>,
    /// Everything that arrived at the server.
    received: Vec<Vec<u8>>,
    moved: bool,
}

impl Pair {
    fn connect() -> Self {
        let mut pair = Self::connect_quietly();
        // Each side probes only once the other has spoken, so both speak.
        pair.client
            .send_reliable(pair.to_server, b"hello", PayloadType::Opaque)
            .expect("send");
        let peer = pair.to_client.expect("filed");
        pair.server
            .send_reliable(peer, b"hello back", PayloadType::Opaque)
            .expect("send");
        pair
    }

    /// Completes the handshake and sends nothing after it.
    fn connect_quietly() -> Self {
        let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        let relay = Relay::spawn(server.local_addr().expect("addr"));
        let public = *server.public_key().expect("identity");
        let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        let to_server = client.connect(relay.addr, Some(&public)).expect("connect");
        server.set_handshake_reply(&[]).expect("reply");
        let mut pair = Self {
            client,
            server,
            relay,
            to_server,
            to_client: None,
            received: Vec::new(),
            moved: false,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut client_ready = false;
        while !(client_ready && pair.to_client.is_some()) {
            assert!(Instant::now() < deadline, "never connected");
            if let Event::Connected { .. } = pair
                .client
                .poll(Some(Duration::from_millis(1)))
                .expect("client poll")
            {
                client_ready = true;
            }
            pair.pump_server();
        }
        pair
    }

    fn pump_server(&mut self) {
        match self
            .server
            .poll(Some(Duration::from_millis(1)))
            .expect("server poll")
        {
            Event::Connected { peer, .. } => self.to_client = Some(peer),
            Event::Message { data, .. } => self.received.push(data),
            Event::PeerMoved { .. } => self.moved = true,
            _ => {}
        }
    }

    /// Drives both sides until `done` holds, or `within` passes.
    fn run_until(&mut self, within: Duration, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if done(self) {
                return true;
            }
            self.client
                .poll(Some(Duration::from_millis(1)))
                .expect("client poll");
            self.pump_server();
        }
        done(self)
    }

    fn client_room(&self) -> usize {
        self.client.max_payload(self.to_server).expect("peer")
    }

    fn server_room(&self) -> usize {
        self.server
            .max_payload(self.to_client.expect("filed"))
            .expect("peer")
    }
}

/// Sets the ceiling for one test and puts it back afterwards, even on panic.
struct Ceiling(usize);

impl Ceiling {
    fn raise() -> Self {
        let original = fectp::max_datagram();
        fectp::set_max_datagram(CEILING);
        fectp::set_path_mtu_discovery(true);
        Self(original)
    }
}

impl Drop for Ceiling {
    fn drop(&mut self) {
        fectp::set_max_datagram(self.0);
        fectp::set_path_mtu_discovery(true);
    }
}

#[test]
fn a_session_starts_at_the_base_and_rises_to_what_the_path_carries() {
    let _serial = exclusive();
    let _ceiling = Ceiling::raise();
    let mut pair = Pair::connect();

    // 1200 bytes, before anything is proved. The base's room is measured
    // rather than written down, so overhead is not this test's business.
    let base = pair.client_room();
    let gained = CEILING - 1200;

    assert!(
        pair.run_until(Duration::from_secs(10), |p| p.client_room()
            == base + gained
            && p.server_room() == base + gained),
        "both directions should reach the ceiling on a path that carries it: \
         client {} server {}, from {base}",
        pair.client_room(),
        pair.server_room()
    );

    // And a frame that size is really sent and delivered.
    let big = incompressible(base + gained);
    pair.client
        .send(pair.to_server, &big, PayloadType::Opaque)
        .expect("a full frame is accepted");
    assert!(
        pair.run_until(Duration::from_secs(5), |p| p.received.contains(&big)),
        "the full-size frame arrived"
    );
}

#[test]
fn a_session_settles_at_the_largest_size_that_crosses() {
    let _serial = exclusive();
    let _ceiling = Ceiling::raise();
    let mut pair = Pair::connect();
    pair.relay.set_limit(1400);
    let base = pair.client_room();

    assert!(
        pair.run_until(Duration::from_secs(10), |p| p.client_room() == base + 200),
        "a path carrying 1400 should be found to carry 1400: room {} from {base}",
        pair.client_room()
    );
    // Long enough for the larger sizes to be given up on, three tries each.
    pair.run_until(Duration::from_secs(3), |_| false);
    assert_eq!(
        pair.client_room(),
        base + 200,
        "and stay there, not above it"
    );
    assert!(
        pair.relay.dropped() > 0,
        "the relay did turn the larger probes away"
    );
}

#[test]
fn a_path_that_stops_carrying_large_frames_is_noticed_and_left() {
    let _serial = exclusive();
    let _ceiling = Ceiling::raise();
    let mut pair = Pair::connect();
    let base = pair.client_room();
    assert!(
        pair.run_until(Duration::from_secs(10), |p| p.client_room() > base),
        "never rose"
    );

    // The path shrinks under the session. The next large message is lost,
    // its resend is lost, and that is what prompts the check.
    pair.relay.set_limit(1200);
    let room = pair.client_room();
    pair.client
        .send_reliable(pair.to_server, &incompressible(room), PayloadType::Opaque)
        .expect("queued");

    assert!(
        pair.run_until(Duration::from_secs(15), |p| p.client_room() == base),
        "the session should fall back to the base: room {} from {base}",
        pair.client_room()
    );

    // And the session still works, at the size the path does carry. Polling
    // above never returned an error, or `expect` would have said so.
    let after = incompressible(base);
    pair.client
        .send_reliable(pair.to_server, &after, PayloadType::Opaque)
        .expect("send");
    assert!(
        pair.run_until(Duration::from_secs(10), |p| p.received.contains(&after)),
        "a message at the base got through after the fall-back"
    );
}

#[test]
fn a_session_that_moves_starts_again_from_the_base() {
    let _serial = exclusive();
    let _ceiling = Ceiling::raise();
    let mut pair = Pair::connect();
    let base = pair.server_room();
    assert!(
        pair.run_until(Duration::from_secs(10), |p| p.server_room() > base),
        "never rose"
    );

    pair.relay.rebind();
    pair.client
        .send_reliable(pair.to_server, b"from somewhere new", PayloadType::Opaque)
        .expect("send");
    let mut fell = false;
    assert!(
        pair.run_until(Duration::from_secs(10), |p| {
            if p.moved {
                fell |= p.server_room() == base;
            }
            p.moved
        }),
        "the server never saw the client move"
    );
    // Checked the moment the move was seen, before a new search could rise.
    assert!(
        fell || pair.server_room() == base,
        "what was learned on the old path must not carry over"
    );
    assert!(
        pair.run_until(Duration::from_secs(10), |p| p.server_room() > base),
        "and the new path is searched in turn"
    );
}

#[test]
fn with_discovery_off_a_session_sends_at_the_ceiling_from_the_start() {
    let _serial = exclusive();
    let _ceiling = Ceiling::raise();
    fectp::set_path_mtu_discovery(false);
    let pair = Pair::connect();
    // The room at the ceiling, from the first moment, as before discovery.
    let gained = CEILING - 1200;
    fectp::set_path_mtu_discovery(true);
    let discovering = Pair::connect();
    assert_eq!(pair.client_room(), discovering.client_room() + gained);
}

/// A handshake alone does not earn a probe.
///
/// Completing one needs the endpoint's public key and a datagram whose source
/// address is whatever its sender wrote, so a session can be filed against an
/// address that never asked for anything. Probes are the largest datagrams an
/// endpoint sends unasked — several sizes at once, each tried three times — so
/// sending them before the peer has spoken would let one forged handshake aim
/// kilobytes at a victim. Keep-alives wait for the same proof.
#[test]
fn nothing_is_probed_before_the_peer_has_spoken() {
    let _serial = exclusive();
    let _ceiling = Ceiling::raise();
    let mut pair = Pair::connect_quietly();
    // Something else to wake the loop for, so a pass that would send probes
    // does run: without it, a quiet session never wakes at all, and the test
    // would pass on that alone.
    pair.client.set_keepalive(Some(Duration::from_millis(100)));
    pair.server.set_keepalive(Some(Duration::from_millis(100)));
    pair.run_until(Duration::from_secs(2), |_| false);
    assert_eq!(
        pair.relay.large(),
        0,
        "no datagram over 1200 bytes before either side heard from the other"
    );

    // The control: once both have spoken, probes go out.
    pair.client
        .send_reliable(pair.to_server, b"hello", PayloadType::Opaque)
        .expect("send");
    let peer = pair.to_client.expect("filed");
    pair.server
        .send_reliable(peer, b"hello back", PayloadType::Opaque)
        .expect("send");
    assert!(
        pair.run_until(Duration::from_secs(5), |p| p.relay.large() > 0),
        "probes follow once the peer has spoken"
    );
}

/// A `Connection` searches the same way, while it is receiving: it has no
/// loop of its own, so its timers run inside `recv` and `flush`, as its
/// keep-alives and retransmissions do.
#[test]
fn a_connection_rises_and_falls_back_as_an_endpoint_does() {
    let _serial = exclusive();
    let _ceiling = Ceiling::raise();
    let echo = common::Echo::start();
    let relay = Relay::spawn(echo.addr());
    let conn =
        Connection::connect(relay.addr, &echo.public(), &Identity::generate()).expect("connect");
    let base = conn.max_payload();
    let gained = CEILING - 1200;

    // The echo answering is the peer speaking.
    conn.send_reliable(b"hello", PayloadType::Opaque)
        .expect("send");
    conn.set_read_timeout(Some(Duration::from_millis(20)))
        .expect("timeout");
    let mut buf = vec![0u8; 65535];
    let mut receive_until = |within: Duration, done: &dyn Fn(&Connection) -> bool| {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if done(&conn) {
                return true;
            }
            let _ = conn.recv(&mut buf);
        }
        done(&conn)
    };

    assert!(
        receive_until(Duration::from_secs(10), &|c| c.max_payload()
            == base + gained),
        "the connection should reach the ceiling: {} from {base}",
        conn.max_payload()
    );

    relay.set_limit(1200);
    conn.send_reliable(
        &incompressible(conn.max_reliable_payload()),
        PayloadType::Opaque,
    )
    .expect("send");
    assert!(
        receive_until(Duration::from_secs(15), &|c| c.max_payload() == base),
        "and fall back when large frames stop arriving: {} from {base}",
        conn.max_payload()
    );
}
