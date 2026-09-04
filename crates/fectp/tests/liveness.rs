//! Noticing that a peer has gone away.
//!
//! A session whose peer has stopped existing looks exactly like a session
//! whose peer has nothing to say. **Silence is not evidence of death** — which
//! is why this is not simply a timer on the last thing heard. It becomes
//! evidence only when there was something to answer: with keep-alives on
//! ([`Endpoint::set_keepalive`]) the peer is asked at intervals, so silence
//! means it did not reply. Without them, this is an idle timeout and will drop
//! a peer that is alive and quiet.
//!
//! The timeout is off by default for that reason. A protocol built for sensors
//! that wake, report and sleep should not decide on their behalf that a quiet
//! device is a dead one.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType, PeerId};
use fectp_core::keys::Keypair;
use fectp_core::session::{Capabilities, Initiator};
use rand_core::OsRng;

const TIMEOUT: Duration = Duration::from_secs(5);

/// How long the server waits before giving up on a peer.
const PEER_TIMEOUT: Duration = Duration::from_millis(400);

/// What the server saw, and how many peers it still holds.
#[derive(Default)]
struct Seen {
    lost: Vec<PeerId>,
    peers: usize,
}

struct Server {
    addr: SocketAddr,
    public: [u8; 32],
    seen: Arc<Mutex<Seen>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn spawn(timeout: Option<Duration>, keepalive: Option<Duration>) -> Self {
        let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        server.set_peer_timeout(timeout);
        server.set_keepalive(keepalive);
        let addr = server.local_addr().expect("addr");
        let public = *server.public_key().expect("identity");
        let stop = Arc::new(AtomicBool::new(false));
        let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Seen::default()));
        let flag = Arc::clone(&stop);
        let record = Arc::clone(&seen);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match server.poll(Some(Duration::from_millis(20))) {
                    Ok(Event::Message { peer, data }) => {
                        let _ = server.send(peer, &data, PayloadType::Opaque);
                    }
                    Ok(Event::PeerLost { peer }) => {
                        record.lock().expect("lock").lost.push(peer);
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
                record.lock().expect("lock").peers = server.peer_count();
            }
        });
        Self {
            addr,
            public,
            seen,
            stop,
            handle: Some(handle),
        }
    }

    fn lost(&self) -> Vec<PeerId> {
        self.seen.lock().expect("lock").lost.clone()
    }

    fn peers(&self) -> usize {
        self.seen.lock().expect("lock").peers
    }

    /// Waits for a peer to be given up on, or gives up itself.
    fn wait_for_a_loss(&self, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if !self.lost().is_empty() {
                return true;
            }
        }
        false
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

fn exchange(conn: &Connection, message: &[u8]) -> fectp::Result<Vec<u8>> {
    conn.set_read_timeout(Some(TIMEOUT))?;
    conn.send(message, PayloadType::Opaque)?;
    let mut buf = vec![0u8; 4096];
    let n = conn.recv(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

#[test]
fn a_peer_that_stops_answering_is_given_up_on() {
    // Keep-alives on, so the server is asking and the silence means something.
    let server = Server::spawn(Some(PEER_TIMEOUT), Some(Duration::from_millis(80)));
    let conn =
        Connection::connect(server.addr, &server.public, &Identity::generate()).expect("connect");

    assert_eq!(
        exchange(&conn, b"here").expect("the session must work first"),
        b"here"
    );
    assert_eq!(server.peers(), 1, "the peer must be on file before it goes");

    // The peer stops existing. Its socket goes with it, so nothing answers the
    // challenges the server keeps sending.
    drop(conn);

    assert!(
        server.wait_for_a_loss(TIMEOUT),
        "a peer that answers nothing must be given up on"
    );
    let deadline = Instant::now() + TIMEOUT;
    while server.peers() > 0 && Instant::now() < deadline {}
    assert_eq!(
        server.peers(),
        0,
        "and its session must be released, not merely reported"
    );
}

#[test]
fn a_peer_that_keeps_answering_is_not() {
    // The control. Without it the test above is satisfied by a timeout that
    // fires on everything.
    let server = Server::spawn(Some(PEER_TIMEOUT), Some(Duration::from_millis(80)));
    let conn =
        Connection::connect(server.addr, &server.public, &Identity::generate()).expect("connect");

    // Sit in `recv` for several timeouts. The client sends nothing of its own;
    // answering the server's keep-alives is all that keeps it on file, which
    // is the whole mechanism under test.
    let deadline = Instant::now() + PEER_TIMEOUT * 5;
    let mut buf = vec![0u8; 4096];
    conn.set_keepalive(Some(Duration::from_millis(80)))
        .expect("keepalive");
    while Instant::now() < deadline {
        conn.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        let _ = conn.recv(&mut buf);
    }

    assert!(
        server.lost().is_empty(),
        "a peer that answers must not be given up on: {:?}",
        server.lost()
    );
    assert_eq!(
        exchange(&conn, b"still here").expect("the session must still work"),
        b"still here"
    );
}

#[test]
fn a_peer_is_kept_indefinitely_when_no_timeout_is_set() {
    // Off by default, and the default is what a sleeping sensor gets.
    let server = Server::spawn(None, None);
    let conn =
        Connection::connect(server.addr, &server.public, &Identity::generate()).expect("connect");
    assert_eq!(
        exchange(&conn, b"here").expect("the session must work first"),
        b"here"
    );

    drop(conn);

    let quiet = Instant::now() + PEER_TIMEOUT * 5;
    while Instant::now() < quiet {}
    assert!(
        server.lost().is_empty(),
        "with no timeout configured, nothing may be given up on"
    );
    assert_eq!(server.peers(), 1, "and the session must still be held");
}

#[test]
fn a_session_that_never_spoke_is_not_sent_keepalives() {
    // Reaching the peer table needs nothing but the endpoint's public key,
    // which is public by design, and one datagram. The source address on that
    // datagram is whatever the sender wrote — so a session can be filed
    // pointing at an address that has never sent anything and may never have
    // heard of this endpoint.
    //
    // Keep-alives then aim 38 bytes at it on every interval, for as long as
    // the session survives eviction. One spoofed datagram in, an unbounded
    // stream out, at a target of the sender's choosing. The proof that an
    // address can receive is that something authenticated arrived from it,
    // which is the flag the eviction order already keeps.
    let server = Server::spawn(None, Some(Duration::from_millis(100)));

    // A socket that completes a handshake and then says nothing. The state it
    // leaves behind is the one a spoofed source address produces: a filed
    // session that has never spoken.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    sock.connect(server.addr).expect("connect");
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");

    let mut initiator = Initiator::new(
        Keypair::generate(&mut OsRng),
        server.public,
        0x51_1E_17_00,
        Capabilities::minimal(1200),
    )
    .expect("initiator");
    let mut wire = vec![0u8; 2048];
    let n = initiator
        .write_init(&mut OsRng, b"", &mut wire)
        .expect("init");
    sock.send(&wire[..n]).expect("send init");

    // The handshake response is the one datagram this exchange is owed.
    let answered = sock.recv(&mut wire).is_ok();
    assert!(answered, "the handshake must have completed for this to mean anything");

    // From here the session exists and has never spoken. Nothing more should
    // arrive.
    let watch = Instant::now() + Duration::from_millis(800);
    let mut unasked_for = 0;
    while Instant::now() < watch {
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");
        if sock.recv(&mut wire).is_ok() {
            unasked_for += 1;
        }
    }

    assert_eq!(
        unasked_for, 0,
        "a session that has never been heard from received {unasked_for} \
         datagrams it did not ask for; one datagram in must not buy a stream out"
    );
}
