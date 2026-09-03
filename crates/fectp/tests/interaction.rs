//! The new mechanisms working together, in the situation they exist for.
//!
//! Keep-alives, address migration and peer timeouts were each built and tested
//! on their own. The case they were built for needs all three at once: a
//! device that connects, goes quiet, and has its NAT mapping re-created on a
//! different port while it is saying nothing.
//!
//! Nothing in the application sends anything during that. If the session
//! survives, it survives because the transport noticed on its own.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType, PeerId};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Short enough that several pass during the quiet period.
const KEEPALIVE: Duration = Duration::from_millis(100);

/// Long enough that a keep-alive answers before it fires, and short enough
/// that a session which stops being reachable is noticed inside the test.
const PEER_TIMEOUT: Duration = Duration::from_millis(1200);

// --------------------------------------------------------------- harness ---

/// A NAT whose mapping is expired on demand and re-created on a new port.
///
/// Expiry is on demand rather than after a fixed number of datagrams, so it
/// can be made to happen while the application is idle. **Re-creation still
/// needs an outbound datagram**, because that is what a NAT does: the mapping
/// appears when something is sent through it. So the new port is never used —
/// and the server never learns of it — unless the side behind the NAT sends
/// something. That is the whole reason keep-alives are the side-behind-the-NAT's
/// job, and the second test below is what holds it to that.
struct RebindingNat {
    addr: SocketAddr,
    rebind: Arc<AtomicBool>,
    rebound: Arc<AtomicBool>,
    from_new_port: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl RebindingNat {
    fn spawn(server: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
        front
            .set_read_timeout(Some(Duration::from_millis(10)))
            .expect("timeout");
        let addr = front.local_addr().expect("addr");

        let mut ports = Vec::new();
        for _ in 0..2 {
            let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
            back.connect(server).expect("connect back");
            back.set_read_timeout(Some(Duration::from_millis(10)))
                .expect("timeout");
            ports.push(back);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let rebind = Arc::new(AtomicBool::new(false));
        let rebound = Arc::new(AtomicBool::new(false));
        let from_new_port = Arc::new(AtomicU64::new(0));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        // Client to server, through whichever mapping is current.
        {
            let front = front.try_clone().expect("clone");
            let out: Vec<UdpSocket> = ports
                .iter()
                .map(|s| s.try_clone().expect("clone"))
                .collect();
            let flag = Arc::clone(&stop);
            let asked = Arc::clone(&rebind);
            let moved = Arc::clone(&rebound);
            let learn = Arc::clone(&client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok((n, from)) = front.recv_from(&mut buf) else {
                        continue;
                    };
                    *learn.lock().expect("lock") = Some(from);
                    let which = if asked.load(Ordering::SeqCst) {
                        moved.store(true, Ordering::SeqCst);
                        1
                    } else {
                        0
                    };
                    let _ = out[which].send(&buf[..n]);
                }
            });
        }

        // Server to client. The old mapping stops carrying anything once it
        // has been replaced, which is what makes the session's survival mean
        // something.
        for (index, back) in ports.into_iter().enumerate() {
            let front = front.try_clone().expect("clone");
            let flag = Arc::clone(&stop);
            let learn = Arc::clone(&client);
            let asked = Arc::clone(&rebind);
            let counted = Arc::clone(&from_new_port);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok(n) = back.recv(&mut buf) else {
                        continue;
                    };
                    if index == 0 && asked.load(Ordering::SeqCst) {
                        continue;
                    }
                    if index == 1 {
                        counted.fetch_add(1, Ordering::SeqCst);
                    }
                    let target = *learn.lock().expect("lock");
                    if let Some(target) = target {
                        let _ = front.send_to(&buf[..n], target);
                    }
                }
            });
        }

        Self {
            addr,
            rebind,
            rebound,
            from_new_port,
            stop,
        }
    }

    /// Expires the current mapping. The next outbound datagram creates a new
    /// one on the other port; until then nothing gets in or out.
    fn expire_the_mapping(&self) {
        self.rebind.store(true, Ordering::SeqCst);
    }

    fn has_rebound(&self) -> bool {
        self.rebound.load(Ordering::SeqCst)
    }

    /// Datagrams the server has sent through the new mapping, which it can
    /// only do once it has followed the peer there.
    fn delivered_on_the_new_port(&self) -> u64 {
        self.from_new_port.load(Ordering::SeqCst)
    }
}

impl Drop for RebindingNat {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct Server {
    addr: SocketAddr,
    public: [u8; 32],
    moves: Arc<Mutex<Vec<(SocketAddr, SocketAddr)>>>,
    lost: Arc<Mutex<Vec<PeerId>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn spawn() -> Self {
        let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        server.set_keepalive(Some(KEEPALIVE));
        server.set_peer_timeout(Some(PEER_TIMEOUT));
        let addr = server.local_addr().expect("addr");
        let public = *server.public_key().expect("identity");

        let stop = Arc::new(AtomicBool::new(false));
        let moves = Arc::new(Mutex::new(Vec::new()));
        let lost = Arc::new(Mutex::new(Vec::new()));
        let flag = Arc::clone(&stop);
        let seen_moves = Arc::clone(&moves);
        let seen_lost = Arc::clone(&lost);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match server.poll(Some(Duration::from_millis(10))) {
                    Ok(Event::Message { peer, data }) => {
                        let _ = server.send(peer, &data, PayloadType::Opaque);
                    }
                    Ok(Event::PeerMoved { from, to, .. }) => {
                        seen_moves.lock().expect("lock").push((from, to));
                    }
                    Ok(Event::PeerLost { peer }) => {
                        seen_lost.lock().expect("lock").push(peer);
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            public,
            moves,
            lost,
            stop,
            handle: Some(handle),
        }
    }

    fn moves(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.moves.lock().expect("lock").clone()
    }

    fn lost(&self) -> Vec<PeerId> {
        self.lost.lock().expect("lock").clone()
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

/// Sits in `recv` for `how_long`, sending nothing of its own.
///
/// This is what an idle device does, and it is where a `Connection` drives its
/// keep-alives from.
fn idle(conn: &Connection, how_long: Duration) {
    let deadline = Instant::now() + how_long;
    let mut buf = vec![0u8; 4096];
    while Instant::now() < deadline {
        let left = deadline.saturating_duration_since(Instant::now());
        if conn
            .set_read_timeout(Some(left.min(Duration::from_millis(50))))
            .is_err()
        {
            break;
        }
        let _ = conn.recv(&mut buf);
    }
}

fn exchange(conn: &Connection, message: &[u8]) -> fectp::Result<Vec<u8>> {
    let deadline = Instant::now() + TIMEOUT;
    let mut last = None;
    let mut buf = vec![0u8; 8 * 1024];
    while Instant::now() < deadline {
        conn.set_read_timeout(Some(Duration::from_millis(400)))?;
        if conn.send(message, PayloadType::Opaque).is_err() {
            continue;
        }
        match conn.recv(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("the deadline must allow one attempt"))
}

// -------------------------------------------------------------- the test ---

#[test]
fn a_mapping_that_moves_while_the_peer_is_idle_is_followed() {
    let server = Server::spawn();
    let nat = RebindingNat::spawn(server.addr);

    let conn =
        Connection::connect(nat.addr, &server.public, &Identity::generate()).expect("connect");
    conn.set_keepalive(Some(KEEPALIVE)).expect("keepalive");

    // The control: the path works before anything moves.
    assert_eq!(
        exchange(&conn, b"before").expect("the session must work first"),
        b"before"
    );

    // The mapping moves. From here the application sends nothing at all — only
    // the keep-alives go out, and only they can reveal the new address.
    nat.expire_the_mapping();
    idle(&conn, PEER_TIMEOUT * 2);

    assert!(
        nat.has_rebound(),
        "the NAT never re-created its mapping; nothing was tested"
    );
    assert!(
        server.lost().is_empty(),
        "a peer whose mapping moved must not be declared dead: {:?}",
        server.lost()
    );
    assert_eq!(
        server.moves().len(),
        1,
        "the session must have followed the mapping exactly once: {:?}",
        server.moves()
    );
    assert!(
        nat.delivered_on_the_new_port() > 0,
        "and the server must be writing through the new mapping"
    );

    // And the session is usable, without ever having been re-established.
    assert_eq!(
        exchange(&conn, b"after").expect("the session must still work"),
        b"after"
    );
}

#[test]
fn a_mapping_that_moves_is_not_followed_if_the_peer_never_speaks() {
    // The documented limit, held to. Only outbound traffic creates a NAT
    // mapping, so the side behind the NAT is the only side that can reveal
    // where it now is. A peer that goes quiet with no keep-alive of its own is
    // unreachable, and the honest outcome is that the server gives up on it —
    // not that it silently holds a session it can never write to.
    let server = Server::spawn();
    let nat = RebindingNat::spawn(server.addr);

    let conn =
        Connection::connect(nat.addr, &server.public, &Identity::generate()).expect("connect");
    // No keep-alive on this side. This is the default.

    assert_eq!(
        exchange(&conn, b"before").expect("the session must work first"),
        b"before"
    );

    nat.expire_the_mapping();
    idle(&conn, PEER_TIMEOUT * 2);

    assert!(
        !nat.has_rebound(),
        "with nothing sent, no new mapping can have been created"
    );
    assert!(
        server.moves().is_empty(),
        "and the server cannot have followed a peer it never heard from: {:?}",
        server.moves()
    );
    assert_eq!(
        server.lost().len(),
        1,
        "the peer must be given up on rather than held unreachable"
    );
}
