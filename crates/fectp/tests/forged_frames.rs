//! What a frame that does not authenticate is allowed to change.
//!
//! Anyone can address a UDP socket, so a server has to assume that some of
//! what arrives is noise, and some of it is noise aimed carefully. The rule
//! that matters is that noise must not be credited: a frame the session could
//! not open says nothing about that session, and must not move it, protect it,
//! or advance anything about it.
//!
//! The concrete case here is eviction. A session that has completed a
//! handshake and never spoken again is what a flood leaves behind, and it is
//! the one to drop when the table is full. Which sessions count as having
//! spoken is therefore a security decision, and "sent us some bytes" is not
//! the same claim as "sent us bytes it could seal".

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

const TIMEOUT: Duration = Duration::from_secs(5);

/// A forwarding relay that can also inject bytes from the same source port the
/// session it carries is filed under.
///
/// This is what makes the test possible at all: a client's socket is inside
/// its `Connection`, so the only way to send something from a peer's own
/// address is to be the thing sitting at that address.
struct Injector {
    addr: SocketAddr,
    last: Arc<Mutex<Option<Vec<u8>>>>,
    inject: Arc<Mutex<Option<Vec<u8>>>>,
    /// Sent on every pass rather than once, for testing what a stream of noise
    /// can hold open.
    repeat: Arc<Mutex<Option<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
}

impl Injector {
    fn spawn(server: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
        front
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");
        let addr = front.local_addr().expect("addr");

        let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
        back.connect(server).expect("connect back");
        back.set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");

        let stop = Arc::new(AtomicBool::new(false));
        let last: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let inject: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let repeat: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        {
            let front = front.try_clone().expect("clone");
            let back = back.try_clone().expect("clone");
            let flag = Arc::clone(&stop);
            let seen = Arc::clone(&last);
            let pending = Arc::clone(&inject);
            let over_and_over = Arc::clone(&repeat);
            let learn = Arc::clone(&client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    if let Some(bytes) = pending.lock().expect("lock").take() {
                        let _ = back.send(&bytes);
                    }
                    if let Some(bytes) = over_and_over.lock().expect("lock").as_ref() {
                        let _ = back.send(bytes);
                    }
                    let Ok((n, from)) = front.recv_from(&mut buf) else {
                        continue;
                    };
                    *learn.lock().expect("lock") = Some(from);
                    *seen.lock().expect("lock") = Some(buf[..n].to_vec());
                    let _ = back.send(&buf[..n]);
                }
            });
        }

        {
            let flag = Arc::clone(&stop);
            let learn = Arc::clone(&client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok(n) = back.recv(&mut buf) else {
                        continue;
                    };
                    let target = *learn.lock().expect("lock");
                    if let Some(target) = target {
                        let _ = front.send_to(&buf[..n], target);
                    }
                }
            });
        }

        Self {
            addr,
            last,
            inject,
            repeat,
            stop,
        }
    }

    fn last(&self) -> Option<Vec<u8>> {
        self.last.lock().expect("lock").clone()
    }

    fn send_from_the_peers_address(&self, bytes: Vec<u8>) {
        *self.inject.lock().expect("lock") = Some(bytes);
    }

    fn keep_sending_from_the_peers_address(&self, bytes: Vec<u8>) {
        *self.repeat.lock().expect("lock") = Some(bytes);
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Builds a data frame that will reach a session and then fail to open.
///
/// Only the session identifier is taken from `captured` — it sits in the clear
/// at offset 2 and is what files a frame against a session. The frame type has
/// to be written fresh: a quiet peer has only ever sent its handshake, and a
/// handshake is turned away by the dispatcher long before any session sees it,
/// so forging from one byte-for-byte would test nothing. That is what the
/// first version of this test did.
fn forge_data_frame_for(captured: &[u8]) -> Vec<u8> {
    assert!(
        captured.len() >= 14,
        "need a whole header to read a session identifier from, got {} bytes",
        captured.len()
    );
    let mut frame = vec![0u8; 14 + 16 + 64];
    // Version 1 in the high nibble, `Data` in the low one.
    frame[0] = (1 << 4) | 3;
    frame[1] = 0;
    frame[2..6].copy_from_slice(&captured[2..6]);
    // A sequence far ahead of the window, so the replay pre-filter passes it
    // through to the authentication that will refuse it. Being dropped as a
    // duplicate would prove nothing about forged frames.
    frame[6..14].copy_from_slice(&0x0000_0000_0001_0000u64.to_le_bytes());
    // The body is zeros, which no key on earth authenticates.
    frame
}

/// Runs an echo server with a peer table of `max_peers`, on its own thread.
struct Echo {
    addr: SocketAddr,
    public: [u8; 32],
    lost: Arc<Mutex<usize>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Echo {
    fn spawn(max_peers: usize) -> Self {
        Self::spawn_with_timeout(max_peers, None)
    }

    fn spawn_with_timeout(max_peers: usize, timeout: Option<Duration>) -> Self {
        let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        server.set_max_peers(max_peers);
        server.set_peer_timeout(timeout);
        let addr = server.local_addr().expect("addr");
        let public = *server.public_key().expect("identity");
        let stop = Arc::new(AtomicBool::new(false));
        let lost = Arc::new(Mutex::new(0usize));
        let flag = Arc::clone(&stop);
        let gone = Arc::clone(&lost);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match server.poll(Some(Duration::from_millis(20))) {
                    Ok(Event::Message { peer, data }) => {
                        let _ = server.send(peer, &data, PayloadType::Opaque);
                    }
                    Ok(Event::PeerLost { .. }) => *gone.lock().expect("lock") += 1,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            public,
            lost,
            stop,
            handle: Some(handle),
        }
    }

    fn lost(&self) -> usize {
        *self.lost.lock().expect("lock")
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

fn exchange(conn: &mut Connection, message: &[u8]) -> fectp::Result<Vec<u8>> {
    conn.set_read_timeout(Some(TIMEOUT))?;
    conn.send(message, PayloadType::Opaque)?;
    let mut buf = vec![0u8; 8 * 1024];
    let n = conn.recv(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

#[test]
fn a_forged_frame_does_not_protect_a_session_from_eviction() {
    // Room for two. The third connection has to displace one of them, and
    // which one is the whole question.
    let echo = Echo::spawn(2);

    // The peer that has actually done something. Filed first, so if the two
    // sessions ever look alike to the eviction order, this is the one that
    // loses — which is exactly the inversion being tested for.
    let mut honest =
        Connection::connect(echo.addr, &echo.public, &Identity::generate()).expect("connect");
    assert_eq!(
        exchange(&mut honest, b"i am here").expect("honest exchange"),
        b"i am here",
        "the honest peer must be working before anything is forged"
    );

    // The peer that has done nothing but complete a handshake — what a flood
    // leaves behind. It speaks through a relay so that something can send from
    // its address without holding its keys.
    let relay = Injector::spawn(echo.addr);
    let quiet =
        Connection::connect(relay.addr, &echo.public, &Identity::generate()).expect("connect");
    let captured = relay.last().expect("the handshake passed through the relay");
    relay.send_from_the_peers_address(forge_data_frame_for(&captured));
    // Long enough for the forgery to be received and acted on.
    thread::sleep(Duration::from_millis(300));

    // The third peer, which forces the choice.
    let mut third =
        Connection::connect(echo.addr, &echo.public, &Identity::generate()).expect("connect");
    assert_eq!(
        exchange(&mut third, b"and me").expect("third exchange"),
        b"and me",
        "the connection that forces the eviction must itself work"
    );

    // The forged frame must not have bought the quiet session anything. The
    // peer that has authenticated is the one that stays.
    assert_eq!(
        exchange(&mut honest, b"still served").expect("honest peer evicted"),
        b"still served",
        "a session kept alive only by frames it could not seal must not \
         outrank one that has authenticated"
    );

    drop(quiet);
}

#[test]
fn a_forged_frame_does_not_hold_a_dead_session_open() {
    // The other half of what "heard from" has to mean. A peer timeout that
    // counted any arriving datagram would be a timeout a stranger could veto:
    // address the socket often enough and the session never expires, and the
    // table fills with peers that left.
    let echo = Echo::spawn_with_timeout(16, Some(Duration::from_millis(300)));
    let relay = Injector::spawn(echo.addr);
    let conn =
        Connection::connect(relay.addr, &echo.public, &Identity::generate()).expect("connect");
    let captured = relay.last().expect("the handshake passed through the relay");

    // Noise from the peer's own address, over and over, while the peer itself
    // says nothing further.
    relay.keep_sending_from_the_peers_address(forge_data_frame_for(&captured));

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while echo.lost() == 0 && std::time::Instant::now() < deadline {}
    assert_eq!(
        echo.lost(),
        1,
        "a session must expire on schedule however much noise arrives for it"
    );

    drop(conn);
}
