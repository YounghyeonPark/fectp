//! What the tunables do when handed a value nobody meant.
//!
//! Every one of these intervals can come from a configuration file, an
//! environment variable, or arithmetic that produced a zero. A transport that
//! takes such a value literally turns a typo into a packet flood, or into a
//! server that drops every peer it accepts. `set_max_peers` already refuses to
//! take zero literally; these are the settings added since, held to the same
//! rule.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Counts what passes in each direction, and forwards it unchanged.
struct Counting {
    addr: SocketAddr,
    to_client: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl Counting {
    fn spawn(server: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
        front
            .set_read_timeout(Some(Duration::from_millis(10)))
            .expect("timeout");
        let addr = front.local_addr().expect("addr");

        let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
        back.connect(server).expect("connect back");
        back.set_read_timeout(Some(Duration::from_millis(10)))
            .expect("timeout");

        let stop = Arc::new(AtomicBool::new(false));
        let to_client = Arc::new(AtomicU64::new(0));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        {
            let front = front.try_clone().expect("clone");
            let back = back.try_clone().expect("clone");
            let flag = Arc::clone(&stop);
            let learn = Arc::clone(&client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok((n, from)) = front.recv_from(&mut buf) else {
                        continue;
                    };
                    *learn.lock().expect("lock") = Some(from);
                    let _ = back.send(&buf[..n]);
                }
            });
        }
        {
            let flag = Arc::clone(&stop);
            let learn = Arc::clone(&client);
            let counted = Arc::clone(&to_client);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !flag.load(Ordering::Relaxed) {
                    let Ok(n) = back.recv(&mut buf) else {
                        continue;
                    };
                    counted.fetch_add(1, Ordering::SeqCst);
                    let target = *learn.lock().expect("lock");
                    if let Some(target) = target {
                        let _ = front.send_to(&buf[..n], target);
                    }
                }
            });
        }

        Self {
            addr,
            to_client,
            stop,
        }
    }

    fn to_client(&self) -> u64 {
        self.to_client.load(Ordering::SeqCst)
    }
}

impl Drop for Counting {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct Server {
    addr: SocketAddr,
    public: [u8; 32],
    lost: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn spawn(keepalive: Option<Duration>, timeout: Option<Duration>) -> Self {
        let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        server.set_keepalive(keepalive);
        server.set_peer_timeout(timeout);
        let addr = server.local_addr().expect("addr");
        let public = *server.public_key().expect("identity");
        let stop = Arc::new(AtomicBool::new(false));
        let lost = Arc::new(AtomicU64::new(0));
        let flag = Arc::clone(&stop);
        let gone = Arc::clone(&lost);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match server.poll(Some(Duration::from_millis(10))) {
                    Ok(Event::Message { peer, data }) => {
                        let _ = server.send(peer, &data, PayloadType::Opaque);
                    }
                    Ok(Event::PeerLost { .. }) => {
                        gone.fetch_add(1, Ordering::SeqCst);
                    }
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

    fn lost(&self) -> u64 {
        self.lost.load(Ordering::SeqCst)
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
fn a_zero_peer_timeout_does_not_drop_every_peer_on_arrival() {
    // Taken literally, "nothing may be heard from for zero time" is true of a
    // session a microsecond after it is filed, so every peer would be released
    // the moment it connected — and the failure would look like a network
    // problem rather than a configuration one.
    let server = Server::spawn(None, Some(Duration::ZERO));
    let conn =
        Connection::connect(server.addr, &server.public, &Identity::generate()).expect("connect");

    assert_eq!(
        exchange(&conn, b"hello").expect("a session must survive being made"),
        b"hello"
    );
    assert_eq!(
        server.lost(),
        0,
        "a zero timeout must not mean every peer is already overdue"
    );
}

#[test]
fn a_zero_keepalive_does_not_become_a_flood() {
    // Taken literally, "say something if nothing has been said for zero time"
    // is true on every pass of the loop, and the endpoint sends as fast as it
    // can poll — at its own peers, from its own socket.
    let server = Server::spawn(Some(Duration::ZERO), None);
    let relay = Counting::spawn(server.addr);
    let conn =
        Connection::connect(relay.addr, &server.public, &Identity::generate()).expect("connect");

    assert_eq!(
        exchange(&conn, b"hello").expect("the session must work"),
        b"hello"
    );
    let after_setup = relay.to_client();

    // Sit still for a fifth of a second. A keep-alive interval that means
    // anything sends a handful of datagrams in that time; one taken literally
    // sends one per loop pass.
    let quiet = Instant::now() + Duration::from_millis(200);
    let mut buf = vec![0u8; 4096];
    while Instant::now() < quiet {
        conn.set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");
        let _ = conn.recv(&mut buf);
    }

    let sent = relay.to_client() - after_setup;
    assert!(
        sent < 20,
        "a zero keep-alive interval sent {sent} datagrams in 200 ms; \
         it must be clamped to something that cannot flood"
    );
}
