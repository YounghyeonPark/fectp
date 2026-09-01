//! A handshake whose datagrams go missing.
//!
//! The data path has retransmitted from the beginning; the handshake did not,
//! so one lost opening frame meant five seconds of silence and a failed
//! `connect`. On a link with any loss at all that is a connection setup that
//! fails outright rather than retrying — worst on exactly the device this
//! protocol is for, which wakes, reports one reading, and sleeps.
//!
//! These tests put a relay in the path and throw specific datagrams away.

mod common;

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::Echo;
use fectp::{Connection, Identity, PayloadType};

/// Forwards datagrams between one client and one server, dropping the first
/// `drop_to_server` from the client and the first `drop_to_client` back.
///
/// Dropping the *first* rather than a random fraction is deliberate: the frame
/// under test is the opening one, and a proportion would make the test pass or
/// fail by luck.
struct Relay {
    addr: SocketAddr,
    dropped: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Relay {
    fn start(server: SocketAddr, mut drop_to_server: usize, mut drop_to_client: usize) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("relay bind");
        socket
            .set_read_timeout(Some(Duration::from_millis(25)))
            .expect("timeout");
        let addr = socket.local_addr().expect("addr");

        let dropped = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let counter = Arc::clone(&dropped);
        let flag = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            let mut client: Option<SocketAddr> = None;
            while !flag.load(Ordering::Relaxed) {
                let (n, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if from == server {
                    if drop_to_client > 0 {
                        drop_to_client -= 1;
                        counter.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if let Some(client) = client {
                        let _ = socket.send_to(&buf[..n], client);
                    }
                } else {
                    client = Some(from);
                    if drop_to_server > 0 {
                        drop_to_server -= 1;
                        counter.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let _ = socket.send_to(&buf[..n], server);
                }
            }
        });

        Self {
            addr,
            dropped,
            stop,
            handle: Some(handle),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
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

/// The opening frame never arrives. Without retransmission this is a five
/// second wait and an error.
#[test]
fn a_lost_opening_frame_is_sent_again() {
    let echo = Echo::start();
    let relay = Relay::start(echo.addr(), 1, 0);

    let started = Instant::now();
    let conn = Connection::connect(relay.addr(), &echo.public(), &Identity::generate())
        .expect("a lost opening frame must be resent, not fatal");
    let elapsed = started.elapsed();

    assert_eq!(relay.dropped(), 1, "the relay must actually have dropped one");
    assert!(
        elapsed < Duration::from_secs(4),
        "connect took {elapsed:?}: it waited out the timeout instead of resending"
    );

    // And the connection that came back is a working one, not just an `Ok`.
    conn.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    conn.send(b"after a lost handshake", PayloadType::Opaque)
        .expect("send");
    let mut buf = vec![0u8; 1024];
    let n = conn.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], b"after a lost handshake");
}

/// The reply is lost instead. The responder has already built its session, so
/// this is the case where a repeat of message 1 must still be answered.
#[test]
fn a_lost_handshake_reply_is_recovered() {
    let echo = Echo::start();
    let relay = Relay::start(echo.addr(), 0, 1);

    let started = Instant::now();
    let conn = Connection::connect(relay.addr(), &echo.public(), &Identity::generate())
        .expect("a lost reply must be recovered");
    assert_eq!(relay.dropped(), 1);
    assert!(started.elapsed() < Duration::from_secs(4));

    conn.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    conn.send(b"reply was lost", PayloadType::Opaque)
        .expect("send");
    let mut buf = vec![0u8; 1024];
    let n = conn.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], b"reply was lost");
}

/// Several in a row, which the linear backoff has to ride out.
#[test]
fn repeated_loss_is_ridden_out() {
    let echo = Echo::start();
    let relay = Relay::start(echo.addr(), 3, 0);

    let conn = Connection::connect(relay.addr(), &echo.public(), &Identity::generate())
        .expect("three lost opening frames are still recoverable");
    assert_eq!(relay.dropped(), 3);

    conn.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    conn.send(b"third time", PayloadType::Opaque).expect("send");
    let mut buf = vec![0u8; 1024];
    let n = conn.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], b"third time");
}

/// Retrying must not turn "nobody is there" into an unbounded wait. A peer that
/// never answers is still reported, and within the documented timeout.
#[test]
fn a_silent_peer_is_still_given_up_on() {
    // A socket that receives and never replies: every attempt is swallowed.
    let silent = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = silent.local_addr().expect("addr");

    let started = Instant::now();
    let result = Connection::connect(addr, &[0x42u8; 32], &Identity::generate());
    let elapsed = started.elapsed();

    assert!(result.is_err(), "a silent peer must not appear to connect");
    assert!(
        elapsed < fectp::HANDSHAKE_TIMEOUT + Duration::from_secs(2),
        "gave up after {elapsed:?}, past the documented {:?}",
        fectp::HANDSHAKE_TIMEOUT
    );
}
