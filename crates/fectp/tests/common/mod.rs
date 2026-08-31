//! A background echo server, shared by the integration tests.
//!
//! Every test needs the same thing: a server running in another thread that
//! answers, and a way to see what it saw. Having one of these rather than four
//! slightly different ones means a change to the server API is felt in one
//! place.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Endpoint, Event, Identity, PayloadType, PeerId};

/// What the server has seen so far.
#[derive(Default, Clone)]
pub struct Observed {
    /// Application payloads, in arrival order.
    pub messages: Vec<Vec<u8>>,
    /// The 0-RTT payload of each handshake, in arrival order.
    pub zero_rtt: Vec<Vec<u8>>,
    /// The authenticated public key of each connecting peer.
    pub peers: Vec<[u8; 32]>,
    /// Whether each connection resumed rather than handshaking in full.
    pub resumed: Vec<bool>,
}

/// A server running in its own thread, stopped when this is dropped.
pub struct Echo {
    addr: SocketAddr,
    public: Option<[u8; 32]>,
    seen: Arc<Mutex<Observed>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Echo {
    /// A public-key server that echoes everything it receives.
    pub fn start() -> Self {
        Self::with(
            Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind"),
            true,
        )
    }

    /// A public-key server that records but never replies.
    ///
    /// Reliable messages are still acknowledged — that happens inside `poll` —
    /// so this keeps the datagram ordering predictable for tests that inject
    /// loss at specific positions.
    pub fn collector() -> Self {
        Self::with(
            Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind"),
            false,
        )
    }

    /// Wraps a server already built in some mode.
    pub fn with(mut server: Endpoint, echo: bool) -> Self {
        let addr = server.local_addr().expect("addr");
        let public = server.public_key().copied();
        let seen = Arc::new(Mutex::new(Observed::default()));
        let stop = Arc::new(AtomicBool::new(false));

        let record = Arc::clone(&seen);
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match server.poll(Some(Duration::from_millis(25))) {
                    Ok(Event::Connected {
                        peer,
                        zero_rtt,
                        resumed,
                        ..
                    }) => {
                        let mut seen = record.lock().expect("lock");
                        seen.zero_rtt.push(zero_rtt);
                        seen.resumed.push(resumed);
                        seen.peers
                            .push(server.peer_public_key(peer).copied().unwrap_or([0u8; 32]));
                    }
                    Ok(Event::Message { peer, data }) => {
                        if echo {
                            // `send` is one frame, so a message that arrived
                            // split across several cannot go back that way.
                            // Falling back rather than checking a limit first:
                            // the frame size is the peer's to advertise and an
                            // `Endpoint` does not expose it per peer.
                            if server.send(peer, &data, PayloadType::Opaque).is_err() {
                                let _ = server.send_reliable(peer, &data, PayloadType::Opaque);
                            }
                        }
                        record.lock().expect("lock").messages.push(data);
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
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

    /// The address clients should connect to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The server's public key. Panics in modes that have none.
    pub fn public(&self) -> [u8; 32] {
        self.public.expect("this server presents an identity")
    }

    /// The server's public key, if it has one.
    pub fn public_key(&self) -> Option<[u8; 32]> {
        self.public
    }

    /// A snapshot of everything seen so far.
    pub fn observed(&self) -> Observed {
        self.seen.lock().expect("lock").clone()
    }

    /// Waits until at least `count` messages have arrived, then returns them.
    ///
    /// Returns whatever arrived if the timeout expires first, so a failing
    /// assertion reports what was actually received rather than hanging.
    pub fn messages(&self, count: usize, timeout: Duration) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            let seen = self.seen.lock().expect("lock").messages.clone();
            if seen.len() >= count || Instant::now() >= deadline {
                return seen;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Waits until at least `count` peers have connected.
    pub fn connections(&self, count: usize, timeout: Duration) -> Observed {
        let deadline = Instant::now() + timeout;
        loop {
            let seen = self.seen.lock().expect("lock").clone();
            if seen.peers.len() >= count || Instant::now() >= deadline {
                return seen;
            }
            thread::sleep(Duration::from_millis(5));
        }
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

/// Unused by some test binaries; silences the resulting warning.
pub fn _use_peer_id(_: PeerId) {}
