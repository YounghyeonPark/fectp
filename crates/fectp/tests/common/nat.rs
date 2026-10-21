//! A host behind an emulated NAT, as a socket an `Endpoint` can run on.
//!
//! Loopback has no NAT, and a relay in front of a real socket cannot make one:
//! a NAT translates *everything* the host sends, to every destination, and a
//! relay only sees what is addressed to it. So the host's socket is replaced
//! instead. Everything it sends leaves through an outside UDP socket — the
//! mapping — and what arrives at that socket is let in or not by the kind of
//! NAT this is. The addresses peers see are the mappings', which are real
//! loopback sockets, so an `Endpoint` that is not behind a NAT talks to this
//! one exactly as it would to a real one.
//!
//! The three kinds are the ones that decide whether hole punching works:
//!
//! - **Full cone**: one mapping per host, and anyone may send to it.
//! - **Port-restricted cone**: one mapping per host, but only an address and
//!   port the host has sent to may send back. Hole punching exists for this
//!   one, and it is the common home router.
//! - **Symmetric**: a new mapping for every destination, each accepting only
//!   that destination. The address a third party saw is of no use to anyone
//!   else, so hole punching cannot work and only a relay can.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fectp::DatagramSocket;

/// What kind of NAT a host is behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    FullCone,
    PortRestricted,
    Symmetric,
}

/// One outside socket and who may send to it.
struct Mapping {
    socket: UdpSocket,
    /// Addresses the host has sent to through this mapping.
    sent_to: Arc<Mutex<HashSet<SocketAddr>>>,
}

/// A host's socket, behind a NAT of the given kind.
pub struct NatSocket {
    kind: Kind,
    /// What the host believes its own address is; nobody outside sees it.
    inside: SocketAddr,
    /// Mappings by destination for a symmetric NAT, or the one mapping under
    /// the key `None` for a cone.
    mappings: Mutex<HashMap<Option<SocketAddr>, Mapping>>,
    deliver: Sender<(Vec<u8>, SocketAddr)>,
    arrived: Mutex<Receiver<(Vec<u8>, SocketAddr)>>,
    stop: Arc<AtomicBool>,
    /// Every datagram the NAT turned away, for tests that need to see it work.
    pub refused: Arc<Mutex<Vec<SocketAddr>>>,
}

impl NatSocket {
    pub fn new(kind: Kind) -> Self {
        let (deliver, arrived) = mpsc::channel();
        Self {
            kind,
            inside: "10.0.0.2:40000".parse().expect("address"),
            mappings: Mutex::new(HashMap::new()),
            deliver,
            arrived: Mutex::new(arrived),
            stop: Arc::new(AtomicBool::new(false)),
            refused: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The outside addresses this host currently has, one per mapping.
    pub fn outside(&self) -> Vec<SocketAddr> {
        self.mappings
            .lock()
            .expect("lock")
            .values()
            .map(|m| m.socket.local_addr().expect("addr"))
            .collect()
    }

    /// The mapping that traffic to `to` leaves through, made if need be.
    fn mapping_for(
        &self,
        to: SocketAddr,
    ) -> io::Result<(UdpSocket, Arc<Mutex<HashSet<SocketAddr>>>)> {
        let key = match self.kind {
            Kind::Symmetric => Some(to),
            Kind::FullCone | Kind::PortRestricted => None,
        };
        let mut mappings = self.mappings.lock().expect("lock");
        if let Some(m) = mappings.get(&key) {
            return Ok((m.socket.try_clone()?, Arc::clone(&m.sent_to)));
        }

        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let sent_to = Arc::new(Mutex::new(HashSet::new()));
        // What arrives at the mapping, filtered as this kind of NAT does.
        // Blocking reads, woken on drop, for the reason every relay in these
        // tests uses them (D80, D81).
        {
            let socket = socket.try_clone()?;
            let sent_to = Arc::clone(&sent_to);
            let deliver = self.deliver.clone();
            let stop = Arc::clone(&self.stop);
            let refused = Arc::clone(&self.refused);
            let kind = self.kind;
            thread::spawn(move || {
                let mut buf = vec![0u8; 65535];
                loop {
                    let got = socket.recv_from(&mut buf);
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok((n, from)) = got else {
                        continue;
                    };
                    let allowed = match kind {
                        Kind::FullCone => true,
                        Kind::PortRestricted | Kind::Symmetric => {
                            sent_to.lock().expect("lock").contains(&from)
                        }
                    };
                    if !allowed {
                        refused.lock().expect("lock").push(from);
                        continue;
                    }
                    if deliver.send((buf[..n].to_vec(), from)).is_err() {
                        break;
                    }
                }
            });
        }
        let handle = (socket.try_clone()?, Arc::clone(&sent_to));
        mappings.insert(key, Mapping { socket, sent_to });
        Ok(handle)
    }
}

impl DatagramSocket for NatSocket {
    fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        let (socket, sent_to) = self.mapping_for(to)?;
        sent_to.lock().expect("lock").insert(to);
        socket.send_to(buf, to)
    }

    fn recv_from(
        &self,
        buf: &mut [u8],
        timeout: Option<Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        let arrived = self.arrived.lock().expect("lock");
        let got = match timeout {
            Some(t) => arrived.recv_timeout(t).map_err(|e| match e {
                RecvTimeoutError::Timeout => io::Error::from(io::ErrorKind::WouldBlock),
                RecvTimeoutError::Disconnected => io::Error::from(io::ErrorKind::BrokenPipe),
            }),
            None => arrived
                .recv()
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe)),
        };
        let (data, from) = got?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, from))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.inside)
    }
}

impl Drop for NatSocket {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for addr in self.outside() {
            super::wake(addr);
        }
    }
}

/// The socket an `Endpoint` runs on, sharing the NAT with the test, which
/// keeps the other handle to look at what the NAT did.
pub struct NatHost(pub Arc<NatSocket>);

/// A host behind a NAT of `kind`: the socket to build an `Endpoint` on, and
/// the test's own view of the NAT.
pub fn behind(kind: Kind) -> (NatHost, Arc<NatSocket>) {
    let nat = Arc::new(NatSocket::new(kind));
    (NatHost(Arc::clone(&nat)), nat)
}

impl DatagramSocket for NatHost {
    fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, to)
    }

    fn recv_from(
        &self,
        buf: &mut [u8],
        timeout: Option<Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf, timeout)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}
