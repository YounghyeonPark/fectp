//! A UDP implementation of [`Transport`].
//!
//! UDP is the transport every FECTP profile shares, because it is the only one
//! the smallest supported targets can run. Richer backends such as QUIC plug
//! in at the same trait on platforms that can afford them.

use std::io;
use std::net::{SocketAddr, UdpSocket};

use fectp_core::Transport;

/// Largest datagram sent by default.
///
/// Chosen to stay below the usual 1500-byte Ethernet MTU once IPv6 and UDP
/// headers are accounted for, so frames are not fragmented. Fragmentation
/// would multiply the loss probability of a single frame.
pub const DEFAULT_MAX_DATAGRAM: usize = 1200;

/// A UDP socket carrying one peer's datagrams.
///
/// Two modes are supported. A *connected* socket is bound to its peer by the
/// kernel and uses `send`/`recv`. A *bound* socket keeps an explicit peer
/// address and uses `send_to`/`recv_from`, discarding datagrams from anyone
/// else; the server side needs this so its replies leave from the port the
/// client is talking to.
pub struct UdpTransport {
    socket: UdpSocket,
    peer: Option<SocketAddr>,
    max_datagram: usize,
}

impl UdpTransport {
    /// Wraps an existing socket that is already connected to a peer.
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            peer: None,
            max_datagram: DEFAULT_MAX_DATAGRAM,
        }
    }

    /// Wraps a bound socket that will exchange datagrams with `peer`.
    ///
    /// Datagrams from any other address are discarded rather than delivered,
    /// so an off-path attacker cannot inject frames merely by knowing the
    /// port. They would still have to defeat the AEAD, but dropping them here
    /// avoids the work.
    pub fn with_peer(socket: UdpSocket, peer: SocketAddr) -> Self {
        Self {
            socket,
            peer: Some(peer),
            max_datagram: DEFAULT_MAX_DATAGRAM,
        }
    }

    /// Binds a local socket and connects it to `peer`.
    pub fn connect(peer: SocketAddr) -> io::Result<Self> {
        let bind: SocketAddr = if peer.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid bind address")
        } else {
            "[::]:0".parse().expect("valid bind address")
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(peer)?;
        Ok(Self::new(socket))
    }

    /// Overrides the maximum datagram size.
    ///
    /// Lower this when the peer advertises a smaller frame limit, as a
    /// constrained device will.
    pub fn set_max_datagram_size(&mut self, size: usize) {
        self.max_datagram = size;
    }

    /// A second handle on the same socket.
    ///
    /// Both handles refer to one kernel socket, which may be sent on and
    /// received on at the same time from different threads — that property is
    /// the operating system's, not this crate's, and it is what lets the two
    /// directions run independently.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
            peer: self.peer,
            max_datagram: self.max_datagram,
        })
    }

    /// The local address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The peer this transport exchanges datagrams with.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self.peer {
            Some(peer) => Ok(peer),
            None => self.socket.peer_addr(),
        }
    }

    /// Sets the read timeout, or clears it with `None`.
    pub fn set_read_timeout(&mut self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }
}

impl Transport for UdpTransport {
    type Error = io::Error;

    fn send(&mut self, datagram: &[u8]) -> Result<(), io::Error> {
        // This hands the bytes to the kernel immediately. UDP has no
        // Nagle-style coalescing, which is exactly the property FECTP needs:
        // any send-side batching would cost milliseconds and defeat the point
        // of the protocol.
        let n = match self.peer {
            Some(peer) => self.socket.send_to(datagram, peer)?,
            None => self.socket.send(datagram)?,
        };
        if n != datagram.len() {
            return Err(io::Error::other(
                "datagram was truncated on send",
            ));
        }
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self.peer {
            None => self.socket.recv(buf),
            Some(peer) => loop {
                let (n, from) = self.socket.recv_from(buf)?;
                if from == peer {
                    return Ok(n);
                }
                // Datagram from a third party: drop it and keep waiting.
            },
        }
    }

    fn max_datagram_size(&self) -> usize {
        self.max_datagram
    }
}
