//! A UDP implementation of [`Transport`].
//!
//! UDP is the transport every FECTP profile shares, because it is the only one
//! the smallest supported targets can run. Richer backends such as QUIC plug
//! in at the same trait on platforms that can afford them.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};

use fectp_core::Transport;

/// Largest datagram sent by default.
///
/// Chosen to stay below the usual 1500-byte Ethernet MTU once IPv6 and UDP
/// headers are accounted for, so frames are not fragmented. Fragmentation
/// would multiply the loss probability of a single frame.
pub const DEFAULT_MAX_DATAGRAM: usize = 1200;

/// The smallest ceiling that still carries a handshake.
///
/// Message 1 is a 14-byte header, a 32-byte ephemeral, a 48-byte encrypted
/// static key and an encrypted 8-byte capability block: 118 bytes before any
/// payload. Below this nothing can connect at all.
pub const MIN_MAX_DATAGRAM: usize = 128;

/// The ceiling in force, shared by every connection in this process.
static MAX_DATAGRAM: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_DATAGRAM);

/// The largest datagram this process will send, or tell a peer it can receive.
pub fn max_datagram() -> usize {
    MAX_DATAGRAM.load(Ordering::Relaxed)
}

/// Raises or lowers that ceiling.
///
/// 1200 by default, because that is what an arbitrary internet path carries
/// without fragmenting. It is deliberately conservative and it costs: on
/// ethernet, 1500 less 20 bytes of IP and 8 of UDP leaves 1472, so a frame is
/// giving up 272 bytes — a fifth of every datagram — that the wire would have
/// taken. There has never been a way to reclaim it, because the peer's
/// advertised limit could only ever lower this, never raise it.
///
/// **This is a property of the network, not of a connection**, which is why it
/// lives here rather than on `Connection` or `Endpoint`. It is also why it has
/// to be set before anything connects: the value is sent to the peer inside the
/// handshake, as the largest frame this side can receive, and a peer that has
/// already been told 1200 will keep sending 1200.
///
/// **Raise it only where the path is known.** Nothing here discovers the MTU —
/// there is no probe and no blackhole detection — so a value the path cannot
/// carry means datagrams that vanish with no error anywhere. A LAN, a tunnel of
/// known overhead, or a link you configured yourself: those are the cases. The
/// open internet is not one.
///
/// Clamped to [`MIN_MAX_DATAGRAM`] and to 65535, which is what the capability
/// field can express.
pub fn set_max_datagram(size: usize) {
    MAX_DATAGRAM.store(
        size.clamp(MIN_MAX_DATAGRAM, u16::MAX as usize),
        Ordering::Relaxed,
    );
}

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
            max_datagram: max_datagram(),
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
            max_datagram: max_datagram(),
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
            return Err(io::Error::other("datagram was truncated on send"));
        }
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self.peer {
            None => self.socket.recv(buf),
            Some(peer) => loop {
                let (n, from) = recv_from_peeking(&self.socket, buf)?;
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

/// Reads one datagram from an unconnected socket, waiting at most `timeout`.
///
/// **On Windows a read that times out can take a datagram with it.** One that
/// arrives as the timeout expires is neither returned nor left queued; the
/// socket documentation says that after a timed-out receive "the socket state
/// is indeterminate". Measured on loopback against a sender every 13 ms: plain
/// sockets waiting by reading, with timeouts of 1 to 12 ms, lost 62 datagrams
/// of 4,800; an `Endpoint` polled every 10 ms lost 169 and 204 of 1,000. A
/// *connected* socket did not lose them — none in 1,200 where an unconnected
/// one lost nine — so `UdpTransport` in its connected mode, which is what
/// `Connection::connect` builds, reads directly.
///
/// **So on Windows nothing waits by reading.** The socket is non-blocking
/// ([`prepare`]), a read is tried first, and only if nothing is queued does
/// this wait, by peeking: a peek that times out took nothing with it. Peeking
/// before every read would do too, and costs: 1.9 µs a datagram against 0.45
/// for a read, measured with the data already queued, because the peek itself
/// is the slow call. Trying the read first costs nothing while datagrams keep
/// coming, and the wait is only ever paid for when there was nothing to read.
///
/// Every error a peek reports other than a timeout is left for the read after
/// it to consume. Windows queues a datagram too large for `buf` and a
/// port-unreachable report ahead of the data, and a peek leaves each of them
/// there and reports it again, so one oversized datagram from anyone would
/// otherwise stop every later wait. The read takes it off and returns the error
/// it always did.
///
/// Elsewhere this sets the timeout and reads, as it always has. `timeout` is a
/// closure so a caller whose timeout lives on the socket pays nothing for it
/// there.
pub(crate) fn recv_from(
    socket: &UdpSocket,
    buf: &mut [u8],
    timeout: impl FnOnce() -> io::Result<Option<std::time::Duration>>,
) -> io::Result<(usize, SocketAddr)> {
    #[cfg(windows)]
    {
        match socket.recv_from(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            read => return read,
        }
        socket.set_nonblocking(false)?;
        let waited = timeout()
            .and_then(|t| socket.set_read_timeout(t))
            .and_then(|()| socket.peek_from(buf).map(drop));
        socket.set_nonblocking(true)?;
        if let Err(e) = waited {
            if crate::is_timeout(&e) {
                return Err(e);
            }
        }
        socket.recv_from(buf)
    }
    #[cfg(not(windows))]
    {
        socket.set_read_timeout(timeout()?)?;
        socket.recv_from(buf)
    }
}

/// Puts a socket into the mode [`recv_from`] and [`send_to`] expect.
///
/// Non-blocking on Windows, for the reason `recv_from` gives; untouched
/// elsewhere.
pub(crate) fn prepare(socket: &UdpSocket) -> io::Result<()> {
    #[cfg(windows)]
    socket.set_nonblocking(true)?;
    #[cfg(not(windows))]
    let _ = socket;
    Ok(())
}

/// Sends on a socket [`prepare`] may have made non-blocking.
///
/// Measured, a non-blocking UDP send on Windows did not once report that it
/// would block — 900,000 sends flat out, at 200 and 1,400 bytes. Should one
/// ever do so, it is sent again blocking, so a caller sees what a blocking
/// socket would have given it rather than a new error.
pub(crate) fn send_to(socket: &UdpSocket, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
    match socket.send_to(buf, addr) {
        #[cfg(windows)]
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            socket.set_nonblocking(false)?;
            let sent = socket.send_to(buf, addr);
            socket.set_nonblocking(true)?;
            sent
        }
        sent => sent,
    }
}

/// Reads one datagram, waiting as the socket's own read timeout says, for a
/// socket this crate did not make non-blocking.
///
/// `UdpTransport::with_peer` takes a socket and cannot report failing to change
/// its mode without changing its signature, so it waits the slower way: a peek
/// before every read on Windows, which loses nothing and costs the 1.4 µs that
/// [`recv_from`] avoids. Nothing in this repository builds one.
fn recv_from_peeking(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    #[cfg(windows)]
    if let Err(e) = socket.peek_from(buf) {
        if crate::is_timeout(&e) {
            return Err(e);
        }
    }
    socket.recv_from(buf)
}
