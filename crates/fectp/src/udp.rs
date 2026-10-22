//! A UDP implementation of [`Transport`].
//!
//! UDP is the transport every FECTP profile shares, because it is the only one
//! the smallest supported targets can run. Richer backends such as QUIC plug
//! in at the same trait on platforms that can afford them.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

/// The largest datagram sent before anything is known about the path.
///
/// A handshake is exactly that moment, so its frames are sized from this
/// rather than from the ceiling, whatever the ceiling has been raised to.
/// Raising the ceiling says what this side can receive and how far it may
/// send once the path is known; it is not evidence that this path carries it.
pub(crate) const BASE_DATAGRAM: usize = 1200;

/// What a handshake frame is sized from: the ceiling, but no more than
/// [`BASE_DATAGRAM`].
///
/// At the default ceiling the two are the same, so this changes nothing
/// there. Its effect is that raising the ceiling no longer raises what a
/// handshake sends.
pub(crate) fn handshake_datagram() -> usize {
    max_datagram().min(BASE_DATAGRAM)
}

/// Whether sessions look for a larger frame size than the base.
static DISCOVERY: AtomicBool = AtomicBool::new(true);

/// Whether path MTU discovery is on.
pub fn path_mtu_discovery() -> bool {
    DISCOVERY.load(Ordering::Relaxed)
}

/// Turns path MTU discovery on or off, for sessions established afterwards.
///
/// On by default. With it on, a session whose peer answers probes starts at
/// 1200 bytes and probes its way up towards the ceiling — the smaller of
/// [`max_datagram`] and the peer's own — and falls back to 1200 when a large
/// reliable frame has to be resent and a check of the size in use goes
/// unanswered, or at the next ten-minute re-check. Off, a session sends at the ceiling from the start, which
/// is how every session behaved before discovery existed: right where the
/// path is known, and silent loss where it is not.
///
/// It decides nothing while the ceiling is at its default, which is the base.
pub fn set_path_mtu_discovery(enabled: bool) {
    DISCOVERY.store(enabled, Ordering::Relaxed);
}

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
/// **Raising it is what lets a session look for more.** With
/// [path MTU discovery](set_path_mtu_discovery) on, as it is by default, a
/// session whose peer answers probes starts at 1200 regardless, sends probes up
/// to the ceiling, uses the largest size that is answered, and falls back to
/// 1200 when a large reliable frame needs resending and a check of that size
/// goes unanswered, or at the next ten-minute re-check; large *unreliable*
/// frames lost in between are lost silently. Handshakes stay at 1200 whatever
/// this says, since nothing about the path is known while one runs.
///
/// On Linux, Android and Apple platforms an answered probe crossed whole: the
/// socket forbids fragmenting while discovery is searching (D89). On Windows nothing
/// safe can, so an answered probe may have been split on the way, and a
/// session there can settle on frames that cross in pieces: delivered, but
/// lost whenever either piece is (D85).
/// With discovery off, or with a peer that does not answer probes, sessions
/// send at the ceiling from the start, and a value the path cannot carry means
/// datagrams that vanish with no error anywhere.
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
        if searches_above_base() {
            forbid_fragmentation(&socket);
        }
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

/// What an [`Endpoint`](crate::Endpoint) sends and receives its datagrams
/// through.
///
/// A UDP socket, ordinarily, and [`Endpoint::bind`](crate::Endpoint::bind)
/// makes one. Anything else that carries whole datagrams between addresses
/// can stand in: a socket with options this crate does not set, a transport
/// of your own, or a simulated network in a test — this crate's own tests put
/// endpoints behind emulated NATs that way, which a real socket on loopback
/// cannot be.
///
/// `Send + Sync` because an `Endpoint` is, and an endpoint built on a socket
/// that was not would quietly stop being either.
pub trait DatagramSocket: Send + Sync {
    /// Sends one datagram to `to`.
    fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize>;

    /// Waits for one datagram, for at most `timeout`, or for as long as it
    /// takes if `None`, and returns its length and where it came from.
    ///
    /// On timeout it must fail with [`io::ErrorKind::WouldBlock`] or
    /// [`io::ErrorKind::TimedOut`]: that is how the endpoint tells "nothing
    /// arrived" from a socket that has failed, and any other error ends
    /// [`poll`](crate::Endpoint::poll). A datagram larger than `buf` may be
    /// truncated or refused, as a UDP socket's is.
    fn recv_from(
        &self,
        buf: &mut [u8],
        timeout: Option<std::time::Duration>,
    ) -> io::Result<(usize, SocketAddr)>;

    /// The address this socket is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// Asks the system not to fragment what `socket` sends, where that can be
/// asked without `unsafe`. Returns whether it was.
///
/// With it, a probe too large for the path is dropped on the way rather than
/// split and reassembled, so an answered probe proves the size crosses
/// whole (D89). On Linux the mode is `IP_PMTUDISC_PROBE`, which sets the bit
/// *and* ignores what the kernel has cached about the path — so it does not
/// split a large datagram itself either, which the default, `WANT`, does once
/// an ICMP error has told it the path's MTU. On Apple platforms it is
/// `IP_DONTFRAG`.
/// Both families are set, since a socket may carry either; the one that does
/// not apply fails, and that is fine.
pub(crate) fn forbid_fragmentation(socket: &UdpSocket) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::net::sockopt::{
            set_ip_mtu_discover, set_ipv6_mtu_discover, Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery,
        };
        let v4 = set_ip_mtu_discover(socket, Ipv4PathMtuDiscovery::PROBE).is_ok();
        let v6 = set_ipv6_mtu_discover(socket, Ipv6PathMtuDiscovery::PROBE).is_ok();
        v4 || v6
    }
    #[cfg(target_vendor = "apple")]
    {
        use nix::sys::socket::{setsockopt, sockopt};
        let v4 = setsockopt(socket, sockopt::IpDontFrag, &true).is_ok();
        let v6 = setsockopt(socket, sockopt::Ipv6DontFrag, &true).is_ok();
        v4 || v6
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        let _ = socket;
        false
    }
}

/// Whether a socket made now will search for sizes above the base, and so
/// should forbid fragmenting: discovery on, and a ceiling raised above
/// [`BASE_DATAGRAM`].
///
/// Not discovery alone. It is on by default, and at the default ceiling there
/// is nothing to search for — and forbidding fragmenting there would change
/// what a default endpoint does on the rare IPv4 path whose MTU is under
/// 1228 bytes, where Linux, left to itself, splits a 1200-byte frame once an
/// ICMP error has told it to, and `PROBE` would have it dropped instead.
pub(crate) fn searches_above_base() -> bool {
    path_mtu_discovery() && max_datagram() > BASE_DATAGRAM
}

/// Whether a send failed because the datagram is larger than the path, as
/// the system knows it, will take: what the don't-fragment bit turns an
/// oversize datagram into, at the sender, instead of a silent drop further
/// on. It is a datagram lost, not a socket failing.
pub(crate) fn is_too_long(e: &io::Error) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const EMSGSIZE: i32 = 90;
    #[cfg(target_vendor = "apple")]
    const EMSGSIZE: i32 = 40;
    #[cfg(windows)]
    const EMSGSIZE: i32 = 10040;
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    )))]
    const EMSGSIZE: i32 = -1;
    e.raw_os_error() == Some(EMSGSIZE)
}

/// A UDP socket in the mode [`recv_from`] and [`send_to`] expect, which is
/// what [`Endpoint::bind`](crate::Endpoint::bind) runs on.
pub(crate) struct Prepared(UdpSocket);

impl Prepared {
    pub(crate) fn new(socket: UdpSocket) -> io::Result<Self> {
        prepare(&socket)?;
        if searches_above_base() {
            forbid_fragmentation(&socket);
        }
        Ok(Self(socket))
    }
}

impl DatagramSocket for Prepared {
    fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        send_to(&self.0, buf, to)
    }

    fn recv_from(
        &self,
        buf: &mut [u8],
        timeout: Option<std::time::Duration>,
    ) -> io::Result<(usize, SocketAddr)> {
        recv_from(&self.0, buf, || Ok(timeout))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
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

#[cfg(test)]
mod fragmentation {
    use super::*;

    /// Whether the system says fragmenting is forbidden on `socket`, read
    /// back from it rather than taken from what was asked for.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn forbidden(socket: &UdpSocket) -> bool {
        use rustix::net::sockopt::{ip_mtu_discover, Ipv4PathMtuDiscovery};
        ip_mtu_discover(socket).expect("getsockopt") == Ipv4PathMtuDiscovery::PROBE
    }

    #[cfg(target_vendor = "apple")]
    fn forbidden(socket: &UdpSocket) -> bool {
        use nix::sys::socket::{getsockopt, sockopt};
        getsockopt(socket, sockopt::IpDontFrag).expect("getsockopt")
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    fn forbidden(_: &UdpSocket) -> bool {
        false
    }

    /// The bit is set on an endpoint's socket while there is something to
    /// search for — discovery on and the ceiling raised — where the platform
    /// allows it safely, and left alone otherwise: at the default ceiling, so
    /// a default endpoint does what it always did, and with discovery off,
    /// where a ceiling raised by hand is one the operator vouches for.
    ///
    /// One test, because both settings are process-wide and a second would
    /// race it.
    #[test]
    fn a_socket_forbids_fragmenting_only_when_there_is_a_size_to_search_for() {
        let supported = cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple"
        ));
        let made =
            || Prepared::new(UdpSocket::bind("127.0.0.1:0").expect("bind")).expect("prepare");
        let original = max_datagram();

        set_path_mtu_discovery(true);
        set_max_datagram(BASE_DATAGRAM);
        let default = made();
        set_max_datagram(1472);
        let searching = made();
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let transport = UdpTransport::connect(peer.local_addr().expect("addr")).expect("connect");
        set_path_mtu_discovery(false);
        let told = made();
        set_path_mtu_discovery(true);
        set_max_datagram(original);

        assert!(
            !forbidden(&default.0),
            "the default ceiling: left as the system had it"
        );
        assert_eq!(
            forbidden(&searching.0),
            supported,
            "a raised ceiling, discovery on"
        );
        assert_eq!(
            forbidden(&transport.socket),
            supported,
            "a connection's socket"
        );
        assert!(
            !forbidden(&told.0),
            "discovery off: left as the system had it"
        );
    }

    #[test]
    fn only_a_datagram_too_long_counts_as_too_long() {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let code = 90;
        #[cfg(target_vendor = "apple")]
        let code = 40;
        #[cfg(windows)]
        let code = 10040;
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            windows
        ))]
        assert!(is_too_long(&io::Error::from_raw_os_error(code)));
        assert!(!is_too_long(&io::Error::from(io::ErrorKind::TimedOut)));
        assert!(!is_too_long(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
    }
}
