//! # FECTP
//!
//! Fast encrypted transport. Send bytes, get bytes; the encryption, framing,
//! and compression decisions are not something the caller has to think about.
//!
//! ```no_run
//! use std::time::Duration;
//! use fectp::{Connection, Event, Identity, Endpoint};
//!
//! # fn main() -> fectp::Result<()> {
//! // Endpoint
//! let server_identity = Identity::generate();
//! let server_public = *server_identity.public();
//! let mut server = Endpoint::bind("0.0.0.0:4433", server_identity)?;
//!
//! // Client. The server's public key must already be known; FECTP has no
//! // certificate authority to look one up from.
//! let mut client = Connection::connect("127.0.0.1:4433", &server_public, &Identity::generate())?;
//! client.send(b"hello")?;
//!
//! match server.poll(Some(Duration::from_secs(1)))? {
//!     Event::Message { peer, data } => server.send(peer, &data)?,
//!     _ => {}
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## What "no delay" means here
//!
//! [`Connection::send`] returns once the datagram has been handed to the
//! kernel. It does not wait for an acknowledgement, and it never coalesces
//! payloads the way a stream protocol would. Connection setup costs one round
//! trip, and the first message already carries application data, so a request
//! can be in flight before the handshake completes.
//!
//! ## Delivery guarantees
//!
//! [`Connection::send`] is fire and forget: a lost datagram stays lost, like
//! the UDP beneath it.
//!
//! [`Connection::send_reliable`] retransmits until the peer acknowledges. It is
//! reliable but **not ordered** — a message that arrives is delivered at once,
//! even if an earlier one is still in flight. Holding it back would be
//! head-of-line blocking, which is the cost this protocol exists to avoid.
//!
//! Retransmission is driven by [`Connection::recv`] and
//! [`Connection::flush`], so one of them must be called for delivery to make
//! progress.
//!
//! ## What this does not do yet
//!
//! There is no congestion control: a sender may saturate a path. The bound on
//! unacknowledged messages ([`MAX_UNACKED`]) caps memory but is not a
//! substitute. Ordering and address migration are also absent, both by
//! decision rather than oversight.

#![warn(missing_docs)]

pub mod compress;
mod link;
mod pipeline;
use link::Link;
use pipeline::{decoded_capacity, deliver, Ingested, Peer, Pending};
pub mod endpoint;
pub mod udp;

use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use fectp_core::codec::{CODECS_CORE, CODEC_ZSTD};
use fectp_core::fragment::{fragments_needed, Fragment};
use fectp_core::frame::HEADER_LEN;
use fectp_core::reliability::MessageId;
use fectp_core::plain::PlainInitiator;
use fectp_core::session::{
    preshared_key, Initiator, ResumeInitiator, ResumptionTicket,
};
use fectp_core::{Keypair, PublicKey, Transport};
use rand_core::{OsRng, RngCore};

pub use compress::PayloadType;
pub use pipeline::MAX_TICKETS;
pub use endpoint::{Endpoint, Event, PeerId, MAX_QUEUED_LARGE};
pub use fectp_core::codec::{CODEC_HEADER_LEN as CODEC_OVERHEAD, CODECS_CORE as CORE_CODECS};
pub use fectp_core::fragment::{MAX_FRAGMENTS, MAX_MESSAGE_LEN};
pub use fectp_core::reliability::{MAX_IN_FLIGHT as MAX_UNACKED, MAX_RETRIES};
pub use fectp_core::session::{ResumptionTicket as Ticket, CAP_RELIABLE, CAP_ZSTD};
pub use fectp_core::{Capabilities, PublicKey as PeerKey};
pub use udp::{UdpTransport, DEFAULT_MAX_DATAGRAM};

/// Whether an I/O error is a receive timeout rather than a real failure.
///
/// Platforms disagree: Unix reports `WouldBlock`, Windows `TimedOut`.
pub(crate) fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// Resolves the first address `addr` names.
fn resolve(addr: impl ToSocketAddrs) -> Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no address resolved").into()
        })
}

/// Errors surfaced by the FECTP API.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The underlying socket failed.
    Io(io::Error),
    /// A protocol-level failure from the core.
    Protocol(fectp_core::Error),
    /// A compressed payload could not be decoded.
    Decompress,
    /// The payload exceeds what one frame can carry to this peer.
    PayloadTooLarge {
        /// Bytes offered.
        len: usize,
        /// Largest payload the peer accepts in one frame.
        limit: usize,
    },
    /// The handshake did not complete.
    Handshake,
    /// Reliable messages were abandoned after exhausting their retries.
    Unacknowledged {
        /// How many messages were given up on.
        count: usize,
    },
    /// The peer does not implement the reliability layer.
    ReliabilityUnsupported,
    /// A resumption named a ticket this peer does not hold.
    UnknownTicket,
    /// The handle does not name a connected peer.
    UnknownPeer,
    /// Public-key mode needs the peer's public key, and none was given.
    MissingPeerKey,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "transport error: {e}"),
            Error::Protocol(e) => write!(f, "protocol error: {e}"),
            Error::Decompress => f.write_str("could not decompress payload"),
            Error::PayloadTooLarge { len, limit } => {
                write!(f, "payload of {len} bytes exceeds the {limit}-byte frame limit")
            }
            Error::Handshake => f.write_str("handshake failed"),
            Error::Unacknowledged { count } => {
                write!(f, "{count} reliable message(s) were never acknowledged")
            }
            Error::ReliabilityUnsupported => {
                f.write_str("the peer does not implement the reliability layer")
            }
            Error::UnknownTicket => f.write_str("unknown or already-used resumption ticket"),
            Error::UnknownPeer => f.write_str("no such connected peer"),
            Error::MissingPeerKey => {
                f.write_str("public-key mode requires the peer's public key")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<fectp_core::Error> for Error {
    fn from(e: fectp_core::Error) -> Self {
        Error::Protocol(e)
    }
}

/// Convenience alias for this crate's results.
pub type Result<T> = std::result::Result<T, Error>;

/// A long-term X25519 identity.
///
/// The secret is kept as raw bytes so it can be written to flash and restored,
/// which is how a constrained device avoids repeating a costly handshake after
/// every reset.
#[derive(Clone)]
pub struct Identity {
    secret: [u8; 32],
    public: PublicKey,
}

impl Identity {
    /// Generates a new identity from the operating system's RNG.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self::from_secret(secret)
    }

    /// Restores an identity from stored secret bytes.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let public = *Keypair::from_secret(secret).public();
        Self { secret, public }
    }

    /// This identity's public key, which peers need in order to reach it.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The secret bytes, for persisting to storage.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    fn keypair(&self) -> Keypair {
        Keypair::from_secret(self.secret)
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Capabilities this build advertises.
///
/// The core transforms are always available: they are pure integer code with
/// no allocator and no tables, so every profile can reverse them. Zstandard is
/// advertised only when this build actually has it.
pub(crate) fn local_capabilities() -> Capabilities {
    let has_zstd = cfg!(feature = "compress");
    Capabilities {
        flags: CAP_RELIABLE | if has_zstd { CAP_ZSTD } else { 0 },
        max_frame_size: DEFAULT_MAX_DATAGRAM as u16,
        codecs: CODECS_CORE | if has_zstd { CODEC_ZSTD } else { 0 },
    }
}

/// An established connection to one peer.
pub struct Connection {
    transport: UdpTransport,
    /// Session, coding, and reliability state. Shared with the multi-client
    /// [`Endpoint`] so the two cannot drift apart.
    peer: Peer,
    tx: Vec<u8>,
    rx: Vec<u8>,
    /// Decoding scratch space, grown on demand.
    scratch: Vec<u8>,
    /// Data frames read while waiting for acknowledgements, held so that
    /// `flush` never has to discard one.
    inbox: VecDeque<Vec<u8>>,
    /// Origin for the millisecond clock the reliability layer is driven by.
    epoch: Instant,
    /// The caller's own receive timeout, which retransmission scheduling must
    /// not silently override.
    read_timeout: Option<Duration>,
}

impl Connection {
    fn new(transport: UdpTransport, link: Link) -> Self {
        let size = transport.max_datagram_size();
        Self {
            transport,
            peer: Peer::new(link, size),
            tx: vec![0u8; size],
            rx: vec![0u8; size],
            scratch: vec![0u8; size],
            inbox: VecDeque::new(),
            epoch: Instant::now(),
            read_timeout: None,
        }
    }

    /// Milliseconds since this connection was established.
    ///
    /// The core reliability layer never reads a clock; this is the only place
    /// time enters, which is what keeps that code portable and its tests
    /// deterministic.
    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Connects to `addr`, whose static public key is `peer_public`.
    ///
    /// Costs one round trip. The peer's public key must be known in advance:
    /// the IK handshake authenticates the responder by that key, and there is
    /// no certificate authority to discover it from.
    pub fn connect(
        addr: impl ToSocketAddrs,
        peer_public: &PublicKey,
        identity: &Identity,
    ) -> Result<Self> {
        Self::connect_with_zero_rtt(addr, peer_public, identity, &[]).map(|(c, _)| c)
    }

    /// Connects while carrying `zero_rtt` in the first handshake message.
    ///
    /// The data reaches the peer without waiting for the handshake to
    /// complete. It is encrypted, but protected only by the responder's static
    /// key: it has no forward secrecy and an attacker who captures the frame
    /// can replay it. Send only requests that are safe to repeat.
    ///
    /// Returns the connection and any payload the peer sent back.
    pub fn connect_with_zero_rtt(
        addr: impl ToSocketAddrs,
        peer_public: &PublicKey,
        identity: &Identity,
        zero_rtt: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let transport = UdpTransport::connect(resolve(addr)?)?;
        Self::handshake(transport, peer_public, identity, zero_rtt)
    }

    /// The ticket that lets the next connection skip most of the handshake.
    ///
    /// Store `*ticket.key()` — 32 bytes — alongside the peer's public key, in
    /// flash on a constrained device, and hand both to
    /// [`resume`](Self::resume) next time.
    ///
    /// Tickets are single use. Each resumption yields a fresh one, which must
    /// replace the stored value or the next attempt will be refused.
    /// Returns `None` for a plaintext session: there is no key schedule to
    /// carry forward, and the handshake it would skip costs nothing anyway.
    pub fn resumption_ticket(&self) -> Option<ResumptionTicket> {
        self.peer.session.resumption_ticket()
    }

    /// Whether this connection is encrypted.
    ///
    /// Worth checking before trusting [`peer_public_key`](Self::peer_public_key):
    /// a plaintext peer has no identity, and the all-zero key reported for one
    /// is a placeholder, not a name.
    pub fn is_encrypted(&self) -> bool {
        self.peer.session.is_encrypted()
    }

    /// Reconnects using a ticket from an earlier session.
    ///
    /// This is the reason resumption exists: a full handshake costs each peer
    /// four X25519 operations, which on a microcontroller is on the order of a
    /// hundred milliseconds and is paid again after every reset. Resumption
    /// costs **one**, because authentication comes from the ticket rather than
    /// from static-key agreement. Fresh ephemerals are still exchanged, so the
    /// resumed session keeps forward secrecy.
    ///
    /// `peer_public` is used only to report the peer's identity on the
    /// resulting connection; the handshake does not consult it.
    ///
    /// If the peer has forgotten the ticket — it was already used, or the peer
    /// restarted — it cannot answer, and this fails with a timeout. Fall back
    /// to [`connect`](Self::connect).
    pub fn resume(
        addr: impl ToSocketAddrs,
        ticket: &ResumptionTicket,
        peer_public: &PublicKey,
        timeout: Duration,
    ) -> Result<Self> {
        Self::resume_with_zero_rtt(addr, ticket, peer_public, &[], timeout).map(|(c, _)| c)
    }

    /// [`resume`](Self::resume), carrying 0-RTT data in the first message.
    ///
    /// The same caveats apply as to 0-RTT on a full handshake: the data is
    /// encrypted, but replayable by anyone who captures the frame. Send only
    /// what is safe to repeat.
    pub fn resume_with_zero_rtt(
        addr: impl ToSocketAddrs,
        ticket: &ResumptionTicket,
        peer_public: &PublicKey,
        zero_rtt: &[u8],
        timeout: Duration,
    ) -> Result<(Self, Vec<u8>)> {
        let mut transport = UdpTransport::connect(resolve(addr)?)?;
        transport.set_read_timeout(Some(timeout))?;

        let size = transport.max_datagram_size();
        let mut tx = vec![0u8; size + ResumeInitiator::OVERHEAD];
        let mut rx = vec![0u8; size];
        let mut scratch = vec![0u8; size];

        let mut initiator = ResumeInitiator::new(
            *ticket,
            *peer_public,
            OsRng.next_u32(),
            local_capabilities(),
        )?;

        let n = initiator.write_init(&mut OsRng, zero_rtt, &mut tx)?;
        transport.send(&tx[..n])?;

        let n = transport.recv(&mut rx)?;
        let (session, len) = initiator.read_response(&rx[..n], &mut scratch)?;
        let reply = scratch[..len].to_vec();

        let mut conn = Self::new(transport, Link::Encrypted(session));
        conn.set_read_timeout(None)?;
        conn.transport.set_read_timeout(None)?;
        Ok((conn, reply))
    }

    /// Connects using a pre-shared secret instead of a public key.
    ///
    /// The traffic is encrypted exactly as in public-key mode; what changes is
    /// what has to be distributed beforehand. Instead of the server's public
    /// key, both sides configure one secret — a passphrase, a device serial,
    /// bytes burned in at manufacture. For a closed system that is usually the
    /// difference between a deployment procedure and none.
    ///
    /// The handshake performs **one** Diffie-Hellman rather than four, because
    /// authentication comes from the secret rather than static-key agreement.
    /// Fresh ephemerals are still exchanged, so forward secrecy holds.
    ///
    /// The secret is symmetric: anyone holding it can impersonate either side.
    /// That is fine within one system and wrong across organisations, where
    /// [`connect`](Self::connect) and its per-peer identities belong.
    pub fn connect_psk(
        addr: impl ToSocketAddrs,
        secret: &[u8],
        timeout: Duration,
    ) -> Result<Self> {
        Self::connect_psk_with_zero_rtt(addr, secret, &[], timeout).map(|(c, _)| c)
    }

    /// [`connect_psk`](Self::connect_psk), carrying 0-RTT data.
    pub fn connect_psk_with_zero_rtt(
        addr: impl ToSocketAddrs,
        secret: &[u8],
        zero_rtt: &[u8],
        timeout: Duration,
    ) -> Result<(Self, Vec<u8>)> {
        // A pre-shared key and a resumption ticket drive the same handshake;
        // only the provenance of the key differs.
        let ticket = preshared_key(secret);
        let mut transport = UdpTransport::connect(resolve(addr)?)?;
        transport.set_read_timeout(Some(timeout))?;

        let size = transport.max_datagram_size();
        let mut tx = vec![0u8; size + ResumeInitiator::OVERHEAD];
        let mut rx = vec![0u8; size];
        let mut scratch = vec![0u8; size];

        let mut initiator = ResumeInitiator::new(
            ticket,
            fectp_core::plain::ANONYMOUS,
            OsRng.next_u32(),
            local_capabilities(),
        )?;
        let n = initiator.write_init(&mut OsRng, zero_rtt, &mut tx)?;
        transport.send(&tx[..n])?;

        let n = transport.recv(&mut rx)?;
        let (session, len) = initiator.read_response(&rx[..n], &mut scratch)?;
        let reply = scratch[..len].to_vec();

        let mut conn = Self::new(transport, Link::Encrypted(session));
        conn.transport.set_read_timeout(None)?;
        Ok((conn, reply))
    }

    /// Connects without encryption.
    ///
    /// Only two situations justify this: a physically trusted link — an
    /// instrument wired to its host — and development, where readable packet
    /// captures are worth more than confidentiality.
    ///
    /// It is **not** the answer to awkward key distribution. Encrypting a
    /// frame costs about a microsecond; distributing keys is what costs
    /// anything, and [`connect_psk`](Self::connect_psk) removes that without
    /// giving up encryption.
    ///
    /// Nothing here is authenticated, so anyone on the path can read, forge,
    /// or alter every byte.
    pub fn connect_plain(addr: impl ToSocketAddrs, timeout: Duration) -> Result<Self> {
        Self::connect_plain_with_data(addr, &[], timeout).map(|(c, _)| c)
    }

    /// [`connect_plain`](Self::connect_plain), carrying data in the opening
    /// frame.
    pub fn connect_plain_with_data(
        addr: impl ToSocketAddrs,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<(Self, Vec<u8>)> {
        let mut transport = UdpTransport::connect(resolve(addr)?)?;
        transport.set_read_timeout(Some(timeout))?;

        let size = transport.max_datagram_size();
        let mut tx = vec![0u8; size + PlainInitiator::OVERHEAD];
        let mut rx = vec![0u8; size];
        let mut scratch = vec![0u8; size];

        // There are no keys to agree; this exchange exists only to swap
        // capability blocks, which keeps codecs and reliability working as
        // they do when encrypted.
        let mut initiator = PlainInitiator::new(OsRng.next_u32(), local_capabilities());
        let n = initiator.write_init(payload, &mut tx)?;
        transport.send(&tx[..n])?;

        let n = transport.recv(&mut rx)?;
        let (session, len) = initiator.read_response(&rx[..n], &mut scratch)?;
        let reply = scratch[..len].to_vec();

        let mut conn = Self::new(transport, Link::Plain(session));
        conn.transport.set_read_timeout(None)?;
        Ok((conn, reply))
    }

    /// Connects, giving up if the peer does not answer within `timeout`.
    ///
    /// Without a timeout a handshake aimed at an unreachable peer, or at the
    /// wrong static key, waits forever: the responder simply drops a frame it
    /// cannot authenticate, so there is no reply and no error to observe.
    pub fn connect_with_timeout(
        addr: impl ToSocketAddrs,
        peer_public: &PublicKey,
        identity: &Identity,
        timeout: std::time::Duration,
    ) -> Result<Self> {
        let mut transport = UdpTransport::connect(resolve(addr)?)?;
        transport.set_read_timeout(Some(timeout))?;
        let (mut conn, _) = Self::handshake(transport, peer_public, identity, &[])?;
        conn.set_read_timeout(None)?;
        Ok(conn)
    }

    fn handshake(
        mut transport: UdpTransport,
        peer_public: &PublicKey,
        identity: &Identity,
        zero_rtt: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let size = transport.max_datagram_size();
        let mut tx = vec![0u8; size + Initiator::OVERHEAD];
        let mut rx = vec![0u8; size];
        let mut scratch = vec![0u8; size];

        let mut initiator = Initiator::new(
            identity.keypair(),
            *peer_public,
            OsRng.next_u32(),
            local_capabilities(),
        )?;

        let n = initiator.write_init(&mut OsRng, zero_rtt, &mut tx)?;
        transport.send(&tx[..n])?;

        let n = transport.recv(&mut rx)?;
        let (session, len) = initiator.read_response(&rx[..n], &mut scratch)?;
        let reply = scratch[..len].to_vec();

        Ok((Self::new(transport, Link::Encrypted(session)), reply))
    }

    /// The peer's authenticated static public key.
    pub fn peer_public_key(&self) -> &PublicKey {
        self.peer.remote_static()
    }

    /// The peer's socket address.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.transport.peer_addr()?)
    }

    /// Largest uncompressed payload that fits in a single [`send`](Self::send).
    ///
    /// A larger payload can still succeed if it compresses below this limit,
    /// since what has to fit is the frame that goes on the wire.
    ///
    /// This is the limit for an *unreliable* send. A reliable one also carries
    /// a message identifier, so its limit is
    /// [`max_reliable_payload`](Self::max_reliable_payload), which is smaller.
    pub fn max_payload(&self) -> usize {
        self.peer.max_payload(self.transport.max_datagram_size())
    }

    /// Largest slice of a [`send_large`](Self::send_large) message that one
    /// frame carries.
    ///
    /// A fragment gives up room to both the message identifier and the
    /// fragment descriptor.
    pub fn max_fragment_payload(&self) -> usize {
        self.peer
            .max_fragment_payload(self.transport.max_datagram_size())
    }

    /// Largest uncompressed payload for a single
    /// [`send_reliable`](Self::send_reliable).
    ///
    /// Smaller than [`max_payload`](Self::max_payload) by the message
    /// identifier a reliable frame carries. Anything above this needs
    /// [`send_large`](Self::send_large), which splits it across frames.
    pub fn max_reliable_payload(&self) -> usize {
        self.peer
            .payload_room(self.transport.max_datagram_size(), true, false)
    }

    /// Pads outgoing frames to a 64-byte boundary to mask payload lengths.
    ///
    /// Off by default: a 10-byte message becomes a 64-byte one, which is a
    /// steep price for the small messages this protocol targets. Turn it on
    /// when the lengths themselves are sensitive. The peer follows the
    /// per-frame flag, so the two directions are independent.
    pub fn set_padding(&mut self, enabled: bool) {
        self.peer.session.set_padding(enabled);
    }

    /// Sets how long [`recv`](Self::recv) waits before giving up.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        // Recorded rather than applied directly: `recv` has to wake for
        // retransmission deadlines too, so it computes the socket timeout as
        // the earlier of the two.
        self.read_timeout = timeout;
        Ok(())
    }

    /// Encrypts and sends `data` as one datagram.
    ///
    /// Returns once the bytes are handed to the kernel. There is no
    /// acknowledgement and no retransmission: a lost datagram is lost.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        self.send_typed(data, self.peer.default_payload_type)
    }

    /// Sets the payload shape [`send`](Self::send) assumes.
    ///
    /// A connection usually carries one kind of data for its whole life — a
    /// sensor stream stays a sensor stream. Declaring the shape once here
    /// means the rest of the code keeps calling plain `send` and still gets
    /// the codec suited to it.
    ///
    /// Defaults to [`PayloadType::Opaque`]. Individual messages that do not
    /// match can still override it with
    /// [`send_typed`](Self::send_typed).
    pub fn set_default_payload_type(&mut self, payload_type: PayloadType) {
        self.peer.default_payload_type = payload_type;
    }

    /// The payload shape [`send`](Self::send) currently assumes.
    pub fn default_payload_type(&self) -> PayloadType {
        self.peer.default_payload_type
    }

    /// Sends `data`, telling the transport what shape it has.
    ///
    /// Declaring a type lets a transform suited to that data run before the
    /// generic compressor. Interleaved `i16` sensor samples, for instance, are
    /// split by channel and delta-coded first, which typically beats running
    /// Zstandard on the raw bytes by a wide margin — an interleaved buffer
    /// hides its redundancy from a byte-oriented compressor.
    ///
    /// A wrong declaration is safe: the payload still round-trips, it just
    /// compresses badly. If the peer cannot reverse the transform, or coding
    /// does not actually shrink the payload, the original bytes are sent.
    pub fn send_typed(&mut self, data: &[u8], payload_type: PayloadType) -> Result<()> {
        let n = self.seal(data, payload_type, None)?;
        self.transport.send(&self.tx[..n])?;
        Ok(())
    }

    /// Sends `data` and keeps resending it until the peer acknowledges it.
    ///
    /// Delivery is guaranteed but **not ordered**. A message that arrives is
    /// delivered immediately, even if an earlier one is still in flight.
    /// Holding it back would be head-of-line blocking, which is the cost this
    /// protocol exists to avoid; an application that needs ordering should
    /// sequence its own payloads.
    ///
    /// Returns as soon as the first transmission is handed to the kernel.
    /// Retransmission is driven by [`recv`](Self::recv) and
    /// [`flush`](Self::flush), so one of those must be called for delivery to
    /// make progress.
    ///
    /// Fails with [`Error::WindowFull`](fectp_core::Error::WindowFull) once
    /// [`MAX_UNACKED`] messages are outstanding, and with
    /// [`Error::ReliabilityUnsupported`] if the peer never advertised the
    /// capability.
    pub fn send_reliable(&mut self, data: &[u8]) -> Result<MessageId> {
        self.send_reliable_typed(data, self.peer.default_payload_type)
    }

    /// [`send_reliable`](Self::send_reliable), declaring the payload's shape.
    pub fn send_reliable_typed(
        &mut self,
        data: &[u8],
        payload_type: PayloadType,
    ) -> Result<MessageId> {
        if !self.peer.session.peer_capabilities().supports_reliable() {
            // Without a peer that acknowledges, every message would be resent
            // until it was abandoned. Refusing now beats failing slowly.
            return Err(Error::ReliabilityUnsupported);
        }
        let now = self.now_ms();
        let id = self.peer.retransmit.register(now)?;
        let n = self.seal(data, payload_type, Some(id))?;
        self.transport.send(&self.tx[..n])?;
        self.peer.pending.push(Pending {
            id,
            payload_type,
            data: data.to_vec(),
            fragment: None,
        });
        Ok(id)
    }

    /// Sends a message too large for one frame, and waits for all of it.
    ///
    /// [`send`](Self::send) and [`send_reliable`](Self::send_reliable) refuse a
    /// payload above [`max_payload`](Self::max_payload), because a datagram
    /// larger than the path MTU is cut up by IP, and an IP-fragmented datagram
    /// is lost entire if any piece of it is. This cuts the message at the
    /// protocol layer instead, where a lost piece is retransmitted on its own.
    ///
    /// Every fragment is a reliable message, so this needs a peer that
    /// acknowledges. It returns once the peer has acknowledged all of them,
    /// which is why it takes a timeout rather than returning immediately: there
    /// is no useful sense in which a large message has been "sent" while most
    /// of it is still queued behind a send window.
    ///
    /// Fragments are coded individually rather than the message being coded
    /// whole, so each frame is self-describing. That costs compression ratio —
    /// a compressor sees one fragment of context, not the message — and buys a
    /// receiver that can decode any frame without waiting for the rest.
    ///
    /// Messages above [`MAX_MESSAGE_LEN`] are refused rather than fragmented.
    pub fn send_large(&mut self, data: &[u8], timeout: Duration) -> Result<()> {
        self.send_large_typed(data, self.peer.default_payload_type, timeout)
    }

    /// [`send_large`](Self::send_large), declaring the payload's shape.
    pub fn send_large_typed(
        &mut self,
        data: &[u8],
        payload_type: PayloadType,
        timeout: Duration,
    ) -> Result<()> {
        if !self.peer.session.peer_capabilities().supports_reliable() {
            return Err(Error::ReliabilityUnsupported);
        }
        let deadline = Instant::now() + timeout;
        let limit = self.transport.max_datagram_size();
        let per_fragment = self.peer.max_fragment_payload(limit);

        let count = fragments_needed(data.len(), per_fragment).ok_or(Error::PayloadTooLarge {
            len: data.len(),
            limit: MAX_MESSAGE_LEN,
        })?;

        let message = self.peer.next_message;
        self.peer.next_message = self.peer.next_message.wrapping_add(1);

        for index in 0..count {
            let start = index as usize * per_fragment;
            let end = (start + per_fragment).min(data.len());
            let chunk = &data[start..end];

            // The in-flight bound doubles as the send window. Waiting here
            // rather than failing is what makes this usable for a message of
            // many more fragments than the window holds — and it is also the
            // only thing pacing the send, so a burst cannot outrun the
            // receiver's socket buffer.
            let id = loop {
                let now = self.now_ms();
                match self.peer.retransmit.register(now) {
                    Ok(id) => break id,
                    Err(fectp_core::Error::WindowFull) => {
                        if Instant::now() >= deadline {
                            return Err(Error::Unacknowledged {
                                count: self.peer.retransmit.in_flight(),
                            });
                        }
                        self.pump(Some(deadline), None)?;
                    }
                    Err(e) => return Err(Error::Protocol(e)),
                }
            };

            let fragment = Fragment {
                message,
                index,
                count,
            };
            let n = self.peer.seal(
                chunk,
                payload_type,
                Some(id),
                Some(fragment),
                limit,
                &mut self.tx,
            )?;
            self.transport.send(&self.tx[..n])?;
            self.peer.pending.push(Pending {
                id,
                payload_type,
                data: chunk.to_vec(),
                fragment: Some(fragment),
            });
        }

        let left = deadline.saturating_duration_since(Instant::now());
        self.flush(left)
    }

    /// Fragmented messages this side has begun receiving but not completed.
    ///
    /// Non-zero means fragments have arrived for a message whose remaining
    /// pieces have not. It is bounded, so a peer cannot grow it without limit.
    pub fn reassembling(&self) -> usize {
        self.peer.reassembly.in_progress()
    }

    /// Reliable messages still awaiting acknowledgement.
    pub fn unacknowledged(&self) -> usize {
        self.peer.retransmit.in_flight()
    }

    /// The current retransmission timeout estimate, in milliseconds.
    pub fn rto_ms(&self) -> u32 {
        self.peer.retransmit.rto_ms()
    }

    /// Blocks until every reliable message is acknowledged, or `timeout` runs
    /// out.
    ///
    /// Data frames that arrive meanwhile are queued, not discarded, and are
    /// returned by later calls to [`recv`](Self::recv).
    ///
    /// Fails with [`Error::Unacknowledged`] if any message was abandoned after
    /// exhausting its retries.
    pub fn flush(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        self.peer.abandoned.clear();

        while self.peer.retransmit.in_flight() > 0 {
            if Instant::now() >= deadline {
                return Err(Error::Unacknowledged {
                    count: self.peer.retransmit.in_flight() + self.peer.abandoned.len(),
                });
            }
            self.pump(Some(deadline), None)?;
        }
        if !self.peer.abandoned.is_empty() {
            return Err(Error::Unacknowledged {
                count: self.peer.abandoned.len(),
            });
        }
        Ok(())
    }

    /// Codes if it pays, then seals into `self.tx`.
    fn seal(
        &mut self,
        data: &[u8],
        payload_type: PayloadType,
        message_id: Option<MessageId>,
    ) -> Result<usize> {
        let limit = self.transport.max_datagram_size();
        self.peer
            .seal(data, payload_type, message_id, None, limit, &mut self.tx)
    }

    /// Receives the next authentic datagram, writing its payload to `out`.
    ///
    /// Frames that fail to authenticate, that replay a sequence number already
    /// seen, or that belong to another session are discarded and the call
    /// keeps waiting. Anyone can send bytes to a UDP port, so a forged frame
    /// is not an application-level error; surfacing it as one would hand an
    /// off-path attacker a denial of service.
    pub fn recv(&mut self, out: &mut [u8]) -> Result<usize> {
        // Anything queued while flushing is delivered before going back to the
        // socket, so ordering between the two paths stays sane.
        if let Some(message) = self.inbox.pop_front() {
            let mut scratch = core::mem::take(&mut self.scratch);
            let delivered = deliver(&message, false, &mut scratch, out);
            self.scratch = scratch;
            return delivered;
        }

        let deadline = self.read_timeout.map(|t| Instant::now() + t);
        loop {
            if let Some(len) = self.pump(deadline, Some(out))? {
                return Ok(len);
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no frame arrived within the read timeout",
                )));
            }
        }
    }

    /// One turn of the event loop: retransmit what is due, wait for a frame,
    /// and dispatch it.
    ///
    /// Returns `Ok(Some(len))` when a data frame was delivered into `out`.
    /// With `out` as `None`, data frames are queued for a later `recv`, which
    /// is what lets `flush` wait for acknowledgements without dropping them.
    fn pump(&mut self, deadline: Option<Instant>, out: Option<&mut [u8]>) -> Result<Option<usize>> {
        self.drive_retransmits()?;

        // Wake for whichever comes first: the caller's timeout or the next
        // retransmission deadline. Sleeping past the latter would leave a lost
        // message unnoticed until some unrelated frame arrived.
        let now = self.now_ms();
        let until_retransmit = self
            .peer
            .retransmit
            .next_deadline_ms()
            .map(|at| Duration::from_millis(at.saturating_sub(now)));
        let until_deadline = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        let wait = match (until_retransmit, until_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        // A zero timeout means "block forever" to the socket layer, which is
        // the opposite of what is meant here.
        self.transport
            .set_read_timeout(wait.map(|w| w.max(Duration::from_millis(1))))?;

        let n = match self.transport.recv(&mut self.rx) {
            Ok(n) => n,
            // Whose deadline expired, and what that means, is the caller's
            // business: `recv` reports a timeout, `flush` reports the messages
            // still outstanding.
            Err(e) if is_timeout(&e) => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        };

        let now = self.now_ms();
        let mut ack_len = 0;
        let ingested = self
            .peer
            .ingest(&mut self.rx[..n], now, &mut self.tx, &mut ack_len)?;
        if ack_len > 0 {
            self.transport.send(&self.tx[..ack_len])?;
        }

        let (len, compressed) = match ingested {
            Ingested::Nothing => return Ok(None),
            Ingested::Data { len, compressed } => (len, compressed),
            // Already whole and already decoded; it never lived in `rx`.
            Ingested::Message(data) => match out {
                Some(out) => {
                    if out.len() < data.len() {
                        return Err(Error::PayloadTooLarge {
                            len: data.len(),
                            limit: out.len(),
                        });
                    }
                    out[..data.len()].copy_from_slice(&data);
                    return Ok(Some(data.len()));
                }
                None => {
                    self.inbox.push_back(data);
                    return Ok(None);
                }
            },
        };

        let body = HEADER_LEN..HEADER_LEN + len;
        let mut scratch = core::mem::take(&mut self.scratch);
        let result = match out {
            Some(out) => deliver(&self.rx[body], compressed, &mut scratch, out).map(Some),
            None => {
                let mut staging = vec![0u8; decoded_capacity(&self.rx[body.clone()], compressed)];
                deliver(&self.rx[body], compressed, &mut scratch, &mut staging).map(|written| {
                    staging.truncate(written);
                    self.inbox.push_back(staging);
                    None
                })
            }
        };
        self.scratch = scratch;
        result
    }

    /// Resends whatever has timed out, and drops whatever has run out of
    /// retries.
    fn drive_retransmits(&mut self) -> Result<()> {
        let now = self.now_ms();
        let limit = self.transport.max_datagram_size();
        let transport = &mut self.transport;
        self.peer
            .drive_retransmits(now, limit, &mut self.tx, |frame| {
                transport.send(frame).map_err(Error::Io)
            })
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("peer", &self.transport.peer_addr().ok())
            .field("session_id", &self.peer.session.session_id())
            .finish_non_exhaustive()
    }
}

