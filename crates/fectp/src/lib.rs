//! # FECTP
//!
//! Fast encrypted transport. Send bytes, get bytes; the encryption, framing,
//! and compression decisions are not something the caller has to think about.
//!
//! ```no_run
//! use std::time::Duration;
//! use fectp::{Connection, Endpoint, Event, Identity, PayloadType};
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
//! client.send(b"hello", PayloadType::Opaque)?;
//!
//! match server.poll(Some(Duration::from_secs(1)))? {
//!     Event::Message { peer, data } => server.send(peer, &data, PayloadType::Opaque)?,
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
mod endpoint;
pub mod udp;

use std::sync::Mutex;
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use fectp_core::codec::{CODECS_CORE, CODEC_ZSTD};
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
pub use endpoint::{Endpoint, Event, PeerId, MAX_HANDSHAKES_PER_SECOND, MAX_PEERS};
pub use pipeline::MAX_QUEUED;
pub use fectp_core::codec::{CODEC_HEADER_LEN as CODEC_OVERHEAD, CODECS_CORE as CORE_CODECS};
/// How long a handshake waits for the peer's reply before giving up.
///
/// Applies to every way of opening a connection, which is why none of them
/// takes a timeout argument.
///
/// Something like this is not optional. A responder that cannot authenticate a
/// frame simply drops it — there is no reply and no error to observe — so a
/// handshake aimed at an unreachable peer, or at the wrong static key, has
/// nothing to wait for and would wait for ever. `connect` did exactly that
/// until it was measured; `connect_with_timeout` existed beside it as the way
/// around it, which is how the argument came to be on some constructors and
/// not others.
///
/// Five seconds is generous enough for a satellite path and short enough that
/// an unreachable peer is reported rather than waited on.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub use fectp_core::fragment::{MAX_FRAGMENTS, MAX_MESSAGE_LEN};
pub use fectp_core::reliability::{
    INITIAL_CWND, MAX_IN_FLIGHT as MAX_UNACKED, MAX_RETRIES, MIN_CWND,
};
pub use fectp_core::session::{ResumptionTicket as Ticket, CAP_RELIABLE, CAP_ZSTD};
pub use fectp_core::{Capabilities, PublicKey as PeerKey};
pub use udp::{
    max_datagram, set_max_datagram, UdpTransport, DEFAULT_MAX_DATAGRAM, MIN_MAX_DATAGRAM,
};

/// Whether an I/O error is a receive timeout rather than a real failure.
///
/// Platforms disagree: Unix reports `WouldBlock`, Windows `TimedOut`.
pub(crate) fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}


/// How long to wait for a handshake reply before sending the opening frame again.
///
/// The same schedule [`Endpoint`] already used for the connections it starts.
const HANDSHAKE_RETRY_MS: u64 = 250;

/// Sends the opening frame and waits for the reply, sending it again if either
/// goes missing.
///
/// A handshake frame is one datagram and carries no acknowledgement of its own,
/// so without this a single lost packet meant the full
/// [`HANDSHAKE_TIMEOUT`] of silence and then a failed connect — no retry, on a
/// protocol whose data path has retransmitted since the beginning. `Endpoint`
/// resent its opening frames all along; the blocking client did not, which left
/// the simpler of the two APIs the less robust one.
///
/// Backoff is linear from [`HANDSHAKE_RETRY_MS`] and the whole thing is bounded
/// by [`HANDSHAKE_TIMEOUT`], so a peer that is genuinely absent is still
/// reported in five seconds rather than waited on — it just costs a handful of
/// datagrams to establish that instead of one.
fn exchange_handshake(
    transport: &mut UdpTransport,
    frame: &[u8],
    rx: &mut [u8],
) -> Result<usize> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;

    for attempt in 1u64.. {
        transport.send(frame)?;

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let wait = Duration::from_millis(HANDSHAKE_RETRY_MS * attempt).min(remaining);
        transport.set_read_timeout(Some(wait))?;

        match transport.recv(rx) {
            Ok(n) => return Ok(n),
            // Nothing came back in time: assume the frame was lost and repeat
            // it. A responder that simply refused us is silent in exactly the
            // same way, which is why this is bounded rather than persistent.
            Err(e) if is_timeout(&e) => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }

    Err(Error::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "no handshake reply within the handshake timeout",
    )))
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
    /// The duplex protocol thread has stopped, so the connection is over.
    ///
    /// Either half being dropped ends it, as does an unrecoverable socket
    /// error on the thread.
    Closed,

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
            Error::Closed => f.write_str("the connection is closed"),
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
        max_frame_size: udp::max_datagram() as u16,
        codecs: CODECS_CORE | if has_zstd { CODEC_ZSTD } else { 0 },
    }
}

/// An established connection to one peer.
struct Core {
    transport: UdpTransport,
    /// Session, coding, and reliability state. Shared with the multi-client
    /// [`Endpoint`] so the two cannot drift apart.
    peer: Peer,
    tx: Vec<u8>,
    /// Data frames read while waiting for acknowledgements, held so that
    /// `flush` never has to discard one.
    inbox: VecDeque<Vec<u8>>,
    /// Origin for the millisecond clock the reliability layer is driven by.
    epoch: Instant,
    /// The caller's own receive timeout, which retransmission scheduling must
    /// not silently override.
    read_timeout: Option<Duration>,
}

impl Core {
    fn new(transport: UdpTransport, link: Link) -> Self {
        let size = transport.max_datagram_size();
        Self {
            transport,
            peer: Peer::new(link, size),
            tx: vec![0u8; size],
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
        Self::connect_and_send(addr, peer_public, identity, &[])
    }

    /// Connects while carrying `zero_rtt` in the first handshake message.
    ///
    /// The data reaches the peer without waiting for the handshake to
    /// complete. It is encrypted, but protected only by the responder's static
    /// key: it has no forward secrecy and an attacker who captures the frame
    /// can replay it. Send only requests that are safe to repeat.
    ///
    /// Returns the connection and any payload the peer sent back.
    pub fn connect_and_send(
        addr: impl ToSocketAddrs,
        peer_public: &PublicKey,
        identity: &Identity,
        zero_rtt: &[u8],
    ) -> Result<Self> {
        let mut transport = UdpTransport::connect(resolve(addr)?)?;
        transport.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        let mut conn = Self::handshake(transport, peer_public, identity, zero_rtt)?;
        // The handshake's deadline is not the caller's; `recv` gets its own.
        conn.set_read_timeout(None)?;
        Ok(conn)
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
    ) -> Result<Self> {
        Self::resume_and_send(addr, ticket, peer_public, &[])
    }

    /// [`resume`](Self::resume), carrying 0-RTT data in the first message.
    ///
    /// The same caveats apply as to 0-RTT on a full handshake: the data is
    /// encrypted, but replayable by anyone who captures the frame. Send only
    /// what is safe to repeat.
    pub fn resume_and_send(
        addr: impl ToSocketAddrs,
        ticket: &ResumptionTicket,
        peer_public: &PublicKey,
        zero_rtt: &[u8],
    ) -> Result<Self> {
        let mut transport = UdpTransport::connect(resolve(addr)?)?;
        transport.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

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
        let n = exchange_handshake(&mut transport, &tx[..n], &mut rx)?;
        let (session, len) = initiator.read_response(&rx[..n], &mut scratch)?;
        let reply = scratch[..len].to_vec();

        let mut conn = Self::new(transport, Link::Encrypted(session));
        conn.set_read_timeout(None)?;
        conn.transport.set_read_timeout(None)?;
        conn.queue_first(reply);
        Ok(conn)
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
    ) -> Result<Self> {
        Self::connect_psk_and_send(addr, secret, &[])
    }

    /// [`connect_psk`](Self::connect_psk), carrying 0-RTT data.
    pub fn connect_psk_and_send(
        addr: impl ToSocketAddrs,
        secret: &[u8],
        zero_rtt: &[u8],
    ) -> Result<Self> {
        // A pre-shared key and a resumption ticket drive the same handshake;
        // only the provenance of the key differs.
        let ticket = preshared_key(secret);
        let mut transport = UdpTransport::connect(resolve(addr)?)?;
        transport.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

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
        let n = exchange_handshake(&mut transport, &tx[..n], &mut rx)?;
        let (session, len) = initiator.read_response(&rx[..n], &mut scratch)?;
        let reply = scratch[..len].to_vec();

        let mut conn = Self::new(transport, Link::Encrypted(session));
        conn.transport.set_read_timeout(None)?;
        conn.queue_first(reply);
        Ok(conn)
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
    pub fn connect_plain(addr: impl ToSocketAddrs) -> Result<Self> {
        let payload: &[u8] = &[];
        let mut transport = UdpTransport::connect(resolve(addr)?)?;
        transport.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

        let size = transport.max_datagram_size();
        let mut tx = vec![0u8; size + PlainInitiator::OVERHEAD];
        let mut rx = vec![0u8; size];
        let mut scratch = vec![0u8; size];

        // There are no keys to agree; this exchange exists only to swap
        // capability blocks, which keeps codecs and reliability working as
        // they do when encrypted.
        let mut initiator = PlainInitiator::new(OsRng.next_u32(), local_capabilities());
        let n = initiator.write_init(payload, &mut tx)?;
        let n = exchange_handshake(&mut transport, &tx[..n], &mut rx)?;
        let (session, len) = initiator.read_response(&rx[..n], &mut scratch)?;
        let reply = scratch[..len].to_vec();

        let mut conn = Self::new(transport, Link::Plain(session));
        conn.transport.set_read_timeout(None)?;
        conn.queue_first(reply);
        Ok(conn)
    }

    /// Puts whatever the peer sent alongside its handshake reply where
    /// `recv` will find it.
    ///
    /// It is the peer's first data, not a different kind of thing, so it
    /// arrives the way every other message does rather than as an extra return
    /// value the caller has to know about.
    fn queue_first(&mut self, first: Vec<u8>) {
        if !first.is_empty() {
            self.inbox.push_back(first);
        }
    }

    fn handshake(
        mut transport: UdpTransport,
        peer_public: &PublicKey,
        identity: &Identity,
        zero_rtt: &[u8],
    ) -> Result<Self> {
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
        let n = exchange_handshake(&mut transport, &tx[..n], &mut rx)?;
        let (session, len) = initiator.read_response(&rx[..n], &mut scratch)?;
        let reply = scratch[..len].to_vec();

        let mut conn = Self::new(transport, Link::Encrypted(session));
        conn.queue_first(reply);
        Ok(conn)
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

    /// Largest slice of a split message that one
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
    /// [`send_reliable`](Self::send_reliable), which splits it across frames.
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
    pub fn send_one(&mut self, data: &[u8], payload_type: PayloadType) -> Result<()> {
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
    /// Sends one reliable frame, for a payload that fits in one.
    pub fn send_one_reliable(
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

/// The receive path's own resources.
///
/// Separate from [`Core`] so that a blocking read holds only this lock, and a
/// send on another thread is not waiting behind it.
struct Reader {
    /// A second handle on the same socket. One kernel socket may be sent on
    /// and received on at once; that property is the operating system's, and
    /// it is what lets the two directions run at the same time.
    transport: UdpTransport,
    rx: Vec<u8>,
    /// Decoding scratch space, grown on demand.
    scratch: Vec<u8>,
}

/// An established session with one peer.
///
/// Every method takes `&self`, so one thread may send while another is blocked
/// receiving. Nothing has to be wrapped or converted first:
///
/// ```no_run
/// # fn main() -> fectp::Result<()> {
/// # let conn: fectp::Connection = unimplemented!();
/// use fectp::PayloadType;
/// std::thread::scope(|s| {
///     s.spawn(|| loop {
///         let _ = conn.recv(&mut [0u8; 2048]);
///     });
///     conn.send(b"sent while the other thread is blocked reading", PayloadType::Opaque)
/// })?;
/// # Ok(()) }
/// ```
///
/// The two directions hold separate cipher states once the handshake splits,
/// and the state they do share — the reliability layer — sits behind a lock
/// held for microseconds, never across a blocking read.
///
/// Retransmission happens inside `recv`, [`flush`](Self::flush) and the send
/// calls, as it always has: a program that sends reliably and then calls none
/// of them will not retransmit.
pub struct Connection {
    core: Mutex<Core>,
    reader: Mutex<Reader>,
}

impl Connection {
    fn wrap(core: Core) -> Result<Self> {
        let size = core.transport.max_datagram_size();
        let reader = Reader {
            transport: core.transport.try_clone()?,
            rx: vec![0u8; size],
            scratch: vec![0u8; size],
        };
        Ok(Self {
            core: Mutex::new(core),
            reader: Mutex::new(reader),
        })
    }

    fn core(&self) -> Result<std::sync::MutexGuard<'_, Core>> {
        self.core.lock().map_err(|_| Error::Closed)
    }

    // ── opening a connection ──────────────────────────────────────────────

    /// Connects to a peer whose public key is already known.
    pub fn connect(
        addr: impl ToSocketAddrs,
        peer_public: &PublicKey,
        identity: &Identity,
    ) -> Result<Self> {
        Self::wrap(Core::connect(addr, peer_public, identity)?)
    }

    /// [`connect`](Self::connect), carrying a payload in the first message.
    ///
    /// That payload is encrypted but **replayable** and has no forward
    /// secrecy; see `SPEC.md` §4.4.1.
    pub fn connect_and_send(
        addr: impl ToSocketAddrs,
        peer_public: &PublicKey,
        identity: &Identity,
        zero_rtt: &[u8],
    ) -> Result<Self> {
        Self::wrap(Core::connect_and_send(addr, peer_public, identity, zero_rtt)?)
    }

    /// Redeems a resumption ticket, sparing three of the four key agreements.
    pub fn resume(
        addr: impl ToSocketAddrs,
        ticket: &ResumptionTicket,
        peer_public: &PublicKey,
    ) -> Result<Self> {
        Self::wrap(Core::resume(addr, ticket, peer_public)?)
    }

    /// [`resume`](Self::resume), carrying a payload in the first message.
    pub fn resume_and_send(
        addr: impl ToSocketAddrs,
        ticket: &ResumptionTicket,
        peer_public: &PublicKey,
        zero_rtt: &[u8],
    ) -> Result<Self> {
        Self::wrap(Core::resume_and_send(addr, ticket, peer_public, zero_rtt)?)
    }

    /// Connects in pre-shared-key mode.
    pub fn connect_psk(
        addr: impl ToSocketAddrs,
        secret: &[u8],
    ) -> Result<Self> {
        Self::wrap(Core::connect_psk(addr, secret)?)
    }

    /// [`connect_psk`](Self::connect_psk), carrying a payload in the first
    /// message.
    pub fn connect_psk_and_send(
        addr: impl ToSocketAddrs,
        secret: &[u8],
        zero_rtt: &[u8],
    ) -> Result<Self> {
        Self::wrap(Core::connect_psk_and_send(addr, secret, zero_rtt)?)
    }

    /// Connects in plaintext mode. Nothing is encrypted or authenticated.
    pub fn connect_plain(addr: impl ToSocketAddrs) -> Result<Self> {
        Self::wrap(Core::connect_plain(addr)?)
    }


    // ── asking about the connection ───────────────────────────────────────

    /// A single-use ticket for resuming this session later, if it is encrypted.
    pub fn resumption_ticket(&self) -> Option<ResumptionTicket> {
        self.core().ok()?.resumption_ticket()
    }

    /// Whether this session encrypts.
    pub fn is_encrypted(&self) -> bool {
        self.core().map(|c| c.is_encrypted()).unwrap_or(false)
    }

    /// The peer's authenticated static public key.
    pub fn peer_public_key(&self) -> Result<PublicKey> {
        Ok(*self.core()?.peer_public_key())
    }

    /// The peer's socket address.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.core()?.peer_addr()
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
        self.core().map(|c| c.max_payload()).unwrap_or(0)
    }

    /// Largest uncompressed payload for a single
    /// [`send_reliable`](Self::send_reliable).
    pub fn max_reliable_payload(&self) -> usize {
        self.core().map(|c| c.max_reliable_payload()).unwrap_or(0)
    }

    /// Largest slice of a split message that one
    /// frame carries.
    pub fn max_fragment_payload(&self) -> usize {
        self.core().map(|c| c.max_fragment_payload()).unwrap_or(0)
    }

    /// Fragmented messages this side has begun receiving but not completed.
    pub fn reassembling(&self) -> usize {
        self.core().map(|c| c.peer.reassembly.in_progress()).unwrap_or(0)
    }

    /// Reliable messages still awaiting acknowledgement.
    pub fn unacknowledged(&self) -> usize {
        self.core()
            .map(|c| c.peer.retransmit.in_flight())
            .unwrap_or(0)
    }

    /// The current retransmission timeout estimate, in milliseconds.
    pub fn rto_ms(&self) -> u32 {
        self.core().map(|c| c.peer.retransmit.rto_ms()).unwrap_or(0)
    }


    // ── settings ──────────────────────────────────────────────────────────


    /// Pads outgoing frames to a 64-byte boundary to mask payload lengths.
    ///
    /// Off by default: a 10-byte message becomes a 64-byte one, which is a
    /// steep price for the small messages this protocol targets.
    pub fn set_padding(&self, enabled: bool) {
        if let Ok(mut core) = self.core() {
            core.set_padding(enabled);
        }
    }

    /// How long [`recv`](Self::recv) waits before reporting a timeout.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.core()?.set_read_timeout(timeout)
    }

    /// Sends `data` to the peer as one datagram.
    ///
    /// `payload_type` says what shape the bytes have, so a transform suited to
    /// them can run before the generic compressor — interleaved sensor samples
    /// are split by channel and delta-coded, for instance, which a byte-oriented
    /// compressor cannot do for itself. [`PayloadType::Opaque`] means "just
    /// bytes" and is always correct; a wrong declaration still round-trips, it
    /// just compresses badly.
    ///
    /// It is named at every call rather than set once on the connection. A
    /// setting would mean this line's behaviour depended on a call somewhere
    /// else, and forgetting it would cost compression silently — no error, no
    /// warning. Repeating a shape is cheap: `PayloadType` is two bytes and
    /// `Copy`, so bind it to a local and pass it.
    ///
    /// Returns once the bytes are handed to the kernel. There is no
    /// acknowledgement and no retransmission: a lost datagram is lost, and
    /// anything above one frame is refused.
    pub fn send(&self, data: &[u8], payload_type: PayloadType) -> Result<()> {
        self.core()?.send_one(data, payload_type)
    }

    /// Sends `data` and keeps resending it until the peer acknowledges it.
    ///
    /// Any size. A payload larger than one frame is split across several, each
    /// retransmitted on its own — so a lost piece costs one frame rather than
    /// the message. There is no separate call for that and no size for the
    /// caller to check, which matters because the frame limit depends on what
    /// the *peer* advertised and is not knowable in advance.
    ///
    /// Returns once the message is on its way, not once it has arrived. A large
    /// one will not fit in the congestion window, so the rest is queued and fed
    /// out by [`recv`](Self::recv), [`flush`](Self::flush) and later sends.
    /// [`flush`](Self::flush) is how you wait for delivery.
    ///
    /// Fails with [`Error::WindowFull`](fectp_core::Error::WindowFull) when too
    /// many messages are already queued, and with
    /// [`Error::ReliabilityUnsupported`] if the peer never advertised the
    /// capability. Payloads above [`MAX_MESSAGE_LEN`] are refused rather than
    /// split.
    pub fn send_reliable(&self, data: &[u8], payload_type: PayloadType) -> Result<()> {
        {
            let mut core = self.core()?;
            let limit = core.transport.max_datagram_size();

            // One frame is the common case and does not need the queue: it goes
            // straight out, as it always has.
            if data.len() <= core.peer.payload_room(limit, true, false) {
                return core.send_one_reliable(data, payload_type).map(|_| ());
            }
            core.peer.queue_message(data, payload_type, limit)?;
        }
        // Start it now rather than at the next call, so a caller that queues
        // and then blocks in `flush` does not wait a round trip for nothing.
        self.drive_queue()?;
        Ok(())
    }

    /// Feeds whatever is queued into the free part of the send window.
    fn drive_queue(&self) -> Result<()> {
        let mut core = self.core()?;
        let now = core.now_ms();
        let limit = core.transport.max_datagram_size();
        let Core {
            peer,
            transport,
            tx,
            ..
        } = &mut *core;
        peer.drive_queue(now, limit, tx, |frame| transport.send(frame).map_err(Error::Io))?;
        Ok(())
    }

    /// Messages split across frames and not yet fully sent.
    pub fn queued(&self) -> usize {
        self.core().map(|c| c.peer.queued()).unwrap_or(0)
    }

    /// Receives the next authentic datagram, writing its payload to `out`.
    ///
    /// Frames that fail to authenticate, that replay a sequence number already
    /// seen, or that belong to another session are discarded and the call keeps
    /// waiting. Anyone can send bytes to a UDP port, so a forged frame is not
    /// an application-level error; surfacing it as one would hand an off-path
    /// attacker a denial of service.
    pub fn recv(&self, out: &mut [u8]) -> Result<usize> {
        // Anything queued while flushing is delivered before going back to the
        // socket, so ordering between the two paths stays sane.
        let queued = self.core()?.inbox.pop_front();
        if let Some(message) = queued {
            let mut reader = self.reader.lock().map_err(|_| Error::Closed)?;
            return deliver(&message, false, &mut reader.scratch, out);
        }

        let deadline = self.core()?.read_timeout.map(|t| Instant::now() + t);
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

    /// Waits until every reliable message has been acknowledged.
    ///
    /// Fails with [`Error::Unacknowledged`] if any message was abandoned after
    /// exhausting its retries, or if the timeout expires first.
    pub fn flush(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        self.core()?.peer.abandoned.clear();

        loop {
            // Queued fragments are part of what "unflushed" means, so this has
            // to keep feeding them or a large message would never finish.
            self.drive_queue()?;
            {
                let core = self.core()?;
                if core.peer.retransmit.in_flight() == 0 && core.peer.queued() == 0 {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(Error::Unacknowledged {
                        count: core.peer.retransmit.in_flight() + core.peer.abandoned.len(),
                    });
                }
            }
            self.pump(Some(deadline), None)?;
        }

        let abandoned = self.core()?.peer.abandoned.len();
        if abandoned > 0 {
            return Err(Error::Unacknowledged { count: abandoned });
        }
        Ok(())
    }

    /// Reads one datagram and applies it, driving retransmission on the way.
    ///
    /// The blocking read holds only the reader lock, so a send on another
    /// thread proceeds while this is waiting.
    fn pump(&self, deadline: Option<Instant>, out: Option<&mut [u8]>) -> Result<Option<usize>> {
        // Wake for whichever comes first: the caller's timeout or the next
        // retransmission deadline. Sleeping past the latter would leave a lost
        // message unnoticed until some unrelated frame arrived.
        self.drive_queue()?;
        let wait = {
            let mut core = self.core()?;
            core.drive_retransmits()?;
            let now = core.now_ms();
            let until_retransmit = core
                .peer
                .retransmit
                .next_deadline_ms()
                .map(|at| Duration::from_millis(at.saturating_sub(now)));
            let until_deadline = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            match (until_retransmit, until_deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            }
        };

        let mut reader = self.reader.lock().map_err(|_| Error::Closed)?;
        let Reader {
            transport,
            rx,
            scratch,
        } = &mut *reader;

        // A zero timeout means "block forever" to the socket layer, which is
        // the opposite of what is meant here.
        transport.set_read_timeout(wait.map(|w| w.max(Duration::from_millis(1))))?;
        let n = match transport.recv(rx) {
            Ok(n) => n,
            // Whose deadline expired, and what that means, is the caller's
            // business: `recv` reports a timeout, `flush` reports the messages
            // still outstanding.
            Err(e) if is_timeout(&e) => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        };

        let mut core = self.core()?;
        let now = core.now_ms();
        let mut ack_len = 0;
        let Core {
            peer,
            transport: sender,
            tx,
            inbox,
            ..
        } = &mut *core;
        let ingested = peer.ingest(&mut rx[..n], now, tx, &mut ack_len)?;
        if ack_len > 0 {
            sender.send(&tx[..ack_len])?;
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
                    inbox.push_back(data);
                    return Ok(None);
                }
            },
        };

        let body = HEADER_LEN..HEADER_LEN + len;
        match out {
            Some(out) => deliver(&rx[body], compressed, scratch, out).map(Some),
            None => {
                let mut staging = vec![0u8; decoded_capacity(&rx[body.clone()], compressed)];
                deliver(&rx[body], compressed, scratch, &mut staging).map(|written| {
                    staging.truncate(written);
                    inbox.push_back(staging);
                    None
                })
            }
        }
    }
}


impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = f.debug_struct("Connection");
        match self.core.lock() {
            Ok(core) => out
                .field("peer", &core.transport.peer_addr().ok())
                .field("session_id", &core.peer.session.session_id()),
            Err(_) => out.field("state", &"poisoned"),
        }
        .finish_non_exhaustive()
    }
}

