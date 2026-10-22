//! A node that talks to many peers over one socket, in either direction.
//!
//! ## Why an event loop rather than a connection per thread
//!
//! The obvious design hands back an owned [`Connection`](crate::Connection)
//! per accepted peer, each holding a clone of the listening socket. That
//! serves exactly one peer: with two, each connection reads datagrams meant
//! for the other and discards them, so traffic vanishes silently. Scaling it
//! instead by giving every peer a thread and a socket would cost a stack and a
//! kernel object apiece, for a protocol whose whole argument is efficiency.
//!
//! The frame header already carries a `session_id` for exactly this.
//! [`Endpoint`] owns the socket, routes each datagram to the right session, and
//! returns what happened as an [`Event`]. One thread, no locks, no per-peer
//! socket.
//!
//! ## Both directions, one socket
//!
//! An endpoint both accepts connections and starts them, on the same port.
//! That is what makes it a peer rather than a server: "initiator" and
//! "responder" are roles a connection has, not properties a node has, and once
//! the handshake is done the session is symmetric either way.
//!
//! Sharing the port matters beyond tidiness. A NAT maps a *local port* to the
//! outside world, so a node that dials out from one port and listens on
//! another cannot be reached on the mapping its own outbound traffic created.
//! One socket is the precondition for hole punching.
//!
//! [`connect`](Endpoint::connect) does not block. It sends the opening frame
//! and returns a [`PeerId`]; the handshake finishes when the reply arrives, at
//! which point [`poll`](Endpoint::poll) yields
//! [`Event::Connected`] with `initiated: true`. A reply that never comes
//! becomes [`Event::ConnectFailed`] after a few retries.
//!
//! ```no_run
//! use std::time::Duration;
//! use fectp::{Endpoint, Event, Identity, PayloadType};
//!
//! # fn main() -> fectp::Result<()> {
//! let mut server = Endpoint::bind("0.0.0.0:4433", Identity::generate())?;
//! loop {
//!     match server.poll(Some(Duration::from_millis(100)))? {
//!         Event::Connected { peer, .. } => println!("{peer:?} arrived"),
//!         Event::Message { peer, data } => server.send(peer, &data, PayloadType::Opaque)?,
//!         _ => {}
//!     }
//! }
//! # }
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use fectp_core::frame::{FrameType, Header, HEADER_LEN};
use fectp_core::reliability::{Rto, MAX_RTO_MS};
use fectp_core::session::{
    preshared_key, Initiator, Responder, ResumeInitiator, ResumeResponder, ResumptionTicket,
    Session, INITIATOR_OVERHEAD, PATH_TOKEN_LEN, RESPONDER_OVERHEAD,
};
use fectp_core::PublicKey;
use rand_core::{OsRng, RngCore};

use crate::pipeline::{decoded_capacity, deliver, Ingested, Peer, Pending, TicketStore};
use crate::pmtu::Pmtu;
use crate::rendezvous::{
    self, Ask, ClientState, Control, Group, GroupTag, Link, Stage, Unavailable,
};
use crate::udp::{DatagramSocket, BASE_DATAGRAM};
use crate::{
    is_stale_unreachable, is_timeout, local_capabilities, max_datagram, Error, Identity,
    PayloadType, Result, SharedKey, MAX_RETRIES,
};

/// A stable handle to one connected peer.
///
/// Handles are never reused, so one belonging to a peer that has gone away
/// stops resolving rather than silently addressing somebody else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub(crate) u64);

/// Something that happened while polling.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// A handshake completed, in either direction.
    Connected {
        /// Handle for addressing this peer.
        peer: PeerId,
        /// The payload the peer's handshake message carried: 0-RTT data for a
        /// connection we accepted, the reply for one we started.
        zero_rtt: Vec<u8>,
        /// Whether the handshake resumed rather than running in full.
        resumed: bool,
        /// Whether this endpoint started the connection.
        initiated: bool,
    },
    /// Application data arrived from a peer.
    Message {
        /// Which peer sent it.
        peer: PeerId,
        /// The payload.
        data: Vec<u8>,
    },
    /// A connection this endpoint started was never answered.
    ///
    /// The peer is unreachable, is running a different mode, or does not hold
    /// the key this endpoint offered. The handle is now dead.
    ConnectFailed {
        /// The handle [`Endpoint::connect`] returned.
        peer: PeerId,
    },
    /// A reliable message reached a verdict.
    ///
    /// For a message that had to be split across frames, this arrives either
    /// way: once every fragment has been acknowledged, or once one has been
    /// abandoned — a fragmented message missing a piece is not partially
    /// delivered, it is not delivered. It arrives **once** per message, not
    /// once per fragment.
    ///
    /// For a message that fitted in one frame, it arrives only when the sender
    /// gave up on it, with `delivered` false. Success is not reported: this
    /// queue is unbounded, and an event for every reliable send would let a
    /// fast sender grow it without limit, while failures are bounded by what
    /// can be outstanding at once. So for a single message, no event is the
    /// good news. The specification requires only that the failure is never
    /// silent (`SPEC.md` §5.5), and this is the cheaper way to satisfy it —
    /// the reasoning is in D63.
    ///
    /// **Not raised for a message still queued when its peer goes away.**
    /// [`Event::PeerLost`] and [`Endpoint::disconnect`] end the session and
    /// everything queued on it at once; that is the report, and a `Sent` for
    /// each abandoned message would only repeat it. A caller keeping a table
    /// of messages in flight should clear the peer's entries on those two.
    Sent {
        /// Which peer it was going to.
        peer: PeerId,
        /// Whether the peer acknowledged all of it.
        delivered: bool,
    },
    /// A peer proved it had moved, and the session followed it.
    ///
    /// Raised only after the new address answered a challenge, so it is a
    /// report of something established rather than of something claimed.
    PeerMoved {
        /// The peer, whose handle is unchanged — it is the same session.
        peer: PeerId,
        /// Where it used to be.
        from: SocketAddr,
        /// Where it is now.
        to: SocketAddr,
    },
    /// Nothing authenticated arrived from a peer for the configured timeout,
    /// and its session has been released.
    ///
    /// This says the endpoint gave up, not that the peer is provably gone.
    /// Silence only becomes evidence when there was something to answer, so
    /// this means what you want it to mean with
    /// [`set_keepalive`](Endpoint::set_keepalive) on and much less without it.
    /// The handle is dead either way; the peer must connect again. Anything
    /// still queued for it is discarded without a separate [`Event::Sent`].
    PeerLost {
        /// The handle, which no longer resolves.
        peer: PeerId,
    },
    /// A member of a group joined with [`Endpoint::join_group`] has been
    /// found: its key is certified by the group's secret, so a rendezvous
    /// could not have made it up. Raised once per key per group, as it is
    /// first seen. Asking to be introduced is the next step, and the member,
    /// having found this endpoint the same way, will be asking too.
    PeerDiscovered {
        /// The member's static key.
        peer_public: PublicKey,
        /// The group it was found in.
        group: GroupTag,
    },
    /// An introduction asked for with [`Endpoint::introduce`] did not end in
    /// a session.
    IntroductionFailed {
        /// The key that was asked for.
        peer_public: PublicKey,
        /// Why.
        reason: crate::rendezvous::Unavailable,
    },
    /// Nothing arrived before the timeout elapsed.
    Idle,
}

/// How long to wait for a reply before resending the opening frame, on a path
/// nothing has been measured about.
///
/// Only the cold schedule. Once a handshake to an address has completed
/// without needing a resend, the interval comes from what that exchange
/// measured instead; see [`Endpoint::handshake_delay`].
const HANDSHAKE_RETRY_MS: u64 = 250;

/// Addresses whose round trip is remembered between handshakes.
///
/// The estimate is per address and never shared between them: what loopback
/// measures says nothing about a satellite link, and an endpoint that pooled
/// the two would give up on the slow peer at the fast peer's pace. Bounded
/// because the addresses come from whoever the caller connects to.
const MAX_MEASURED_PATHS: usize = 64;

/// How many opening frames must be sent before a connect attempt is given up.
///
/// A floor on attempts rather than a ceiling, and the time the cold schedule
/// would have taken is a second floor: an endpoint gives up only once it has
/// spent both. Cold that is exactly what it always was — four attempts at 250,
/// 500, 750 and 1000 ms, reported after a measured 2.55 s. On a path it has
/// measured the intervals are far shorter, so more attempts fit in the same
/// 2.5 s; what cannot happen is giving up sooner than before the estimate
/// existed (D71).
///
/// [`HANDSHAKE_TIMEOUT`](crate::HANDSHAKE_TIMEOUT) is `Connection`'s
/// equivalent and is a clock, because there the call blocks and something has
/// to end it. Replaced per endpoint by
/// [`set_handshake_attempts`](Endpoint::set_handshake_attempts).
pub const HANDSHAKE_ATTEMPTS: u8 = 4;

/// The most sessions one endpoint will hold at once, unless told otherwise.
///
/// Reaching the handshake needs nothing but this endpoint's public key, which
/// is public by design, so anyone can complete one and be filed. Measured, a
/// single-threaded attacker on loopback files 34 a second and never sends a
/// byte — and that is a floor, since it politely waits for each reply.
///
/// Without a bound that is unbounded memory, and on the microcontroller this
/// protocol is for, 358 bytes of session state each fills 32 KiB in under three
/// seconds. The bound is generous for a real server and still finite.
///
/// [`Endpoint::set_max_peers`] overrides it. A microcontroller wants far fewer
/// than this and a large server may want more, and neither is served by one
/// number compiled in.
pub const MAX_PEERS: usize = 1024;

/// How many times one session's handshake response may be sent again.
///
/// A client resends its opening frame a handful of times at most, inside
/// [`HANDSHAKE_TIMEOUT`](crate::HANDSHAKE_TIMEOUT); anything past that is not
/// an honest client waiting.
const HANDSHAKE_REPLIES: u8 = 8;

/// New handshakes answered per second before the rest are dropped unanswered.
///
/// [`MAX_PEERS`] bounds the memory but not the work: answering costs four
/// X25519 operations, and evicting to make room would leave an attacker able
/// to buy that for the price of a datagram, indefinitely. This bounds the work
/// as well.
///
/// It is a ceiling on *new* sessions, not on traffic — established peers are
/// routed without passing through here, so a flood slows connection setup and
/// leaves everything already connected alone.
///
/// The number comes from what a handshake costs rather than from taste. A full
/// one is a 0.66 ms round trip in release (BENCHMARKS.md §1), of which the
/// responder's share is roughly half, so a core manages a few thousand a
/// second; this spends well under a fifth of one on strangers. It was 64 to
/// begin with, which was a guess, and a bad one — it would have throttled a
/// fleet of devices that wake, report and sleep, which is the traffic this
/// protocol is written for, long before it inconvenienced anybody hostile.
///
/// Resumption and pre-shared-key handshakes are a quarter of the work and are
/// charged the same, so the ceiling is more conservative for them than for the
/// case it was sized against.
///
/// [`Endpoint::set_max_handshakes_per_second`] overrides it.
pub const MAX_HANDSHAKES_PER_SECOND: u32 = 512;

/// Attempts a second, **per session**, to open a frame that arrived from an
/// address that session is not filed under.
///
/// This is what following a moved peer costs: the address is unknown, so the
/// identifier in the clear is all there is to go on, and the frame has to be
/// tried against the session it names. Anyone who can address the socket can
/// ask for that.
///
/// **Per session, not per endpoint, and the difference is the whole point.** A
/// budget shared by every peer is one any single peer can empty: it needs one
/// session of its own and frames naming that session's identifier from a
/// second port, after which nobody else can migrate at all. With
/// `set_peer_timeout` on — the pairing a peer timeout is meant to have — a
/// migration that cannot complete becomes a lost session. Spending each
/// session's own budget confines the damage to whoever is causing it.
///
/// The total is still bounded: [`MAX_PEERS`] sessions at this rate, each
/// attempt costing an AEAD verification and up to four key derivations before
/// it, is a few percent of one core.
///
/// Eight a second is far above what a real migration needs — a peer that has
/// moved sends a handful of frames, and one of them succeeding is enough.
pub const MAX_MIGRATION_ATTEMPTS_PER_PEER: u32 = 8;

/// The shortest keep-alive interval that will be honoured.
///
/// A NAT mapping lives tens of seconds at worst, so ten datagrams a second
/// cannot be serving one — anything faster is arithmetic that produced a
/// number nobody meant. Taken literally, a zero interval sends one datagram
/// per pass of the loop: measured, 1,123 in 200 ms at a single peer, from the
/// endpoint's own socket at its own peers.
///
/// `set_max_peers` has refused to take zero literally since it was written;
/// this is the same rule.
pub const MIN_KEEPALIVE: Duration = Duration::from_millis(100);

/// The shortest peer timeout that will be honoured.
///
/// Below about a second there is nothing to distinguish a peer that has gone
/// from one that is slow: a single retransmission cycle takes longer than
/// that. Taken literally, a zero timeout makes every session overdue the
/// instant it is filed, and the endpoint releases each peer as it arrives —
/// which looks like a network fault rather than a configuration one.
pub const MIN_PEER_TIMEOUT: Duration = Duration::from_secs(1);

/// Sessions tried against one frame from an unknown address.
///
/// The identifier is chosen by whoever opens the session, so one peer can put
/// the same value on all of its own — and the index the migration lookup uses
/// is keyed on the identifier alone. Without a cap, one datagram is worth an
/// authentication attempt for every session wearing the identifier it names.
/// Measured, with 400 sharing one: an established peer's median round trip
/// went from 39 µs to 78 ms.
///
/// Two sessions sharing an identifier by accident is already a one-in-ten-
/// thousand event across a full table of randomly chosen 32-bit values; three
/// is far rarer than that. Four is generous for every honest case and refuses
/// to pay for a crowd.
///
/// The residue: a session whose identifier is already worn by four others
/// cannot be found by this lookup, so it cannot migrate. Reaching that needs
/// the crowd to have been filed first under the identifier the newcomer then
/// picks at random, which is about one in ten million per session.
const MAX_CANDIDATES: usize = 4;

/// Challenges sent to one unproved address before the attempt is abandoned.
///
/// A genuine peer answers the first one it receives; the repeats exist for the
/// case where a challenge or its answer is lost. Bounding them is what stops a
/// session being used to send repeatedly to an address that never asked.
const PATH_PROBES: u8 = 3;

/// How long an unanswered probe is kept before the address is forgotten.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Shortest gap between challenges to the same unproved address.
const PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// A handshake this endpoint started, waiting for its reply.
enum Handshake {
    Full(Box<Initiator<SharedKey>>),
    Psk(Box<ResumeInitiator>),
}

struct Outbound {
    handshake: Handshake,
    /// The key this handshake names, in public-key mode.
    peer_key: Option<PublicKey>,
    addr: SocketAddr,
    session_id: u32,
    /// The opening frame, kept so it can be sent again if the reply is lost.
    frame: Vec<u8>,
    next_attempt: Instant,
    attempts: u8,
    /// When the first attempt left, for the round-trip measurement and for the
    /// budget that decides when to stop.
    first_sent: Instant,
    /// When the latest attempt left, which bounds the round trip from below
    /// when a resent handshake is answered.
    last_sent: Instant,
}

/// What an endpoint has learned about reaching one address.
#[derive(Clone, Copy)]
struct Path {
    /// The estimate, once a handshake has completed without a resend.
    rto: Option<Rto>,
    /// A floor on the first wait, left by a handshake that had to resend.
    ///
    /// Karn's rule keeps a resent handshake out of the estimate, and on a path
    /// slower than the cold schedule every handshake resends — so on its own
    /// the rule means that path is never measured. Karn's answer is the other
    /// half of his algorithm: keep the backed-off timer until a clean sample
    /// arrives. This is that timer. It is set from the one thing a resent
    /// reply does say unambiguously, that the round trip was no longer than
    /// the time since the first attempt, and doubled so the next first attempt
    /// has room to be answered. The clean sample that follows clears it.
    floor: Option<Duration>,
}

/// How a server authenticates the peers that connect to it.
///
/// A server speaks exactly one of these. It is not a negotiation and there is
/// no wire field for it: a peer using a different mode sends frame types this
/// server does not accept, and is ignored. A server that accepted several
/// modes at once would let an attacker pick the weakest.
enum Mode {
    /// Public-key: peers must know this server's public key.
    ///
    /// A [`SharedKey`] rather than an [`Identity`] so the key may live in a
    /// secure element. An `Identity` converts into one, which is what
    /// [`Endpoint::bind`] does, and costs an `Arc` per endpoint rather than
    /// per handshake.
    PublicKey(SharedKey),
    /// Pre-shared key: peers must hold the same secret. Encrypted, but with
    /// nothing to distribute except that secret.
    Psk(ResumptionTicket),
}

/// Serves many FECTP peers from one UDP socket.
pub struct Endpoint {
    socket: Box<dyn DatagramSocket>,
    mode: Mode,
    tickets: TicketStore,

    peers: HashMap<PeerId, PeerEntry>,
    /// Sessions are addressed by socket address *and* session identifier. The
    /// identifier alone is chosen by the client and could collide between two
    /// of them; the pair cannot.
    routes: HashMap<(SocketAddr, u32), PeerId>,
    /// The same sessions filed by identifier alone.
    ///
    /// Only consulted when a frame arrives from an address with no session on
    /// it, which is the one case where the identifier has to stand on its own.
    /// It can collide — the client chooses it — so this maps to every session
    /// wearing it and authentication decides which, if any, is the right one.
    /// A collision costs one extra AEAD verification, not a wrong delivery.
    by_session: HashMap<u32, Vec<PeerId>>,
    /// Handshakes started here and still awaiting a reply.
    outbound: HashMap<PeerId, Outbound>,
    /// Completions produced outside `poll`, delivered by the next one.
    ///
    /// Queued rather than returned so that a completion raised while queuing a
    /// message, or two completing in the same pass, cannot be dropped.
    events: VecDeque<Event>,
    /// Budget for answering new handshakes, refilled over time.
    handshake_budget: f32,
    handshake_refilled: Instant,
    handshake_rate: u32,
    /// The per-session ceiling on attempts from unknown addresses.
    migration_rate: u32,
    /// When the earliest time-driven work falls due, or `None` when none is
    /// pending.
    ///
    /// Retransmissions, keep-alives, peer timeouts and unanswered handshakes
    /// all happen at a moment, not because a datagram arrived. They used to be
    /// driven on every pass of the poll loop, and that loop goes round once per
    /// datagram — so each arriving datagram cost a walk of the whole peer table,
    /// including datagrams rejected at the version check, which anybody can
    /// send. Measured at 64 sessions, a burst of 4,000 such datagrams took a
    /// round trip from 280 µs to 153 ms.
    ///
    /// Kept as a single instant rather than a queue: the table is bounded at
    /// [`MAX_PEERS`], and the recompute runs only when something is actually
    /// due, which is a few times a second at most.
    next_wake: Option<Instant>,
    /// Peers with a split message still being fed out.
    ///
    /// The queue pass is the one drive that is not purely time-driven — an
    /// acknowledgement frees window space — so it cannot be gated behind
    /// `next_wake`. This lets it be skipped in O(1) instead, which is what
    /// happens whenever nobody is sending a message too large for one frame.
    queueing: usize,
    max_peers: usize,
    /// Sent in the payload of every handshake response.
    handshake_reply: Vec<u8>,
    /// How long a peer may go without being sent anything, or `None` to say
    /// nothing when there is nothing to say.
    keepalive: Option<Duration>,
    /// Opening frames sent before a connect attempt is given up on.
    handshake_attempts: u8,
    /// What a completed handshake measured, per address.
    ///
    /// A `Vec` rather than a map: it holds [`MAX_MEASURED_PATHS`] at most and
    /// is walked once per handshake, so the scan is cheaper than the hashing
    /// would be, and the order is what makes the eviction obvious.
    paths: Vec<(SocketAddr, Path)>,
    /// Attempts before a reliable message is abandoned, applied to every peer.
    max_retries: u8,
    /// How long a peer may go unheard from before its session is released.
    peer_timeout: Option<Duration>,
    next_id: u64,

    rx: Vec<u8>,
    tx: Vec<u8>,
    ack: Vec<u8>,
    scratch: Vec<u8>,
    epoch: Instant,
    /// This endpoint as a client of a rendezvous, if it is one.
    rv: ClientState,
}

/// Sends one datagram, treating "nobody is listening there" as ordinary.
///
/// See [`is_stale_unreachable`]. Everything an endpoint sends goes through
/// here, because every one of those sends can be the one that draws the
/// report, and only the peer it was aimed at is affected.
fn send_datagram(socket: &dyn DatagramSocket, buf: &[u8], addr: SocketAddr) -> Result<()> {
    match socket.send_to(buf, addr) {
        Ok(_) => Ok(()),
        Err(e) if is_stale_unreachable(&e) => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

/// An address under test, and what has been spent testing it.
struct Probe {
    addr: SocketAddr,
    token: [u8; PATH_TOKEN_LEN],
    /// Challenges sent so far.
    sent: u8,
    /// When the last one went out.
    last: Instant,
    /// When the address was first heard from, which bounds the whole attempt.
    started: Instant,
}

struct PeerEntry {
    peer: Peer,
    addr: SocketAddr,
    session_id: u32,
    datagram_limit: usize,
    /// When this session was established, which orders eviction.
    filed: Instant,
    /// The response sent for this session's handshake, and how many more times
    /// it may be sent again.
    ///
    /// Kept so that seeing message 1 again resends the same bytes instead of
    /// performing the handshake a second time. Dropped once the peer speaks,
    /// which proves it received the response and will not ask again.
    ///
    /// The count bounds it as a reflector: resending is cheap enough that an
    /// attacker could otherwise get one datagram sent for each one it sends,
    /// to an address it does not control. A client retransmits its opening
    /// frame at most a handful of times inside the handshake timeout, so a
    /// small allowance covers every honest case.
    handshake_reply: Option<(Vec<u8>, u8)>,
    /// Budget for trying this session against frames from addresses it is not
    /// filed under, refilled over time. See [`MAX_MIGRATION_ATTEMPTS_PER_PEER`].
    migration_budget: f32,
    migration_refilled: Instant,
    /// When something that authenticated was last received from this peer.
    ///
    /// Only authenticated frames move it. Anyone can address a UDP socket, and
    /// a session that a stranger could hold open by sending noise at it would
    /// have a timeout in name only — the same rule as `spoke`, for the same
    /// reason ([D48]).
    ///
    /// [D48]: https://github.com/YounghyeonPark/fectp/blob/main/docs/DECISIONS.md
    last_heard: Instant,
    /// When something was last sent to this peer.
    ///
    /// Only outbound traffic refreshes a NAT mapping, so this — not when the
    /// peer was last heard from — is what a keep-alive is measured against.
    last_sent: Instant,
    /// An address this peer has been heard from but has not proved it can
    /// receive at.
    ///
    /// Authentication says the frame came from someone holding the key. It
    /// does not say where that someone is: an on-path attacker can forward a
    /// genuine frame with a source address of its choosing, and a session that
    /// followed it would be pointing its data stream at whoever was named.
    /// Nothing is sent here but the challenge until the answer comes back.
    probe: Option<Probe>,
    /// What this session has learned about its path's frame size, when it is
    /// looking. `datagram_limit` follows it.
    ///
    /// None when discovery is off or the peer does not answer probes; the
    /// limit is then the ceiling, as it always was.
    pmtu: Option<Pmtu>,
    /// Whether anything has ever arrived from this peer since.
    ///
    /// This is what separates a flood from a quiet peer. Completing a
    /// handshake costs an attacker nothing and proves nothing; sending an
    /// authenticated frame afterwards is the first thing that does. A session
    /// that has never done it is the one to drop when room is needed.
    spoke: bool,
}

impl Endpoint {
    /// Binds to `addr` and serves the given identity, in public-key mode.
    ///
    /// Peers must know [`public_key`](Self::public_key) in advance.
    pub fn bind(addr: impl ToSocketAddrs, identity: Identity) -> Result<Self> {
        Self::with_mode(addr, Mode::PublicKey(identity.into()))
    }

    /// Binds an endpoint whose long-term key lives outside this process.
    ///
    /// For a secure element or an HSM: the device performs the Diffie-Hellman
    /// and never releases the key, which is the whole reason to have one.
    /// [`bind`](Self::bind) is the same thing with the key in memory, and is
    /// what almost every caller wants.
    ///
    /// The `Arc` is shared rather than taken. A device belongs to the
    /// application and gets asked things an endpoint knows nothing about, so
    /// keep your handle: this only borrows it.
    ///
    /// Its public half is read once here. Everything else about the endpoint
    /// is unchanged, including that a peer cannot tell the difference — which
    /// is the point.
    pub fn bind_with_key(addr: impl ToSocketAddrs, key: impl Into<SharedKey>) -> Result<Self> {
        Self::with_mode(addr, Mode::PublicKey(key.into()))
    }

    /// Binds in pre-shared-key mode.
    ///
    /// Traffic is encrypted exactly as in public-key mode; what changes is what
    /// must be distributed beforehand — one secret, shared by both sides,
    /// rather than this server's public key. The handshake costs one
    /// Diffie-Hellman instead of four, and still exchanges fresh ephemerals, so
    /// forward secrecy holds.
    ///
    /// The secret is symmetric, so every peer holding it can impersonate any
    /// other. Right for one closed system; wrong across organisations.
    pub fn bind_psk(addr: impl ToSocketAddrs, secret: &[u8]) -> Result<Self> {
        Self::with_mode(addr, Mode::Psk(preshared_key(secret)))
    }

    /// Serves the given identity over a socket of the caller's making.
    ///
    /// [`bind`](Self::bind) is this with a UDP socket bound to an address,
    /// which is what almost every caller wants. The trait says what a socket
    /// has to do; see [`DatagramSocket`].
    pub fn bind_socket(socket: impl DatagramSocket + 'static, identity: Identity) -> Result<Self> {
        Self::on_socket(Box::new(socket), Mode::PublicKey(identity.into()))
    }

    fn with_mode(addr: impl ToSocketAddrs, mode: Mode) -> Result<Self> {
        let socket = crate::udp::Prepared::new(UdpSocket::bind(addr)?)?;
        Self::on_socket(Box::new(socket), mode)
    }

    fn on_socket(socket: Box<dyn DatagramSocket>, mode: Mode) -> Result<Self> {
        let size = max_datagram() + INITIATOR_OVERHEAD;
        Ok(Self {
            socket,
            mode,
            tickets: TicketStore::default(),
            peers: HashMap::new(),
            routes: HashMap::new(),
            by_session: HashMap::new(),
            events: VecDeque::new(),
            handshake_attempts: HANDSHAKE_ATTEMPTS,
            paths: Vec::new(),
            max_retries: MAX_RETRIES,
            handshake_budget: MAX_HANDSHAKES_PER_SECOND as f32,
            handshake_refilled: Instant::now(),
            handshake_rate: MAX_HANDSHAKES_PER_SECOND,
            migration_rate: MAX_MIGRATION_ATTEMPTS_PER_PEER,
            next_wake: None,
            queueing: 0,
            max_peers: MAX_PEERS,
            handshake_reply: Vec::new(),
            keepalive: None,
            peer_timeout: None,
            outbound: HashMap::new(),
            next_id: 0,
            rx: vec![0u8; size],
            tx: vec![0u8; size],
            ack: vec![0u8; size],
            scratch: vec![0u8; size],
            epoch: Instant::now(),
            rv: ClientState::default(),
        })
    }

    // ---- rendezvous, as a client (SPEC Appendix A) -------------------------

    /// Connects to a [`Rendezvous`](crate::Rendezvous) and registers with it,
    /// so that other clients of it can ask to be introduced to this one.
    ///
    /// Registration is sent once the handshake completes, which arrives as
    /// [`Event::Connected`] for the handle returned here, as any connection's
    /// does, and is done once the rendezvous answers with where it sees this
    /// endpoint ([`observed_addr`](Self::observed_addr)). Messages on that
    /// session are the rendezvous's own and are not raised as
    /// [`Event::Message`]. One rendezvous at a time; connecting to another
    /// replaces it, and the old one's session stays open as an ordinary
    /// peer's until it is disconnected. Fails with
    /// [`Error::MissingPeerKey`] on a pre-shared-key endpoint, which has no
    /// static key for a rendezvous to know it by.
    pub fn connect_rendezvous(
        &mut self,
        addr: impl ToSocketAddrs,
        rendezvous_public: &PublicKey,
    ) -> Result<PeerId> {
        if !matches!(self.mode, Mode::PublicKey(_)) {
            // A rendezvous knows its clients by their static keys, which a
            // pre-shared-key session does not have.
            return Err(Error::MissingPeerKey);
        }
        let peer = self.connect(addr, Some(rendezvous_public))?;
        self.rv.rendezvous = Some(peer);
        self.rv.registered = false;
        self.rv.observed = None;
        Ok(peer)
    }

    /// Asks the rendezvous to introduce this endpoint to the holder of `key`.
    ///
    /// Nothing happens until that holder asks for this endpoint too, within
    /// the rendezvous's window, even if it has not registered yet: an
    /// introduction tells each side where the other is and has each send to
    /// the other, so it takes both to agree (SPEC A.3). Then the two punch
    /// holes in their NATs and connect directly, or through the rendezvous
    /// if their NATs will not allow that. Success is the ordinary
    /// [`Event::Connected`], for a peer whose
    /// [`peer_public_key`](Self::peer_public_key) is `key`; failure is
    /// [`Event::IntroductionFailed`]. With a session to `key` already open,
    /// nothing is asked: that session is the answer.
    ///
    /// Fails with [`Error::NoRendezvous`] with no rendezvous connected — none
    /// asked for, or the one asked for never answered or has been lost — and
    /// with [`Error::Protocol`] wrapping `WindowFull` with
    /// [`MAX_INTRODUCTIONS`](crate::rendezvous::MAX_INTRODUCTIONS) already
    /// outstanding.
    pub fn introduce(&mut self, key: &PublicKey) -> Result<()> {
        if self.rv.rendezvous.is_none() {
            return Err(Error::NoRendezvous);
        }
        if self.has_session_with(key) {
            return Ok(());
        }
        if !self.rv.asks.contains_key(key) && self.rv.asks.len() >= rendezvous::MAX_INTRODUCTIONS {
            return Err(Error::Protocol(fectp_core::Error::WindowFull));
        }
        self.rv.asks.insert(
            *key,
            Ask {
                since: Instant::now(),
                stage: Stage::Asked,
            },
        );
        if self.rv.registered {
            self.tell_rendezvous(&Control::Introduce(*key));
        }
        self.wake_at(Instant::now());
        Ok(())
    }

    /// Where the rendezvous sees this endpoint: its address outside its NAT,
    /// as of registering. `None` until registration is done.
    pub fn observed_addr(&self) -> Option<SocketAddr> {
        self.rv.observed
    }

    /// Whether a session runs through a rendezvous's relay rather than
    /// directly.
    ///
    /// A relay releases a session that has carried nothing for
    /// [`RELAY_IDLE`](crate::rendezvous::RELAY_IDLE), a minute, so one that
    /// may fall quiet wants [`set_keepalive`](Self::set_keepalive) at less
    /// than that.
    pub fn is_relayed(&self, peer: PeerId) -> bool {
        self.rv.relayed.contains_key(&peer)
    }

    /// Joins the group whose secret is `secret`, at the rendezvous, so its
    /// other members are found and raised as [`Event::PeerDiscovered`].
    ///
    /// The rendezvous files the group under a tag derived from the secret and
    /// never sees the secret. Each member files its key with a certificate
    /// keyed by the secret, and a member checks every certificate it is sent,
    /// so a rendezvous cannot add a key of its own to a group (SPEC A.7). It
    /// does learn which keys share a group.
    ///
    /// **The secret must be random**, sixteen bytes or more from a CSPRNG:
    /// the rendezvous sees the tag and can try guesses against it, and a
    /// secret it guesses is one it can forge members with. Anyone holding the
    /// secret is a member, and there is no removing one but changing it.
    ///
    /// Fails with [`Error::GroupSecretTooShort`] below
    /// [`MIN_GROUP_SECRET`](crate::rendezvous::MIN_GROUP_SECRET), with
    /// [`Error::NoRendezvous`] with none connected, and with
    /// [`Error::Protocol`] wrapping `WindowFull` in
    /// [`MAX_GROUPS`](crate::rendezvous::MAX_GROUPS) groups already.
    pub fn join_group(&mut self, secret: &[u8]) -> Result<GroupTag> {
        if secret.len() < rendezvous::MIN_GROUP_SECRET {
            return Err(Error::GroupSecretTooShort);
        }
        if self.rv.rendezvous.is_none() {
            return Err(Error::NoRendezvous);
        }
        let Some(own) = self.own_key() else {
            return Err(Error::MissingPeerKey);
        };
        let tag = rendezvous::group_tag(secret);
        if !self.rv.groups.contains_key(&tag) && self.rv.groups.len() >= rendezvous::MAX_GROUPS {
            return Err(Error::Protocol(fectp_core::Error::WindowFull));
        }
        let key = rendezvous::group_key(secret);
        let mac = rendezvous::member_mac(&key, &own);
        self.rv.groups.insert(
            tag,
            Group {
                key,
                mac,
                members: HashSet::new(),
            },
        );
        if self.rv.registered {
            self.tell_rendezvous(&Control::Join(tag, mac));
        }
        Ok(tag)
    }

    /// Leaves a group. Returns whether this endpoint was in it.
    pub fn leave_group(&mut self, group: &GroupTag) -> bool {
        let was = self.rv.groups.remove(group).is_some();
        if was {
            self.tell_rendezvous(&Control::Leave(*group));
        }
        was
    }

    /// The members of a group found so far, this endpoint not among them.
    pub fn group_members(&self, group: &GroupTag) -> Vec<PublicKey> {
        self.rv
            .groups
            .get(group)
            .map(|g| g.members.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Whether a session with `key` is open or a full handshake to it is
    /// under way.
    fn has_session_with(&self, key: &PublicKey) -> bool {
        self.peers
            .values()
            .any(|e| e.peer.session.remote_static() == key)
            || self
                .outbound
                .values()
                .any(|o| o.peer_key.as_ref() == Some(key))
    }

    /// Sends the rendezvous a message, dropping it if it cannot go: what was
    /// asked fails at its deadline instead, and the poll loop is not the
    /// rendezvous's to end.
    fn tell_rendezvous(&mut self, control: &Control) {
        if let Some(rendezvous) = self.rv.rendezvous {
            let _ = self.send_reliable(rendezvous, &control.encode(), PayloadType::Opaque);
        }
    }

    /// Our own static key, in public-key mode.
    fn own_key(&self) -> Option<PublicKey> {
        self.public_key().copied()
    }

    /// Ends an introduction as failed.
    fn fail_introduction(&mut self, key: PublicKey, reason: Unavailable) {
        if self.rv.asks.remove(&key).is_some() {
            self.events.push_back(Event::IntroductionFailed {
                peer_public: key,
                reason,
            });
        }
    }

    /// The rendezvous is gone: everything asked of it fails.
    fn lose_rendezvous(&mut self) {
        self.rv.rendezvous = None;
        self.rv.registered = false;
        self.rv.observed = None;
        // What it said about groups was its to say; another rendezvous will
        // say it again, and the members it names will be raised again.
        for group in self.rv.groups.values_mut() {
            group.members.clear();
        }
        let keys: Vec<PublicKey> = self.rv.asks.keys().copied().collect();
        for key in keys {
            self.fail_introduction(key, Unavailable::Unreachable);
        }
    }

    /// Sends what the introductions need sent now, and gives up on the ones
    /// that have run out of time.
    fn drive_introductions(&mut self) {
        let now = Instant::now();
        let expired: Vec<PublicKey> = self
            .rv
            .asks
            .iter()
            .filter(|(_, ask)| now.duration_since(ask.since) > rendezvous::INTRODUCTION_DEADLINE)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.fail_introduction(key, Unavailable::Unreachable);
        }

        let mut binds = Vec::new();
        let mut abandoned = Vec::new();
        for (key, ask) in &mut self.rv.asks {
            if let Stage::Relaying {
                port,
                token,
                checked,
                legacy,
                binds: sent,
                next_bind,
                ..
            } = &mut ask.stage
            {
                if now < *next_bind || *sent > rendezvous::BINDS {
                    continue;
                }
                if *sent == rendezvous::BINDS {
                    if !*checked && !*legacy {
                        // No hello answered: a port of version 0.3.1, which
                        // knows only the bind with the token in the clear.
                        // It cannot follow a move, and nothing is lost by
                        // telling it the token, which is all it can check.
                        *legacy = true;
                        *sent = 0;
                        *next_bind = now;
                        continue;
                    }
                    // Every bind sent. Never checked means the port is not
                    // there for us; checked, the session decides.
                    *sent += 1;
                    if !*checked {
                        abandoned.push(*key);
                    }
                    continue;
                }
                // Binds keep going after a check, up to `BINDS` of them: an
                // answer can be lost, and the next bind draws a new check.
                *sent += 1;
                *next_bind = now + rendezvous::BIND_INTERVAL;
                let bind = if *legacy {
                    let mut bind = vec![rendezvous::NOT_A_FRAME, rendezvous::BIND];
                    bind.extend_from_slice(token);
                    bind
                } else {
                    rendezvous::hello()
                };
                binds.push((bind, *port));
            }
        }
        // A relayed session proves its address again from time to time, so
        // a NAT that moves it is followed rather than ending the session.
        for link in self.rv.relayed.values_mut() {
            if !link.legacy && now >= link.next_refresh {
                link.last_hello = now;
                link.next_refresh = now + rendezvous::RELAY_REFRESH;
                binds.push((rendezvous::hello(), link.port));
            }
        }
        for key in abandoned {
            self.fail_introduction(key, Unavailable::Unreachable);
        }
        // A bind that cannot be sent is a port that is never checked, which
        // the count above already handles.
        for (bind, port) in binds {
            let _ = self.socket.send_to(&bind, port);
        }
    }

    /// When an introduction next needs attention.
    fn next_introduction_deadline(&self) -> Option<Instant> {
        let asks = self.rv.asks.values().map(|ask| match &ask.stage {
            Stage::Relaying {
                binds, next_bind, ..
            } if *binds <= rendezvous::BINDS => *next_bind,
            _ => ask.since + rendezvous::INTRODUCTION_DEADLINE,
        });
        let links = self
            .rv
            .relayed
            .values()
            .filter(|l| !l.legacy)
            .map(|l| l.next_refresh);
        asks.chain(links).min()
    }

    /// Takes the events that belong to the rendezvous machinery, acting on
    /// them; passes the rest through.
    fn intercept(&mut self, event: Event) -> Option<Event> {
        match event {
            Event::Connected { peer, .. } if Some(peer) == self.rv.rendezvous => {
                // Registration is done when the rendezvous answers it; what
                // was asked meanwhile waits for that, because reliable
                // messages are not ordered and a request that overtook the
                // registration would be dropped.
                self.tell_rendezvous(&Control::Register);
                Some(event)
            }
            Event::Connected { peer, .. } => {
                let Some(key) = self.peer_public_key(peer).copied() else {
                    return Some(event);
                };
                // A session with the key asked for answers the request,
                // however it came about. Counted only if the handshake
                // authenticated that key: the waiting side accepts any
                // opening frame (SPEC A.3).
                if let Some(ask) = self.rv.asks.remove(&key) {
                    if let Stage::Relaying {
                        port,
                        token,
                        legacy,
                        ..
                    } = ask.stage
                    {
                        if self.peer_addr(peer) == Some(port) {
                            let now = Instant::now();
                            self.rv.relayed.insert(
                                peer,
                                Link {
                                    port,
                                    token,
                                    legacy,
                                    next_refresh: now + rendezvous::RELAY_REFRESH,
                                    // As if the last hello were a floor ago:
                                    // binding was not a hello a resend asked
                                    // for, and the first resend after it must
                                    // not wait. It used to, and a move in the
                                    // first second of a session lost the
                                    // message that noticed it.
                                    last_hello: now
                                        .checked_sub(rendezvous::REFRESH_FLOOR)
                                        .unwrap_or(now),
                                },
                            );
                            self.wake_at(now + rendezvous::RELAY_REFRESH);
                        }
                    }
                }
                Some(event)
            }
            Event::Message { peer, data } if Some(peer) == self.rv.rendezvous => {
                if let Some(control) = Control::decode(&data) {
                    self.on_control(control);
                }
                None
            }
            Event::ConnectFailed { peer } if Some(peer) == self.rv.rendezvous => {
                self.lose_rendezvous();
                Some(event)
            }
            Event::ConnectFailed { peer } => {
                let owner = self.rv.asks.iter().find_map(|(key, ask)| match &ask.stage {
                    Stage::Introduced {
                        outbound: Some(id), ..
                    }
                    | Stage::Relaying {
                        outbound: Some(id), ..
                    } if *id == peer => Some(*key),
                    _ => None,
                });
                let Some(key) = owner else {
                    return Some(event);
                };
                // Not the application's handle: it asked for an
                // introduction, not for this connect.
                let first_failure = match self.rv.asks.get_mut(&key).map(|a| &mut a.stage) {
                    Some(Stage::Introduced { relay_asked, .. }) if !*relay_asked => {
                        *relay_asked = true;
                        true
                    }
                    _ => false,
                };
                if first_failure {
                    self.tell_rendezvous(&Control::Relay(key));
                } else {
                    self.fail_introduction(key, Unavailable::Unreachable);
                }
                None
            }
            Event::PeerLost { peer } => {
                self.rv.relayed.remove(&peer);
                if Some(peer) == self.rv.rendezvous {
                    self.lose_rendezvous();
                }
                Some(event)
            }
            other => Some(other),
        }
    }

    /// Acts on one message from the rendezvous.
    fn on_control(&mut self, control: Control) {
        match control {
            Control::Observed(addr) => {
                self.rv.observed = Some(addr);
                if !self.rv.registered {
                    self.rv.registered = true;
                    let waiting: Vec<PublicKey> = self
                        .rv
                        .asks
                        .iter()
                        .filter(|(_, a)| matches!(a.stage, Stage::Asked))
                        .map(|(k, _)| *k)
                        .collect();
                    for key in waiting {
                        self.tell_rendezvous(&Control::Introduce(key));
                    }
                    let joins: Vec<Control> = self
                        .rv
                        .groups
                        .iter()
                        .map(|(tag, g)| Control::Join(*tag, g.mac))
                        .collect();
                    for join in joins {
                        self.tell_rendezvous(&join);
                    }
                }
            }
            Control::Unavailable(key, reason) => {
                self.fail_introduction(key, Unavailable::from_byte(reason));
            }
            Control::Introduction(key, addr) => {
                // Only what was asked for, and not twice (SPEC A.3): a
                // rendezvous is trusted to say where a peer is, not to have
                // this endpoint send wherever it likes.
                let asked = self
                    .rv
                    .asks
                    .get(&key)
                    .is_some_and(|a| matches!(a.stage, Stage::Asked));
                if !asked || self.has_session_with(&key) {
                    return;
                }
                // A punch that cannot be sent — an address this socket cannot
                // reach — fails this introduction, not the poll loop.
                let _ = self
                    .socket
                    .send_to(&[rendezvous::NOT_A_FRAME, rendezvous::PUNCH], addr);
                let outbound = match self.own_key() {
                    Some(ours) if rendezvous::starts(&ours, &key) => {
                        match self.connect(addr, Some(&key)) {
                            Ok(id) => Some(id),
                            Err(_) => {
                                return self.fail_introduction(key, Unavailable::Unreachable);
                            }
                        }
                    }
                    _ => None,
                };
                if let Some(ask) = self.rv.asks.get_mut(&key) {
                    ask.stage = Stage::Introduced {
                        outbound,
                        relay_asked: false,
                    };
                }
            }
            Control::RelayOffer(key, port, token) => {
                let Some(ask) = self.rv.asks.get_mut(&key) else {
                    return;
                };
                // An offer again for a port already being proved is covered
                // by the binds already under way.
                if matches!(ask.stage, Stage::Introduced { .. }) {
                    ask.stage = Stage::Relaying {
                        port,
                        token,
                        checked: false,
                        legacy: false,
                        binds: 0,
                        next_bind: Instant::now(),
                        outbound: None,
                    };
                    self.wake_at(Instant::now());
                }
            }
            Control::Members(tag, list) => {
                let own = self.own_key();
                let Some(group) = self.rv.groups.get_mut(&tag) else {
                    return;
                };
                // Only certified keys: the rendezvous assembled this list, and
                // it cannot make a certificate, so a key without a good one is
                // one it added.
                let checked: HashSet<PublicKey> = list
                    .into_iter()
                    .filter(|(key, mac)| {
                        Some(*key) != own
                            && rendezvous::same(mac, &rendezvous::member_mac(&group.key, key))
                    })
                    .map(|(key, _)| key)
                    .collect();
                let mut found: Vec<PublicKey> =
                    checked.difference(&group.members).copied().collect();
                found.sort_unstable();
                group.members = checked;
                for peer_public in found {
                    self.events.push_back(Event::PeerDiscovered {
                        peer_public,
                        group: tag,
                    });
                }
            }
            // Not ours to receive.
            Control::Register
            | Control::Introduce(_)
            | Control::Relay(_)
            | Control::Join(..)
            | Control::Leave(_) => {}
        }
    }

    /// A datagram that is not a frame (SPEC A.5). The only one a client
    /// answers is a check from a relay port it was offered, for as long as
    /// the session through it is not up: a proof can be lost, and the port
    /// checks again on the next bind.
    fn not_a_frame(&mut self, n: usize, from: SocketAddr) {
        let datagram = &self.rx[..n];
        let [rendezvous::NOT_A_FRAME, rendezvous::CHECK, nonce @ ..] = datagram else {
            return;
        };
        if nonce.len() != rendezvous::SECRET_LEN {
            return;
        }
        // A relayed session's port, checking an address this side proved
        // again: answered, and that is all.
        if let Some(link) = self.rv.relayed.values().find(|l| l.port == from) {
            let answer = rendezvous::answer(&link.token, nonce, link.legacy);
            let _ = self.socket.send_to(&answer, from);
            return;
        }
        let ours = self.own_key();
        let owner = self.rv.asks.iter().find_map(|(key, ask)| match &ask.stage {
            Stage::Relaying {
                port,
                token,
                legacy,
                ..
            } if *port == from => Some((*key, rendezvous::answer(token, nonce, *legacy))),
            _ => None,
        });
        let Some((key, answer)) = owner else {
            return;
        };
        let _ = self.socket.send_to(&answer, from);
        let first = matches!(
            self.rv.asks.get(&key).map(|a| &a.stage),
            Some(Stage::Relaying { checked: false, .. })
        );
        // The starting side connects through the port once, on the first
        // check; the handshake's own retransmissions cover the other side
        // not having proved its address yet.
        let outbound = match ours {
            Some(ours) if first && rendezvous::starts(&ours, &key) => {
                match self.connect(from, Some(&key)) {
                    Ok(id) => Some(id),
                    Err(_) => return self.fail_introduction(key, Unavailable::Unreachable),
                }
            }
            _ => None,
        };
        if let Some(Ask {
            stage:
                Stage::Relaying {
                    checked,
                    outbound: slot,
                    ..
                },
            ..
        }) = self.rv.asks.get_mut(&key)
        {
            *checked = true;
            if outbound.is_some() {
                *slot = outbound;
            }
        }
    }

    /// The address the server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// The public key clients must know in order to connect.
    ///
    /// `None` in pre-shared-key mode, which authenticates both sides with a
    /// secret they already share and so presents no identity of its own.
    pub fn public_key(&self) -> Option<&PublicKey> {
        match &self.mode {
            Mode::PublicKey(key) => Some(key.public()),
            Mode::Psk(_) => None,
        }
    }

    /// How many resumption tickets are currently outstanding.
    pub fn outstanding_tickets(&self) -> usize {
        self.tickets.len()
    }

    /// How many peers are currently connected.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Handles for every connected peer, in a stable order.
    pub fn peers(&self) -> Vec<PeerId> {
        let mut ids: Vec<PeerId> = self.peers.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// A peer's authenticated static public key.
    pub fn peer_public_key(&self, peer: PeerId) -> Option<&PublicKey> {
        self.peers.get(&peer).map(|e| e.peer.remote_static())
    }

    /// A peer's address.
    pub fn peer_addr(&self, peer: PeerId) -> Option<SocketAddr> {
        self.peers.get(&peer).map(|e| e.addr)
    }

    /// Starts a connection to `addr`, from this endpoint's own socket.
    ///
    /// `peer_public` is the responder's static public key, required in
    /// public-key mode and ignored in the others, which authenticate from a
    /// shared secret or not at all.
    ///
    /// Returns immediately with a handle. The handshake completes when the
    /// reply arrives, surfacing as [`Event::Connected`] with `initiated: true`,
    /// or as [`Event::ConnectFailed`] if no reply comes. Nothing may be sent to
    /// the handle before then.
    pub fn connect(
        &mut self,
        addr: impl ToSocketAddrs,
        peer_public: Option<&PublicKey>,
    ) -> Result<PeerId> {
        self.connect_and_send(addr, peer_public, &[])
    }

    /// [`connect`](Self::connect), carrying data in the opening frame.
    ///
    /// In the encrypted modes this is 0-RTT data, with the caveats that
    /// implies: encrypted, but replayable by anyone who captures the frame.
    pub fn connect_and_send(
        &mut self,
        addr: impl ToSocketAddrs,
        peer_public: Option<&PublicKey>,
        zero_rtt: &[u8],
    ) -> Result<PeerId> {
        let addr = crate::resolve(addr)?;
        let session_id = OsRng.next_u32();
        let caps = local_capabilities();
        let overhead = match &self.mode {
            Mode::PublicKey(_) => INITIATOR_OVERHEAD,
            Mode::Psk(_) => ResumeInitiator::OVERHEAD,
        };
        let mut frame = crate::opening_frame(crate::udp::handshake_datagram(), overhead, zero_rtt)?;

        let (handshake, len) = match &self.mode {
            Mode::PublicKey(key) => {
                let peer = peer_public.ok_or(Error::MissingPeerKey)?;
                let mut initiator = Initiator::new(key.clone(), *peer, session_id, caps)?;
                let len = initiator.write_init(&mut OsRng, zero_rtt, &mut frame)?;
                (Handshake::Full(Box::new(initiator)), len)
            }
            Mode::Psk(psk) => {
                let mut initiator =
                    ResumeInitiator::new(psk.clone(), fectp_core::ANONYMOUS, session_id, caps)?;
                let len = initiator.write_init(&mut OsRng, zero_rtt, &mut frame)?;
                (Handshake::Psk(Box::new(initiator)), len)
            }
        };
        frame.truncate(len);
        send_datagram(&*self.socket, &frame, addr)?;

        let peer_id = PeerId(self.next_id);
        self.next_id += 1;
        let sent_at = Instant::now();
        let next_attempt = sent_at + self.handshake_delay(addr, 1);
        self.outbound.insert(
            peer_id,
            Outbound {
                handshake,
                peer_key: peer_public.copied(),
                addr,
                session_id,
                frame,
                next_attempt,
                attempts: 1,
                first_sent: sent_at,
                last_sent: sent_at,
            },
        );
        self.wake_at(next_attempt);
        Ok(peer_id)
    }

    /// How long to wait before resending an opening frame to `addr`.
    ///
    /// Cold, this is the linear schedule that was here before: 250 ms, then
    /// 500, then 750. Warm — once a handshake to this address has completed
    /// without a resend — it is what that exchange measured, backed off
    /// exponentially, which on loopback is the 20 ms floor rather than a
    /// quarter of a second.
    ///
    /// The estimate is looked up by address and never pooled across them.
    /// Pooling would let a fast path shorten a slow one's schedule, and the
    /// endpoint would abandon the slow peer before its first reply could
    /// arrive.
    ///
    /// A floor left by an earlier resent handshake applies to the first wait
    /// only. Its job is to give the first attempt time to be answered, so the
    /// exchange yields a clean sample; once that wait has passed without a
    /// reply the attempt is lost rather than slow, and the ordinary schedule
    /// takes over. Stretching every interval would instead multiply the time
    /// to give up on a path that has since died.
    fn handshake_delay(&self, addr: SocketAddr, attempts: u8) -> Duration {
        let path = self.paths.iter().find(|(a, _)| *a == addr).map(|(_, p)| p);
        let ordinary = match path.and_then(|p| p.rto) {
            Some(rto) => {
                Duration::from_millis(u64::from(rto.with_backoff(attempts.saturating_sub(1))))
            }
            None => Duration::from_millis(HANDSHAKE_RETRY_MS * u64::from(attempts)),
        };
        match path.and_then(|p| p.floor) {
            Some(floor) if attempts <= 1 => ordinary.max(floor),
            _ => ordinary,
        }
    }

    /// The wall clock the cold schedule would have spent on `attempts` tries.
    ///
    /// A warm schedule runs through its attempts far sooner, so the count
    /// alone would have an endpoint that has measured loopback give up on an
    /// unanswered peer in a tenth of a second. Both have to be spent: the
    /// attempts, and the time they would have taken cold. Nothing gives up
    /// earlier than it did before this existed.
    fn handshake_budget(attempts: u8) -> Duration {
        let n = u64::from(attempts);
        Duration::from_millis(HANDSHAKE_RETRY_MS * n * (n + 1) / 2)
    }

    /// Folds a completed handshake's round trip into what this address has
    /// measured.
    ///
    /// Only unambiguous exchanges are offered here. Once an opening frame has
    /// been resent, the reply cannot be attributed to a particular attempt —
    /// the frame is resent byte for byte, so there is nothing in it to tell
    /// them apart — and a sample from the wrong one skews the estimate. That
    /// is Karn's algorithm, and the retransmit queue applies the same rule to
    /// data.
    fn measure_path(&mut self, addr: SocketAddr, rtt: Duration) {
        let ms = u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX);
        let path = self.path_mut(addr);
        path.rto.get_or_insert_with(Rto::new).sample(ms);
        // A clean sample is what the floor was waiting for.
        path.floor = None;
    }

    /// Learns what it can from a handshake that completed only after a resend.
    ///
    /// Not a sample: the reply may answer any of the attempts. Two bounds are
    /// certain all the same. The round trip was no longer than the time since
    /// the first attempt, and no shorter than the time since the last.
    ///
    /// If the path has an estimate and the reply came inside one timeout of
    /// the latest attempt, the estimate explains everything seen — an attempt
    /// was lost on a path as fast as measured — and nothing is recorded. That
    /// is the ordinary loss, and treating it as slowness would lengthen every
    /// later handshake on a lossy fast path. Otherwise the path is slower than
    /// anything known about it, and the first wait of the next handshake is
    /// raised to twice the upper bound, so that handshake can be measured.
    fn learn_from_resent(&mut self, addr: SocketAddr, since_first: Duration, since_last: Duration) {
        let path = self.path_mut(addr);
        if let Some(rto) = path.rto {
            if since_last <= Duration::from_millis(u64::from(rto.current())) {
                path.floor = None;
                return;
            }
        }
        let doubled = since_first.saturating_mul(2);
        path.floor = Some(doubled.min(Duration::from_millis(u64::from(MAX_RTO_MS))));
    }

    /// This address's entry in the path table, created if it has none.
    fn path_mut(&mut self, addr: SocketAddr) -> &mut Path {
        let index = match self.paths.iter().position(|(a, _)| *a == addr) {
            Some(index) => index,
            None => {
                if self.paths.len() >= MAX_MEASURED_PATHS {
                    // The oldest goes. A caller that cycles through more
                    // addresses than this pays the cold schedule, which is what
                    // it paid before.
                    self.paths.remove(0);
                }
                self.paths.push((
                    addr,
                    Path {
                        rto: None,
                        floor: None,
                    },
                ));
                self.paths.len() - 1
            }
        };
        &mut self.paths[index].1
    }

    /// Handshakes this endpoint started that are still awaiting a reply.
    pub fn connecting(&self) -> usize {
        self.outbound.len()
    }

    /// Forgets a peer. Later frames from it are treated as noise.
    pub fn disconnect(&mut self, peer: PeerId) -> bool {
        if self.outbound.remove(&peer).is_some() {
            return true;
        }
        self.rv.relayed.remove(&peer);
        match self.peers.remove(&peer) {
            Some(entry) => {
                self.routes.remove(&(entry.addr, entry.session_id));
                self.unfile_session(entry.session_id, peer);
                true
            }
            None => false,
        }
    }

    /// Milliseconds since the server started.
    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Waits for the next event, giving up after `timeout`.
    ///
    /// Also drives retransmission for every peer, so this must be called
    /// regularly for reliable delivery to make progress.
    pub fn poll(&mut self, timeout: Option<Duration>) -> Result<Event> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            // Introductions have timers of their own, and some events are
            // theirs to consume; neither may cost the caller their timeout.
            if !self.rv.asks.is_empty() || !self.rv.relayed.is_empty() {
                self.drive_introductions();
            }
            if let Some(event) = self.events.pop_front() {
                if let Some(event) = self.intercept(event) {
                    return Ok(event);
                }
                continue;
            }
            let now = Instant::now();
            let until_deadline = deadline.map(|d| d.saturating_duration_since(now));
            let until_introduction = self
                .next_introduction_deadline()
                .map(|at| at.saturating_duration_since(now));
            let wait = [until_deadline, until_introduction]
                .into_iter()
                .flatten()
                .min();
            let event = self.poll_once(wait)?;
            if !matches!(event, Event::Idle) {
                if let Some(event) = self.intercept(event) {
                    return Ok(event);
                }
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(Event::Idle);
            }
        }
    }

    /// One pass of the loop under [`poll`](Self::poll): everything but the
    /// rendezvous.
    fn poll_once(&mut self, timeout: Option<Duration>) -> Result<Event> {
        let deadline = timeout.map(|t| Instant::now() + t);

        loop {
            // Time-driven work runs when it is due, not once per datagram.
            if self.next_wake.is_some_and(|at| Instant::now() >= at) {
                self.drive_retransmits()?;
                if let Some(event) = self.drive_handshakes()? {
                    return Ok(event);
                }
                self.drive_liveness();
                self.drive_keepalives()?;
                self.drive_pmtu();
                self.next_wake = self.earliest_deadline();
            }
            // The exception: a queue moves when an acknowledgement frees
            // window space, which is not a moment this loop can predict. It is
            // skipped in O(1) when nothing is queued, which is the usual case.
            if self.queueing > 0 {
                self.drive_queues()?;
            }
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }

            // Wake for whichever comes first: the caller's timeout, or the
            // moment the next piece of time-driven work falls due. The second
            // is read rather than recomputed — recomputing it walked the peer
            // table three times per datagram.
            let now = Instant::now();
            let until_deadline = deadline.map(|d| d.saturating_duration_since(now));
            let until_work = self.next_wake.map(|at| at.saturating_duration_since(now));
            let wait = [until_deadline, until_work].into_iter().flatten().min();
            // A zero timeout means "block forever" to the socket layer, which
            // is the opposite of what is meant here.
            let wait = wait.map(|w| w.max(Duration::from_millis(1)));

            match self.socket.recv_from(&mut self.rx, wait) {
                Ok((n, from)) => {
                    if let Some(event) = self.dispatch(n, from)? {
                        return Ok(event);
                    }
                }
                // Somebody this endpoint wrote to is not listening. That is
                // news about one peer, not a failure of the socket, and an
                // endpoint serving a thousand others must not stop for it.
                Err(e) if is_stale_unreachable(&e) => {}
                Err(e) if is_timeout(&e) => {
                    if deadline.is_none_or(|d| Instant::now() >= d) {
                        return Ok(Event::Idle);
                    }
                }
                Err(e) => return Err(Error::Io(e)),
            }

            // The timeout belongs to the caller, and a datagram arriving is
            // not a reason to extend it. This used to be checked only when the
            // socket read timed out, so an endpoint went round this loop for
            // as long as datagrams kept coming — and the cheapest datagram to
            // send is one that fails at the version check, which needs no key,
            // no handshake and no session. Measured, `poll(50 ms)` took 3.7
            // seconds to return under one flooding thread on loopback, and
            // everything the caller does between polls waited for it.
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(Event::Idle);
            }
        }
    }

    /// Routes one received datagram.
    fn dispatch(&mut self, n: usize, from: SocketAddr) -> Result<Option<Event>> {
        // Not a frame (SPEC A.5): a punch, which is never answered, or a relay
        // port checking an address this endpoint bound.
        if self.rx[..n].first() == Some(&rendezvous::NOT_A_FRAME) {
            if !self.rv.asks.is_empty() || !self.rv.relayed.is_empty() {
                self.not_a_frame(n, from);
            }
            return Ok(None);
        }
        let Ok(header) = Header::decode(&self.rx[..n]) else {
            return Ok(None);
        };

        // Each mode accepts only its own opening frames. A peer speaking a
        // different mode is simply not understood, which is what makes the
        // choice unnegotiable.
        if matches!(
            header.frame_type,
            FrameType::HandshakeInit | FrameType::ResumeInit
        ) && self.repeat_handshake(from, header.session_id)?
        {
            return Ok(None);
        }

        // Answering a new handshake is the expensive, unauthenticated path.
        // Everything below this that establishes a session passes the check;
        // a reply to a handshake *we* started, and traffic on an established
        // session, do not — a flood must not stop either.
        if matches!(
            header.frame_type,
            FrameType::HandshakeInit | FrameType::ResumeInit
        ) && !self.may_answer_handshake()
        {
            return Ok(None);
        }

        match (header.frame_type, &self.mode) {
            (FrameType::HandshakeInit, Mode::PublicKey(_)) => {
                self.accept_full(n, from).map(Some).or(Ok(None))
            }
            (FrameType::ResumeInit, Mode::PublicKey(_) | Mode::Psk(_)) => {
                self.accept_resumed(n, from).map(Some).or(Ok(None))
            }
            // A full handshake aimed at a pre-shared-key server. The modes do
            // not interoperate, and this is where that is enforced: not by
            // deciding, but by having no arm that accepts it.
            (FrameType::HandshakeInit, _) => Ok(None),
            (FrameType::HandshakeResponse | FrameType::ResumeResponse, _) => {
                self.complete_outbound(n, from, header.session_id)
            }
            _ => self.route(n, from, header.session_id),
        }
    }

    /// Delivers a data or acknowledgement frame to its session.
    ///
    /// Two lookups, in order. The address and identifier together name a
    /// session outright. Failing that, the identifier alone gives a shortlist
    /// and the AEAD tag decides — the peer may have moved, or this may be
    /// someone who guessed an identifier, and only authentication tells those
    /// apart.
    fn route(&mut self, n: usize, from: SocketAddr, session_id: u32) -> Result<Option<Event>> {
        if let Some(&peer_id) = self.routes.get(&(from, session_id)) {
            return self.deliver(peer_id, n, from, true);
        }

        // The address is new to us. This is the one path where the identifier
        // has to stand on its own, and it is reachable by anyone who can
        // address the socket.
        //
        // Walk the sessions wearing this identifier by index rather than
        // collecting them, so the path does not allocate either.
        let mut at = 0;
        while at < MAX_CANDIDATES {
            let Some(peer_id) = self
                .by_session
                .get(&session_id)
                .and_then(|sharing| sharing.get(at))
                .copied()
            else {
                return Ok(None);
            };
            at += 1;

            // Every candidate is an authentication attempt, bought by a frame
            // that has authenticated to nothing. The budget used to be spent
            // once per datagram while the work was per candidate, so a crowded
            // identifier multiplied what the rate limit was meant to cap —
            // and a sequence number forged some generations ahead multiplied
            // it again, since the key has to be derived before the tag can be
            // checked. Spend for each.
            // A session out of budget is skipped rather than ending the
            // walk: the next candidate has its own allowance, and one peer
            // must not be able to hide the others behind it.
            if !self.may_try_unknown_address(peer_id) {
                continue;
            }

            // A frame that does not open leaves the session untouched — the
            // replay window is only advanced once the tag verifies — so trying
            // a candidate that turns out to be the wrong one costs nothing but
            // the verification.
            match self.deliver(peer_id, n, from, false)? {
                Some(event) => return Ok(Some(event)),
                None if self.claimed(peer_id, from) => return Ok(None),
                None => {}
            }
        }
        Ok(None)
    }

    /// Whether this session has just been heard from at `from`.
    ///
    /// Ends the search once a candidate has accepted the frame, since
    /// accepting it without producing an event is an ordinary outcome.
    fn claimed(&self, peer_id: PeerId, from: SocketAddr) -> bool {
        self.peers.get(&peer_id).is_some_and(|entry| {
            entry.addr == from || entry.probe.as_ref().is_some_and(|p| p.addr == from)
        })
    }

    /// Feeds one frame to one session.
    ///
    /// `established` says whether `from` is the address this session is filed
    /// under. When it is not, nothing goes back to `from` but a challenge: the
    /// frame proves someone holding the key sent it, and says nothing at all
    /// about who is at the address it came from.
    fn deliver(
        &mut self,
        peer_id: PeerId,
        n: usize,
        from: SocketAddr,
        established: bool,
    ) -> Result<Option<Event>> {
        let Some(entry) = self.peers.get_mut(&peer_id) else {
            return Ok(None);
        };

        let now = self.epoch.elapsed().as_millis() as u64;
        let mut ack_len = 0;
        let ingested = entry
            .peer
            .ingest(&mut self.rx[..n], now, &mut self.ack, &mut ack_len)?;

        if matches!(ingested, Ingested::Rejected) {
            // Anyone can address a UDP socket. A frame that did not open says
            // nothing about this session and must not be credited to it.
            return Ok(None);
        }

        // The frame authenticated, which is the first thing a peer does that
        // an attacker completing handshakes never does. It is what keeps this
        // session off the eviction list, and what keeps it off the timeout.
        let first_word = !entry.spoke;
        entry.spoke = true;
        entry.last_heard = Instant::now();
        // It answered, so it has the handshake response and will not ask again.
        entry.handshake_reply = None;
        // Probes wait for this, for the reason keep-alives do: until the peer
        // has spoken, the address on file is only what a datagram claimed,
        // and a probe is the largest thing this endpoint sends unasked.
        if first_word && entry.pmtu.is_some() {
            self.wake_at(Instant::now());
        }

        if established {
            if ack_len > 0 {
                send_datagram(&*self.socket, &self.ack[..ack_len], from)?;
                if let Some(entry) = self.peers.get_mut(&peer_id) {
                    entry.last_sent = Instant::now();
                }
            }
            if let Ingested::PathValidated(token) = &ingested {
                if let Some(entry) = self.peers.get_mut(&peer_id) {
                    if let Some(pmtu) = &mut entry.pmtu {
                        pmtu.answered(token, Instant::now());
                        entry.datagram_limit = pmtu.current();
                    }
                }
            }
        } else if let Ingested::PathValidated(token) = ingested {
            return Ok(self.settle_probe(peer_id, from, token));
        } else {
            // Heard from an address that has not proved it can receive. The
            // payload is genuine, so it is delivered; the acknowledgement is
            // withheld, because until the address answers, sending anything
            // there is sending it somewhere nobody asked for. The peer repeats
            // the message, and the repeat is acknowledged once the path holds.
            self.start_probe(peer_id, from)?;
        }

        match ingested {
            Ingested::Rejected | Ingested::Nothing => Ok(None),
            // An answer from the address already on file settles nothing that
            // was in question.
            Ingested::PathValidated(_) => Ok(None),
            Ingested::Data { len, compressed } => {
                let body = &self.rx[HEADER_LEN..HEADER_LEN + len];
                let mut staging = vec![0u8; decoded_capacity(body, compressed)];
                // A payload this peer coded in a way we cannot reverse is that
                // peer's problem, not a reason to stop serving everyone else.
                let Ok(written) = deliver(body, compressed, &mut self.scratch, &mut staging) else {
                    return Ok(None);
                };
                staging.truncate(written);
                Ok(Some(Event::Message {
                    peer: peer_id,
                    data: staging,
                }))
            }
            Ingested::Message(data) => Ok(Some(Event::Message {
                peer: peer_id,
                data,
            })),
        }
    }

    /// Asks an address to prove it can receive, if it is worth asking again.
    fn start_probe(&mut self, peer_id: PeerId, addr: SocketAddr) -> Result<()> {
        let Some(entry) = self.peers.get_mut(&peer_id) else {
            return Ok(());
        };
        let now = Instant::now();

        // A different address supersedes whatever was under test: the newest
        // place the peer was heard from is the one worth proving.
        let fresh = match &entry.probe {
            Some(probe) if probe.addr == addr => {
                if now.duration_since(probe.started) > PROBE_TIMEOUT {
                    // The attempt has aged out. Start another rather than
                    // giving up on the address for good: three challenges lost
                    // in a row is a bad minute on a path, not proof that
                    // nobody is there, and a peer that really did move would
                    // otherwise be stranded for the life of the session.
                    true
                } else if probe.sent >= PATH_PROBES
                    || now.duration_since(probe.last) < PROBE_INTERVAL
                {
                    return Ok(());
                } else {
                    false
                }
            }
            _ => true,
        };

        let mut token = [0u8; PATH_TOKEN_LEN];
        if fresh {
            OsRng.fill_bytes(&mut token);
            entry.probe = Some(Probe {
                addr,
                token,
                sent: 0,
                last: now,
                started: now,
            });
        } else if let Some(probe) = &entry.probe {
            token = probe.token;
        }

        let len = entry.peer.challenge(&token, &mut self.ack)?;
        if let Some(probe) = &mut entry.probe {
            probe.sent += 1;
            probe.last = now;
        }
        send_datagram(&*self.socket, &self.ack[..len], addr)?;
        if let Some(entry) = self.peers.get_mut(&peer_id) {
            entry.last_sent = Instant::now();
        }
        Ok(())
    }

    /// Moves a session to an address that has answered its challenge.
    fn settle_probe(
        &mut self,
        peer_id: PeerId,
        from: SocketAddr,
        token: [u8; PATH_TOKEN_LEN],
    ) -> Option<Event> {
        let entry = self.peers.get_mut(&peer_id)?;
        let probe = entry.probe.as_ref()?;
        // The answer has to come from the address that was asked, carrying the
        // token it was asked with. Either alone would be a way in: a token
        // replayed from somewhere else, or a fresh address answering a
        // question that was put to another one.
        if probe.addr != from || probe.token != token {
            return None;
        }

        let previous = entry.addr;
        entry.addr = from;
        entry.probe = None;
        // The round-trip time and window were earned on the old path and do
        // not describe this one, and nor was the frame size.
        entry.peer.forget_path();
        let moved_at = Instant::now();
        if let Some(pmtu) = &mut entry.pmtu {
            pmtu.reset(moved_at);
            entry.datagram_limit = pmtu.current();
        }
        let session_id = entry.session_id;

        self.routes.remove(&(previous, session_id));

        // Two sessions cannot share one route. The identifier is chosen by the
        // client, so a peer moving to an address where another session already
        // wears the same identifier is possible — vanishingly unlikely by
        // accident, since it needs a 32-bit collision *and* the same address.
        // `file` has always displaced the older entry in this situation;
        // discarding the return here instead left the displaced peer in
        // `peers` and `by_session` with no route, which is a state nothing
        // else in this file expects. Its traffic would then be handed to the
        // session that took its place, fail to open, and be dropped for ever,
        // with no event to say so.
        if let Some(displaced) = self.routes.insert((from, session_id), peer_id) {
            if let Some(entry) = self.peers.remove(&displaced) {
                self.unfile_session(entry.session_id, displaced);
                self.events.push_back(Event::PeerLost { peer: displaced });
            }
        }

        self.wake_at(moved_at);
        Some(Event::PeerMoved {
            peer: peer_id,
            from: previous,
            to: from,
        })
    }

    /// Matches a handshake reply to the connection this endpoint started.
    fn complete_outbound(
        &mut self,
        n: usize,
        from: SocketAddr,
        session_id: u32,
    ) -> Result<Option<Event>> {
        let Some((&peer_id, _)) = self
            .outbound
            .iter()
            .find(|(_, o)| o.addr == from && o.session_id == session_id)
        else {
            // Not a reply we are waiting for. Late, forged, or misdirected.
            return Ok(None);
        };
        let outbound = self.outbound.remove(&peer_id).expect("just found");
        let addr = outbound.addr;
        if outbound.attempts == 1 {
            self.measure_path(addr, outbound.first_sent.elapsed());
        } else {
            self.learn_from_resent(
                addr,
                outbound.first_sent.elapsed(),
                outbound.last_sent.elapsed(),
            );
        }

        let mut staging = vec![0u8; self.rx.len()];
        let completed = match outbound.handshake {
            Handshake::Full(initiator) => initiator
                .read_response(&self.rx[..n], &mut staging)
                .map(|(session, len)| (session, len, false)),
            Handshake::Psk(initiator) => initiator
                .read_response(&self.rx[..n], &mut staging)
                .map(|(session, len)| (session, len, true)),
        };

        let Ok((link, len, resumed)) = completed else {
            // The reply did not authenticate: the wrong key, a different mode,
            // or a forgery. Reading it consumed the handshake state either
            // way, so the attempt ends here and the caller may start another.
            //
            // Reaching this deliberately means guessing a random 32-bit
            // session identifier *and* spoofing the peer's address, so it is
            // not a cheap way to disrupt a connection.
            return Ok(Some(Event::ConnectFailed { peer: peer_id }));
        };

        let reply = staging[..len].to_vec();
        Ok(Some(
            self.register_as(peer_id, link, addr, reply, resumed, true),
        ))
    }

    fn accept_full(&mut self, n: usize, from: SocketAddr) -> Result<Event> {
        let Mode::PublicKey(key) = &self.mode else {
            return Err(Error::Handshake);
        };
        let mut responder = Responder::new(key.clone(), local_capabilities());
        let mut staging = vec![0u8; self.rx.len()];
        let len = responder.read_init(&self.rx[..n], &mut staging)?;
        let zero_rtt = staging[..len].to_vec();

        let reply = core::mem::take(&mut self.handshake_reply);
        let written = responder.write_response(&mut OsRng, &reply, &mut self.tx);
        self.handshake_reply = reply;
        let (session, sent) = written?;
        send_datagram(&*self.socket, &self.tx[..sent], from)?;
        let reply = self.tx[..sent].to_vec();
        let event = self.register(session, from, zero_rtt, false);
        self.remember_reply(&event, reply);
        Ok(event)
    }

    fn accept_resumed(&mut self, n: usize, from: SocketAddr) -> Result<Event> {
        let id = ResumeResponder::ticket_id(&self.rx[..n])?;

        // A configured pre-shared key is long-lived and reusable; an earned
        // resumption ticket is spent when redeemed, so that a captured
        // resumption request cannot be replayed.
        let configured = match &self.mode {
            Mode::Psk(psk) if psk.id() == &id => Some((psk.clone(), fectp_core::ANONYMOUS)),
            _ => None,
        };
        let (ticket, remote_static) = match configured {
            Some(pair) => pair,
            None => self.tickets.take(&id).ok_or(Error::UnknownTicket)?,
        };

        let mut responder = ResumeResponder::new(local_capabilities(), remote_static);
        let mut staging = vec![0u8; self.rx.len()];
        let len = responder.read_init(&ticket, &self.rx[..n], &mut staging)?;
        let zero_rtt = staging[..len].to_vec();

        let reply = core::mem::take(&mut self.handshake_reply);
        let written = responder.write_response(&mut OsRng, &reply, &mut self.tx);
        self.handshake_reply = reply;
        let (session, sent) = written?;
        send_datagram(&*self.socket, &self.tx[..sent], from)?;
        let reply = self.tx[..sent].to_vec();
        let event = self.register(session, from, zero_rtt, true);
        self.remember_reply(&event, reply);
        Ok(event)
    }

    /// Files a freshly established session and issues its next ticket.
    fn register(
        &mut self,
        link: Session,
        addr: SocketAddr,
        zero_rtt: Vec<u8>,
        resumed: bool,
    ) -> Event {
        // Every handshake issues the ticket for the next one.
        self.tickets
            .insert(link.resumption_ticket(), *link.remote_static());

        let session_id = link.session_id();
        let peer_id = PeerId(self.next_id);
        self.next_id += 1;
        self.file(peer_id, link, addr, session_id);

        Event::Connected {
            peer: peer_id,
            zero_rtt,
            resumed,
            initiated: false,
        }
    }

    /// Files a session under a handle that already exists, as an outbound
    /// handshake's does.
    fn register_as(
        &mut self,
        peer_id: PeerId,
        link: Session,
        addr: SocketAddr,
        zero_rtt: Vec<u8>,
        resumed: bool,
        initiated: bool,
    ) -> Event {
        self.tickets
            .insert(link.resumption_ticket(), *link.remote_static());
        let session_id = link.session_id();
        self.file(peer_id, link, addr, session_id);

        Event::Connected {
            peer: peer_id,
            zero_rtt,
            resumed,
            initiated,
        }
    }

    /// Releases a peer nothing has been heard from for `within`.
    ///
    /// The session is dropped and [`Event::PeerLost`] is raised. Only frames
    /// that authenticate count as being heard, so a stranger cannot hold a
    /// dead peer's session open by addressing the socket.
    ///
    /// **Silence is not evidence of death.** A peer that is alive and has
    /// nothing to say looks exactly like one that has gone. Pair this with
    /// [`set_keepalive`](Self::set_keepalive) and the silence means something:
    /// the peer was asked at intervals and did not answer. Without it, this is
    /// an idle timeout and will drop peers that are merely quiet — which is
    /// occasionally what a caller wants, and should be what a caller chose.
    ///
    /// Off by default, and the default is what a sensor that wakes, reports
    /// and sleeps for an hour gets. Memory is bounded without it:
    /// [`MAX_PEERS`] and the eviction order already drop the longest-silent
    /// session when room is needed.
    ///
    /// Anything shorter than [`MIN_PEER_TIMEOUT`] is raised to it. `None`
    /// turns it off.
    pub fn set_peer_timeout(&mut self, within: Option<Duration>) {
        self.peer_timeout = within.map(|t| t.max(MIN_PEER_TIMEOUT));
        self.rescan_wake();
    }

    /// Sends a small frame to any peer nothing has been sent to for `every`.
    ///
    /// Only to peers something authenticated has been heard from. A session
    /// can be filed pointing at an address that never asked for it — the
    /// handshake needs one datagram and the source address on it is whatever
    /// the sender wrote — and keeping such a session alive would aim a steady
    /// stream at that address.
    ///
    /// Off by default, and deliberately so: a battery-powered peer that wakes,
    /// reports a reading and sleeps must not be kept awake by the library.
    ///
    /// Turn it on where sessions stay open through quiet periods. A NAT maps
    /// an inside address to an outside one when something is sent out and
    /// forgets the mapping when nothing has been for a while — thirty seconds
    /// on plenty of equipment — after which **inbound datagrams have nowhere
    /// to go**, with both ends still believing the session is fine.
    ///
    /// Only outbound traffic refreshes a mapping, so this helps the side
    /// *behind* the NAT. An endpoint that dialled out is that side; one that
    /// only accepts is not, and gains liveness from it rather than reachability.
    ///
    /// The frame is a path challenge, which the peer answers, so one exchange
    /// refreshes the mapping in both directions. It costs 38 bytes each way,
    /// per peer, per interval — worth pricing before turning it on for a
    /// thousand of them.
    ///
    /// Anything shorter than [`MIN_KEEPALIVE`] is raised to it. `None` turns
    /// it off.
    pub fn set_keepalive(&mut self, every: Option<Duration>) {
        self.keepalive = every.map(|t| t.max(MIN_KEEPALIVE));
        self.rescan_wake();
    }

    /// Sets how many opening frames are sent before a connect attempt is given
    /// up on, replacing [`HANDSHAKE_ATTEMPTS`].
    ///
    /// A count rather than a duration, because a count is the part a caller
    /// can reason about: how many chances a lost opening frame gets. A
    /// `Duration` would have to be divided by an interval that is no longer
    /// fixed — on a measured path it is what that path measured (D71) — so it
    /// would report a budget nothing honours. `Connection` is the other way
    /// round: its handshake blocks, so a clock ends it, and
    /// [`HANDSHAKE_TIMEOUT`](crate::HANDSHAKE_TIMEOUT) is that clock. It has
    /// no setter because the handshake is over before there is a `Connection`
    /// to call one on.
    ///
    /// The wall clock this buys is the sum of the *cold* intervals, which grow
    /// linearly, and it is a floor as well as an estimate: an endpoint gives
    /// up only once it has spent both the attempts and that much time.
    /// Measured against a bound socket that never answers, two attempts take
    /// 788 ms, four 2.55 s and eight 9.09 s. On a path this endpoint has
    /// measured the same wall clock buys more attempts rather than fewer.
    ///
    /// Raise it for a path that loses opening frames, or for a host too busy
    /// to keep to the schedule — a desktop that has been idle runs two to
    /// three times slow, which is measurable with no protocol in it at all
    /// (`cargo run --release --bin idle`).
    ///
    /// Zero is raised to one. Taken literally it would mean never sending the
    /// opening frame, so the peer would be reported unreachable without one
    /// datagram having been aimed at it.
    pub fn set_handshake_attempts(&mut self, attempts: u8) {
        self.handshake_attempts = attempts.max(1);
    }

    /// How many opening frames are sent before a connect attempt is given up on.
    pub fn handshake_attempts(&self) -> u8 {
        self.handshake_attempts
    }

    /// Sets how many times a reliable message is resent before it is given up
    /// on, replacing [`MAX_RETRIES`] for every peer on this endpoint.
    ///
    /// Applies to the sessions already open as well as the ones still to
    /// arrive, so a program does not have to set it before its first peer.
    ///
    /// The default of five is a count, and what an application usually wants
    /// is a span of time. They are not the same thing: the budget a count buys
    /// is roughly twice the last backoff interval, and that interval comes
    /// from the round trip measured on that peer's path. Near the 20 ms floor
    /// five attempts are spent in about 1.3 seconds; from a cold start they
    /// last about eleven. A sender descheduled for longer than that gives up
    /// on a message a slower estimate would still be retrying.
    ///
    /// Zero is raised to one. Past five the backoff stops doubling: each
    /// further attempt repeats the fifth interval. On a fast path that is
    /// 640 ms, so twelve attempts come to 5.7 seconds; from a cold start it is
    /// five seconds and twelve attempts are 46.
    pub fn set_max_retries(&mut self, attempts: u8) {
        self.max_retries = attempts.max(1);
        for entry in self.peers.values_mut() {
            entry.peer.retransmit.set_max_retries(self.max_retries);
        }
    }

    /// Sets how many sessions this endpoint will hold, replacing [`MAX_PEERS`].
    ///
    /// Above the limit, the peer that has been quiet longest is dropped to make
    /// room — see [`MAX_PEERS`] for why the alternative is unbounded memory.
    /// Sessions already held are not dropped by lowering it; the new limit
    /// applies as peers arrive.
    ///
    /// A limit of zero is treated as one, because an endpoint that can hold no
    /// sessions cannot do anything.
    pub fn set_max_peers(&mut self, limit: usize) {
        self.max_peers = limit.max(1);
    }

    /// Sets how many attempts a second **each session** may spend being tried
    /// against frames from addresses it is not filed under.
    ///
    /// The default is [`MAX_MIGRATION_ATTEMPTS_PER_PEER`]. Raise it for peers
    /// on paths that move often; lower it, or set it to zero, for an endpoint
    /// whose peers never move — at zero no session will ever follow a peer
    /// that changes address.
    pub fn set_max_migration_attempts_per_peer(&mut self, rate: u32) {
        self.migration_rate = rate;
    }

    /// Files the response just sent against the session it established.
    fn remember_reply(&mut self, event: &Event, reply: Vec<u8>) {
        let Event::Connected { peer, .. } = event else {
            return;
        };
        if let Some(entry) = self.peers.get_mut(peer) {
            entry.handshake_reply = Some((reply, HANDSHAKE_REPLIES));
        }
    }

    /// Answers a repeated opening frame without performing the handshake again.
    ///
    /// Returns whether the frame was one, in which case nothing further should
    /// be done with it.
    ///
    /// Two things arrive here. The ordinary one is a client whose reply was
    /// lost and has resent message 1 — it needs the same answer, and building
    /// a fresh one would establish a second session while the client is still
    /// expecting the first. The other is a replay of a captured frame, which
    /// names a session identifier that already exists, and answering *that*
    /// afresh replaces the session the frame names. One captured packet would
    /// then cut off one chosen peer.
    ///
    /// Both are handled by never handshaking twice for the same pair. If the
    /// response is still held it goes out again — the same bytes an attacker
    /// already has, so nothing is given away. If it is not, the peer has
    /// already spoken and therefore already has it, and the frame is ignored.
    fn repeat_handshake(&mut self, from: SocketAddr, session_id: u32) -> Result<bool> {
        let Some(&peer_id) = self.routes.get(&(from, session_id)) else {
            return Ok(false);
        };
        let Some(entry) = self.peers.get(&peer_id) else {
            return Ok(false);
        };
        let Some((reply, left)) = entry.handshake_reply.clone() else {
            // Already spoken for, or resent as often as an honest client could
            // need. Either way this is not a handshake to answer.
            return Ok(true);
        };
        send_datagram(&*self.socket, &reply, from)?;
        if let Some(entry) = self.peers.get_mut(&peer_id) {
            entry.handshake_reply = left.checked_sub(1).map(|left| (reply, left));
        }
        Ok(true)
    }

    /// Sets a payload to carry in the response to every handshake.
    ///
    /// A peer that sends data with its handshake ([`Connection::connect_and_send`](crate::Connection::connect_and_send))
    /// gets an answer in the same round trip rather than the one after it — the
    /// other half of the property this protocol exists for, and until now the
    /// half an `Endpoint` could not reach. `Connection` already delivers it:
    /// the payload arrives through the first [`recv`](crate::Connection::recv) as
    /// though it were any other message.
    ///
    /// **This is not 0-RTT data and does not carry its caveats.** The opening
    /// frame is replayable and protected only by the responder's static key
    /// (SPEC §4.4.1). The *response* is encrypted after the ephemeral exchange,
    /// so it has forward secrecy, and reading it needs the initiator's static
    /// secret — which whoever replayed the opening frame does not have.
    ///
    /// It is the same bytes for every peer, decided before any of them
    /// connects, because the response is written inside `poll` before the
    /// application hears anything. An answer that depends on what the peer
    /// said needs the round trip after.
    ///
    /// Fails with [`Error::PayloadTooLarge`](fectp_core::Error::PayloadTooLarge)
    /// if it would not fit a handshake frame, which is sized for a path nothing
    /// is known about yet: at most 1200 bytes, even when
    /// [`set_max_datagram`](crate::set_max_datagram) has raised the ceiling.
    pub fn set_handshake_reply(&mut self, payload: &[u8]) -> Result<()> {
        let overhead = RESPONDER_OVERHEAD.max(ResumeResponder::OVERHEAD);
        if payload.len() + overhead > crate::udp::handshake_datagram() {
            return Err(Error::Protocol(fectp_core::Error::PayloadTooLarge));
        }
        self.handshake_reply = payload.to_vec();
        Ok(())
    }

    /// Sets how long a resumption ticket this endpoint issued stays redeemable,
    /// replacing [`TICKET_LIFETIME`](crate::TICKET_LIFETIME).
    ///
    /// A ticket is single use, but until it is used it is enough on its own to
    /// impersonate the peer it was issued to, so the lifetime bounds what a
    /// captured one is worth. Shorten it where that matters more than the
    /// hundred milliseconds a full handshake costs; lengthen it for a device
    /// that sleeps between reports and would otherwise always pay for one.
    pub fn set_ticket_lifetime(&mut self, lifetime: Duration) {
        self.tickets.set_lifetime(lifetime);
    }

    /// Sets how many new handshakes a second this endpoint will answer,
    /// replacing [`MAX_HANDSHAKES_PER_SECOND`].
    ///
    /// Raise it on a server that genuinely sees more than the default and can
    /// afford the work; lower it to spend less on strangers. It bounds new
    /// sessions only — traffic on established ones never passes through it.
    ///
    /// Zero is treated as one: an endpoint that answers no handshakes can
    /// never acquire a peer.
    pub fn set_max_handshakes_per_second(&mut self, per_second: u32) {
        self.handshake_rate = per_second.max(1);
        self.handshake_budget = self.handshake_budget.min(self.handshake_rate as f32);
    }

    /// Whether there is budget to answer one more new handshake.
    ///
    /// A token bucket rather than a counter per interval, so a burst is
    /// absorbed and a sustained flood is not.
    /// Whether this session may be tried against a frame from an address it is
    /// not filed under.
    ///
    /// Spends from the session's own budget rather than one the endpoint
    /// shares, so a peer flooding the lookup empties its own allowance and
    /// nobody else's. Refills over time, so a real migration — a handful of
    /// frames, one of which needs to land — is never refused.
    fn may_try_unknown_address(&mut self, peer_id: PeerId) -> bool {
        let rate = self.migration_rate;
        let Some(entry) = self.peers.get_mut(&peer_id) else {
            return false;
        };
        let now = Instant::now();
        let elapsed = now.duration_since(entry.migration_refilled).as_secs_f32();
        entry.migration_refilled = now;
        entry.migration_budget = (entry.migration_budget + elapsed * rate as f32).min(rate as f32);

        if entry.migration_budget < 1.0 {
            return false;
        }
        entry.migration_budget -= 1.0;
        true
    }

    fn may_answer_handshake(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.handshake_refilled).as_secs_f32();
        self.handshake_refilled = now;
        self.handshake_budget = (self.handshake_budget + elapsed * self.handshake_rate as f32)
            .min(self.handshake_rate as f32);

        if self.handshake_budget < 1.0 {
            return false;
        }
        self.handshake_budget -= 1.0;
        true
    }

    /// Makes room for one more session, if there is none.
    ///
    /// Drops the oldest peer that has never sent anything, because that is
    /// what a flood looks like and what an established session does not. Only
    /// when every peer has spoken does this fall back to the oldest outright —
    /// at which point the endpoint is genuinely full of real peers and
    /// something has to give.
    fn make_room(&mut self) {
        if self.peers.len() < self.max_peers {
            return;
        }
        let victim = self
            .peers
            .iter()
            .min_by_key(|(_, e)| (e.spoke, e.filed))
            .map(|(id, _)| *id);
        if let Some(victim) = victim {
            if let Some(entry) = self.peers.remove(&victim) {
                self.routes.remove(&(entry.addr, entry.session_id));
                self.unfile_session(entry.session_id, victim);
            }
        }
    }

    /// Drops one session from the identifier index, and the entry with it if
    /// it was the last one wearing that identifier.
    fn unfile_session(&mut self, session_id: u32, peer_id: PeerId) {
        if let Some(sharing) = self.by_session.get_mut(&session_id) {
            sharing.retain(|&id| id != peer_id);
            if sharing.is_empty() {
                self.by_session.remove(&session_id);
            }
        }
    }

    fn file(&mut self, peer_id: PeerId, link: Session, addr: SocketAddr, session_id: u32) {
        self.make_room();

        // The most this session may ever send: what the peer can take, or
        // what this side allows, whichever is less. With discovery, it starts
        // at the base and earns the rest.
        let cap = (link.peer_capabilities().max_frame_size as usize).min(max_datagram());
        let pmtu = (crate::udp::path_mtu_discovery()
            && link.peer_capabilities().supports_pmtu_probe()
            && cap > BASE_DATAGRAM)
            .then(|| Pmtu::new(cap, Instant::now()));
        let datagram_limit = pmtu.as_ref().map_or(cap, Pmtu::current);

        // A reconnect from the same address and session id replaces the old
        // entry rather than shadowing it.
        if let Some(previous) = self.routes.insert((addr, session_id), peer_id) {
            self.peers.remove(&previous);
            self.unfile_session(session_id, previous);
        }
        self.by_session.entry(session_id).or_default().push(peer_id);
        self.peers.insert(
            peer_id,
            PeerEntry {
                peer: {
                    let mut peer = Peer::new(link, max_datagram());
                    peer.retransmit.set_max_retries(self.max_retries);
                    peer
                },
                addr,
                session_id,
                filed: Instant::now(),
                // Full, like the endpoint-wide bucket this replaced. A peer
                // that moves moments after connecting is not doing anything
                // suspicious, and starting empty would make it wait out a
                // refill before it could be found.
                migration_budget: MAX_MIGRATION_ATTEMPTS_PER_PEER as f32,
                migration_refilled: Instant::now(),
                last_heard: Instant::now(),
                last_sent: Instant::now(),
                handshake_reply: None,
                probe: None,
                pmtu,
                spoke: false,
                datagram_limit,
            },
        );
        // A new session brings its own keep-alive and timeout deadlines.
        self.rescan_wake();
    }

    /// Feeds queued fragments into whatever send window each peer has free.
    ///
    /// Completions go onto the event queue rather than being returned, so a
    /// pass that finishes two messages reports both.
    fn drive_queues(&mut self) -> Result<()> {
        let now = self.now_ms();
        let ids: Vec<PeerId> = self.peers.keys().copied().collect();

        for id in ids {
            let Some(entry) = self.peers.get_mut(&id) else {
                continue;
            };
            let addr = entry.addr;
            let socket = &*self.socket;
            let stamp = &mut entry.last_sent;
            let finished = entry.peer.drive_queue(now, &mut self.tx, |frame| {
                send_datagram(socket, frame, addr)?;
                *stamp = Instant::now();
                Ok(())
            })?;
            if let Some(finished) = finished {
                self.events.push_back(Event::Sent {
                    peer: id,
                    delivered: finished.delivered,
                });
            }
        }
        // Recounted from the peers themselves rather than tracked, so the gate
        // cannot drift out of step with what is actually queued.
        self.queueing = self.peers.values().filter(|e| e.peer.queued() > 0).count();
        Ok(())
    }

    /// Resends unanswered opening frames, and abandons the hopeless ones.
    fn drive_handshakes(&mut self) -> Result<Option<Event>> {
        let now = Instant::now();
        let due: Vec<PeerId> = self
            .outbound
            .iter()
            .filter(|(_, o)| o.next_attempt <= now)
            .map(|(id, _)| *id)
            .collect();

        for id in due {
            let Some(outbound) = self.outbound.get(&id) else {
                continue;
            };
            let spent = now.saturating_duration_since(outbound.first_sent);
            if outbound.attempts >= self.handshake_attempts
                && spent >= Self::handshake_budget(self.handshake_attempts)
            {
                self.outbound.remove(&id);
                return Ok(Some(Event::ConnectFailed { peer: id }));
            }
            // Read what the next interval needs before the entry is borrowed
            // again: `handshake_delay` reads the path table, which is also
            // `self`.
            // Saturating because a measured path can fit many more attempts
            // into the same budget than the cold schedule ever did, and the
            // counter is a byte.
            let attempts = outbound.attempts.saturating_add(1);
            let addr = outbound.addr;
            let frame = outbound.frame.clone();
            // Back off, so an unreachable peer is not hammered.
            let next = now + self.handshake_delay(addr, attempts);
            if let Some(outbound) = self.outbound.get_mut(&id) {
                outbound.attempts = attempts;
                outbound.next_attempt = next;
                outbound.last_sent = now;
            }
            send_datagram(&*self.socket, &frame, addr)?;
        }
        Ok(None)
    }

    /// Recomputes the wake from scratch.
    ///
    /// For the places that change what is pending rather than add to it — a
    /// new setting, a peer arriving or leaving. Walks the table, so it belongs
    /// on those paths and not on the datagram path.
    fn rescan_wake(&mut self) {
        self.next_wake = self.earliest_deadline();
    }

    /// Notes that something falls due at `at`, so the loop wakes for it.
    ///
    /// Only ever brings the wake forward. A deadline moving later is safe to
    /// ignore: the loop wakes once too early, finds nothing due, and recomputes.
    fn wake_at(&mut self, at: Instant) {
        self.next_wake = Some(match self.next_wake {
            Some(existing) => existing.min(at),
            None => at,
        });
    }

    /// The earliest moment any time-driven work falls due.
    ///
    /// Walks the peer table, which is why it runs after a drive pass rather
    /// than before every datagram.
    fn earliest_deadline(&self) -> Option<Instant> {
        let now_ms = self.now_ms();
        let now = Instant::now();
        let retransmit = self
            .peers
            .values()
            .filter_map(|e| e.peer.retransmit.next_deadline_ms())
            .min()
            .map(|at| now + Duration::from_millis(at.saturating_sub(now_ms)));
        let handshake = self.outbound.values().map(|o| o.next_attempt).min();
        let pmtu = self
            .peers
            .values()
            .filter(|e| e.spoke)
            .filter_map(|e| {
                let retry = Duration::from_millis(e.peer.retransmit.rto_ms().into());
                e.pmtu.as_ref()?.next_deadline(retry)
            })
            .min();
        [
            retransmit,
            handshake,
            pmtu,
            self.next_keepalive().map(|d| now + d),
            self.next_liveness_check().map(|d| now + d),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Releases peers nothing has been heard from inside the timeout.
    ///
    /// Runs before the keep-alives, so a peer is never sent a challenge on the
    /// same pass that gives up on it.
    fn drive_liveness(&mut self) {
        let Some(limit) = self.peer_timeout else {
            return;
        };
        let now = Instant::now();
        let lost: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_heard) >= limit)
            .map(|(id, _)| *id)
            .collect();

        for id in lost {
            // The same removal as `disconnect`, so a peer given up on leaves
            // nothing behind in either index.
            if let Some(entry) = self.peers.remove(&id) {
                self.routes.remove(&(entry.addr, entry.session_id));
                self.unfile_session(entry.session_id, id);
                self.events.push_back(Event::PeerLost { peer: id });
            }
        }
    }

    /// When the earliest peer timeout falls due, if any.
    fn next_liveness_check(&self) -> Option<Duration> {
        let limit = self.peer_timeout?;
        let now = Instant::now();
        self.peers
            .values()
            .map(|e| (e.last_heard + limit).saturating_duration_since(now))
            .min()
    }

    /// Sends a keep-alive to every peer that has not been sent to recently.
    ///
    /// A path challenge is what goes out: it already exists, is authenticated,
    /// is 38 bytes, and is answered — so one exchange refreshes a NAT mapping
    /// in both directions rather than only this one.
    fn drive_keepalives(&mut self) -> Result<()> {
        let Some(every) = self.keepalive else {
            return Ok(());
        };
        let now = Instant::now();
        let due: Vec<PeerId> = self
            .peers
            .iter()
            // Only peers that have been heard from. Reaching the peer table
            // needs the endpoint's public key and one datagram, and the source
            // address on that datagram is whatever the sender wrote — so a
            // session can be filed pointing at an address that never asked for
            // anything. Keeping it alive would aim 38 bytes at that address on
            // every interval for as long as the session survived eviction: one
            // datagram in, an unbounded stream out, at a target of the
            // sender's choosing.
            //
            // `spoke` is the proof, and it is the proof the eviction order
            // already relies on: an authenticated frame arrived, which cannot
            // happen unless the handshake response reached somebody who held
            // the keys.
            .filter(|(_, e)| e.spoke && now.duration_since(e.last_sent) >= every)
            .map(|(id, _)| *id)
            .collect();

        for id in due {
            let Some(entry) = self.peers.get_mut(&id) else {
                continue;
            };
            let addr = entry.addr;
            let mut token = [0u8; PATH_TOKEN_LEN];
            OsRng.fill_bytes(&mut token);
            let n = entry.peer.challenge(&token, &mut self.ack)?;
            send_datagram(&*self.socket, &self.ack[..n], addr)?;
            if let Some(entry) = self.peers.get_mut(&id) {
                entry.last_sent = Instant::now();
            }
        }
        Ok(())
    }

    /// Sends whatever path MTU probes are due, to peers that have spoken.
    ///
    /// A probe that fails to send is left to go unanswered: a size the
    /// socket refuses is a size the path does not carry, which is exactly
    /// what an unanswered probe concludes. Treating it as an error would end
    /// the poll loop for every peer over one session's search.
    fn drive_pmtu(&mut self) {
        let now = Instant::now();
        for entry in self.peers.values_mut() {
            if !entry.spoke {
                continue;
            }
            let Some(pmtu) = &mut entry.pmtu else {
                continue;
            };
            let retry = Duration::from_millis(entry.peer.retransmit.rto_ms().into());
            let sends = pmtu.due(now, retry);
            // A search that ran out may have fallen back.
            entry.datagram_limit = pmtu.current();
            for send in sends {
                let Ok(n) = entry.peer.probe(&send.token, send.size, &mut self.tx) else {
                    continue;
                };
                if self.socket.send_to(&self.tx[..n], entry.addr).is_ok() {
                    entry.last_sent = now;
                }
            }
        }
    }

    /// When the earliest keep-alive falls due, if any.
    fn next_keepalive(&self) -> Option<Duration> {
        let every = self.keepalive?;
        let now = Instant::now();
        self.peers
            .values()
            .map(|e| (e.last_sent + every).saturating_duration_since(now))
            .min()
    }

    /// Resends whatever has timed out, for every peer.
    fn drive_retransmits(&mut self) -> Result<()> {
        let now = self.now_ms();
        let ids: Vec<PeerId> = self.peers.keys().copied().collect();

        for id in ids {
            let Some(entry) = self.peers.get_mut(&id) else {
                continue;
            };
            let addr = entry.addr;
            let socket = &*self.socket;
            let stamp = &mut entry.last_sent;
            let mut large_resent = false;
            let mut resent = false;
            entry.peer.drive_retransmits(now, &mut self.tx, |frame| {
                large_resent |= frame.len() > BASE_DATAGRAM;
                resent = true;
                send_datagram(socket, frame, addr)?;
                *stamp = Instant::now();
                Ok(())
            })?;
            // A large frame needing a second go is ordinary loss, or a path
            // that no longer carries large frames. Asking is how to tell.
            if large_resent {
                if let Some(pmtu) = &mut entry.pmtu {
                    pmtu.suspect(Instant::now());
                }
            }
            // Through a relay, a resend may mean this side's NAT has moved it
            // and the port no longer knows where it is. Proving the address
            // again costs a hello, and is how the port finds out.
            if resent {
                if let Some(link) = self.rv.relayed.get_mut(&id) {
                    let soonest = link.last_hello + rendezvous::REFRESH_FLOOR;
                    if !link.legacy && link.next_refresh > soonest {
                        link.next_refresh = soonest;
                        // `wake_at`, written out: `entry` still borrows the
                        // peer table.
                        self.next_wake = Some(self.next_wake.map_or(soonest, |w| w.min(soonest)));
                    }
                }
            }

            // Anything given up on above that no queue is waiting for. A
            // fragmented message reports itself when its queue finishes; this
            // is the single unfragmented send, which reported nothing at all
            // until SPEC.md §5.5 was written down and found to be unmet here.
            let unreported = core::mem::take(&mut entry.peer.abandoned_unqueued);
            for _ in 0..unreported {
                self.events.push_back(Event::Sent {
                    peer: id,
                    delivered: false,
                });
            }
        }
        Ok(())
    }

    /// The largest payload one frame to `peer` carries now, the most
    /// [`send`](Self::send) accepts.
    ///
    /// It can change during a session. With path MTU discovery on, a session
    /// starts at what any path carries, rises as larger frames are confirmed,
    /// and falls back when a large reliable frame's resend prompts a check that
    /// goes unanswered; read it when sizing a message, not once at connect.
    pub fn max_payload(&self, peer: PeerId) -> Result<usize> {
        let entry = self.peers.get(&peer).ok_or(Error::UnknownPeer)?;
        Ok(entry.peer.max_payload(entry.datagram_limit))
    }

    /// Sends `data` to one peer, unreliably.
    ///
    /// `payload_type` says what shape the bytes have, so a transform suited to
    /// them runs before the generic compressor. [`PayloadType::Opaque`] means
    /// "just bytes" and is always correct.
    ///
    /// One frame only; anything larger is refused. A lost datagram is lost.
    pub fn send(&mut self, peer: PeerId, data: &[u8], payload_type: PayloadType) -> Result<()> {
        let entry = self.peers.get_mut(&peer).ok_or(Error::UnknownPeer)?;
        let addr = entry.addr;
        let limit = entry.datagram_limit;
        let n = entry
            .peer
            .seal(data, payload_type, None, None, limit, &mut self.tx)?;
        send_datagram(&*self.socket, &self.tx[..n], addr)?;
        entry.last_sent = Instant::now();
        Ok(())
    }

    /// Sends `data` to one peer, retransmitting until acknowledged.
    ///
    /// Any size. A payload larger than one frame is split across several and
    /// queued, so this returns without waiting either way. A message that
    /// needed splitting reports its outcome later as [`Event::Sent`].
    ///
    /// Progress happens inside [`poll`](Self::poll); an endpoint that queues a
    /// message and never polls sends nothing further.
    pub fn send_reliable(
        &mut self,
        peer: PeerId,
        data: &[u8],
        payload_type: PayloadType,
    ) -> Result<()> {
        let entry = self.peers.get_mut(&peer).ok_or(Error::UnknownPeer)?;
        let limit = entry.datagram_limit;

        // One frame is the common case and skips the queue entirely.
        if data.len() <= entry.peer.payload_room(limit, true, false) {
            if !entry.peer.session.peer_capabilities().supports_reliable() {
                return Err(Error::ReliabilityUnsupported);
            }
            let now = self.now_ms();
            let entry = self.peers.get_mut(&peer).ok_or(Error::UnknownPeer)?;
            let id = entry
                .peer
                .retransmit
                .register(now)
                .map_err(Error::Protocol)?;
            let addr = entry.addr;
            let n = entry
                .peer
                .seal(data, payload_type, Some(id), None, limit, &mut self.tx)?;
            send_datagram(&*self.socket, &self.tx[..n], addr)?;
            let entry = self.peers.get_mut(&peer).ok_or(Error::UnknownPeer)?;
            entry.last_sent = Instant::now();
            entry.peer.pending.push(Pending {
                id,
                payload_type,
                data: data.to_vec(),
                fragment: None,
                limit,
            });
            // A retransmission is now pending, and the loop only wakes for
            // work it has been told about.
            let due = entry.peer.retransmit.next_deadline_ms();
            if let Some(at) = due {
                let now_ms = self.now_ms();
                self.wake_at(Instant::now() + Duration::from_millis(at.saturating_sub(now_ms)));
            }
            return Ok(());
        }

        entry.peer.queue_message(data, payload_type, limit)?;
        // Opens the queue gate; `drive_queues` recounts and closes it again
        // once everything has gone out.
        self.queueing += 1;
        // Start it now rather than at the next poll, so a caller that queues
        // and then blocks in poll does not wait a round trip for nothing.
        self.drive_queues()?;
        self.rescan_wake();
        Ok(())
    }

    /// Reliable messages to one peer still awaiting acknowledgement.
    pub fn unacknowledged(&self, peer: PeerId) -> usize {
        self.peers
            .get(&peer)
            .map(|e| e.peer.retransmit.in_flight())
            .unwrap_or(0)
    }
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("addr", &self.socket.local_addr().ok())
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}
