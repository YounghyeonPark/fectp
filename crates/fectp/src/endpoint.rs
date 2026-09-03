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

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use fectp_core::frame::{FrameType, Header, HEADER_LEN};
use fectp_core::session::{
    preshared_key, Initiator, ResumeInitiator, ResumeResponder, Responder, ResumptionTicket,
    Session, PATH_TOKEN_LEN,
};
use fectp_core::PublicKey;
use rand_core::{OsRng, RngCore};

use crate::pipeline::{decoded_capacity, deliver, Ingested, Peer, Pending, TicketStore};
use crate::{
    is_timeout, local_capabilities, max_datagram, Error, Identity, PayloadType, Result,
};

/// A stable handle to one connected peer.
///
/// Handles are never reused, so one belonging to a peer that has gone away
/// stops resolving rather than silently addressing somebody else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(u64);

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
    /// A message that had to be split across frames finished.
    ///
    /// Arrives once every fragment has been acknowledged, or once one has been
    /// abandoned — a fragmented message missing a piece is not partially
    /// delivered, it is not delivered.
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
    /// Nothing arrived before the timeout elapsed.
    Idle,
}

/// How long to wait for a reply before resending the opening frame.
const HANDSHAKE_RETRY_MS: u64 = 250;

/// How many times to send an opening frame before giving up.
const HANDSHAKE_ATTEMPTS: u8 = 4;

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

/// Frames per second from unknown addresses that will be tried against a
/// session before the rest are dropped unexamined.
///
/// Routing on the address costs a hash lookup. Routing on the identifier alone
/// costs an AEAD verification, and anyone who can address the socket can ask
/// for one by guessing a 32-bit value. This is the ceiling on that: comfortably
/// above any rate a real migration produces — a peer that has moved sends a
/// handful of frames, not hundreds — and far below what would cost anything.
pub const MAX_MIGRATIONS_PER_SECOND: u32 = 256;

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
    Full(Box<Initiator>),
    Psk(Box<ResumeInitiator>),
}

struct Outbound {
    handshake: Handshake,
    addr: SocketAddr,
    session_id: u32,
    /// The opening frame, kept so it can be sent again if the reply is lost.
    frame: Vec<u8>,
    next_attempt: Instant,
    attempts: u8,
}

/// How a server authenticates the peers that connect to it.
///
/// A server speaks exactly one of these. It is not a negotiation and there is
/// no wire field for it: a peer using a different mode sends frame types this
/// server does not accept, and is ignored. A server that accepted several
/// modes at once would let an attacker pick the weakest.
enum Mode {
    /// Public-key: peers must know this server's public key.
    PublicKey(Identity),
    /// Pre-shared key: peers must hold the same secret. Encrypted, but with
    /// nothing to distribute except that secret.
    Psk(ResumptionTicket),
}

/// Serves many FECTP peers from one UDP socket.
pub struct Endpoint {
    socket: UdpSocket,
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
    /// The same, for frames arriving from an address with no session on it.
    migration_budget: f32,
    migration_refilled: Instant,
    migration_rate: u32,
    max_peers: usize,
    /// Sent in the payload of every handshake response.
    handshake_reply: Vec<u8>,
    /// How long a peer may go without being sent anything, or `None` to say
    /// nothing when there is nothing to say.
    keepalive: Option<Duration>,
    next_id: u64,

    rx: Vec<u8>,
    tx: Vec<u8>,
    ack: Vec<u8>,
    scratch: Vec<u8>,
    epoch: Instant,
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
        Self::with_mode(addr, Mode::PublicKey(identity))
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

    fn with_mode(addr: impl ToSocketAddrs, mode: Mode) -> Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        let size = max_datagram() + Initiator::OVERHEAD;
        Ok(Self {
            socket,
            mode,
            tickets: TicketStore::default(),
            peers: HashMap::new(),
            routes: HashMap::new(),
            by_session: HashMap::new(),
            events: VecDeque::new(),
            handshake_budget: MAX_HANDSHAKES_PER_SECOND as f32,
            handshake_refilled: Instant::now(),
            handshake_rate: MAX_HANDSHAKES_PER_SECOND,
            migration_budget: MAX_MIGRATIONS_PER_SECOND as f32,
            migration_refilled: Instant::now(),
            migration_rate: MAX_MIGRATIONS_PER_SECOND,
            max_peers: MAX_PEERS,
            handshake_reply: Vec::new(),
            keepalive: None,
            outbound: HashMap::new(),
            next_id: 0,
            rx: vec![0u8; size],
            tx: vec![0u8; size],
            ack: vec![0u8; size],
            scratch: vec![0u8; size],
            epoch: Instant::now(),
        })
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
            Mode::PublicKey(identity) => Some(identity.public()),
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
        let mut frame = vec![0u8; max_datagram() + Initiator::OVERHEAD];

        let (handshake, len) = match &self.mode {
            Mode::PublicKey(identity) => {
                let peer = peer_public.ok_or(Error::MissingPeerKey)?;
                let mut initiator =
                    Initiator::new(identity.keypair(), *peer, session_id, caps)?;
                let len = initiator.write_init(&mut OsRng, zero_rtt, &mut frame)?;
                (Handshake::Full(Box::new(initiator)), len)
            }
            Mode::Psk(psk) => {
                let mut initiator = ResumeInitiator::new(
                    *psk,
                    fectp_core::ANONYMOUS,
                    session_id,
                    caps,
                )?;
                let len = initiator.write_init(&mut OsRng, zero_rtt, &mut frame)?;
                (Handshake::Psk(Box::new(initiator)), len)
            }
        };
        frame.truncate(len);
        self.socket.send_to(&frame, addr)?;

        let peer_id = PeerId(self.next_id);
        self.next_id += 1;
        self.outbound.insert(
            peer_id,
            Outbound {
                handshake,
                addr,
                session_id,
                frame,
                next_attempt: Instant::now() + Duration::from_millis(HANDSHAKE_RETRY_MS),
                attempts: 1,
            },
        );
        Ok(peer_id)
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
            self.drive_retransmits()?;
            if let Some(event) = self.drive_handshakes()? {
                return Ok(event);
            }
            self.drive_queues()?;
            self.drive_keepalives()?;
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }

            // Wake for whichever comes first: the caller's timeout or the
            // nearest retransmission deadline across all peers.
            let now = self.now_ms();
            let until_retransmit = self
                .peers
                .values()
                .filter_map(|e| e.peer.retransmit.next_deadline_ms())
                .min()
                .map(|at| Duration::from_millis(at.saturating_sub(now)));
            let until_deadline = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            // An unanswered handshake needs waking for too.
            let until_retransmit = match self
                .outbound
                .values()
                .map(|o| o.next_attempt)
                .min()
                .map(|at| at.saturating_duration_since(Instant::now()))
            {
                Some(handshake) => Some(match until_retransmit {
                    Some(data) => data.min(handshake),
                    None => handshake,
                }),
                None => until_retransmit,
            };
            // A keep-alive is a third thing worth waking for. Sleeping past
            // it would let a NAT mapping lapse while this endpoint sat in
            // `poll` with nothing else to do.
            let wait = [until_retransmit, until_deadline, self.next_keepalive()]
                .into_iter()
                .flatten()
                .min();
            // A zero timeout means "block forever" to the socket layer, which
            // is the opposite of what is meant here.
            self.socket
                .set_read_timeout(wait.map(|w| w.max(Duration::from_millis(1))))?;

            let (n, from) = match self.socket.recv_from(&mut self.rx) {
                Ok(v) => v,
                Err(e) if is_timeout(&e) => {
                    if deadline.is_none_or(|d| Instant::now() >= d) {
                        return Ok(Event::Idle);
                    }
                    continue;
                }
                Err(e) => return Err(Error::Io(e)),
            };

            if let Some(event) = self.dispatch(n, from)? {
                return Ok(event);
            }
        }
    }

    /// Routes one received datagram.
    fn dispatch(&mut self, n: usize, from: SocketAddr) -> Result<Option<Event>> {
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
            (
                FrameType::HandshakeResponse | FrameType::ResumeResponse,
                _,
            ) => self.complete_outbound(n, from, header.session_id),
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
        // address the socket, so it is paid for out of a budget.
        if self.by_session.contains_key(&session_id) && !self.may_try_unknown_address() {
            return Ok(None);
        }

        // Walk the sessions wearing this identifier by index rather than
        // collecting them, so the path does not allocate either.
        let mut at = 0;
        loop {
            let Some(peer_id) = self
                .by_session
                .get(&session_id)
                .and_then(|sharing| sharing.get(at))
                .copied()
            else {
                return Ok(None);
            };
            at += 1;

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
        // session off the eviction list.
        entry.spoke = true;
        // It answered, so it has the handshake response and will not ask again.
        entry.handshake_reply = None;

        if established {
            if ack_len > 0 {
                self.socket.send_to(&self.ack[..ack_len], from)?;
                if let Some(entry) = self.peers.get_mut(&peer_id) {
                    entry.last_sent = Instant::now();
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
        self.socket.send_to(&self.ack[..len], addr)?;
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
        // not describe this one.
        entry.peer.forget_path();
        let session_id = entry.session_id;

        self.routes.remove(&(previous, session_id));
        self.routes.insert((from, session_id), peer_id);

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
        Ok(Some(self.register_as(peer_id, link, addr, reply, resumed, true)))
    }

    fn accept_full(&mut self, n: usize, from: SocketAddr) -> Result<Event> {
        let Mode::PublicKey(identity) = &self.mode else {
            return Err(Error::Handshake);
        };
        let mut responder = Responder::new(identity.keypair(), local_capabilities());
        let mut staging = vec![0u8; self.rx.len()];
        let len = responder.read_init(&self.rx[..n], &mut staging)?;
        let zero_rtt = staging[..len].to_vec();

        let reply = core::mem::take(&mut self.handshake_reply);
        let written = responder.write_response(&mut OsRng, &reply, &mut self.tx);
        self.handshake_reply = reply;
        let (session, sent) = written?;
        self.socket.send_to(&self.tx[..sent], from)?;
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
            Mode::Psk(psk) if psk.id() == &id => Some((*psk, fectp_core::ANONYMOUS)),
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
        self.socket.send_to(&self.tx[..sent], from)?;
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
        let datagram_limit =
            (link.peer_capabilities().max_frame_size as usize).min(max_datagram());

        let peer_id = PeerId(self.next_id);
        self.next_id += 1;
        self.file(peer_id, link, addr, session_id, datagram_limit);

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
        let datagram_limit =
            (link.peer_capabilities().max_frame_size as usize).min(max_datagram());
        self.file(peer_id, link, addr, session_id, datagram_limit);

        Event::Connected {
            peer: peer_id,
            zero_rtt,
            resumed,
            initiated,
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
    /// Sends a small frame to any peer nothing has been sent to for `every`.
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
    /// `None` turns it off.
    pub fn set_keepalive(&mut self, every: Option<Duration>) {
        self.keepalive = every;
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

    /// Sets how many frames a second from unknown addresses may be tried
    /// against a session.
    ///
    /// The default is [`MAX_MIGRATIONS_PER_SECOND`]. Raise it for an endpoint
    /// serving many peers on paths that move often; lower it, or set it to
    /// zero, for one whose peers never move — at zero no session will ever
    /// follow a peer that changes address.
    pub fn set_max_migrations_per_second(&mut self, rate: u32) {
        self.migration_rate = rate;
        self.migration_budget = self.migration_budget.min(rate as f32);
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
        self.socket.send_to(&reply, from)?;
        if let Some(entry) = self.peers.get_mut(&peer_id) {
            entry.handshake_reply = left.checked_sub(1).map(|left| (reply, left));
        }
        Ok(true)
    }

    /// Sets a payload to carry in the response to every handshake.
    ///
    /// A peer that sends data with its handshake ([`Connection::connect_and_send`])
    /// gets an answer in the same round trip rather than the one after it — the
    /// other half of the property this protocol exists for, and until now the
    /// half an `Endpoint` could not reach. `Connection` already delivers it:
    /// the payload arrives through the first [`recv`](Connection::recv) as
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
    /// if it would not fit a handshake frame.
    pub fn set_handshake_reply(&mut self, payload: &[u8]) -> Result<()> {
        let overhead = Responder::OVERHEAD
            .max(ResumeResponder::OVERHEAD)
;
        if payload.len() + overhead > max_datagram() {
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
    /// Whether a frame from an unknown address may be tried against a session.
    ///
    /// Spends from a budget rather than refusing outright, so a genuine
    /// migration — a few frames — always gets through, and a flood of guessed
    /// identifiers cannot buy unbounded verification.
    fn may_try_unknown_address(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.migration_refilled).as_secs_f32();
        self.migration_refilled = now;
        self.migration_budget = (self.migration_budget + elapsed * self.migration_rate as f32)
            .min(self.migration_rate as f32);

        if self.migration_budget < 1.0 {
            return false;
        }
        self.migration_budget -= 1.0;
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

    fn file(
        &mut self,
        peer_id: PeerId,
        link: Session,
        addr: SocketAddr,
        session_id: u32,
        datagram_limit: usize,
    ) {
        self.make_room();

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
                peer: Peer::new(link, max_datagram()),
                addr,
                session_id,
                filed: Instant::now(),
                last_sent: Instant::now(),
                handshake_reply: None,
                probe: None,
                spoke: false,
                datagram_limit,
            },
        );
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
            let limit = entry.datagram_limit;
            let socket = &self.socket;
            let stamp = &mut entry.last_sent;
            let finished =
                entry
                    .peer
                    .drive_queue(now, limit, &mut self.tx, |frame| {
                        socket.send_to(frame, addr)?;
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
        Ok(())
    }

    /// Resends unanswered opening frames, and abandons the hopeless ones.    /// Resends unanswered opening frames, and abandons the hopeless ones.
    fn drive_handshakes(&mut self) -> Result<Option<Event>> {
        let now = Instant::now();
        let due: Vec<PeerId> = self
            .outbound
            .iter()
            .filter(|(_, o)| o.next_attempt <= now)
            .map(|(id, _)| *id)
            .collect();

        for id in due {
            let Some(outbound) = self.outbound.get_mut(&id) else {
                continue;
            };
            if outbound.attempts >= HANDSHAKE_ATTEMPTS {
                self.outbound.remove(&id);
                return Ok(Some(Event::ConnectFailed { peer: id }));
            }
            outbound.attempts += 1;
            // Back off, so an unreachable peer is not hammered.
            outbound.next_attempt = now
                + Duration::from_millis(HANDSHAKE_RETRY_MS * u64::from(outbound.attempts));
            let (frame, addr) = (outbound.frame.clone(), outbound.addr);
            self.socket.send_to(&frame, addr)?;
        }
        Ok(None)
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
            .filter(|(_, e)| now.duration_since(e.last_sent) >= every)
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
            self.socket.send_to(&self.ack[..n], addr)?;
            if let Some(entry) = self.peers.get_mut(&id) {
                entry.last_sent = Instant::now();
            }
        }
        Ok(())
    }

    /// When the earliest keep-alive falls due, if any.
    fn next_keepalive(&self) -> Option<Duration> {
        let every = self.keepalive?;
        let now = Instant::now();
        self.peers
            .values()
            .map(|e| {
                (e.last_sent + every).saturating_duration_since(now)
            })
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
            let limit = entry.datagram_limit;
            let socket = &self.socket;
            let stamp = &mut entry.last_sent;
            entry
                .peer
                .drive_retransmits(now, limit, &mut self.tx, |frame| {
                    socket.send_to(frame, addr)?;
                    *stamp = Instant::now();
                    Ok(())
                })?;
        }
        Ok(())
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
        self.socket.send_to(&self.tx[..n], addr)?;
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
            let id = entry.peer.retransmit.register(now).map_err(Error::Protocol)?;
            let addr = entry.addr;
            let n = entry
                .peer
                .seal(data, payload_type, Some(id), None, limit, &mut self.tx)?;
            self.socket.send_to(&self.tx[..n], addr)?;
            let entry = self.peers.get_mut(&peer).ok_or(Error::UnknownPeer)?;
            entry.last_sent = Instant::now();
            entry.peer.pending.push(Pending {
                id,
                payload_type,
                data: data.to_vec(),
                fragment: None,
            });
            return Ok(());
        }

        entry.peer.queue_message(data, payload_type, limit)?;
        // Start it now rather than at the next poll, so a caller that queues
        // and then blocks in poll does not wait a round trip for nothing.
        self.drive_queues()
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
