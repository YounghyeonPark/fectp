//! Rendezvous and relay: two peers behind NATs reaching one another through a
//! third that both can reach (SPEC Appendix A).
//!
//! [`Rendezvous`] is that third peer. Clients are ordinary [`Endpoint`]s that
//! register with it ([`Endpoint::connect_rendezvous`]) and ask for one
//! another by key ([`Endpoint::introduce`]). When both have asked, each is
//! told where the other is, and they punch holes in their NATs and connect
//! directly. When a NAT will not allow that — a symmetric one gives every
//! destination its own mapping, so the address the rendezvous saw is no use
//! to anyone else — the rendezvous relays their datagrams instead, without
//! being able to read them: the session is still between the two clients'
//! keys.
//!
//! Every message here rides on an ordinary FECTP session, so nothing about a
//! frame changes. What is defined is what the messages say.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use fectp_core::PublicKey;
use rand_core::{OsRng, RngCore};

use crate::{Endpoint, Event, Identity, PayloadType, PeerId, Result};

/// Takes a lock whatever happened to its last holder. Every value behind one
/// here is complete after each write, so a thread that panicked holding it
/// left nothing half-done — and a panic here would end the poll loop, or, in
/// a binding, the process.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A key, as the messages carry it.
pub(crate) type Key = PublicKey;

/// Byte 0 of every datagram here that is not a frame: version 15, which no
/// version-1 receiver implements (SPEC A.5).
pub(crate) const NOT_A_FRAME: u8 = 0xF0;
pub(crate) const PUNCH: u8 = 0x50;
pub(crate) const BIND: u8 = 0x42;
pub(crate) const CHECK: u8 = 0x43;
pub(crate) const PROOF: u8 = 0x44;
/// A bind's token and a check's nonce.
pub(crate) const SECRET_LEN: usize = 16;

/// How long one client's request waits for the other's (SPEC A.3).
pub const INTRODUCTION_WINDOW: Duration = Duration::from_secs(30);

/// How long after an introduction a relay may be asked for it (SPEC A.4).
pub const RELAY_WINDOW: Duration = Duration::from_secs(60);

/// How long a relay allocation lives without forwarding anything.
pub const RELAY_IDLE: Duration = Duration::from_secs(60);

/// Relay allocations held at once, by one rendezvous.
pub const MAX_RELAYS: usize = 64;

/// Relay allocations held at once for clients at one IP address.
///
/// Per address rather than per key: keys cost nothing to make, so a cap per
/// key is no cap at all.
pub const MAX_RELAYS_PER_IP: usize = 4;

/// Clients registered at once from one IP address.
pub const MAX_CLIENTS_PER_IP: usize = 32;

/// Bytes a second one relay allocation forwards, in both directions together.
/// More is dropped.
pub const RELAY_BYTES_PER_SECOND: usize = 1 << 20;

/// Requests — to be introduced, or to be relayed — that one IP address may
/// make of a rendezvous in a second, sustained; a burst of twice this is
/// allowed.
pub const INTRODUCTIONS_PER_SECOND: f32 = 4.0;

/// Why a rendezvous would not introduce or relay (SPEC A.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unavailable {
    /// The key is not registered with the rendezvous.
    NotRegistered,
    /// The rendezvous will not introduce this pair.
    Refused,
    /// The rendezvous will not relay for this pair.
    NoRelay,
    /// The key's holder did not ask for this client in time.
    NotAsked,
    /// A reason this version does not know.
    Other(u8),
    /// Nothing answered: the direct handshake and the relayed one both failed,
    /// or the rendezvous never replied.
    Unreachable,
}

impl Unavailable {
    pub(crate) fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::NotRegistered,
            1 => Self::Refused,
            2 => Self::NoRelay,
            3 => Self::NotAsked,
            other => Self::Other(other),
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Self::NotRegistered => 0,
            Self::Refused => 1,
            Self::NoRelay => 2,
            Self::NotAsked => 3,
            Self::Other(b) => b,
            Self::Unreachable => 0xFF,
        }
    }
}

/// One message between a client and the rendezvous (SPEC A.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Control {
    Register,
    Introduce(Key),
    Relay(Key),
    Observed(SocketAddr),
    Introduction(Key, SocketAddr),
    Unavailable(Key, u8),
    RelayOffer(Key, SocketAddr, [u8; SECRET_LEN]),
}

fn put_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_le_bytes());
}

/// An address at the start of `body`, and what follows it.
fn take_addr(body: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let (&family, rest) = body.split_first()?;
    let len = match family {
        4 => 4,
        6 => 16,
        _ => return None,
    };
    if rest.len() < len + 2 {
        return None;
    }
    let ip = match family {
        4 => IpAddr::from(<[u8; 4]>::try_from(&rest[..4]).ok()?),
        _ => IpAddr::from(<[u8; 16]>::try_from(&rest[..16]).ok()?),
    };
    let port = u16::from_le_bytes([rest[len], rest[len + 1]]);
    Some((SocketAddr::new(ip, port), &rest[len + 2..]))
}

fn take_key(body: &[u8]) -> Option<(Key, &[u8])> {
    if body.len() < 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&body[..32]);
    Some((key, &body[32..]))
}

impl Control {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Control::Register => out.push(0x01),
            Control::Introduce(key) => {
                out.push(0x02);
                out.extend_from_slice(key);
            }
            Control::Relay(key) => {
                out.push(0x03);
                out.extend_from_slice(key);
            }
            Control::Observed(addr) => {
                out.push(0x81);
                put_addr(&mut out, *addr);
            }
            Control::Introduction(key, addr) => {
                out.push(0x82);
                out.extend_from_slice(key);
                put_addr(&mut out, *addr);
            }
            Control::Unavailable(key, reason) => {
                out.push(0x83);
                out.extend_from_slice(key);
                out.push(*reason);
            }
            Control::RelayOffer(key, addr, token) => {
                out.push(0x84);
                out.extend_from_slice(key);
                put_addr(&mut out, *addr);
                out.extend_from_slice(token);
            }
        }
        out
    }

    /// `None` for a kind this version does not know, or a body of the wrong
    /// length for its kind: both are ignored (SPEC A.2).
    pub(crate) fn decode(message: &[u8]) -> Option<Self> {
        let (&kind, body) = message.split_first()?;
        let parsed = match kind {
            0x01 if body.is_empty() => Control::Register,
            0x02 => {
                let (key, rest) = take_key(body)?;
                rest.is_empty().then_some(())?;
                Control::Introduce(key)
            }
            0x03 => {
                let (key, rest) = take_key(body)?;
                rest.is_empty().then_some(())?;
                Control::Relay(key)
            }
            0x81 => {
                let (addr, rest) = take_addr(body)?;
                rest.is_empty().then_some(())?;
                Control::Observed(addr)
            }
            0x82 => {
                let (key, rest) = take_key(body)?;
                let (addr, rest) = take_addr(rest)?;
                rest.is_empty().then_some(())?;
                Control::Introduction(key, addr)
            }
            0x83 => {
                let (key, rest) = take_key(body)?;
                match rest {
                    [reason] => Control::Unavailable(key, *reason),
                    _ => return None,
                }
            }
            0x84 => {
                let (key, rest) = take_key(body)?;
                let (addr, rest) = take_addr(rest)?;
                let token: [u8; SECRET_LEN] = rest.try_into().ok()?;
                Control::RelayOffer(key, addr, token)
            }
            _ => return None,
        };
        Some(parsed)
    }
}

/// Whether the holder of `ours` starts the handshake with the holder of
/// `theirs`: the smaller key does (SPEC A.3).
pub(crate) fn starts(ours: &Key, theirs: &Key) -> bool {
    ours < theirs
}

/// A pair of keys in a fixed order, so either side's request finds the same
/// entry.
type Pair = (Key, Key);

fn pair(a: &Key, b: &Key) -> Pair {
    if a < b {
        (*a, *b)
    } else {
        (*b, *a)
    }
}

/// A registered client.
struct Client {
    key: Key,
    addr: SocketAddr,
}

/// What one IP address may still ask of a rendezvous, refilled over time.
///
/// Per address rather than per client: keys cost nothing, so one address can
/// hold many registrations, and a budget per registration would multiply by
/// however many it chose to make.
struct Budget {
    left: f32,
    refilled: Instant,
}

/// Who may be introduced to whom.
type Policy = Box<dyn Fn(&Key, &Key) -> bool + Send + Sync>;

/// The longest [`Rendezvous::poll`] waits, whatever it is asked to: requests
/// and relays expire on time only if it comes round.
const MAX_POLL_WAIT: Duration = Duration::from_secs(1);

/// The third party two NATed peers both reach (SPEC Appendix A).
///
/// An [`Endpoint`] underneath, in public-key mode, plus the bookkeeping for
/// introductions and the relay allocations. Drive it with [`poll`](Self::poll)
/// in a loop, as an endpoint is driven.
pub struct Rendezvous {
    endpoint: Endpoint,
    clients: HashMap<PeerId, Client>,
    by_key: HashMap<Key, PeerId>,
    budgets: HashMap<IpAddr, Budget>,
    /// Who asked for whom, and when.
    asked: HashMap<(Key, Key), Instant>,
    /// Pairs introduced, and when, which is what a relay may be asked for.
    introduced: HashMap<Pair, Instant>,
    relays: HashMap<Pair, Allocation>,
    policy: Policy,
    window: Duration,
    public: PublicKey,
    /// The address relay ports are advertised at, when it is not the one the
    /// rendezvous is bound to.
    relay_ip: Option<IpAddr>,
}

impl Rendezvous {
    /// Binds to `addr`, serving `identity`. Clients must know its public key.
    ///
    /// Relay ports are opened on the same IP address and advertised at it. If
    /// that is a wildcard — `0.0.0.0`, `[::]` — or not the address clients
    /// reach this host at, as behind a cloud provider's 1:1 NAT, say which one
    /// they do reach with [`set_relay_address`](Self::set_relay_address);
    /// until then a wildcard-bound rendezvous refuses to relay rather than
    /// advertise an address nobody can send to.
    pub fn bind(addr: impl ToSocketAddrs, identity: Identity) -> Result<Self> {
        let public = *identity.public();
        let mut endpoint = Endpoint::bind(addr, identity)?;
        // A rendezvous holds sessions with strangers for as long as they want
        // to be found. Keep-alives keep their NAT mappings open, and the
        // timeout releases the ones that have gone, so a departed client's
        // address — which may be someone else's by now — is not handed out.
        endpoint.set_keepalive(Some(Duration::from_secs(15)));
        endpoint.set_peer_timeout(Some(Duration::from_secs(60)));
        Ok(Self {
            endpoint,
            clients: HashMap::new(),
            by_key: HashMap::new(),
            budgets: HashMap::new(),
            asked: HashMap::new(),
            introduced: HashMap::new(),
            relays: HashMap::new(),
            policy: Box::new(|_, _| true),
            window: INTRODUCTION_WINDOW,
            public,
            relay_ip: None,
        })
    }

    /// The key clients connect to.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Where it is bound.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// The IP address clients reach this host at, for relay ports to be
    /// advertised at. Needed when it is bound to a wildcard, or reached
    /// through a NAT of its own.
    pub fn set_relay_address(&mut self, ip: IpAddr) {
        self.relay_ip = Some(ip);
    }

    /// Decides which pairs may be introduced, and so relayed. Every pair
    /// that has asked for each other, by default.
    pub fn set_policy(&mut self, allow: impl Fn(&Key, &Key) -> bool + Send + Sync + 'static) {
        self.policy = Box::new(allow);
    }

    /// How long one client's request waits for the other's, replacing
    /// [`INTRODUCTION_WINDOW`].
    ///
    /// A client gives up on an introduction after
    /// [`INTRODUCTION_DEADLINE`], ninety seconds, whatever this says, so a
    /// window longer than that ends in the client reporting it unreachable
    /// first.
    pub fn set_introduction_window(&mut self, window: Duration) {
        self.window = window;
    }

    /// Clients registered now.
    pub fn clients(&self) -> usize {
        self.clients.len()
    }

    /// Relay allocations held now.
    pub fn relays(&self) -> usize {
        self.relays.len()
    }

    /// Does whatever is due, waiting up to `timeout` for something to.
    ///
    /// Returns within a second whatever `timeout` says, `None` included:
    /// requests and relays expire on time only if this comes round.
    ///
    /// A client cannot make this fail. What it sends that cannot be answered
    /// — a full window, a session that has gone — is that client's problem
    /// and is dropped; an error here is the socket's.
    pub fn poll(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.expire();
        let wait = timeout.map_or(MAX_POLL_WAIT, |t| t.min(MAX_POLL_WAIT));
        match self.endpoint.poll(Some(wait))? {
            Event::Message { peer, data } => {
                if let Some(control) = Control::decode(&data) {
                    self.handle(peer, control);
                }
            }
            Event::PeerLost { peer } => self.forget(peer),
            _ => {}
        }
        Ok(())
    }

    /// Sends a client a message, dropping it if it cannot go.
    fn send(&mut self, peer: PeerId, control: &Control) {
        let _ = self
            .endpoint
            .send_reliable(peer, &control.encode(), PayloadType::Opaque);
    }

    fn forget(&mut self, peer: PeerId) {
        if let Some(client) = self.clients.remove(&peer) {
            if self.by_key.get(&client.key) == Some(&peer) {
                self.by_key.remove(&client.key);
            }
        }
    }

    /// Takes one request's worth from an address's budget, if it has one.
    fn spend(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let budget = self.budgets.entry(ip).or_insert(Budget {
            left: 2.0 * INTRODUCTIONS_PER_SECOND,
            refilled: now,
        });
        let refill = now.duration_since(budget.refilled).as_secs_f32();
        budget.left =
            (budget.left + refill * INTRODUCTIONS_PER_SECOND).min(2.0 * INTRODUCTIONS_PER_SECOND);
        budget.refilled = now;
        if budget.left < 1.0 {
            return false;
        }
        budget.left -= 1.0;
        true
    }

    fn handle(&mut self, peer: PeerId, control: Control) {
        if control == Control::Register {
            return self.register(peer);
        }
        // Nothing but registration is listened to from a session that has not
        // registered: the address of one that has not spoken is unproven.
        let Some(client) = self.clients.get(&peer) else {
            return;
        };
        let (from, ip) = (client.key, client.addr.ip());
        let target = match control {
            Control::Introduce(target) | Control::Relay(target) => target,
            _ => return,
        };
        // Bounded per address: each request has its target send to an
        // address it did not choose (SPEC A.3), and a relay costs this host's
        // bandwidth. Over budget, it is refused, not silently dropped.
        if !self.spend(ip) {
            // Told to the asker only, relay or not. Over budget is the cheap
            // path by design: answering the other side as well would let a
            // flood of requests become a flood of messages to whoever they
            // name.
            return self.send(
                peer,
                &Control::Unavailable(target, Unavailable::Refused.to_byte()),
            );
        }
        match control {
            Control::Introduce(_) => self.introduce(peer, from, target),
            _ => self.relay(peer, from, target),
        }
    }

    fn register(&mut self, peer: PeerId) {
        let (Some(key), Some(addr)) = (
            self.endpoint.peer_public_key(peer).copied(),
            self.endpoint.peer_addr(peer),
        ) else {
            return;
        };
        if !self.clients.contains_key(&peer) {
            let from_ip = self
                .clients
                .values()
                .filter(|c| c.addr.ip() == addr.ip())
                .count();
            if from_ip >= MAX_CLIENTS_PER_IP {
                return;
            }
        }
        // A key reconnecting replaces its old registration.
        if let Some(old) = self.by_key.insert(key, peer) {
            if old != peer {
                self.clients.remove(&old);
            }
        }
        self.clients.insert(peer, Client { key, addr });
        self.send(peer, &Control::Observed(addr));
    }

    fn introduce(&mut self, peer: PeerId, from: Key, target: Key) {
        if target == from {
            return;
        }
        if !(self.policy)(&from, &target) {
            return self.send(
                peer,
                &Control::Unavailable(target, Unavailable::Refused.to_byte()),
            );
        }
        let now = Instant::now();
        // Held for the window even if the target has not registered yet: two
        // peers starting at the same moment should not depend on which one's
        // registration lands first.
        self.asked.insert((from, target), now);
        // Introduced only once both have asked (SPEC A.3).
        let mutual = self
            .asked
            .get(&(target, from))
            .is_some_and(|at| now.duration_since(*at) <= self.window);
        let Some(&other) = self.by_key.get(&target) else {
            return;
        };
        if !mutual {
            return;
        }
        // The addresses as they are now: a session that moved has been
        // validated at its new one (SPEC 5.8), and that is the one to give.
        let (Some(here), Some(there)) = (
            self.endpoint.peer_addr(peer),
            self.endpoint.peer_addr(other),
        ) else {
            return;
        };
        self.asked.remove(&(from, target));
        self.asked.remove(&(target, from));
        self.introduced.insert(pair(&from, &target), now);
        self.send(peer, &Control::Introduction(target, there));
        self.send(other, &Control::Introduction(from, here));
    }

    /// Refuses a relay to both sides of the pair: each is waiting on it, and
    /// the one that did not ask would otherwise hear only its own deadline.
    fn refuse_relay(&mut self, from: Key, target: Key, reason: Unavailable) {
        for (to, about) in [(from, target), (target, from)] {
            if let Some(&peer) = self.by_key.get(&to) {
                self.send(peer, &Control::Unavailable(about, reason.to_byte()));
            }
        }
    }

    fn relay(&mut self, peer: PeerId, from: Key, target: Key) {
        let key = pair(&from, &target);
        let recent = self
            .introduced
            .get(&key)
            .is_some_and(|at| at.elapsed() <= RELAY_WINDOW);
        let Some(&other) = self.by_key.get(&target) else {
            return self.send(
                peer,
                &Control::Unavailable(target, Unavailable::NotRegistered.to_byte()),
            );
        };
        // A pair not introduced recently has nobody waiting on the other
        // side, so only the asker hears; telling the other too would let
        // anyone send it a message per request.
        if !recent {
            return self.send(
                peer,
                &Control::Unavailable(target, Unavailable::NoRelay.to_byte()),
            );
        }
        if !(self.policy)(&from, &target) {
            return self.refuse_relay(from, target, Unavailable::NoRelay);
        }

        if !self.relays.contains_key(&key) {
            let ips = [self.clients.get(&peer), self.clients.get(&other)]
                .into_iter()
                .flatten()
                .map(|c| c.addr.ip())
                .collect::<HashSet<_>>();
            let crowded = ips.iter().any(|ip| {
                self.relays.values().filter(|a| a.ips.contains(ip)).count() >= MAX_RELAYS_PER_IP
            });
            let Ok(bound) = self.local_addr().map(|a| a.ip()) else {
                return self.refuse_relay(from, target, Unavailable::NoRelay);
            };
            // Advertised where clients can send. A wildcard is not such an
            // address, and nothing better is known without being told.
            let advertised = self.relay_ip.unwrap_or(bound);
            if self.relays.len() >= MAX_RELAYS || crowded || advertised.is_unspecified() {
                return self.refuse_relay(from, target, Unavailable::NoRelay);
            }
            let Ok(allocation) = Allocation::open(bound, advertised, ips) else {
                return self.refuse_relay(from, target, Unavailable::NoRelay);
            };
            self.relays.insert(key, allocation);
        }
        let allocation = &self.relays[&key];
        // Port 0 for the smaller key, port 1 for the other, whoever asked.
        let (first, second) = key;
        let offers = [
            (
                first,
                second,
                allocation.ports[0].advertised,
                allocation.ports[0].token,
            ),
            (
                second,
                first,
                allocation.ports[1].advertised,
                allocation.ports[1].token,
            ),
        ];
        for (to_key, other_key, addr, token) in offers {
            if let Some(&to) = self.by_key.get(&to_key) {
                self.send(to, &Control::RelayOffer(other_key, addr, token));
            }
        }
    }

    /// Releases what has run out: unanswered requests, old introductions,
    /// relays that have forwarded nothing for a while.
    fn expire(&mut self) {
        let now = Instant::now();
        let window = self.window;
        let mut expired = Vec::new();
        self.asked.retain(|&(from, target), at| {
            let live = now.duration_since(*at) <= window;
            if !live {
                expired.push((from, target));
            }
            live
        });
        for (from, target) in expired {
            if let Some(&peer) = self.by_key.get(&from) {
                // Never registered, or registered and did not ask.
                let reason = if self.by_key.contains_key(&target) {
                    Unavailable::NotAsked
                } else {
                    Unavailable::NotRegistered
                };
                self.send(peer, &Control::Unavailable(target, reason.to_byte()));
            }
        }
        self.introduced
            .retain(|_, at| now.duration_since(*at) <= RELAY_WINDOW);
        self.relays.retain(|_, a| !a.idle(now));
        self.budgets
            .retain(|_, b| now.duration_since(b.refilled) < Duration::from_secs(60));
    }
}

impl std::fmt::Debug for Rendezvous {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rendezvous")
            .field("clients", &self.clients.len())
            .field("relays", &self.relays.len())
            .finish_non_exhaustive()
    }
}

/// One side of a relay allocation.
struct Port {
    socket: UdpSocket,
    /// Where the socket is bound, which may be a wildcard.
    bound: SocketAddr,
    /// Where clients are told to send.
    advertised: SocketAddr,
    token: [u8; SECRET_LEN],
    /// The address its party proved it can receive at, once it has.
    party: Mutex<Option<SocketAddr>>,
    /// The check outstanding, if one is: where it went, and its nonce.
    checking: Mutex<Option<(SocketAddr, [u8; SECRET_LEN], Instant)>>,
}

/// Checks a port will send in a second. A bind costs whoever sends it as much
/// as the check it draws, but a forged source address makes the check
/// somebody else's, and this bounds how much of that one port does.
const CHECKS_PER_SECOND: u32 = 10;

/// Two ports and the threads forwarding between them.
struct Allocation {
    ports: [Arc<Port>; 2],
    /// The client addresses it was made for, which is what its share of
    /// [`MAX_RELAYS_PER_IP`] is counted against.
    ips: HashSet<IpAddr>,
    last_forward: Arc<Mutex<Instant>>,
    stop: Arc<AtomicBool>,
}

impl Allocation {
    fn open(bound: IpAddr, advertised: IpAddr, ips: HashSet<IpAddr>) -> io::Result<Self> {
        let make = || -> io::Result<Arc<Port>> {
            let socket = UdpSocket::bind(SocketAddr::new(bound, 0))?;
            let local = socket.local_addr()?;
            let mut token = [0u8; SECRET_LEN];
            OsRng.fill_bytes(&mut token);
            Ok(Arc::new(Port {
                socket,
                bound: local,
                advertised: SocketAddr::new(advertised, local.port()),
                token,
                party: Mutex::new(None),
                checking: Mutex::new(None),
            }))
        };
        let ports = [make()?, make()?];
        let last_forward = Arc::new(Mutex::new(Instant::now()));
        let stop = Arc::new(AtomicBool::new(false));
        let budget = Arc::new(Mutex::new((RELAY_BYTES_PER_SECOND as f64, Instant::now())));

        for side in 0..2 {
            let this = Arc::clone(&ports[side]);
            let other = Arc::clone(&ports[1 - side]);
            let stop = Arc::clone(&stop);
            let last_forward = Arc::clone(&last_forward);
            let budget = Arc::clone(&budget);
            thread::spawn(move || serve_port(&this, &other, &stop, &last_forward, &budget));
        }
        Ok(Self {
            ports,
            ips,
            last_forward,
            stop,
        })
    }

    fn idle(&self, now: Instant) -> bool {
        let last = *lock(&self.last_forward);
        now.duration_since(last) > RELAY_IDLE
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Each thread blocks in a read with no timeout (D80: a timed read on
        // Windows can lose the datagram it was waiting for). A datagram from
        // the port to itself wakes it to see `stop`.
        for port in &self.ports {
            // A wildcard cannot be sent to on every platform; the loopback
            // address of the same family reaches the same socket.
            let mut wake = port.bound;
            if wake.ip().is_unspecified() {
                wake.set_ip(match wake.ip() {
                    IpAddr::V4(_) => IpAddr::from([127, 0, 0, 1]),
                    IpAddr::V6(_) => IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
                });
            }
            let _ = port.socket.send_to(&[], wake);
        }
    }
}

/// One port's thread: proves its party's address, then forwards.
fn serve_port(
    this: &Port,
    other: &Port,
    stop: &AtomicBool,
    last_forward: &Mutex<Instant>,
    budget: &Mutex<(f64, Instant)>,
) {
    let mut buf = vec![0u8; 65535];
    let mut checks = (0u32, Instant::now());
    loop {
        let got = this.socket.recv_from(&mut buf);
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let Ok((n, from)) = got else {
            continue;
        };
        let datagram = &buf[..n];
        let party = *lock(&this.party);

        match party {
            Some(recorded) if recorded == from => {
                // A bind or proof after the address is recorded is discarded,
                // never forwarded: it is not the party's traffic.
                if datagram.first() == Some(&NOT_A_FRAME)
                    && matches!(datagram.get(1), Some(&BIND) | Some(&PROOF))
                {
                    continue;
                }
                let Some(to) = *lock(&other.party) else {
                    continue;
                };
                // Bounded per allocation, both directions together.
                {
                    let mut budget = lock(budget);
                    let now = Instant::now();
                    let refill =
                        now.duration_since(budget.1).as_secs_f64() * RELAY_BYTES_PER_SECOND as f64;
                    budget.0 = (budget.0 + refill).min(RELAY_BYTES_PER_SECOND as f64);
                    budget.1 = now;
                    if budget.0 < n as f64 {
                        continue;
                    }
                    budget.0 -= n as f64;
                }
                if other.socket.send_to(datagram, to).is_ok() {
                    *lock(last_forward) = Instant::now();
                }
            }
            // Recorded, and this is someone else: discarded, and not counted
            // as activity.
            Some(_) => {}
            None => match datagram {
                [NOT_A_FRAME, BIND, token @ ..] if token == this.token => {
                    let now = Instant::now();
                    if now.duration_since(checks.1) >= Duration::from_secs(1) {
                        checks = (0, now);
                    }
                    if checks.0 >= CHECKS_PER_SECOND {
                        continue;
                    }
                    checks.0 += 1;
                    let mut nonce = [0u8; SECRET_LEN];
                    OsRng.fill_bytes(&mut nonce);
                    *lock(&this.checking) = Some((from, nonce, now));
                    let mut check = vec![NOT_A_FRAME, CHECK];
                    check.extend_from_slice(&nonce);
                    let _ = this.socket.send_to(&check, from);
                }
                [NOT_A_FRAME, PROOF, nonce @ ..] => {
                    let mut checking = lock(&this.checking);
                    if let Some((asked, expected, _)) = *checking {
                        if asked == from && nonce == expected {
                            *lock(&this.party) = Some(from);
                            *checking = None;
                        }
                    }
                }
                _ => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_round_trips() {
        let key = [7u8; 32];
        let v4: SocketAddr = "203.0.113.9:4500".parse().expect("addr");
        let v6: SocketAddr = "[2001:db8::1]:65000".parse().expect("addr");
        for message in [
            Control::Register,
            Control::Introduce(key),
            Control::Relay(key),
            Control::Observed(v4),
            Control::Observed(v6),
            Control::Introduction(key, v4),
            Control::Introduction(key, v6),
            Control::Unavailable(key, 3),
            Control::RelayOffer(key, v6, [9u8; SECRET_LEN]),
        ] {
            assert_eq!(Control::decode(&message.encode()), Some(message));
        }
    }

    #[test]
    fn a_body_of_the_wrong_length_or_an_unknown_kind_is_ignored() {
        let key = [7u8; 32];
        let good = Control::Introduction(key, "203.0.113.9:4500".parse().expect("addr")).encode();
        for cut in 0..good.len() {
            assert_eq!(Control::decode(&good[..cut]), None, "truncated to {cut}");
        }
        let mut long = good.clone();
        long.push(0);
        assert_eq!(Control::decode(&long), None);
        assert_eq!(Control::decode(&[0x7f]), None);
        assert_eq!(
            Control::decode(&[0x01, 0]),
            None,
            "register carries nothing"
        );
        let mut bad_family = good;
        bad_family[33] = 5;
        assert_eq!(Control::decode(&bad_family), None);
    }

    #[test]
    fn exactly_one_of_two_keys_starts() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(starts(&a, &b));
        assert!(!starts(&b, &a));
        assert!(!starts(&a, &a), "nobody starts a handshake with itself");
    }
}

/// Introductions a client may have outstanding at once (SPEC A.3: a client
/// SHOULD bound how many it acts on).
pub const MAX_INTRODUCTIONS: usize = 16;

/// How long a client waits on one introduction, end to end, before reporting
/// it failed: the window for the other side to ask, then a direct attempt,
/// then a relayed one. Ninety seconds.
pub const INTRODUCTION_DEADLINE: Duration = Duration::from_secs(90);

/// Binds a client sends a relay port before giving up on it, and how far
/// apart.
pub(crate) const BINDS: u8 = 5;
pub(crate) const BIND_INTERVAL: Duration = Duration::from_millis(500);

/// Where one introduction a client asked for has got to.
#[derive(Debug)]
pub(crate) enum Stage {
    /// Asked; waiting for the other side to ask too.
    Asked,
    /// Told where the other is. The starting side has a handshake under way.
    Introduced {
        outbound: Option<PeerId>,
        relay_asked: bool,
    },
    /// Offered a relay port; proving this side's address to it, then, for
    /// the starting side, connecting through it.
    Relaying {
        port: SocketAddr,
        token: [u8; SECRET_LEN],
        /// Whether the port has checked this side's address at least once.
        checked: bool,
        binds: u8,
        next_bind: Instant,
        outbound: Option<PeerId>,
    },
}

/// One introduction a client asked for.
#[derive(Debug)]
pub(crate) struct Ask {
    pub since: Instant,
    pub stage: Stage,
}

/// A client's side of the rendezvous: who it is registered with, what it
/// asked for, which of its sessions run through a relay.
#[derive(Debug, Default)]
pub(crate) struct ClientState {
    pub rendezvous: Option<PeerId>,
    pub registered: bool,
    pub observed: Option<SocketAddr>,
    pub asks: HashMap<Key, Ask>,
    pub relayed: HashSet<PeerId>,
}
