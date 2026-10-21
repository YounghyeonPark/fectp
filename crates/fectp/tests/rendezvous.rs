//! Two endpoints behind NATs, introduced by a rendezvous (SPEC Appendix A).
//!
//! The NATs are the emulated ones of `common/nat.rs`, checked in
//! `nat_emulation.rs` before anything here relies on them. Which pairs connect
//! directly and which need the relay is decided by the kinds of NAT, not by
//! chance, and each test says which it expects and why.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::nat::{behind, Kind};
use fectp::rendezvous::Unavailable;
use fectp::{Endpoint, Event, Identity, PayloadType, PeerId, Rendezvous};

/// A rendezvous on its own thread.
struct Server {
    addr: std::net::SocketAddr,
    public: [u8; 32],
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<Rendezvous>>,
}

impl Server {
    fn spawn(configure: impl FnOnce(&mut Rendezvous)) -> Self {
        let mut rendezvous = Rendezvous::bind("127.0.0.1:0", Identity::generate()).expect("bind");
        configure(&mut rendezvous);
        let addr = rendezvous.local_addr().expect("addr");
        let public = *rendezvous.public_key();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                rendezvous
                    .poll(Some(Duration::from_millis(10)))
                    .expect("rendezvous poll");
            }
            rendezvous
        });
        Self {
            addr,
            public,
            stop,
            handle: Some(handle),
        }
    }

    /// Stops it and hands it back, to be asked how it ended up.
    fn stop(mut self) -> Rendezvous {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.take().expect("running").join().expect("join")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A client behind a NAT of `kind`, registered with the rendezvous.
struct Client {
    endpoint: Endpoint,
    key: [u8; 32],
    /// Sessions that came up, by the key they authenticated.
    sessions: Vec<(PeerId, [u8; 32])>,
    failed: Vec<([u8; 32], Unavailable)>,
    messages: Vec<Vec<u8>>,
}

impl Client {
    fn behind(kind: Kind, server: &Server) -> Self {
        Self::with(kind, server, Identity::generate(), Faults::default())
    }

    /// As `behind`, with a chosen identity and the given faults.
    fn with(kind: Kind, server: &Server, identity: Identity, faults: Faults) -> Self {
        let (socket, _nat) = behind(kind);
        let key = *identity.public();
        let socket = Faulty {
            inner: socket,
            faults,
            lost_proof: AtomicBool::new(false),
            lost_data: AtomicBool::new(false),
        };
        let mut endpoint = Endpoint::bind_socket(socket, identity).expect("bind");
        endpoint
            .connect_rendezvous(server.addr, &server.public)
            .expect("connect");
        Self {
            endpoint,
            key,
            sessions: Vec::new(),
            failed: Vec::new(),
            messages: Vec::new(),
        }
    }

    fn pump(&mut self) {
        match self
            .endpoint
            .poll(Some(Duration::from_millis(2)))
            .expect("client poll")
        {
            Event::Connected { peer, .. } => {
                if let Some(key) = self.endpoint.peer_public_key(peer) {
                    self.sessions.push((peer, *key));
                }
            }
            Event::IntroductionFailed {
                peer_public,
                reason,
            } => self.failed.push((peer_public, reason)),
            Event::Message { data, .. } => self.messages.push(data),
            _ => {}
        }
    }

    fn session_with(&self, key: &[u8; 32]) -> Option<PeerId> {
        self.sessions
            .iter()
            .find(|(_, k)| k == key)
            .map(|(peer, _)| *peer)
    }
}

/// Drives both clients until `done` holds, or `within` passes.
fn run(
    a: &mut Client,
    b: &mut Client,
    within: Duration,
    done: impl Fn(&Client, &Client) -> bool,
) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if done(a, b) {
            return true;
        }
        a.pump();
        b.pump();
    }
    done(a, b)
}

/// Both registered, then each asks for the other; returns once both have a
/// session with the other, or panics saying what happened instead.
fn introduce(a: &mut Client, b: &mut Client) -> (PeerId, PeerId) {
    assert!(
        run(a, b, Duration::from_secs(10), |a, b| {
            a.endpoint.observed_addr().is_some() && b.endpoint.observed_addr().is_some()
        }),
        "both should be registered and told where they appear"
    );
    let (ka, kb) = (a.key, b.key);
    a.endpoint.introduce(&kb).expect("introduce");
    b.endpoint.introduce(&ka).expect("introduce");
    let connected = run(a, b, Duration::from_secs(40), |a, b| {
        a.session_with(&kb).is_some() && b.session_with(&ka).is_some()
    });
    assert!(
        connected,
        "no session: a failed {:?}, b failed {:?}",
        a.failed, b.failed
    );
    (
        a.session_with(&kb).expect("a"),
        b.session_with(&ka).expect("b"),
    )
}

/// Each side sends the other a message over the session they ended up with.
fn talk(a: &mut Client, b: &mut Client, ab: PeerId, ba: PeerId) {
    a.endpoint
        .send_reliable(ab, b"from a", PayloadType::Opaque)
        .expect("send");
    b.endpoint
        .send_reliable(ba, b"from b", PayloadType::Opaque)
        .expect("send");
    assert!(
        run(a, b, Duration::from_secs(10), |a, b| {
            b.messages.iter().any(|m| m == b"from a") && a.messages.iter().any(|m| m == b"from b")
        }),
        "the session carries messages both ways"
    );
}

#[test]
fn two_port_restricted_nats_are_punched_through_directly() {
    let server = Server::spawn(|_| {});
    let mut a = Client::behind(Kind::PortRestricted, &server);
    let mut b = Client::behind(Kind::PortRestricted, &server);
    let (ab, ba) = introduce(&mut a, &mut b);
    assert!(
        !a.endpoint.is_relayed(ab) && !b.endpoint.is_relayed(ba),
        "a cone on each side can be punched through; no relay was needed"
    );
    talk(&mut a, &mut b, ab, ba);
    let rendezvous = server.stop();
    assert_eq!(rendezvous.relays(), 0, "and none was allocated");
}

/// Two identities, the first of which starts the handshake with the second.
fn starter_and_waiter() -> (Identity, Identity) {
    loop {
        let (x, y) = (Identity::generate(), Identity::generate());
        if x.public() < y.public() {
            return (x, y);
        }
        if y.public() < x.public() {
            return (y, x);
        }
    }
}

/// Which side starts depends on the keys, so each ordering is pinned rather
/// than left to whichever keys were generated.
#[test]
fn a_symmetric_nat_that_starts_is_reached_through_the_relay() {
    let server = Server::spawn(|_| {});
    let (starts, waits) = starter_and_waiter();
    let mut a = Client::with(Kind::Symmetric, &server, starts, Faults::default());
    let mut b = Client::with(Kind::PortRestricted, &server, waits, Faults::default());
    let (ab, ba) = introduce(&mut a, &mut b);
    assert!(a.endpoint.is_relayed(ab) && b.endpoint.is_relayed(ba));
    talk(&mut a, &mut b, ab, ba);
}

#[test]
fn a_symmetric_nat_is_reached_through_the_relay() {
    let server = Server::spawn(|_| {});
    let (starts, waits) = starter_and_waiter();
    let mut a = Client::with(Kind::Symmetric, &server, waits, Faults::default());
    let mut b = Client::with(Kind::PortRestricted, &server, starts, Faults::default());
    let (ab, ba) = introduce(&mut a, &mut b);
    assert!(
        a.endpoint.is_relayed(ab) && b.endpoint.is_relayed(ba),
        "a symmetric NAT shows each destination its own address, so the one \
         the rendezvous saw is no use to the other side: only a relay works"
    );
    talk(&mut a, &mut b, ab, ba);
    let rendezvous = server.stop();
    assert_eq!(rendezvous.relays(), 1);
}

#[test]
fn two_symmetric_nats_are_reached_through_the_relay() {
    let server = Server::spawn(|_| {});
    let mut a = Client::behind(Kind::Symmetric, &server);
    let mut b = Client::behind(Kind::Symmetric, &server);
    let (ab, ba) = introduce(&mut a, &mut b);
    assert!(a.endpoint.is_relayed(ab) && b.endpoint.is_relayed(ba));
    talk(&mut a, &mut b, ab, ba);
}

#[test]
fn nobody_is_introduced_who_did_not_ask() {
    let server = Server::spawn(|r| r.set_introduction_window(Duration::from_millis(500)));
    let mut a = Client::behind(Kind::PortRestricted, &server);
    let mut b = Client::behind(Kind::PortRestricted, &server);
    assert!(run(&mut a, &mut b, Duration::from_secs(10), |a, b| {
        a.endpoint.observed_addr().is_some() && b.endpoint.observed_addr().is_some()
    }));

    // Only `a` asks. `b` is registered and reachable, and must not be made to
    // send anywhere on `a`'s say-so.
    let kb = b.key;
    a.endpoint.introduce(&kb).expect("introduce");
    assert!(
        run(&mut a, &mut b, Duration::from_secs(10), |a, _| !a
            .failed
            .is_empty()),
        "the request should be answered once the window passes"
    );
    assert_eq!(a.failed, vec![(kb, Unavailable::NotAsked)]);
    assert!(a.sessions.iter().all(|(_, k)| *k != kb));
    assert!(b.sessions.iter().all(|(_, k)| *k != a.key));
}

#[test]
fn asking_for_a_key_nobody_registered_fails_when_the_window_closes() {
    let server = Server::spawn(|r| r.set_introduction_window(Duration::from_millis(500)));
    let mut a = Client::behind(Kind::FullCone, &server);
    let mut b = Client::behind(Kind::FullCone, &server);
    assert!(run(&mut a, &mut b, Duration::from_secs(10), |a, _| {
        a.endpoint.observed_addr().is_some()
    }));
    let stranger = *Identity::generate().public();
    a.endpoint.introduce(&stranger).expect("introduce");
    assert!(run(&mut a, &mut b, Duration::from_secs(10), |a, _| !a
        .failed
        .is_empty()));
    assert_eq!(a.failed, vec![(stranger, Unavailable::NotRegistered)]);
}

#[test]
fn introducing_without_a_rendezvous_is_refused() {
    let mut lone = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    assert!(matches!(
        lone.introduce(&[1u8; 32]),
        Err(fectp::Error::NoRendezvous)
    ));
}

/// What a client does when a rendezvous tells it about a key: `asked` says
/// whether the client asked for that key first. Returns how many datagrams
/// reached the address the "rendezvous" named.
///
/// The rendezvous here is a plain endpoint speaking the messages by hand, so
/// it can say what a real one never would.
fn datagrams_sent_on_say_so(asked: bool) -> usize {
    let mut liar = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let liar_addr = liar.local_addr().expect("addr");
    let liar_key = *liar.public_key().expect("identity");
    let victim = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let victim_addr = victim.local_addr().expect("addr");

    // A key smaller than any real one, so this client is the side that would
    // start the handshake as well as punch: the most it can be made to send.
    let named = [0xFFu8; 32];
    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    client
        .connect_rendezvous(liar_addr, &liar_key)
        .expect("connect");
    if asked {
        client.introduce(&named).expect("introduce");
    }

    // Wait for the client to register, then lie to it.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut registered = None;
    while registered.is_none() {
        assert!(Instant::now() < deadline, "never registered");
        let _ = client.poll(Some(Duration::from_millis(2)));
        if let Event::Message { peer, data } =
            liar.poll(Some(Duration::from_millis(2))).expect("poll")
        {
            if data == [0x01] {
                registered = Some(peer);
            }
        }
    }
    let mut introduction = vec![0x82];
    introduction.extend_from_slice(&named);
    introduction.push(4);
    introduction.extend_from_slice(&[127, 0, 0, 1]);
    introduction.extend_from_slice(&victim_addr.port().to_le_bytes());
    liar.send_reliable(
        registered.expect("registered"),
        &introduction,
        PayloadType::Opaque,
    )
    .expect("send");

    let until = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < until {
        let _ = client.poll(Some(Duration::from_millis(2)));
        let _ = liar.poll(Some(Duration::from_millis(2)));
    }
    victim.set_nonblocking(true).expect("nonblocking");
    let mut buf = [0u8; 2048];
    let mut count = 0;
    while victim.recv_from(&mut buf).is_ok() {
        count += 1;
    }
    count
}

/// A rendezvous is trusted to say where a peer is, not to have its clients
/// send wherever it likes (SPEC A.3). An introduction for a key the client
/// did not ask for is ignored; the control shows the same introduction acted
/// on when it was asked for.
#[test]
fn an_introduction_nobody_asked_for_sends_nothing() {
    assert_eq!(datagrams_sent_on_say_so(false), 0, "unasked: nothing sent");
    assert!(
        datagrams_sent_on_say_so(true) > 0,
        "the control: asked for, the same introduction is acted on"
    );
}

/// Faults a test can ask a client's socket for.
#[derive(Clone, Copy, Default)]
struct Faults {
    /// Drop the first relay proof sent.
    lose_proof: bool,
    /// Drop the first data frame sent to this address: with the rendezvous's
    /// address, that is the registration, which then arrives late.
    lose_first_data_to: Option<std::net::SocketAddr>,
}

/// A client's socket with [`Faults`] applied, and nothing else changed.
struct Faulty {
    inner: common::nat::NatHost,
    faults: Faults,
    lost_proof: AtomicBool,
    lost_data: AtomicBool,
}

impl fectp::DatagramSocket for Faulty {
    fn send_to(&self, buf: &[u8], to: std::net::SocketAddr) -> std::io::Result<usize> {
        if self.faults.lose_proof
            && buf.starts_with(&[0xF0, 0x44])
            && !self.lost_proof.swap(true, Ordering::SeqCst)
        {
            return Ok(buf.len());
        }
        // 0x13: version 1, frame type 3, data.
        if self.faults.lose_first_data_to == Some(to)
            && buf.first() == Some(&0x13)
            && !self.lost_data.swap(true, Ordering::SeqCst)
        {
            return Ok(buf.len());
        }
        self.inner.send_to(buf, to)
    }

    fn recv_from(
        &self,
        buf: &mut [u8],
        timeout: Option<Duration>,
    ) -> std::io::Result<(usize, std::net::SocketAddr)> {
        self.inner.recv_from(buf, timeout)
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}

/// A proof lost on the way to the relay port is not the end of the relay: the
/// client binds again, the port checks again, and the second proof records
/// the address. Stopping at the first proof sent, as this once did, left the
/// port waiting on a nonce that never came.
#[test]
fn a_lost_proof_is_made_up_for_by_the_next_bind() {
    let server = Server::spawn(|_| {});
    for lose_on_starting_side in [true, false] {
        let (starts, waits) = starter_and_waiter();
        let lose = |yes| Faults {
            lose_proof: yes,
            ..Faults::default()
        };
        let mut a = Client::with(
            Kind::Symmetric,
            &server,
            starts,
            lose(lose_on_starting_side),
        );
        let mut b = Client::with(
            Kind::Symmetric,
            &server,
            waits,
            lose(!lose_on_starting_side),
        );
        let (ab, ba) = introduce(&mut a, &mut b);
        assert!(a.endpoint.is_relayed(ab) && b.endpoint.is_relayed(ba));
    }
}

/// A rendezvous bound to a wildcard address cannot advertise relay ports at
/// it — nobody can send to 0.0.0.0 — so it refuses to relay, to both sides,
/// until it is told the address clients reach it at.
#[test]
fn a_wildcard_bound_rendezvous_relays_only_once_told_its_address() {
    for told in [false, true] {
        let mut rendezvous = Rendezvous::bind("0.0.0.0:0", Identity::generate()).expect("bind");
        if told {
            rendezvous.set_relay_address("127.0.0.1".parse().expect("ip"));
        }
        let port = rendezvous.local_addr().expect("addr").port();
        let public = *rendezvous.public_key();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                rendezvous
                    .poll(Some(Duration::from_millis(10)))
                    .expect("poll");
            }
        });
        let server = Server {
            addr: ([127, 0, 0, 1], port).into(),
            public,
            stop: Arc::clone(&stop),
            handle: None,
        };
        let mut a = Client::behind(Kind::Symmetric, &server);
        let mut b = Client::behind(Kind::Symmetric, &server);
        assert!(run(&mut a, &mut b, Duration::from_secs(10), |a, b| {
            a.endpoint.observed_addr().is_some() && b.endpoint.observed_addr().is_some()
        }));
        let (ka, kb) = (a.key, b.key);
        a.endpoint.introduce(&kb).expect("introduce");
        b.endpoint.introduce(&ka).expect("introduce");
        if told {
            assert!(
                run(&mut a, &mut b, Duration::from_secs(40), |a, b| {
                    a.session_with(&kb).is_some() && b.session_with(&ka).is_some()
                }),
                "told its address, it relays: a {:?} b {:?}",
                a.failed,
                b.failed
            );
        } else {
            assert!(
                run(&mut a, &mut b, Duration::from_secs(40), |a, b| {
                    !a.failed.is_empty() && !b.failed.is_empty()
                }),
                "both sides should hear the relay was refused"
            );
            assert_eq!(a.failed, vec![(kb, Unavailable::NoRelay)]);
            assert_eq!(b.failed, vec![(ka, Unavailable::NoRelay)]);
        }
        stop.store(true, Ordering::Relaxed);
        handle.join().expect("join");
    }
}

/// Asking straight after connecting, before registration is done, is held
/// until it is: reliable messages are not ordered, and a request that
/// overtook the registration would be dropped by the rendezvous.
///
/// The registration is made to arrive late — its first transmission is lost,
/// so the retransmission comes after anything sent straight after it —
/// because on loopback nothing else reorders them, and a test that relied on
/// order holding would pass whether or not the requests waited.
#[test]
fn asking_before_registration_is_done_still_works() {
    let server = Server::spawn(|_| {});
    let late = Faults {
        lose_first_data_to: Some(server.addr),
        ..Faults::default()
    };
    let mut a = Client::with(Kind::PortRestricted, &server, Identity::generate(), late);
    let mut b = Client::with(Kind::PortRestricted, &server, Identity::generate(), late);
    let (ka, kb) = (a.key, b.key);
    a.endpoint.introduce(&kb).expect("introduce");
    b.endpoint.introduce(&ka).expect("introduce");
    assert!(
        run(&mut a, &mut b, Duration::from_secs(20), |a, b| {
            a.session_with(&kb).is_some() && b.session_with(&ka).is_some()
        }),
        "a {:?} b {:?}",
        a.failed,
        b.failed
    );
}
