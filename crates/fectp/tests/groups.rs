//! Finding peers by a shared group secret (SPEC A.7).
//!
//! A rendezvous files each group under a tag derived from its secret and
//! hands every member the whole group; each member checks every key's
//! certificate against the secret, which the rendezvous never sees. So a
//! rendezvous can say who is in a group but cannot add anyone to one — which
//! is the property these tests hold it to, with a rendezvous made to lie.

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::nat::{behind, Kind};
use fectp::rendezvous::GroupTag;
use fectp::{Endpoint, Event, Identity, PayloadType, PeerId, Rendezvous};
use rand_core::{OsRng, RngCore};

fn secret() -> [u8; 16] {
    let mut secret = [0u8; 16];
    OsRng.fill_bytes(&mut secret);
    secret
}

struct Server {
    addr: std::net::SocketAddr,
    public: [u8; 32],
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn spawn() -> Self {
        let mut rendezvous = Rendezvous::bind("127.0.0.1:0", Identity::generate()).expect("bind");
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
        });
        Self {
            addr,
            public,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// A client, optionally behind a NAT, and what it has heard.
struct Member {
    endpoint: Endpoint,
    key: [u8; 32],
    found: Vec<([u8; 32], GroupTag)>,
    sessions: Vec<(PeerId, [u8; 32])>,
    /// Introduce whoever is found, as an application would.
    introduce_found: bool,
}

impl Member {
    fn new(server: &Server, nat: Option<Kind>) -> Self {
        let identity = Identity::generate();
        let key = *identity.public();
        let mut endpoint = match nat {
            Some(kind) => Endpoint::bind_socket(behind(kind).0, identity),
            None => Endpoint::bind("127.0.0.1:0", identity),
        }
        .expect("bind");
        endpoint
            .connect_rendezvous(server.addr, &server.public)
            .expect("connect");
        Self {
            endpoint,
            key,
            found: Vec::new(),
            sessions: Vec::new(),
            introduce_found: false,
        }
    }

    fn pump(&mut self) {
        match self
            .endpoint
            .poll(Some(Duration::from_millis(2)))
            .expect("poll")
        {
            Event::PeerDiscovered { peer_public, group } => {
                self.found.push((peer_public, group));
                if self.introduce_found {
                    self.endpoint.introduce(&peer_public).expect("introduce");
                }
            }
            Event::Connected { peer, .. } => {
                if let Some(key) = self.endpoint.peer_public_key(peer) {
                    self.sessions.push((peer, *key));
                }
            }
            _ => {}
        }
    }

    fn found_keys(&self) -> HashSet<[u8; 32]> {
        self.found.iter().map(|(k, _)| *k).collect()
    }
}

fn run(
    members: &mut [&mut Member],
    within: Duration,
    done: impl Fn(&[&mut Member]) -> bool,
) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if done(members) {
            return true;
        }
        for m in members.iter_mut() {
            m.pump();
        }
    }
    done(members)
}

#[test]
fn members_of_a_group_find_each_other_and_nobody_else() {
    let server = Server::spawn();
    let ours = secret();
    let theirs = secret();
    let mut a = Member::new(&server, None);
    let mut b = Member::new(&server, None);
    let mut c = Member::new(&server, None);
    let mut outsider = Member::new(&server, None);
    let tag = a.endpoint.join_group(&ours).expect("join");
    b.endpoint.join_group(&ours).expect("join");
    c.endpoint.join_group(&ours).expect("join");
    let other = outsider.endpoint.join_group(&theirs).expect("join");
    assert_ne!(tag, other);

    let (ka, kb, kc) = (a.key, b.key, c.key);
    assert!(
        run(
            &mut [&mut a, &mut b, &mut c, &mut outsider],
            Duration::from_secs(10),
            |m| {
                m[0].found_keys() == HashSet::from([kb, kc])
                    && m[1].found_keys() == HashSet::from([ka, kc])
                    && m[2].found_keys() == HashSet::from([ka, kb])
            }
        ),
        "each member should find the other two: a {:?} b {:?} c {:?}",
        a.found.len(),
        b.found.len(),
        c.found.len()
    );
    // A moment more, for anything that should not arrive to have the chance.
    run(
        &mut [&mut a, &mut b, &mut c, &mut outsider],
        Duration::from_millis(500),
        |_| false,
    );
    assert!(
        outsider.found.is_empty(),
        "another group's member finds none of them"
    );
    for m in [&a, &b, &c] {
        assert!(!m.found_keys().contains(&outsider.key));
        assert!(
            m.found.iter().all(|(_, g)| *g == tag),
            "found in the group joined"
        );
        assert_eq!(m.found.len(), 2, "each found once");
    }
    assert_eq!(
        a.endpoint
            .group_members(&tag)
            .into_iter()
            .collect::<HashSet<_>>(),
        HashSet::from([kb, kc])
    );
}

/// Found, then introduced, then connected, through two NATs: what the
/// feature is for. Each side introduces whoever it finds, and since each
/// finds the other, both ask, which is what an introduction takes.
#[test]
fn members_found_through_a_group_connect_through_their_nats() {
    let server = Server::spawn();
    let shared = secret();
    let mut a = Member::new(&server, Some(Kind::PortRestricted));
    let mut b = Member::new(&server, Some(Kind::PortRestricted));
    a.introduce_found = true;
    b.introduce_found = true;
    a.endpoint.join_group(&shared).expect("join");
    b.endpoint.join_group(&shared).expect("join");
    let (ka, kb) = (a.key, b.key);
    assert!(
        run(&mut [&mut a, &mut b], Duration::from_secs(20), |m| {
            m[0].sessions.iter().any(|(_, k)| *k == kb)
                && m[1].sessions.iter().any(|(_, k)| *k == ka)
        }),
        "found each other and connected"
    );
    let peer = a
        .sessions
        .iter()
        .find(|(_, k)| *k == kb)
        .expect("session")
        .0;
    a.endpoint
        .send_reliable(peer, b"found you", PayloadType::Opaque)
        .expect("send");
}

#[test]
fn a_member_that_leaves_is_dropped_from_the_others_view() {
    let server = Server::spawn();
    let shared = secret();
    let mut a = Member::new(&server, None);
    let mut b = Member::new(&server, None);
    let tag = a.endpoint.join_group(&shared).expect("join");
    b.endpoint.join_group(&shared).expect("join");
    assert!(run(&mut [&mut a, &mut b], Duration::from_secs(10), |m| {
        !m[0].found.is_empty() && !m[1].found.is_empty()
    }));
    assert!(b.endpoint.leave_group(&tag));
    assert!(
        run(&mut [&mut a, &mut b], Duration::from_secs(10), |m| {
            m[0].endpoint.group_members(&tag).is_empty()
        }),
        "the one left behind sees the group without it"
    );
    assert!(b.endpoint.group_members(&tag).is_empty());
}

#[test]
fn a_secret_short_enough_to_guess_is_refused() {
    let server = Server::spawn();
    let mut a = Member::new(&server, None);
    assert!(matches!(
        a.endpoint.join_group(b"password"),
        Err(fectp::Error::GroupSecretTooShort)
    ));
    let mut lone = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    assert!(matches!(
        lone.join_group(&secret()),
        Err(fectp::Error::NoRendezvous)
    ));
}

/// The certificate a member files: as SPEC A.7 defines it, computed here
/// independently of the crate's own code.
fn certificate(secret: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let group_key = fectp_core::noise::hash(&[b"fectp group key", secret]);
    let digest = fectp_core::noise::hash(&[b"fectp group member", &group_key, key]);
    digest[..16].try_into().expect("16")
}

fn tag_of(secret: &[u8]) -> [u8; 16] {
    fectp_core::noise::hash(&[b"fectp group tag", secret])[..16]
        .try_into()
        .expect("16")
}

/// A rendezvous sees each group's tag and every member's certificate, and
/// can send whatever list it likes. It cannot make a certificate, so a key it
/// adds is not raised. The control in the same list — a key certified with
/// the secret — is.
#[test]
fn a_rendezvous_cannot_add_a_member_to_a_group() {
    let mut liar = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let liar_addr = liar.local_addr().expect("addr");
    let liar_key = *liar.public_key().expect("identity");
    let shared = secret();
    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    client
        .connect_rendezvous(liar_addr, &liar_key)
        .expect("connect");
    let tag = client.join_group(&shared).expect("join");
    assert_eq!(tag, tag_of(&shared), "the tag is as SPEC A.7 derives it");

    // Registration, then the join, arrive at the liar.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut session = None;
    let mut joined = None;
    while joined.is_none() {
        assert!(Instant::now() < deadline, "never joined");
        client.poll(Some(Duration::from_millis(2))).expect("poll");
        if let Event::Message { peer, data } =
            liar.poll(Some(Duration::from_millis(2))).expect("poll")
        {
            if data == [0x01] {
                let mut observed = vec![0x81, 4, 127, 0, 0, 1];
                observed.extend_from_slice(&1u16.to_le_bytes());
                liar.send_reliable(peer, &observed, PayloadType::Opaque)
                    .expect("send");
                session = Some(peer);
            } else if data.first() == Some(&0x04) {
                joined = Some(data);
            }
        }
    }
    let join = joined.expect("joined");
    assert_eq!(&join[1..17], &tag);
    assert_eq!(
        &join[17..33],
        &certificate(&shared, client.public_key().expect("identity")),
        "the certificate is as SPEC A.7 defines it"
    );

    let made_up = [0x11u8; 32];
    let real = [0x22u8; 32];
    let mut members = vec![0x85];
    members.extend_from_slice(&tag);
    members.extend_from_slice(&made_up);
    members.extend_from_slice(&[0u8; 16]); // no certificate it could make
    members.extend_from_slice(&made_up.map(|b| b ^ 1));
    members.extend_from_slice(&join[17..33]); // somebody else's certificate
    members.extend_from_slice(&real);
    members.extend_from_slice(&certificate(&shared, &real));
    liar.send_reliable(session.expect("session"), &members, PayloadType::Opaque)
        .expect("send");

    let mut found = Vec::new();
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until && found.is_empty() {
        if let Event::PeerDiscovered { peer_public, .. } =
            client.poll(Some(Duration::from_millis(2))).expect("poll")
        {
            found.push(peer_public);
        }
        let _ = liar.poll(Some(Duration::from_millis(2)));
    }
    let until = Instant::now() + Duration::from_millis(300);
    while Instant::now() < until {
        if let Event::PeerDiscovered { peer_public, .. } =
            client.poll(Some(Duration::from_millis(2))).expect("poll")
        {
            found.push(peer_public);
        }
    }
    assert_eq!(found, vec![real], "only the certified key is raised");
}
