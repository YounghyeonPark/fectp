//! What a rendezvous does for someone who is not playing fair (SPEC A.1, A.4).
//!
//! The clients here speak the rendezvous messages by hand, from plain
//! endpoints, so they can do what `Endpoint::introduce` never would: hold a
//! relay token and use it from somewhere else, skip registering, or never
//! answer a check. Each test has a control showing the same steps done
//! honestly do get through, so a refusal is the rule working and not the
//! setup failing.

mod common;

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Endpoint, Event, Identity, PayloadType, PeerId, Rendezvous};

const REGISTER: u8 = 0x01;
const INTRODUCE: u8 = 0x02;
const RELAY: u8 = 0x03;
const OBSERVED: u8 = 0x81;
const RELAY_OFFER: u8 = 0x84;

fn spawn() -> (
    SocketAddr,
    [u8; 32],
    Arc<AtomicBool>,
    thread::JoinHandle<Rendezvous>,
) {
    let mut rendezvous = Rendezvous::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let addr = rendezvous.local_addr().expect("addr");
    let public = *rendezvous.public_key();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            rendezvous
                .poll(Some(Duration::from_millis(5)))
                .expect("poll");
        }
        rendezvous
    });
    (addr, public, stop, handle)
}

/// A plain endpoint connected to the rendezvous, its messages surfaced.
struct Raw {
    endpoint: Endpoint,
    key: [u8; 32],
    rendezvous: PeerId,
    inbox: Vec<Vec<u8>>,
}

impl Raw {
    fn connect(addr: SocketAddr, public: &[u8; 32]) -> Self {
        let identity = Identity::generate();
        let key = *identity.public();
        let mut endpoint = Endpoint::bind("127.0.0.1:0", identity).expect("bind");
        let rendezvous = endpoint.connect(addr, Some(public)).expect("connect");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline, "never connected");
            if let Event::Connected { .. } =
                endpoint.poll(Some(Duration::from_millis(5))).expect("poll")
            {
                break;
            }
        }
        Self {
            endpoint,
            key,
            rendezvous,
            inbox: Vec::new(),
        }
    }

    fn say(&mut self, kind: u8, body: &[u8]) {
        let mut message = vec![kind];
        message.extend_from_slice(body);
        self.endpoint
            .send_reliable(self.rendezvous, &message, PayloadType::Opaque)
            .expect("send");
    }

    /// Polls for `within`, keeping whatever the rendezvous says.
    fn listen(&mut self, within: Duration) {
        let until = Instant::now() + within;
        while Instant::now() < until {
            if let Event::Message { data, .. } = self
                .endpoint
                .poll(Some(Duration::from_millis(5)))
                .expect("poll")
            {
                self.inbox.push(data);
            }
        }
    }

    fn heard(&self, kind: u8) -> Option<&Vec<u8>> {
        self.inbox.iter().find(|m| m.first() == Some(&kind))
    }
}

/// A relay offer's port and token.
fn offer(message: &[u8]) -> (SocketAddr, [u8; 16]) {
    assert_eq!(message.len(), 56, "an IPv4 offer");
    assert_eq!(message[33], 4);
    let ip = std::net::Ipv4Addr::new(message[34], message[35], message[36], message[37]);
    let port = u16::from_le_bytes([message[38], message[39]]);
    let token: [u8; 16] = message[40..56].try_into().expect("token");
    (SocketAddr::from((ip, port)), token)
}

/// Two raw clients, registered, introduced, and offered a relay; the
/// rendezvous's thread and both offers.
struct Relayed {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<Rendezvous>>,
    /// Port and token for each side: index 0 is `x`'s, 1 is `y`'s.
    offers: [(SocketAddr, [u8; 16]); 2],
}

impl Relayed {
    fn set_up() -> Self {
        let (addr, public, stop, handle) = spawn();
        let mut x = Raw::connect(addr, &public);
        let mut y = Raw::connect(addr, &public);
        x.say(REGISTER, &[]);
        y.say(REGISTER, &[]);
        x.listen(Duration::from_millis(200));
        y.listen(Duration::from_millis(200));
        let (kx, ky) = (x.key, y.key);
        x.say(INTRODUCE, &ky);
        y.say(INTRODUCE, &kx);
        x.listen(Duration::from_millis(300));
        y.listen(Duration::from_millis(300));
        x.say(RELAY, &ky);
        x.listen(Duration::from_millis(300));
        y.listen(Duration::from_millis(300));
        let ox = offer(x.heard(RELAY_OFFER).expect("x offered a relay"));
        let oy = offer(y.heard(RELAY_OFFER).expect("y offered a relay"));
        Self {
            stop,
            handle: Some(handle),
            offers: [ox, oy],
        }
    }
}

impl Drop for Relayed {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn bind(socket: &UdpSocket, port: SocketAddr, token: &[u8; 16]) {
    let mut bind = vec![0xF0, 0x42];
    bind.extend_from_slice(token);
    socket.send_to(&bind, port).expect("bind");
}

/// Waits for a check and answers it; returns whether one came.
fn prove(socket: &UdpSocket, port: SocketAddr) -> bool {
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let mut buf = [0u8; 64];
    let Ok((n, from)) = socket.recv_from(&mut buf) else {
        return false;
    };
    if from != port || n != 18 || buf[..2] != [0xF0, 0x43] {
        return false;
    }
    let mut proof = vec![0xF0, 0x44];
    proof.extend_from_slice(&buf[2..18]);
    socket.send_to(&proof, port).expect("proof");
    true
}

/// Everything waiting on `socket`, read without blocking.
fn drain(socket: &UdpSocket) -> Vec<Vec<u8>> {
    socket.set_nonblocking(true).expect("nonblocking");
    let mut got = Vec::new();
    let mut buf = vec![0u8; 65535];
    while let Ok((n, _)) = socket.recv_from(&mut buf) {
        got.push(buf[..n].to_vec());
    }
    socket.set_nonblocking(false).expect("blocking");
    got
}

/// Anyone who asked for a relay holds a token, and a token can be sent from a
/// forged source address. A port that recorded whoever sent the bind would
/// then send the other side's traffic there: an open relay, aimed by the
/// forger. So it records an address only once a check sent there is
/// answered (SPEC A.4).
#[test]
fn a_bind_records_nothing_until_its_address_answers_a_check() {
    let relayed = Relayed::set_up();
    let [(port_x, token_x), (port_y, token_y)] = relayed.offers;

    // `x` binds honestly.
    let x = UdpSocket::bind("127.0.0.1:0").expect("bind");
    bind(&x, port_x, &token_x);
    assert!(prove(&x, port_x), "x is checked and answers");

    // `y`'s token is used from an address that never answers: the victim of
    // a forged source, as far as the port can tell.
    let victim = UdpSocket::bind("127.0.0.1:0").expect("bind");
    bind(&victim, port_y, &token_y);
    thread::sleep(Duration::from_millis(200));
    x.send_to(b"aimed at the victim", port_x).expect("send");
    thread::sleep(Duration::from_millis(300));
    let got = drain(&victim);
    assert!(
        got.iter().all(|d| d.len() == 18 && d[..2] == [0xF0, 0x43]),
        "the victim gets the check, no larger than the bind, and nothing else: {got:?}"
    );

    // The control: once the address answers, the same traffic is forwarded.
    bind(&victim, port_y, &token_y);
    assert!(prove(&victim, port_y), "checked again, and answered");
    thread::sleep(Duration::from_millis(100));
    x.send_to(b"now it is wanted", port_x).expect("send");
    victim
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let mut buf = [0u8; 64];
    let (n, from) = victim.recv_from(&mut buf).expect("forwarded");
    assert_eq!(&buf[..n], b"now it is wanted");
    assert_eq!(from, port_y, "sent on from the other side's port");
}

/// The first address proved is the party's for the life of the allocation.
/// A token travels in the clear, so anyone on the path can replay a bind from
/// elsewhere, and if that moved the binding it would cut the party off and
/// send its peer's traffic to whoever replayed it.
#[test]
fn a_recorded_address_is_not_moved_by_a_later_bind() {
    let relayed = Relayed::set_up();
    let [(port_x, token_x), (port_y, token_y)] = relayed.offers;
    let x = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let y = UdpSocket::bind("127.0.0.1:0").expect("bind");
    bind(&x, port_x, &token_x);
    assert!(prove(&x, port_x));
    bind(&y, port_y, &token_y);
    assert!(prove(&y, port_y));

    let thief = UdpSocket::bind("127.0.0.1:0").expect("bind");
    bind(&thief, port_y, &token_y);
    let checked = prove(&thief, port_y);
    assert!(
        !checked,
        "a port with a recorded party sends no further checks"
    );

    x.send_to(b"for y", port_x).expect("send");
    y.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let mut buf = [0u8; 64];
    let (n, _) = y.recv_from(&mut buf).expect("y still receives");
    assert_eq!(&buf[..n], b"for y");
    assert!(drain(&thief).is_empty(), "and the thief nothing");
}

/// A completed handshake proves nothing about the address it came from — it
/// takes the rendezvous's public key and one datagram, whose source can be
/// anybody's. So a session is not a client until it has said `REGISTER`, an
/// authenticated frame, and is sent nothing before.
#[test]
fn a_session_that_has_not_registered_is_told_nothing() {
    let (addr, public, stop, handle) = spawn();
    let mut quiet = Raw::connect(addr, &public);
    quiet.listen(Duration::from_millis(500));
    assert!(quiet.inbox.is_empty(), "nothing before registering");

    // The control: registering is answered with where it appears.
    quiet.say(REGISTER, &[]);
    quiet.listen(Duration::from_millis(500));
    let observed = quiet.heard(OBSERVED).expect("told where it appears");
    let port = quiet.endpoint.local_addr().expect("addr").port();
    assert_eq!(
        &observed[6..8],
        &port.to_le_bytes(),
        "its own address, as seen"
    );

    stop.store(true, Ordering::Relaxed);
    let rendezvous = handle.join().expect("join");
    assert_eq!(rendezvous.clients(), 1, "registered once it asked to be");
}

/// A relay forwards at a bounded rate: an allocation is the rendezvous's
/// bandwidth, spent at the request of two strangers.
#[test]
fn a_relay_forwards_no_faster_than_its_cap() {
    let relayed = Relayed::set_up();
    let [(port_x, token_x), (port_y, token_y)] = relayed.offers;
    let x = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let y = UdpSocket::bind("127.0.0.1:0").expect("bind");
    bind(&x, port_x, &token_x);
    assert!(prove(&x, port_x));
    bind(&y, port_y, &token_y);
    assert!(prove(&y, port_y));

    // Count what reaches `y` while `x` sends four times the cap's worth.
    let counted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let reader = {
        let y = y.try_clone().expect("clone");
        let (counted, done) = (Arc::clone(&counted), Arc::clone(&done));
        y.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");
        thread::spawn(move || {
            let mut buf = vec![0u8; 2048];
            while !done.load(Ordering::Relaxed) {
                if let Ok((n, _)) = y.recv_from(&mut buf) {
                    counted.fetch_add(n, Ordering::Relaxed);
                }
            }
        })
    };
    let chunk = vec![0x5Au8; 1000];
    let started = Instant::now();
    let mut sent = 0usize;
    while sent < 4 * fectp::rendezvous::RELAY_BYTES_PER_SECOND {
        x.send_to(&chunk, port_x).expect("send");
        sent += chunk.len();
        // Paced enough that loopback's own buffers are not what limits it.
        if sent % (64 * 1000) == 0 {
            thread::sleep(Duration::from_millis(5));
        }
    }
    thread::sleep(Duration::from_millis(300));
    done.store(true, Ordering::Relaxed);
    reader.join().expect("reader");
    let elapsed = started.elapsed().as_secs_f64();
    let received = counted.load(Ordering::Relaxed);
    let allowed = fectp::rendezvous::RELAY_BYTES_PER_SECOND as f64 * (elapsed + 1.0);
    assert!(
        (received as f64) <= allowed,
        "{received} bytes forwarded in {elapsed:.2} s; the cap allows {allowed:.0}"
    );
    assert!(received > 0, "the control: some of it is forwarded");
}

/// A client that stops acknowledging cannot stop the rendezvous.
///
/// Its session's reliable window fills — 32 messages unacknowledged — and
/// every send to it after that is refused. That refusal used to be an error
/// out of `Rendezvous::poll`, so one silent client ended service for all of
/// them. Here the client goes silent after an introduction, and its peer asks
/// for a relay over and over, each request having the offer sent to both.
#[test]
fn a_client_that_stops_answering_does_not_stop_the_rendezvous() {
    let (addr, public, stop, handle) = spawn();
    let mut x = Raw::connect(addr, &public);
    let mut y = Raw::connect(addr, &public);
    x.say(REGISTER, &[]);
    y.say(REGISTER, &[]);
    x.listen(Duration::from_millis(200));
    y.listen(Duration::from_millis(200));
    let (kx, ky) = (x.key, y.key);
    x.say(INTRODUCE, &ky);
    y.say(INTRODUCE, &kx);
    x.listen(Duration::from_millis(300));
    y.listen(Duration::from_millis(300));

    // Silent from here on: nothing it is sent is acknowledged.
    drop(x);
    // Each request costs one of the rate bound's 4 a second, and has an offer
    // sent to the silent client; 48 of them fill its window and then some.
    for _ in 0..48 {
        y.say(RELAY, &kx);
        y.listen(Duration::from_millis(260));
    }

    stop.store(true, Ordering::Relaxed);
    let rendezvous = handle
        .join()
        .expect("the rendezvous's poll must not have failed");
    assert_eq!(rendezvous.relays(), 1, "and it was serving all along");
}

/// The keyed answer a port expects to a check carrying `nonce` (SPEC A.5).
fn keyed_answer(token: &[u8; 16], nonce: &[u8]) -> Vec<u8> {
    let digest = fectp_core::noise::hash(&[b"fectp relay answer", token, nonce]);
    let mut answer = vec![0xF0, 0x46];
    answer.extend_from_slice(nonce);
    answer.extend_from_slice(&digest[..16]);
    answer
}

/// Proves `socket`'s address to `port` the keyed way: a hello, the check it
/// draws, and an answer only the token's holder can make. Returns the answer
/// sent, which an observer on the path would have seen.
fn hello_and_answer(socket: &UdpSocket, port: SocketAddr, token: &[u8; 16]) -> Option<Vec<u8>> {
    let mut hello = vec![0xF0, 0x45];
    hello.extend_from_slice(&[0u8; 16]);
    socket.send_to(&hello, port).expect("hello");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let mut buf = [0u8; 64];
    let (n, from) = socket.recv_from(&mut buf).ok()?;
    if from != port || n != 18 || buf[..2] != [0xF0, 0x43] {
        return None;
    }
    let answer = keyed_answer(token, &buf[2..18]);
    socket.send_to(&answer, port).expect("answer");
    Some(answer)
}

/// What `to` receives of a datagram sent through the relay from `via`.
fn delivered(from: &UdpSocket, via: SocketAddr, to: &UdpSocket) -> bool {
    drain(to);
    from.send_to(b"through the relay", via).expect("send");
    to.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    let mut buf = [0u8; 64];
    matches!(to.recv_from(&mut buf), Ok((n, _)) if &buf[..n] == b"through the relay")
}

/// A party can move, and nobody else can move it.
///
/// The token never crosses the wire on this path: an answer is a MAC over the
/// check's nonce, and a check's nonce is bound to the address it was sent to.
/// So the holder of the token can prove a new address, and an observer who
/// saw every answer so far cannot prove theirs — neither by replaying one nor
/// by reusing its MAC on a nonce of their own.
#[test]
fn a_keyed_answer_moves_a_binding_and_nothing_else_does() {
    let relayed = Relayed::set_up();
    let [(port_x, token_x), (port_y, token_y)] = relayed.offers;
    let x = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let y = UdpSocket::bind("127.0.0.1:0").expect("bind");
    assert!(hello_and_answer(&x, port_x, &token_x).is_some());
    let seen = hello_and_answer(&y, port_y, &token_y).expect("y answers");
    thread::sleep(Duration::from_millis(100));
    assert!(delivered(&x, port_x, &y), "both recorded, the keyed way");

    // An observer on the path has the answer `y` sent. Replayed from its own
    // address, it names a nonce that was never sent there.
    let observer = UdpSocket::bind("127.0.0.1:0").expect("bind");
    observer.send_to(&seen, port_y).expect("replay");
    // Its own hello draws a check of its own; the MAC it saw does not fit it.
    let mut hello = vec![0xF0, 0x45];
    hello.extend_from_slice(&[0u8; 16]);
    observer.send_to(&hello, port_y).expect("hello");
    observer
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let mut buf = [0u8; 64];
    let (n, _) = observer.recv_from(&mut buf).expect("checked");
    assert_eq!(n, 18);
    let mut forged = vec![0xF0, 0x46];
    forged.extend_from_slice(&buf[2..18]);
    forged.extend_from_slice(&seen[18..34]);
    observer.send_to(&forged, port_y).expect("forged");
    thread::sleep(Duration::from_millis(100));
    assert!(delivered(&x, port_x, &y), "y keeps its binding");
    assert!(drain(&observer).is_empty(), "and the observer gets nothing");

    // The control: `y` itself, from a new address, is followed.
    let moved = UdpSocket::bind("127.0.0.1:0").expect("bind");
    assert!(hello_and_answer(&moved, port_y, &token_y).is_some());
    thread::sleep(Duration::from_millis(100));
    assert!(delivered(&x, port_x, &moved), "the move is followed");
    assert!(
        !delivered(&x, port_x, &y),
        "and the old address hears nothing"
    );
}

/// A port whose token went over the wire in a version-0.3.1 bind has had it
/// seen by anyone on the path, so a keyed answer from it proves nothing: such
/// a port keeps its first address for good, as every port did in 0.3.1.
#[test]
fn a_port_that_saw_its_token_in_the_clear_never_moves() {
    let relayed = Relayed::set_up();
    let [(port_x, token_x), (port_y, token_y)] = relayed.offers;
    let x = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let y = UdpSocket::bind("127.0.0.1:0").expect("bind");
    assert!(hello_and_answer(&x, port_x, &token_x).is_some());
    bind(&y, port_y, &token_y);
    assert!(prove(&y, port_y), "recorded the 0.3.1 way");
    thread::sleep(Duration::from_millis(100));
    assert!(delivered(&x, port_x, &y));

    let thief = UdpSocket::bind("127.0.0.1:0").expect("bind");
    assert!(
        hello_and_answer(&thief, port_y, &token_y).is_none(),
        "no check is offered for a keyed answer"
    );
    assert!(delivered(&x, port_x, &y), "y keeps its binding");
}
