//! Replaying a captured opening frame, in each of the two modes that accept
//! one.
//!
//! These exist because [`docs/formal/resumption.vp`](../../../docs/formal/resumption.vp)
//! said they should. Verifpal reports non-injective agreement on message 1 of
//! the resumption handshake: the responder contributes nothing to that frame
//! before accepting it, so nothing *in the cryptography* stops the same frame
//! being accepted twice. SPEC 4.6 answers that with a rule rather than a
//! construction — a resumption ticket MUST be spent when redeemed — and SPEC
//! 1.2.1 exempts a configured pre-shared key from it, because a responder that
//! spent the key would refuse the peer's next connection.
//!
//! Both halves of that are deliberate. What follows from them is that the two
//! modes have different replay exposure, and these measure the pre-shared-key
//! side of it — what a replay buys an attacker, and where it stops. The
//! resumption side needs nothing here: `resumption.rs::a_ticket_is_single_use`
//! already redeems a ticket twice, from a fresh socket each time, and the
//! second attempt fails.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use fectp::{Endpoint, Event};

/// A configured secret, for the pre-shared-key mode.
const SECRET: &[u8] = b"a secret both ends were given out of band";

/// First byte of a `ResumeInit` frame: version 1, frame type 6.
const RESUME_INIT: u8 = 0x16;

/// Forwards client datagrams to the server, keeping the first `ResumeInit` so
/// a test can send it again.
///
/// Not a thread: the test drives it, so that "capture, then replay" is a
/// sequence rather than a race.
struct Tap {
    socket: UdpSocket,
    server: SocketAddr,
    client: Option<SocketAddr>,
    captured: Option<Vec<u8>>,
}

impl Tap {
    fn new(server: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("tap bind");
        socket
            .set_read_timeout(Some(Duration::from_millis(2)))
            .expect("timeout");
        Self {
            socket,
            server,
            client: None,
            captured: None,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("addr")
    }

    /// Moves whatever is waiting, in both directions.
    fn pump(&mut self) {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = self.socket.recv_from(&mut buf) {
            if from == self.server {
                if let Some(client) = self.client {
                    let _ = self.socket.send_to(&buf[..n], client);
                }
                continue;
            }
            self.client = Some(from);
            if n > 0 && buf[0] == RESUME_INIT && self.captured.is_none() {
                self.captured = Some(buf[..n].to_vec());
            }
            let _ = self.socket.send_to(&buf[..n], self.server);
        }
    }

    /// Sends the captured opening frame to the server again, from an address
    /// it has not been seen from.
    ///
    /// The address matters, and finding that out is why this test exists in
    /// this shape. Replaying from the *same* address gets nowhere:
    /// `repeat_handshake` finds the route the first handshake left behind,
    /// takes the frame for an honest client whose reply went missing, and
    /// resends the cached response instead of building a second session. An
    /// attacker holding a captured datagram has no reason to cooperate with
    /// that — sending it from anywhere else is easier, not harder.
    fn replay_from_elsewhere(&self) {
        let frame = self.captured.as_ref().expect("an opening frame was captured");
        let other = UdpSocket::bind("127.0.0.1:0").expect("replay bind");
        other.send_to(frame, self.server).expect("replay the frame");
    }
}

/// Runs both endpoints and the tap until `want` events have been collected
/// from the server, or the deadline passes.
fn collect_zero_rtt(
    server: &mut Endpoint,
    client: &mut Endpoint,
    tap: &mut Tap,
    want: usize,
    within: Duration,
) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + within;
    let mut seen = Vec::new();
    while Instant::now() < deadline && seen.len() < want {
        tap.pump();
        if let Ok(Event::Connected { zero_rtt, .. }) = server.poll(Some(Duration::from_millis(1))) {
            seen.push(zero_rtt);
        }
        let _ = client.poll(Some(Duration::from_millis(1)));
    }
    seen
}

/// In pre-shared-key mode a captured opening frame is accepted twice, and the
/// data it carries reaches the application twice.
///
/// Nothing here is a defect in the implementation: SPEC 1.2.1 requires that a
/// configured key not be consumed, and SPEC 4.8 says 0-RTT data is replayable.
/// This test is what joins those two sentences into the consequence neither of
/// them states, so that it is a measured property with a name rather than
/// something a reader has to derive.
#[test]
fn a_configured_key_accepts_a_replayed_opening_frame() {
    let mut server = Endpoint::bind_psk("127.0.0.1:0", SECRET).expect("server");
    let server_addr = server.local_addr().expect("addr");
    let mut tap = Tap::new(server_addr);
    let mut client = Endpoint::bind_psk("127.0.0.1:0", SECRET).expect("client");

    client
        .connect_and_send(tap.addr(), None, b"reading 1")
        .expect("connect");

    let first = collect_zero_rtt(&mut server, &mut client, &mut tap, 1, Duration::from_secs(5));
    assert_eq!(first.len(), 1, "the handshake did not complete");
    assert_eq!(first[0], b"reading 1", "the 0-RTT payload arrived");

    tap.replay_from_elsewhere();
    let again = collect_zero_rtt(&mut server, &mut client, &mut tap, 1, Duration::from_secs(5));

    assert_eq!(
        again.len(),
        1,
        "the replayed frame was refused. If that is now the intended \
         behaviour, SPEC 1.2.1 and docs/formal/README.md both say the \
         opposite and need changing with this test."
    );
    assert_eq!(
        again[0], b"reading 1",
        "the replayed frame delivered its 0-RTT payload a second time"
    );
}

/// One captured datagram, replayed from many addresses, fills the responder's
/// session table.
///
/// This is the part that is not just "0-RTT data is replayable". An attacker
/// who does **not** hold the pre-shared key cannot make this responder
/// allocate anything: a handshake it cannot author is refused before a session
/// exists. Replay hands it that ability anyway, from a single datagram it only
/// had to observe — and every session it creates is one the eviction order may
/// drop a legitimate peer to make room for.
#[test]
fn a_replayed_opening_frame_takes_a_session_slot_each_time() {
    let mut server = Endpoint::bind_psk("127.0.0.1:0", SECRET).expect("server");
    let server_addr = server.local_addr().expect("addr");
    let mut tap = Tap::new(server_addr);
    let mut client = Endpoint::bind_psk("127.0.0.1:0", SECRET).expect("client");

    client
        .connect_and_send(tap.addr(), None, b"reading 1")
        .expect("connect");
    let first = collect_zero_rtt(&mut server, &mut client, &mut tap, 1, Duration::from_secs(5));
    assert_eq!(first.len(), 1, "the handshake did not complete");
    let honest = server.peers().len();
    assert_eq!(honest, 1, "one honest peer");

    // Ten replays, each from an address of its own, which is what a captured
    // datagram costs an attacker to resend.
    const REPLAYS: usize = 10;
    for _ in 0..REPLAYS {
        tap.replay_from_elsewhere();
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && server.peers().len() < honest + REPLAYS {
        tap.pump();
        let _ = server.poll(Some(Duration::from_millis(1)));
    }

    assert_eq!(
        server.peers().len(),
        honest + REPLAYS,
        "expected one session per replayed copy of the same frame"
    );
}

/// A peer that has spoken survives any number of replayed frames.
///
/// The obvious worry about the test above is the next step: fill the table and
/// evict the honest peers. It does not happen, and the reason is the eviction
/// order rather than anything about replay. `make_room` drops the oldest peer
/// that has **never sent an authenticated frame**, and a session conjured from
/// a replayed opening frame never sends one — the attacker cannot, because it
/// does not hold the key. So the replays evict each other.
///
/// Measured rather than read off the code, because the first reading of this
/// was wrong in the other direction.
#[test]
fn replays_evict_each_other_and_not_a_peer_that_has_spoken() {
    let mut server = Endpoint::bind_psk("127.0.0.1:0", SECRET).expect("server");
    server.set_max_peers(8);
    let server_addr = server.local_addr().expect("addr");
    let mut tap = Tap::new(server_addr);
    let mut client = Endpoint::bind_psk("127.0.0.1:0", SECRET).expect("client");

    let peer = client
        .connect_and_send(tap.addr(), None, b"reading 1")
        .expect("connect");
    let first = collect_zero_rtt(&mut server, &mut client, &mut tap, 1, Duration::from_secs(5));
    assert_eq!(first.len(), 1, "the handshake did not complete");

    // The server is connected before the client is: `collect_zero_rtt` stops
    // on the server's event, and the reply is still in flight. Wait for the
    // client's own side, or its handle is not yet one it can send on.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    while Instant::now() < deadline && !ready {
        tap.pump();
        let _ = server.poll(Some(Duration::from_millis(1)));
        if let Ok(Event::Connected { .. }) = client.poll(Some(Duration::from_millis(1))) {
            ready = true;
        }
    }
    assert!(ready, "the client never completed its side of the handshake");

    // The honest peer says something, which is what separates it from a
    // session that was only ever conjured.
    client
        .send(peer, b"an authenticated frame", fectp::PayloadType::Opaque)
        .expect("send");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut heard = false;
    while Instant::now() < deadline && !heard {
        tap.pump();
        if let Ok(Event::Message { .. }) = server.poll(Some(Duration::from_millis(1))) {
            heard = true;
        }
        let _ = client.poll(Some(Duration::from_millis(1)));
    }
    assert!(heard, "the honest peer's frame must arrive");
    let honest = server.peers();
    assert_eq!(honest.len(), 1);

    // Four times the table's worth of replays.
    for _ in 0..32 {
        tap.replay_from_elsewhere();
        let end = Instant::now() + Duration::from_millis(40);
        while Instant::now() < end {
            tap.pump();
            let _ = server.poll(Some(Duration::from_millis(1)));
        }
    }

    assert!(
        server.peers().contains(&honest[0]),
        "the peer that spoke was evicted by sessions that never did"
    );
    assert!(
        server.peers().len() <= 8,
        "the table grew past max_peers: {}",
        server.peers().len()
    );
}
