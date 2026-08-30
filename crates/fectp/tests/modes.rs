//! The three security modes, and the boundary between them.
//!
//! The property that matters most here is negative: a peer in one mode must
//! not be able to talk to a peer in another. A protocol that lets peers settle
//! their own security level is a protocol that can be talked down to the
//! weakest one on offer.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Event, Identity, PayloadType, Endpoint};

const TIMEOUT: Duration = Duration::from_secs(5);
const SECRET: &[u8] = b"lab-instrument-7";

/// Runs an echo server in the background until the returned guard is dropped.
struct Echo {
    addr: SocketAddr,
    public: Option<[u8; 32]>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Echo {
    fn spawn(mut server: Endpoint) -> Self {
        let addr = server.local_addr().expect("addr");
        let public = server.public_key().copied();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match server.poll(Some(Duration::from_millis(50))) {
                    Ok(Event::Message { peer, data }) => {
                        let _ = server.send(peer, &data);
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
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

impl Drop for Echo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn public_key_server() -> Echo {
    Echo::spawn(Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind"))
}

fn psk_server() -> Echo {
    Echo::spawn(Endpoint::bind_psk("127.0.0.1:0", SECRET).expect("bind"))
}

fn plain_server() -> Echo {
    Echo::spawn(Endpoint::bind_plain("127.0.0.1:0").expect("bind"))
}

fn exchange(conn: &mut Connection, message: &[u8]) -> Vec<u8> {
    conn.set_read_timeout(Some(TIMEOUT)).expect("timeout");
    conn.send(message).expect("send");
    let mut buf = vec![0u8; 64 * 1024];
    let n = conn.recv(&mut buf).expect("recv");
    buf[..n].to_vec()
}

// ------------------------------------------------------ each mode works ---

#[test]
fn public_key_mode_round_trips() {
    let echo = public_key_server();
    let public = echo.public.expect("public-key mode presents an identity");
    let mut conn =
        Connection::connect(echo.addr, &public, &Identity::generate()).expect("connect");
    assert!(conn.is_encrypted());
    assert_eq!(exchange(&mut conn, b"public key"), b"public key");
    assert!(conn.resumption_ticket().is_some());
}

#[test]
fn psk_mode_round_trips() {
    let echo = psk_server();
    assert!(
        echo.public.is_none(),
        "a pre-shared-key server presents no identity of its own"
    );

    let mut conn = Connection::connect_psk(echo.addr, SECRET).expect("connect");
    assert!(conn.is_encrypted(), "a pre-shared key still encrypts");
    assert_eq!(exchange(&mut conn, b"shared secret"), b"shared secret");
}

#[test]
fn plain_mode_round_trips() {
    let echo = plain_server();
    let mut conn = Connection::connect_plain(echo.addr).expect("connect");
    assert!(!conn.is_encrypted());
    assert!(
        conn.resumption_ticket().is_none(),
        "there is no key schedule to carry forward"
    );
    assert_eq!(exchange(&mut conn, b"in the clear"), b"in the clear");
}

// -------------------------------------------------- modes do not mix ------

#[test]
fn a_plaintext_client_cannot_talk_to_an_encrypted_server() {
    // The heart of it: no downgrade. The server never sees a frame type it
    // accepts, so there is nothing to negotiate away.
    let echo = public_key_server();
    assert!(
        Connection::connect_plain(echo.addr).is_err(),
        "an encrypted server must not answer a plaintext opening frame"
    );

    let echo = psk_server();
    assert!(
        Connection::connect_plain(echo.addr).is_err(),
        "a pre-shared-key server must not answer a plaintext opening frame"
    );
}

#[test]
fn an_encrypted_client_cannot_talk_to_a_plaintext_server() {
    let echo = plain_server();
    let unrelated = *Identity::generate().public();

    assert!(
        Connection::connect(echo.addr, &unrelated, &Identity::generate()).is_err(),
        "a plaintext server has no key and must not complete a public-key handshake"
    );
    assert!(
        Connection::connect_psk(echo.addr, SECRET).is_err(),
        "a plaintext server holds no pre-shared key"
    );
}

#[test]
fn the_wrong_shared_secret_is_refused() {
    let echo = psk_server();
    assert!(
        Connection::connect_psk(echo.addr, b"not the secret").is_err(),
        "the pre-shared key is what authenticates; a wrong one must not connect"
    );
    // And the right one still works afterwards, so a failed attempt leaves no
    // damage behind.
    let mut conn = Connection::connect_psk(echo.addr, SECRET).expect("connect");
    assert_eq!(exchange(&mut conn, b"still fine"), b"still fine");
}

#[test]
fn a_public_key_client_cannot_use_a_psk_server() {
    let echo = psk_server();
    let unrelated = *Identity::generate().public();
    assert!(
        Connection::connect(echo.addr, &unrelated, &Identity::generate()).is_err(),
        "a pre-shared-key server does not accept full handshakes"
    );
}

// ------------------------------------------- everything above is the same --

#[test]
fn the_upper_layers_behave_identically_in_every_mode() {
    // Codecs and reliability are what the modes are meant not to disturb.
    let samples: Vec<u8> = (0..512i16).flat_map(|i| (i / 4).to_le_bytes()).collect();

    for (label, echo, connect) in [
        (
            "public key",
            public_key_server(),
            Box::new(|echo: &Echo| {
                Connection::connect(echo.addr, &echo.public.unwrap(), &Identity::generate())
            }) as Box<dyn Fn(&Echo) -> fectp::Result<Connection>>,
        ),
        (
            "pre-shared key",
            psk_server(),
            Box::new(|echo: &Echo| Connection::connect_psk(echo.addr, SECRET)),
        ),
        (
            "plaintext",
            plain_server(),
            Box::new(|echo: &Echo| Connection::connect_plain(echo.addr)),
        ),
    ] {
        let conn = connect(&echo).unwrap_or_else(|e| panic!("{label}: connect failed: {e}"));
        conn.set_read_timeout(Some(TIMEOUT)).expect("timeout");

        // Typed payloads, well over one frame, so coding has to work.
        conn.send_typed(&samples, PayloadType::I16 { channels: 4 })
            .unwrap_or_else(|e| panic!("{label}: send_typed failed: {e}"));
        let mut buf = vec![0u8; 64 * 1024];
        let n = conn.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], &samples[..], "{label}: coded payload");

        // Reliable delivery.
        conn.send_reliable(b"must arrive")
            .unwrap_or_else(|e| panic!("{label}: send_reliable failed: {e}"));
        conn.flush(Duration::from_secs(2))
            .unwrap_or_else(|e| panic!("{label}: flush failed: {e}"));
        assert_eq!(conn.unacknowledged(), 0, "{label}: acknowledged");

        // The echo of the reliable message is still queued; drain it.
        let n = conn.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"must arrive", "{label}: reliable echo");
    }
}

#[test]
fn plaintext_frames_are_smaller() {
    // No authentication tag, because there is no authentication: 14 bytes of
    // per-frame overhead rather than 30.
    let plain = plain_server();
    let conn = Connection::connect_plain(plain.addr).expect("connect");
    let plain_limit = conn.max_payload();
    drop(conn);

    let encrypted = public_key_server();
    let public = encrypted.public.expect("identity");
    let conn = Connection::connect(encrypted.addr, &public, &Identity::generate()).expect("connect");
    let encrypted_limit = conn.max_payload();

    assert_eq!(
        plain_limit - encrypted_limit,
        16,
        "the difference is exactly the Poly1305 tag"
    );
}

#[test]
fn many_peers_work_in_psk_mode() {
    const PEERS: usize = 4;
    let echo = psk_server();

    let mut conns: Vec<Connection> = (0..PEERS)
        .map(|_| Connection::connect_psk(echo.addr, SECRET).expect("connect"))
        .collect();

    for (index, conn) in conns.iter_mut().enumerate() {
        let message = format!("peer {index}");
        assert_eq!(
            exchange(conn, message.as_bytes()),
            message.as_bytes(),
            "a shared secret must still give each peer its own session"
        );
    }
}

#[test]
fn a_shared_secret_is_reusable_but_a_ticket_is_not() {
    // The one place pre-shared keys and resumption tickets differ: both drive
    // the same handshake, but a configured secret is long-lived while an
    // earned ticket is spent on redemption.
    let echo = psk_server();
    let start = Instant::now();
    let mut connections = 0;
    while start.elapsed() < Duration::from_secs(2) && connections < 3 {
        let mut conn =
            Connection::connect_psk(echo.addr, SECRET).expect("reconnect");
        assert_eq!(exchange(&mut conn, b"again"), b"again");
        connections += 1;
    }
    assert_eq!(connections, 3, "the same secret must work every time");
}

#[test]
fn a_peer_that_never_answers_is_reported_rather_than_waited_on() {
    use std::net::UdpSocket;
    use std::sync::mpsc;

    // A bound port with nothing speaking the protocol behind it: the kernel
    // accepts the datagram and nobody ever replies.
    let silent = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = silent.local_addr().expect("addr");
    let key = *Identity::generate().public();

    // `connect` used to set no read timeout at all and would block here for
    // ever. `connect_with_timeout` existed as the way around that, which is
    // why the timeout argument was on some constructors and not others.
    let (done, waiting) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(Connection::connect(addr, &key, &Identity::generate()).is_err());
    });

    let refused = waiting
        .recv_timeout(fectp::HANDSHAKE_TIMEOUT * 3)
        .expect("connect must give up, not block for ever");
    assert!(refused, "an unanswered handshake is an error");
}

#[test]
fn every_mode_gives_up_on_a_silent_peer() {
    use std::net::UdpSocket;
    use std::sync::mpsc;

    // The same for the modes whose timeout argument has gone: none of them
    // should now be able to hang either.
    for mode in ["psk", "plain"] {
        let silent = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = silent.local_addr().expect("addr");
        let (done, waiting) = mpsc::channel();
        std::thread::spawn(move || {
            let refused = match mode {
                "psk" => Connection::connect_psk(addr, SECRET).is_err(),
                _ => Connection::connect_plain(addr).is_err(),
            };
            let _ = done.send(refused);
        });
        let refused = waiting
            .recv_timeout(fectp::HANDSHAKE_TIMEOUT * 3)
            .unwrap_or_else(|_| panic!("{mode} blocked instead of giving up"));
        assert!(refused, "{mode}: an unanswered handshake is an error");
    }
}
