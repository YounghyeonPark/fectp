//! Echo servers and clients for each transport being compared.
//!
//! All of them run over loopback, so the absolute latencies below are far
//! smaller than any real network's. That is deliberate: it removes the network
//! from the comparison so what remains is the protocol's own cost. The round
//! trips a protocol *needs* are counted separately, because those are what
//! dominate once a real path is involved.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

// ────────────────────────────────────────────────────────────── FECTP ─────

/// A FECTP echo endpoint running in its own thread.
pub struct FectpEcho {
    pub addr: SocketAddr,
    pub public: Option<[u8; 32]>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FectpEcho {
    pub fn spawn(endpoint: Endpoint) -> Self {
        Self::run(endpoint, true)
    }

    /// Accepts and decrypts but sends nothing back.
    ///
    /// Echoing costs the server thread a decrypt and a send per message, and
    /// that thread competes for the same cores as the client being measured.
    /// For send-side measurements that contention is pure noise.
    pub fn drain(endpoint: Endpoint) -> Self {
        Self::run(endpoint, false)
    }

    fn run(mut endpoint: Endpoint, echo: bool) -> Self {
        let addr = endpoint.local_addr().expect("addr");
        let public = endpoint.public_key().copied();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match endpoint.poll(Some(Duration::from_millis(5))) {
                    Ok(Event::Message { peer, data }) => {
                        if echo {
                            let _ = endpoint.send(peer, &data, PayloadType::Opaque);
                        }
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

    pub fn public_key() -> Self {
        Self::spawn(Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind"))
    }

    pub fn public_key_drain() -> Self {
        Self::drain(Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind"))
    }

    pub fn plain_drain() -> Self {
        Self::drain(Endpoint::bind_plain("127.0.0.1:0").expect("bind"))
    }

    pub fn psk(secret: &[u8]) -> Self {
        Self::spawn(Endpoint::bind_psk("127.0.0.1:0", secret).expect("bind"))
    }

    pub fn plain() -> Self {
        Self::spawn(Endpoint::bind_plain("127.0.0.1:0").expect("bind"))
    }
}

impl Drop for FectpEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// One request and its echo, on an established FECTP connection.
pub fn fectp_round_trip(conn: &mut Connection, payload: &[u8], buf: &mut [u8]) {
    conn.send(payload, PayloadType::Opaque).expect("send");
    conn.recv(buf).expect("recv");
}

// ──────────────────────────────────────────────────────────── raw UDP ─────

/// An unencrypted UDP echo, as the floor any transport is measured against.
pub struct UdpEcho {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl UdpEcho {
    /// Receives and discards, the matching baseline for a send-side measurement.
    pub fn sink() -> Self {
        Self::build(false)
    }

    pub fn spawn() -> Self {
        Self::build(true)
    }

    fn build(echo: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_millis(5)))
            .expect("timeout");
        let addr = socket.local_addr().expect("addr");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while !flag.load(Ordering::Relaxed) {
                if let Ok((n, from)) = socket.recv_from(&mut buf) {
                    if echo {
                        let _ = socket.send_to(&buf[..n], from);
                    }
                }
            }
        });
        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for UdpEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ─────────────────────────────────────────────────────── TCP + TLS 1.3 ────

/// Counts the bytes a stream actually moves, so per-message overhead can be
/// measured rather than assumed.
pub struct Counted<S> {
    inner: S,
    pub written: Arc<AtomicU64>,
    pub read: Arc<AtomicU64>,
}

impl<S> Counted<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            written: Arc::new(AtomicU64::new(0)),
            read: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl<S: Read> Read for Counted<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl<S: Write> Write for Counted<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A self-signed certificate and the client configuration that trusts it.
pub struct TlsSetup {
    pub server: Arc<rustls::ServerConfig>,
    pub client: Arc<rustls::ClientConfig>,
}

impl TlsSetup {
    pub fn new() -> Self {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed certificate");
        let cert = issued.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            issued.key_pair.serialize_der().into(),
        );

        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .expect("server config");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).expect("trust the test certificate");
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        Self {
            server: Arc::new(server),
            client: Arc::new(client),
        }
    }
}

/// A TLS 1.3 echo server over TCP.
pub struct TlsEcho {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TlsEcho {
    pub fn spawn(config: Arc<rustls::ServerConfig>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((tcp, _)) => {
                        let config = Arc::clone(&config);
                        thread::spawn(move || {
                            tcp.set_nonblocking(false).ok();
                            tcp.set_nodelay(true).ok();
                            let Ok(conn) = rustls::ServerConnection::new(config) else {
                                return;
                            };
                            let mut tls = rustls::StreamOwned::new(conn, tcp);
                            // Length-prefixed messages, so a stream can be cut
                            // back into the messages a datagram protocol has
                            // for free.
                            let mut header = [0u8; 4];
                            let mut body = vec![0u8; 65535];
                            while tls.read_exact(&mut header).is_ok() {
                                let len = u32::from_le_bytes(header) as usize;
                                if len > body.len() || tls.read_exact(&mut body[..len]).is_err() {
                                    return;
                                }
                                if tls.write_all(&header).is_err()
                                    || tls.write_all(&body[..len]).is_err()
                                    || tls.flush().is_err()
                                {
                                    return;
                                }
                            }
                        });
                    }
                    Err(_) => thread::sleep(Duration::from_millis(1)),
                }
            }
        });

        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for TlsEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// An established TLS client stream, with byte counters.
pub struct TlsClient {
    pub stream: rustls::StreamOwned<rustls::ClientConnection, Counted<TcpStream>>,
    pub written: Arc<AtomicU64>,
}

/// Connects and completes the TLS handshake.
pub fn tls_connect(setup: &TlsSetup, addr: SocketAddr) -> TlsClient {
    let tcp = TcpStream::connect(addr).expect("tcp connect");
    tcp.set_nodelay(true).expect("nodelay");
    let counted = Counted::new(tcp);
    let written = Arc::clone(&counted.written);

    let conn = rustls::ClientConnection::new(
        Arc::clone(&setup.client),
        "localhost".try_into().expect("server name"),
    )
    .expect("client connection");
    let mut stream = rustls::StreamOwned::new(conn, counted);

    // Drive the handshake to completion so it is not charged to the first
    // message.
    stream.flush().expect("flush");
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).expect("handshake");
    }
    TlsClient { stream, written }
}

/// One request and its echo over TLS.
pub fn tls_round_trip(client: &mut TlsClient, payload: &[u8], buf: &mut [u8]) {
    let header = (payload.len() as u32).to_le_bytes();
    client.stream.write_all(&header).expect("write header");
    client.stream.write_all(payload).expect("write body");
    client.stream.flush().expect("flush");

    let mut back = [0u8; 4];
    client.stream.read_exact(&mut back).expect("read header");
    let len = u32::from_le_bytes(back) as usize;
    client.stream.read_exact(&mut buf[..len]).expect("read body");
}

// ───────────────────────────────────────────────────────── lossy path ─────

/// A UDP relay that drops a fixed proportion of what passes through it.
///
/// Loss is the one thing loopback cannot supply, and it is the condition the
/// reliability layer exists for — so it has to be manufactured. The drop
/// decision comes from a seeded generator rather than the system's, so a run is
/// reproducible and two protocols can be given the same pattern of loss.
///
/// The opening datagram in each direction is exempt. These measure steady-state
/// delivery, and a dropped handshake would measure connection setup instead.
pub struct LossyRelay {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl LossyRelay {
    pub fn spawn(server: SocketAddr, per_mille: u32, seed: u64) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
        let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
        back.connect(server).expect("connect back");
        front
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");
        back.set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");
        let addr = front.local_addr().expect("addr");

        let stop = Arc::new(AtomicBool::new(false));
        let client: Arc<std::sync::Mutex<Option<SocketAddr>>> =
            Arc::new(std::sync::Mutex::new(None));

        let front_rx = front.try_clone().expect("clone");
        let back_tx = back.try_clone().expect("clone");
        let learn = Arc::clone(&client);
        let flag = Arc::clone(&stop);
        thread::spawn(move || {
            let mut rng = seed;
            let mut buf = [0u8; 65535];
            let mut seen = 0u64;
            while !flag.load(Ordering::Relaxed) {
                let Ok((n, from)) = front_rx.recv_from(&mut buf) else {
                    continue;
                };
                *learn.lock().expect("lock") = Some(from);
                seen += 1;
                if seen > 1 && drops(&mut rng, per_mille) {
                    continue;
                }
                let _ = back_tx.send(&buf[..n]);
            }
        });

        let flag = Arc::clone(&stop);
        thread::spawn(move || {
            let mut rng = seed ^ 0x9E37_79B9_7F4A_7C15;
            let mut buf = [0u8; 65535];
            let mut seen = 0u64;
            while !flag.load(Ordering::Relaxed) {
                let Ok(n) = back.recv(&mut buf) else {
                    continue;
                };
                seen += 1;
                if seen > 1 && drops(&mut rng, per_mille) {
                    continue;
                }
                let Some(dest) = *client.lock().expect("lock") else {
                    continue;
                };
                let _ = front.send_to(&buf[..n], dest);
            }
        });

        Self { addr, stop }
    }
}

impl Drop for LossyRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn drops(state: &mut u64, per_mille: u32) -> bool {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    (*state >> 33) % 1000 < u64::from(per_mille)
}

// ──────────────────────────────────────────── other things a path does ────

/// A relay that delivers datagrams out of order.
///
/// Holds every `every`-th datagram for `delay`, which is what a path with more
/// than one route does. Loss and reordering look the same to a naive receiver,
/// so this is worth separating: a protocol can be right about one and wrong
/// about the other.
///
/// The delay is a *time*, not a count of datagrams that must arrive first. An
/// earlier version released the held frame only when the next one turned up,
/// which deadlocks whenever the held frame is the one the sender is waiting on
/// — and then reports the retransmission timeout as the cost of reordering.
///
/// `every == 1` delays every datagram equally, which reorders nothing. That is
/// the control the reordering runs need: delaying a datagram slows any protocol
/// down, so the question is whether reordering costs more than the delay it
/// comes with, and only a same-delay-no-reordering run can answer it.
pub struct ReorderingRelay {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl ReorderingRelay {
    pub fn spawn(server: SocketAddr, every: u64, delay: Duration) -> Self {
        let (front, back, addr, stop, client) = relay_sockets(server);

        let front_rx = front.try_clone().expect("clone");
        let back_tx = back.try_clone().expect("clone");
        let learn = Arc::clone(&client);
        let flag = Arc::clone(&stop);
        thread::spawn(move || {
            let mut buf = [0u8; 65535];
            let mut seen = 0u64;
            let mut held: std::collections::VecDeque<(Vec<u8>, Instant)> =
                std::collections::VecDeque::new();
            while !flag.load(Ordering::Relaxed) {
                // Checked on every pass, including the ones where the socket
                // timed out, so a held frame is released whether or not the
                // sender has anything else to say.
                while let Some((frame, since)) = held.front() {
                    if since.elapsed() < delay {
                        break;
                    }
                    let _ = back_tx.send(frame);
                    held.pop_front();
                }

                let Ok((n, from)) = front_rx.recv_from(&mut buf) else {
                    continue;
                };
                *learn.lock().expect("lock") = Some(from);
                seen += 1;

                if seen > 1 && seen.is_multiple_of(every) {
                    held.push_back((buf[..n].to_vec(), Instant::now()));
                    continue;
                }
                let _ = back_tx.send(&buf[..n]);
            }
        });

        spawn_return_path(back, front, client, flag_clone(&stop));
        Self { addr, stop }
    }
}

impl Drop for ReorderingRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A relay with a bandwidth limit and a finite queue.
///
/// This is the condition FECTP has no answer for: its send window is fixed, so
/// it does not slow down when a path cannot keep up. Whatever will not fit in
/// the queue is dropped, and the drops are the sender's own doing.
pub struct BottleneckRelay {
    pub addr: SocketAddr,
    /// Datagrams dropped because the queue was full.
    pub overflowed: Arc<AtomicU64>,
    /// Datagrams that arrived at the bottleneck.
    pub offered: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl BottleneckRelay {
    /// `bytes_per_sec` is the link rate; `queue_bytes` is what it can buffer.
    pub fn spawn(server: SocketAddr, bytes_per_sec: u64, queue_bytes: usize) -> Self {
        let (front, back, addr, stop, client) = relay_sockets(server);
        let overflowed = Arc::new(AtomicU64::new(0));
        let offered = Arc::new(AtomicU64::new(0));

        let front_rx = front.try_clone().expect("clone");
        let back_tx = back.try_clone().expect("clone");
        let learn = Arc::clone(&client);
        let flag = Arc::clone(&stop);
        let over = Arc::clone(&overflowed);
        let off = Arc::clone(&offered);
        thread::spawn(move || {
            let mut buf = [0u8; 65535];
            let mut queue: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
            let mut queued_bytes = 0usize;
            let mut credit = 0f64;
            let mut last = Instant::now();

            while !flag.load(Ordering::Relaxed) {
                // Refill the link's budget for however long has passed.
                let now = Instant::now();
                credit += now.duration_since(last).as_secs_f64() * bytes_per_sec as f64;
                last = now;
                credit = credit.min(bytes_per_sec as f64);

                while let Some(frame) = queue.front() {
                    if credit < frame.len() as f64 {
                        break;
                    }
                    credit -= frame.len() as f64;
                    queued_bytes -= frame.len();
                    let _ = back_tx.send(frame);
                    queue.pop_front();
                }

                let Ok((n, from)) = front_rx.recv_from(&mut buf) else {
                    continue;
                };
                *learn.lock().expect("lock") = Some(from);
                off.fetch_add(1, Ordering::Relaxed);

                if queued_bytes + n > queue_bytes {
                    over.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                queued_bytes += n;
                queue.push_back(buf[..n].to_vec());
            }
        });

        spawn_return_path(back, front, client, flag_clone(&stop));
        Self {
            addr,
            overflowed,
            offered,
            stop,
        }
    }
}

impl Drop for BottleneckRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Sockets, address and shared state common to every relay here.
#[allow(clippy::type_complexity)]
fn relay_sockets(
    server: SocketAddr,
) -> (
    UdpSocket,
    UdpSocket,
    SocketAddr,
    Arc<AtomicBool>,
    Arc<std::sync::Mutex<Option<SocketAddr>>>,
) {
    let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
    let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
    back.connect(server).expect("connect back");
    front
        .set_read_timeout(Some(Duration::from_millis(2)))
        .expect("timeout");
    back.set_read_timeout(Some(Duration::from_millis(2)))
        .expect("timeout");
    let addr = front.local_addr().expect("addr");
    (
        front,
        back,
        addr,
        Arc::new(AtomicBool::new(false)),
        Arc::new(std::sync::Mutex::new(None)),
    )
}

fn flag_clone(stop: &Arc<AtomicBool>) -> Arc<AtomicBool> {
    Arc::clone(stop)
}

/// Forwards the server's replies back to whichever address the client used.
fn spawn_return_path(
    back: UdpSocket,
    front: UdpSocket,
    client: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    flag: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while !flag.load(Ordering::Relaxed) {
            let Ok(n) = back.recv(&mut buf) else {
                continue;
            };
            let Some(dest) = *client.lock().expect("lock") else {
                continue;
            };
            let _ = front.send_to(&buf[..n], dest);
        }
    });
}

/// A relay that changes the source address it forwards from, part-way through.
///
/// This is what a NAT does when its mapping expires and is re-created on a new
/// port. A session keyed on the peer's address cannot follow it.
pub struct RebindingRelay {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl RebindingRelay {
    pub fn spawn(server: SocketAddr, rebind_after: u64) -> Self {
        let (front, back, addr, stop, client) = relay_sockets(server);
        let second = UdpSocket::bind("127.0.0.1:0").expect("bind second");
        second.connect(server).expect("connect second");
        second
            .set_read_timeout(Some(Duration::from_millis(2)))
            .expect("timeout");

        let front_rx = front.try_clone().expect("clone");
        let first_tx = back.try_clone().expect("clone");
        let second_tx = second.try_clone().expect("clone");
        let learn = Arc::clone(&client);
        let flag = Arc::clone(&stop);
        thread::spawn(move || {
            let mut buf = [0u8; 65535];
            let mut seen = 0u64;
            while !flag.load(Ordering::Relaxed) {
                let Ok((n, from)) = front_rx.recv_from(&mut buf) else {
                    continue;
                };
                *learn.lock().expect("lock") = Some(from);
                seen += 1;
                let _ = if seen > rebind_after {
                    second_tx.send(&buf[..n])
                } else {
                    first_tx.send(&buf[..n])
                };
            }
        });

        spawn_return_path(back, front.try_clone().expect("clone"), Arc::clone(&client), flag_clone(&stop));
        spawn_return_path(second, front, client, flag_clone(&stop));
        Self { addr, stop }
    }
}

impl Drop for RebindingRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A relay that varies how long each datagram takes.
///
/// Delay is uniform in `[0, spread]`, which both jitters and reorders — that is
/// what variable queueing actually does. It counts what passes so a caller can
/// tell retransmissions from first transmissions: nothing is dropped here, so
/// every datagram above the expected count is one the sender resent for no
/// reason.
pub struct JitterRelay {
    pub addr: SocketAddr,
    /// Datagrams forwarded towards the server.
    pub forwarded: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl JitterRelay {
    pub fn spawn(server: SocketAddr, spread: Duration, seed: u64) -> Self {
        let (front, back, addr, stop, client) = relay_sockets(server);
        let forwarded = Arc::new(AtomicU64::new(0));

        let front_rx = front.try_clone().expect("clone");
        let back_tx = back.try_clone().expect("clone");
        let learn = Arc::clone(&client);
        let flag = Arc::clone(&stop);
        let counted = Arc::clone(&forwarded);
        thread::spawn(move || {
            let mut rng = seed | 1;
            let mut buf = [0u8; 65535];
            let mut held: Vec<(Vec<u8>, Instant)> = Vec::new();
            while !flag.load(Ordering::Relaxed) {
                // Released by time, and not necessarily in the order received:
                // that reordering is part of what jitter is.
                let now = Instant::now();
                held.retain(|(frame, due)| {
                    if *due <= now {
                        let _ = back_tx.send(frame);
                        false
                    } else {
                        true
                    }
                });

                let Ok((n, from)) = front_rx.recv_from(&mut buf) else {
                    continue;
                };
                *learn.lock().expect("lock") = Some(from);
                counted.fetch_add(1, Ordering::Relaxed);

                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let share = (rng >> 40) as f64 / (1u64 << 24) as f64;
                let wait = spread.mul_f64(share);
                if wait.is_zero() {
                    let _ = back_tx.send(&buf[..n]);
                } else {
                    held.push((buf[..n].to_vec(), Instant::now() + wait));
                }
            }
        });

        spawn_return_path(back, front, client, flag_clone(&stop));
        Self {
            addr,
            forwarded,
            stop,
        }
    }
}

impl Drop for JitterRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A [`LossyRelay`] that drops at different rates in each direction.
///
/// Losing an acknowledgement and losing the data it would have acknowledged are
/// not the same event, and a protocol can be much better at one than the other.
pub struct AsymmetricRelay {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl AsymmetricRelay {
    pub fn spawn(server: SocketAddr, forward_per_mille: u32, back_per_mille: u32, seed: u64) -> Self {
        let (front, back, addr, stop, client) = relay_sockets(server);

        let front_rx = front.try_clone().expect("clone");
        let back_tx = back.try_clone().expect("clone");
        let learn = Arc::clone(&client);
        let flag = Arc::clone(&stop);
        thread::spawn(move || {
            let mut rng = seed | 1;
            let mut buf = [0u8; 65535];
            let mut seen = 0u64;
            while !flag.load(Ordering::Relaxed) {
                let Ok((n, from)) = front_rx.recv_from(&mut buf) else {
                    continue;
                };
                *learn.lock().expect("lock") = Some(from);
                seen += 1;
                if seen > 1 && drops(&mut rng, forward_per_mille) {
                    continue;
                }
                let _ = back_tx.send(&buf[..n]);
            }
        });

        let flag = flag_clone(&stop);
        let learn = Arc::clone(&client);
        thread::spawn(move || {
            let mut rng = (seed ^ 0x9E37_79B9_7F4A_7C15) | 1;
            let mut buf = [0u8; 65535];
            let mut seen = 0u64;
            while !flag.load(Ordering::Relaxed) {
                let Ok(n) = back.recv(&mut buf) else {
                    continue;
                };
                seen += 1;
                if seen > 1 && drops(&mut rng, back_per_mille) {
                    continue;
                }
                let Some(dest) = *learn.lock().expect("lock") else {
                    continue;
                };
                let _ = front.send_to(&buf[..n], dest);
            }
        });

        Self { addr, stop }
    }
}

impl Drop for AsymmetricRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
