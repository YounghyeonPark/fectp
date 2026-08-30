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
use std::time::Duration;

use fectp::{Connection, Endpoint, Event, Identity};

// ────────────────────────────────────────────────────────────── FECTP ─────

/// A FECTP echo endpoint running in its own thread.
pub struct FectpEcho {
    pub addr: SocketAddr,
    pub public: Option<[u8; 32]>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FectpEcho {
    pub fn spawn(mut endpoint: Endpoint) -> Self {
        let addr = endpoint.local_addr().expect("addr");
        let public = endpoint.public_key().copied();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match endpoint.poll(Some(Duration::from_millis(5))) {
                    Ok(Event::Message { peer, data }) => {
                        let _ = endpoint.send(peer, &data);
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
    conn.send(payload).expect("send");
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
    pub fn spawn() -> Self {
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
                    let _ = socket.send_to(&buf[..n], from);
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
