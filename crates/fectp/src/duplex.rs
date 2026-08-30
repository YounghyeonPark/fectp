//! Sending and receiving at the same time, from different threads.
//!
//! [`Connection`](crate::Connection) takes `&mut self` for both `send` and
//! `recv`, so one cannot run while the other is blocked. That is a property of
//! the API rather than of the protocol: after the Noise handshake splits, the
//! two directions have separate cipher states and share nothing, and one UDP
//! socket may be sent on and received on at once.
//!
//! What is *not* independent is the reliability layer. An acknowledgement is an
//! encrypted frame in the send direction, so the receiving side has to send;
//! and a retransmission has to happen whether or not the application is asking
//! for anything. A plain "split into two halves" API leaves both of those as
//! the caller's problem — the halves look symmetric but the receiving one has
//! to keep being polled or the *sending* one silently stops retransmitting.
//!
//! So this does not split the connection; it puts the protocol on its own
//! thread and hands back two handles with no such contract. Acknowledgements
//! and retransmissions happen because the thread is running, not because the
//! caller remembered to ask.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fectp_core::frame::HEADER_LEN;
use fectp_core::Transport;

use crate::compress::PayloadType;
use crate::pipeline::{deliver, decoded_capacity, Ingested, Peer};
use crate::udp::UdpTransport;
use crate::{Connection, Error, Result};

/// How long the protocol thread waits on the socket when nothing is due.
///
/// It wakes for a retransmission deadline before this, so the interval only
/// bounds how quickly a shutdown is noticed.
const IDLE_POLL: Duration = Duration::from_millis(20);

/// The state both directions touch.
///
/// Held across a seal or an ingest — microseconds — and never across a blocking
/// socket read, which happens on a separate handle with no lock held.
struct Shared {
    peer: Peer,
    transport: UdpTransport,
    tx: Vec<u8>,
    /// Origin of the millisecond clock, shared with the worker so a timestamp
    /// taken here means the same thing as one taken there.
    epoch: Instant,
}

/// The sending half.
///
/// Usable from any thread, and from a different one than the receiver.
pub struct DuplexSender {
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
}

/// The receiving half.
///
/// Usable from any thread, and from a different one than the sender.
pub struct DuplexReceiver {
    inbox: Receiver<Vec<u8>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Connection {
    /// Splits into a sender and a receiver that work at the same time.
    ///
    /// ```no_run
    /// # fn main() -> fectp::Result<()> {
    /// # let conn: fectp::Connection = unimplemented!();
    /// let (tx, rx) = conn.into_duplex();
    ///
    /// std::thread::spawn(move || {
    ///     while let Ok(message) = rx.recv() {
    ///         println!("{} bytes", message.len());
    ///     }
    /// });
    ///
    /// tx.send(b"sent while the other thread is blocked reading")?;
    /// # Ok(()) }
    /// ```
    ///
    /// The two halves have no obligations to each other. Acknowledgements go
    /// out and lost messages are retransmitted whether or not anything is
    /// calling [`recv`](DuplexReceiver::recv), because the protocol runs on a
    /// thread of its own rather than inside the calls.
    ///
    /// The thread stops when either half is dropped, and
    /// [`recv`](DuplexReceiver::recv) then reports the connection closed.
    pub fn into_duplex(self) -> (DuplexSender, DuplexReceiver) {
        let Connection {
            transport,
            peer,
            tx,
            mut rx,
            mut scratch,
            inbox,
            epoch,
            ..
        } = self;

        // A second handle on the same socket, so the thread can block on a read
        // without holding the lock the sender needs.
        let mut reader = transport
            .try_clone()
            .expect("a connected UDP socket can be cloned");

        let shared = Arc::new(Mutex::new(Shared {
            peer,
            transport,
            tx,
            epoch,
        }));
        let (outbox, receiver) = mpsc::channel();

        // Anything `recv` had already buffered belongs to the application.
        for message in inbox {
            let _ = outbox.send(message);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut ack = vec![0u8; 128];
                while !stop.load(Ordering::Relaxed) {
                    let now = epoch.elapsed().as_millis() as u64;

                    // Retransmissions are this thread's job. Doing them here
                    // rather than inside `recv` is the whole point: a caller
                    // that only ever sends still gets them.
                    let wait = {
                        let mut guard = shared.lock().expect("duplex lock");
                        let Shared {
                            peer,
                            transport,
                            tx,
                            ..
                        } = &mut *guard;
                        let limit = transport.max_datagram_size();
                        if peer
                            .drive_retransmits(now, limit, tx, |frame| {
                                transport.send(frame).map_err(Error::Io)
                            })
                            .is_err()
                        {
                            break;
                        }
                        peer.retransmit
                            .next_deadline_ms()
                            .map(|at| Duration::from_millis(at.saturating_sub(now)))
                            .unwrap_or(IDLE_POLL)
                            .min(IDLE_POLL)
                    };

                    if reader
                        .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
                        .is_err()
                    {
                        break;
                    }
                    let n = match reader.recv(&mut rx) {
                        Ok(n) => n,
                        Err(e) if crate::is_timeout(&e) => continue,
                        Err(_) => break,
                    };

                    let mut guard = shared.lock().expect("duplex lock");
                    let Shared {
                        peer, transport, ..
                    } = &mut *guard;
                    let mut ack_len = 0;
                    let ingested = match peer.ingest(&mut rx[..n], now, &mut ack, &mut ack_len) {
                        Ok(v) => v,
                        // Forged, replayed, or misdirected. Not a reason to
                        // stop serving the connection.
                        Err(_) => continue,
                    };
                    if ack_len > 0 && transport.send(&ack[..ack_len]).is_err() {
                        break;
                    }

                    let message = match ingested {
                        Ingested::Nothing => continue,
                        Ingested::Message(data) => data,
                        Ingested::Data { len, compressed } => {
                            let body = &rx[HEADER_LEN..HEADER_LEN + len];
                            let mut staging = vec![0u8; decoded_capacity(body, compressed)];
                            match deliver(body, compressed, &mut scratch, &mut staging) {
                                Ok(written) => {
                                    staging.truncate(written);
                                    staging
                                }
                                // One frame this peer coded in a way we cannot
                                // reverse. Drop it and keep going.
                                Err(_) => continue,
                            }
                        }
                    };
                    drop(guard);

                    if outbox.send(message).is_err() {
                        break;
                    }
                }
            })
        };

        (
            DuplexSender {
                shared,
                stop: Arc::clone(&stop),
            },
            DuplexReceiver {
                inbox: receiver,
                stop,
                worker: Some(worker),
            },
        )
    }
}

impl DuplexSender {
    /// Encrypts and sends `data` as one datagram.
    ///
    /// Takes `&self`, so this may be called from any thread and while the
    /// receiver is blocked. It seals and writes on the calling thread rather
    /// than handing the payload to the protocol thread, which keeps the send
    /// path the same length it is on a plain [`Connection`].
    pub fn send(&self, data: &[u8]) -> Result<()> {
        let mut guard = self.shared.lock().map_err(|_| Error::Closed)?;
        let payload_type = guard.peer.default_payload_type;
        self.seal_and_send(&mut guard, data, payload_type)
    }

    /// [`send`](Self::send), declaring the payload's shape.
    pub fn send_typed(&self, data: &[u8], payload_type: PayloadType) -> Result<()> {
        let mut guard = self.shared.lock().map_err(|_| Error::Closed)?;
        self.seal_and_send(&mut guard, data, payload_type)
    }

    /// Sends `data` and keeps resending it until the peer acknowledges.
    ///
    /// Unlike [`Connection::send_reliable`](crate::Connection::send_reliable),
    /// nothing has to be called afterwards to make retransmission happen.
    pub fn send_reliable(&self, data: &[u8]) -> Result<fectp_core::reliability::MessageId> {
        let mut guard = self.shared.lock().map_err(|_| Error::Closed)?;
        if !guard.peer.session.peer_capabilities().supports_reliable() {
            return Err(Error::ReliabilityUnsupported);
        }
        let payload_type = guard.peer.default_payload_type;
        let now = guard.peer_now_ms();
        let id = guard.peer.retransmit.register(now).map_err(Error::Protocol)?;

        let Shared {
            peer,
            transport,
            tx,
            ..
        } = &mut *guard;
        let limit = transport.max_datagram_size();
        let n = peer.seal(data, payload_type, Some(id), None, limit, tx)?;
        transport.send(&tx[..n]).map_err(Error::Io)?;
        peer.pending.push(crate::pipeline::Pending {
            id,
            payload_type,
            data: data.to_vec(),
            fragment: None,
        });
        Ok(id)
    }

    /// Reliable messages still awaiting acknowledgement.
    pub fn unacknowledged(&self) -> usize {
        self.shared
            .lock()
            .map(|g| g.peer.retransmit.in_flight())
            .unwrap_or(0)
    }

    /// Sets the payload shape [`send`](Self::send) assumes.
    pub fn set_default_payload_type(&self, payload_type: PayloadType) {
        if let Ok(mut guard) = self.shared.lock() {
            guard.peer.default_payload_type = payload_type;
        }
    }

    /// Largest uncompressed payload one [`send`](Self::send) carries.
    pub fn max_payload(&self) -> usize {
        self.shared
            .lock()
            .map(|g| {
                let limit = g.transport.max_datagram_size();
                g.peer.max_payload(limit)
            })
            .unwrap_or(0)
    }

    fn seal_and_send(
        &self,
        guard: &mut Shared,
        data: &[u8],
        payload_type: PayloadType,
    ) -> Result<()> {
        let Shared {
            peer,
            transport,
            tx,
            ..
        } = guard;
        let limit = transport.max_datagram_size();
        let n = peer.seal(data, payload_type, None, None, limit, tx)?;
        transport.send(&tx[..n]).map_err(Error::Io)
    }
}

impl Shared {
    fn peer_now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }
}

impl DuplexReceiver {
    /// Waits for the next message.
    ///
    /// Blocks until one arrives or the connection closes. Nothing else has to
    /// be running for this to make progress.
    pub fn recv(&self) -> Result<Vec<u8>> {
        self.inbox.recv().map_err(|_| Error::Closed)
    }

    /// [`recv`](Self::recv), giving up after `timeout`.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Vec<u8>> {
        match self.inbox.recv_timeout(timeout) {
            Ok(message) => Ok(message),
            Err(RecvTimeoutError::Timeout) => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no message arrived within the timeout",
            ))),
            Err(RecvTimeoutError::Disconnected) => Err(Error::Closed),
        }
    }

    /// Takes a message if one is already waiting, without blocking.
    pub fn try_recv(&self) -> Result<Option<Vec<u8>>> {
        match self.inbox.try_recv() {
            Ok(message) => Ok(Some(message)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(Error::Closed),
        }
    }
}

impl Drop for DuplexReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for DuplexSender {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
