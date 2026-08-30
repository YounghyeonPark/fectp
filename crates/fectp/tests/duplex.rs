//! Sending and receiving at the same time.
//!
//! The point of `into_duplex` is not that two handles exist — that much a
//! plain split would give — but that neither owes the other anything. These
//! check the parts that a split would get wrong.

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

mod common;

use common::Echo;
use fectp::{Connection, Identity};

const TIMEOUT: Duration = Duration::from_secs(5);

fn client(echo: &Echo) -> Connection {
    Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect")
}

/// Forwards between client and server, dropping chosen datagrams on the way in.
///
/// Index 0 is the handshake, so the first data frame is index 1.
fn spawn_relay(server: SocketAddr, drop_forward: Vec<usize>) -> SocketAddr {
    let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
    let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
    back.connect(server).expect("connect back");
    let addr = front.local_addr().expect("addr");
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let front_rx = front.try_clone().expect("clone");
    let back_tx = back.try_clone().expect("clone");
    let learn = Arc::clone(&client);
    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        let mut seen = 0usize;
        while let Ok((n, from)) = front_rx.recv_from(&mut buf) {
            *learn.lock().expect("lock") = Some(from);
            let index = seen;
            seen += 1;
            if drop_forward.contains(&index) {
                continue;
            }
            let _ = back_tx.send(&buf[..n]);
        }
    });

    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while let Ok(n) = back.recv(&mut buf) {
            let Some(dest) = *client.lock().expect("lock") else {
                continue;
            };
            let _ = front.send_to(&buf[..n], dest);
        }
    });

    addr
}

#[test]
fn a_message_round_trips_through_the_duplex_halves() {
    let echo = Echo::start();
    let (tx, rx) = client(&echo).into_duplex();

    tx.send(b"there and back").expect("send");

    let message = rx.recv_timeout(TIMEOUT).expect("recv");
    assert_eq!(message, b"there and back");
}

#[test]
fn sending_works_while_the_other_half_is_blocked_reading() {
    let echo = Echo::start();
    let (tx, rx) = client(&echo).into_duplex();

    // Blocked in `recv` with nothing to read. On a `&mut self` API this thread
    // would hold the connection and the send below could not happen at all.
    let reader = thread::spawn(move || rx.recv_timeout(TIMEOUT));

    thread::sleep(Duration::from_millis(50));
    tx.send(b"sent while the reader waits").expect("send");

    let message = reader.join().expect("reader thread").expect("recv");
    assert_eq!(message, b"sent while the reader waits");
}

#[test]
fn both_halves_can_be_used_from_their_own_threads_at_once() {
    let echo = Echo::start();
    let (tx, rx) = client(&echo).into_duplex();

    const MESSAGES: usize = 100;
    let sender = thread::spawn(move || {
        for i in 0..MESSAGES {
            tx.send(&(i as u32).to_le_bytes()).expect("send");
        }
        tx
    });

    let mut seen = Vec::new();
    while seen.len() < MESSAGES {
        seen.push(rx.recv_timeout(TIMEOUT).expect("recv"));
    }
    let _tx = sender.join().expect("sender thread");

    seen.sort();
    let mut expected: Vec<Vec<u8>> = (0..MESSAGES as u32)
        .map(|i| i.to_le_bytes().to_vec())
        .collect();
    expected.sort();
    assert_eq!(seen, expected);
}

#[test]
fn a_lost_message_is_retransmitted_without_anyone_calling_recv() {
    let echo = Echo::collector();
    // Drop the first data frame, so only a retransmission can deliver it.
    let relay = spawn_relay(echo.addr(), vec![1]);
    let conn =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    let (tx, _rx) = conn.into_duplex();

    tx.send_reliable(b"survives a drop").expect("send_reliable");

    // Nothing here reads. On a plain `Connection` retransmission happens inside
    // `recv` and `flush`, so this message would never be resent — which is the
    // hidden contract a two-halves split would inherit and this design exists
    // to remove.
    assert_eq!(
        echo.messages(1, TIMEOUT),
        vec![b"survives a drop".to_vec()],
        "the protocol thread must retransmit on its own"
    );
}

#[test]
fn acknowledgements_flow_without_anyone_calling_recv() {
    let echo = Echo::collector();
    let (tx, _rx) = client(&echo).into_duplex();

    // More than the send window holds, so this only finishes if
    // acknowledgements are being processed as it goes.
    for i in 0..50u32 {
        let deadline = std::time::Instant::now() + TIMEOUT;
        loop {
            match tx.send_reliable(&i.to_le_bytes()) {
                Ok(_) => break,
                Err(_) if std::time::Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("send_reliable stalled: {e:?}"),
            }
        }
    }
    echo.messages(50, TIMEOUT);

    // Acknowledgements are what free the send window. If they were only
    // processed inside `recv`, this would still be full.
    let deadline = std::time::Instant::now() + TIMEOUT;
    while tx.unacknowledged() > 0 && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        tx.unacknowledged(),
        0,
        "every message should have been acknowledged with no help from the caller"
    );
}

#[test]
fn dropping_the_receiver_closes_the_sender() {
    let echo = Echo::start();
    let (tx, rx) = client(&echo).into_duplex();
    drop(rx);

    // The worker owns the socket handle it reads on; once it stops there is
    // nothing to service the connection, so a send must not silently succeed
    // forever. It is allowed to fail either now or on the next call.
    let mut failed = false;
    for _ in 0..50 {
        if tx.send(b"after the receiver went away").is_err() {
            failed = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = failed;
}

#[test]
fn a_closed_receiver_reports_it_rather_than_hanging() {
    let echo = Echo::start();
    let (tx, rx) = client(&echo).into_duplex();
    drop(tx);

    // The sender going away stops the worker, which drops the channel.
    match rx.recv() {
        Err(fectp::Error::Closed) => {}
        other => panic!("expected Closed, got {other:?}"),
    }
}

#[test]
fn large_messages_still_arrive_through_the_duplex_receiver() {
    let echo = Echo::start();
    let mut conn = client(&echo);
    conn.set_read_timeout(Some(TIMEOUT)).expect("timeout");
    let limit = conn.max_payload();
    let (tx, rx) = conn.into_duplex();

    // High-entropy, so nothing compresses it under the frame limit.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let payload: Vec<u8> = (0..limit * 4)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();

    match tx.send(&payload) {
        Err(fectp::Error::PayloadTooLarge { .. }) => {}
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }

    // The echo server replies through an `Endpoint`, which has no `send_large`,
    // so the round trip has to fit one frame both ways.
    tx.send(&payload[..limit]).expect("a payload at the limit is not refused");
    let message = rx.recv_timeout(TIMEOUT).expect("recv");
    assert_eq!(message, payload[..limit]);
}
