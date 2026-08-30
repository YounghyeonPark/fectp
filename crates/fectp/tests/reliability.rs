//! Reliable delivery over a UDP path that actually drops datagrams.
//!
//! The loss is injected by a relay sitting between the two peers, so the whole
//! stack is exercised: retransmission, acknowledgement, deduplication, and the
//! fresh sequence number every retransmission needs.

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

mod common;

use common::Echo;
use fectp::{Connection, Identity};

const TIMEOUT: Duration = Duration::from_secs(5);
const FLUSH: Duration = Duration::from_secs(3);

/// A UDP relay that forwards between one client and one server, dropping
/// datagrams at chosen positions in each direction.
///
/// Indices count datagrams seen in that direction, starting at 0. Index 0
/// client-to-server is the handshake, so the first data frame is index 1.
fn spawn_relay(server: SocketAddr, drop_forward: Vec<usize>, drop_back: Vec<usize>) -> SocketAddr {
    let front = UdpSocket::bind("127.0.0.1:0").expect("bind front");
    let back = UdpSocket::bind("127.0.0.1:0").expect("bind back");
    back.connect(server).expect("connect back");
    let addr = front.local_addr().expect("addr");
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let front_rx = front.try_clone().expect("clone");
    let back_tx = back.try_clone().expect("clone");
    let learn = Arc::clone(&client);
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
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
        let mut buf = [0u8; 4096];
        let mut seen = 0usize;
        while let Ok(n) = back.recv(&mut buf) {
            let index = seen;
            seen += 1;
            if drop_back.contains(&index) {
                continue;
            }
            let Some(dest) = *client.lock().expect("lock") else {
                continue;
            };
            let _ = front.send_to(&buf[..n], dest);
        }
    });

    addr
}

/// A server that records without echoing.
///
/// Not echoing keeps the server-to-client datagram ordering predictable, which
/// matters because these tests drop datagrams at specific positions.
fn server() -> Echo {
    Echo::collector()
}

#[test]
fn a_dropped_message_is_retransmitted() {
    let echo = server();
    // Index 1 is the first data frame; the handshake is index 0.
    let relay = spawn_relay(echo.addr(), vec![1], vec![]);

    let mut client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    client.send_reliable(b"survives a drop").expect("send");
    assert_eq!(client.unacknowledged(), 1);

    client.flush(FLUSH).expect("flush");
    assert_eq!(client.unacknowledged(), 0, "everything was acknowledged");

    assert_eq!(echo.messages(1, TIMEOUT), vec![b"survives a drop".to_vec()]);
}

#[test]
fn several_drops_in_a_row_are_survived() {
    let echo = server();
    // Drop the first transmission and the first two retransmissions.
    let relay = spawn_relay(echo.addr(), vec![1, 2, 3], vec![]);

    let mut client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    client.send_reliable(b"third time lucky").expect("send");
    client.flush(FLUSH).expect("flush");

    assert_eq!(
        echo.messages(1, TIMEOUT),
        vec![b"third time lucky".to_vec()]
    );
}

#[test]
fn a_lost_acknowledgement_does_not_duplicate_the_message() {
    let echo = server();
    // The message gets through, but the acknowledgement is dropped, so the
    // sender retransmits. The receiver must acknowledge again and deliver
    // nothing extra.
    let relay = spawn_relay(echo.addr(), vec![], vec![1]);

    let mut client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    client.send_reliable(b"exactly once").expect("send");
    client.flush(FLUSH).expect("flush");

    // Give any duplicate time to arrive before concluding there was none.
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        echo.observed().messages,
        vec![b"exactly once".to_vec()],
        "a retransmission caused by a lost ack must not be delivered twice"
    );
}

#[test]
fn only_the_lost_message_is_resent() {
    let echo = server();
    // Of three data frames, lose the middle one.
    let relay = spawn_relay(echo.addr(), vec![2], vec![]);

    let mut client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    for i in 0..3u8 {
        client.send_reliable(&[i; 8]).expect("send");
    }
    client.flush(FLUSH).expect("flush");

    let mut received = echo.messages(3, TIMEOUT);
    received.sort();
    assert_eq!(
        received,
        vec![vec![0u8; 8], vec![1u8; 8], vec![2u8; 8]],
        "all three arrive exactly once, whatever order they land in"
    );
}

#[test]
fn reliable_and_unreliable_messages_share_a_session() {
    let echo = server();
    let relay = spawn_relay(echo.addr(), vec![], vec![]);

    let mut client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    client.send_reliable(b"guaranteed").expect("send reliable");
    client.send(b"best effort").expect("send unreliable");
    client.flush(FLUSH).expect("flush");

    let mut received = echo.messages(2, TIMEOUT);
    received.sort();
    assert_eq!(
        received,
        vec![b"best effort".to_vec(), b"guaranteed".to_vec()]
    );
}

#[test]
fn typed_payloads_can_be_sent_reliably() {
    let echo = server();
    let relay = spawn_relay(echo.addr(), vec![1], vec![]);

    let mut client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    let samples: Vec<u8> = (0..256i16).flat_map(|i| (i * 3).to_le_bytes()).collect();
    client
        .send_reliable_typed(&samples, fectp::PayloadType::I16 { channels: 4 })
        .expect("send");
    client.flush(FLUSH).expect("flush");

    assert_eq!(
        echo.messages(1, TIMEOUT),
        vec![samples],
        "coding and retransmission must compose"
    );
}

#[test]
fn the_in_flight_window_is_bounded() {
    let echo = server();
    // Drop every data frame so nothing is ever acknowledged and the window
    // fills up.
    let relay = spawn_relay(echo.addr(), (1..500).collect(), vec![]);

    let mut client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    for _ in 0..fectp::MAX_UNACKED {
        client.send_reliable(b"never arrives").expect("send");
    }
    assert_eq!(client.unacknowledged(), fectp::MAX_UNACKED);
    assert!(
        client.send_reliable(b"one too many").is_err(),
        "the window must bound memory rather than growing without limit"
    );
}

#[test]
fn flush_reports_messages_that_were_never_delivered() {
    let echo = server();
    let relay = spawn_relay(echo.addr(), (1..500).collect(), vec![]);

    let mut client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    client.send_reliable(b"into the void").expect("send");

    // Give up quickly rather than waiting out the full retry budget.
    let result = client.flush(Duration::from_millis(300));
    assert!(
        matches!(result, Err(fectp::Error::Unacknowledged { .. })),
        "a message that never lands must be reported, not silently forgotten: {result:?}"
    );
}

#[test]
fn a_round_trip_estimate_is_learned() {
    let echo = server();
    let relay = spawn_relay(echo.addr(), vec![], vec![]);

    let mut client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    for i in 0..4u8 {
        client.send_reliable(&[i; 4]).expect("send");
        client.flush(FLUSH).expect("flush");
    }

    // A loopback path is far quicker than the initial guess, so the estimate
    // must have come down.
    assert!(
        client.rto_ms() < 200,
        "expected the estimate to fall below the initial guess, got {}",
        client.rto_ms()
    );
    assert_eq!(echo.messages(4, TIMEOUT).len(), 4);
}
