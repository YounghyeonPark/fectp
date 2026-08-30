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

    let client =
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

    let client =
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

    let client =
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

    let client =
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

    let client =
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

    let client =
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

    let client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");

    // Nothing is acknowledged, so the congestion window never widens past what
    // it opens at. That is the bound now, and it is below the memory bound.
    let opened = fectp::INITIAL_CWND;
    for _ in 0..opened {
        client.send_reliable(b"never arrives").expect("send");
    }
    assert_eq!(client.unacknowledged(), opened);
    assert!(
        client.send_reliable(b"one too many").is_err(),
        "the window must bound sending rather than growing without limit"
    );
    assert!(
        opened <= fectp::MAX_UNACKED,
        "the congestion window must never exceed the memory bound"
    );
}

#[test]
fn flush_reports_messages_that_were_never_delivered() {
    let echo = server();
    let relay = spawn_relay(echo.addr(), (1..500).collect(), vec![]);

    let client =
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

    let client =
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

#[test]
fn a_fragmented_message_survives_a_dropped_fragment() {
    let echo = server();
    // Index 0 is the handshake, so 1..=4 are the four fragments below. Drop
    // one from the middle: the retransmission has to arrive still carrying its
    // fragment descriptor, or the receiver will take it for a whole message
    // and the reassembly will never complete.
    let relay = spawn_relay(echo.addr(), vec![3], vec![]);

    let client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");

    let payload: Vec<u8> = {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        (0..client.max_fragment_payload() * 4)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    };

    client.send_large(&payload, FLUSH).expect("send_large");

    let received = echo.messages(1, TIMEOUT);
    assert_eq!(received.len(), 1, "delivered once, not once per fragment");
    assert_eq!(received[0], payload, "and whole");
}

#[test]
fn a_fragmented_message_whose_fragment_never_arrives_is_reported() {
    let echo = server();
    // Drop one fragment and every retransmission of it. MAX_RETRIES attempts
    // then give up, so this fragment never lands.
    let relay = spawn_relay(echo.addr(), (1..40).collect(), vec![]);

    let client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");
    let payload = vec![0xA5u8; client.max_fragment_payload() * 3];

    // The caller has to be told. Silently returning success on a message the
    // peer will never be able to assemble is the worst available outcome.
    assert!(
        matches!(
            client.send_large(&payload, FLUSH),
            Err(fectp::Error::Unacknowledged { .. })
        ),
        "a message that cannot be delivered must not report success"
    );
}

#[test]
fn an_early_loss_is_recovered_in_a_stream_far_longer_than_the_ack_window() {
    let echo = server();
    // Drop the first data frame — the message's first fragment. What matters
    // is not the drop but how far the stream runs on afterwards.
    let relay = spawn_relay(echo.addr(), vec![1], vec![]);

    let client =
        Connection::connect(relay, &echo.public(), &Identity::generate()).expect("connect");

    // A receiver reports what it has seen as a highest identifier plus a bitmap
    // of the 64 below it. A sender that runs further ahead than that leaves the
    // lost message unnameable: no acknowledgement can mention it, and its
    // retransmission now falls outside the receiver's replay window, so it is
    // discarded rather than delivered. It is then lost however many retries
    // remain.
    //
    // Bounding in-flight *count* does not prevent this, which is what makes it
    // easy to miss: the stuck message holds one of thirty-two slots while the
    // other thirty-one keep cycling, and the identifier space runs away from
    // it. This needs a send that keeps going as slots free rather than waiting
    // for all of them, which is exactly what `send_large` does.
    let payload = vec![0x3Cu8; client.max_fragment_payload() * 200];

    client
        .send_large(&payload, FLUSH)
        .expect("a single early loss must not lose the message");

    let received = echo.messages(1, TIMEOUT);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], payload, "and it must arrive intact");
}
