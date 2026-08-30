//! Messages larger than one frame.
//!
//! The interesting cases are not "does a big payload arrive" but the ones
//! where fragmentation could quietly do the wrong thing: deliver a message in
//! pieces, mis-order it, lose the descriptor on a retransmission, or let a
//! peer decide how much memory to take.

use std::time::Duration;

mod common;

use common::Echo;
use fectp::{Connection, Identity, PayloadType};

const TIMEOUT: Duration = Duration::from_secs(5);

fn client(echo: &Echo) -> Connection {
    Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect")
}

/// High-entropy bytes, so nothing is carried by compression.
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

#[test]
fn a_message_larger_than_one_frame_arrives_whole() {
    let echo = Echo::collector();
    let mut client = client(&echo);
    let payload = incompressible(client.max_payload() * 3 + 17);

    client.send_large(&payload, TIMEOUT).expect("send_large");

    let received = echo.messages(1, TIMEOUT);
    assert_eq!(received.len(), 1, "a fragmented message is delivered once");
    assert_eq!(received[0], payload);
}

#[test]
fn a_message_needing_more_fragments_than_the_window_holds_still_arrives() {
    let echo = Echo::collector();
    let mut client = client(&echo);

    // Comfortably more fragments than MAX_UNACKED, so the send has to wait for
    // acknowledgements part-way through rather than queueing the lot.
    let payload = incompressible(client.max_payload() * (fectp::MAX_UNACKED * 3));

    client.send_large(&payload, TIMEOUT).expect("send_large");

    let received = echo.messages(1, TIMEOUT);
    assert_eq!(received[0].len(), payload.len());
    assert_eq!(received[0], payload);
}

#[test]
fn a_single_frame_message_still_works_through_the_large_path() {
    let echo = Echo::collector();
    let mut client = client(&echo);
    let payload = incompressible(64);

    client.send_large(&payload, TIMEOUT).expect("send_large");

    let received = echo.messages(1, TIMEOUT);
    assert_eq!(received[0], payload);
}

#[test]
fn an_empty_message_survives_the_round_trip() {
    let echo = Echo::collector();
    let mut client = client(&echo);

    client.send_large(&[], TIMEOUT).expect("send_large");

    let received = echo.messages(1, TIMEOUT);
    assert!(received[0].is_empty());
}

#[test]
fn a_message_above_the_reassembly_ceiling_is_refused() {
    let echo = Echo::collector();
    let mut client = client(&echo);

    // A receiver commits memory on the strength of the sender's fragment
    // count, so there has to be a size no sender can ask for.
    let huge = vec![0u8; fectp::MAX_MESSAGE_LEN + 1];
    assert!(
        client.send_large(&huge, TIMEOUT).is_err(),
        "a message past the ceiling must be refused, not fragmented anyway"
    );
}

#[test]
fn typed_fragments_round_trip() {
    let echo = Echo::collector();
    let mut client = client(&echo);

    // Sensor data long enough to need several frames. Each fragment is coded
    // on its own, so this also checks that a coded fragment is reassembled
    // from its decoded form rather than its wire form.
    let samples: Vec<u8> = (0..8000i16)
        .flat_map(|i| ((i % 512) * 4).to_le_bytes())
        .collect();

    client
        .send_large_typed(&samples, PayloadType::I16 { channels: 4 }, TIMEOUT)
        .expect("send_large_typed");

    let received = echo.messages(1, TIMEOUT);
    assert_eq!(received[0], samples);
}

#[test]
fn ordinary_sends_are_unaffected_by_a_fragmented_one() {
    let echo = Echo::collector();
    let mut client = client(&echo);
    let big = incompressible(client.max_payload() * 2);

    client.send_large(&big, TIMEOUT).expect("send_large");
    client.send(b"after").expect("send");

    let received = echo.messages(2, TIMEOUT);
    assert_eq!(received[0], big, "the large message stays one message");
    assert_eq!(received[1], b"after", "and does not swallow the next one");
}

#[test]
fn two_fragmented_messages_do_not_mix() {
    let echo = Echo::collector();
    let mut client = client(&echo);
    let first = incompressible(client.max_payload() * 2 + 5);
    let second: Vec<u8> = incompressible(client.max_payload() * 2 + 5)
        .into_iter()
        .map(|b| !b)
        .collect();

    client.send_large(&first, TIMEOUT).expect("first");
    client.send_large(&second, TIMEOUT).expect("second");

    let received = echo.messages(2, TIMEOUT);
    assert_eq!(received[0], first);
    assert_eq!(received[1], second);
    assert_ne!(received[0], received[1], "the two must not be conflated");
}

#[test]
fn nothing_is_left_half_assembled_afterwards() {
    let echo = Echo::collector();
    let mut client = client(&echo);
    let payload = incompressible(client.max_payload() * 4);

    client.send_large(&payload, TIMEOUT).expect("send_large");
    echo.messages(1, TIMEOUT);

    // The sender's own table: it should never have started a reassembly, and
    // a completed one must not be left behind holding memory.
    assert_eq!(client.reassembling(), 0);
}
#[test]
fn a_reliable_message_of_exactly_its_advertised_limit_is_sendable() {
    let echo = Echo::collector();
    let mut client = client(&echo);
    let payload = incompressible(client.max_reliable_payload());

    // A reliable frame carries a message identifier too, so its ceiling is
    // below `max_payload`. Sending exactly the advertised number must work,
    // or the number is not the limit.
    client
        .send_reliable(&payload)
        .expect("send_reliable at the advertised limit");
    client.flush(TIMEOUT).expect("flush");

    let received = echo.messages(1, TIMEOUT);
    assert_eq!(received[0], payload);
}

#[test]
fn an_oversized_reliable_message_is_refused_clearly() {
    let echo = Echo::collector();
    let mut client = client(&echo);
    let payload = incompressible(client.max_reliable_payload() + 1);

    // One byte over. This must be the protocol saying the payload is too
    // large, not an internal buffer running out — the caller can act on the
    // first and not on the second.
    match client.send_reliable(&payload) {
        Err(fectp::Error::PayloadTooLarge { .. }) => {}
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
}
