//! Large messages sent *from* an endpoint.
//!
//! A `Connection` can simply wait for its send window. An endpoint cannot: it
//! serves many peers from one loop, so it queues the message and feeds it out
//! as the window frees. These check that the queue works and, more to the
//! point, that it does not stop the endpoint doing anything else.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use fectp::{Connection, Endpoint, Event, Identity, PeerId};

const TIMEOUT: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(20);

/// High-entropy bytes, so nothing here is carried by compression.
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
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
fn an_endpoint_sends_a_message_larger_than_a_frame() {
    let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let addr = server.local_addr().expect("addr");
    let public = *server.public_key().expect("identity");

    let payload = incompressible(20_000);
    let outgoing = payload.clone();

    let handle = thread::spawn(move || {
        loop {
            match server.poll(Some(TICK)).expect("poll") {
                Event::Connected { peer, .. } => {
                    server.send_large(peer, &outgoing).expect("send_large");
                }
                Event::Sent { delivered, .. } => return delivered,
                _ => {}
            }
        }
    });

    let mut client =
        Connection::connect(addr, &public, &Identity::generate()).expect("connect");
    client.set_read_timeout(Some(TIMEOUT)).expect("timeout");

    let mut buf = vec![0u8; payload.len()];
    let n = client.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], &payload[..], "reassembled and unchanged");

    assert!(
        handle.join().expect("server thread"),
        "the endpoint must report the message as delivered"
    );
}

#[test]
fn a_large_send_does_not_stop_the_endpoint_serving_another_peer() {
    let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let addr = server.local_addr().expect("addr");
    let public = *server.public_key().expect("identity");

    // Big enough to need many windows, so the endpoint is still feeding it out
    // while the second peer is asking for attention.
    let payload = incompressible(200_000);
    let (ready, started) = mpsc::channel::<()>();

    let handle = thread::spawn(move || {
        let mut first: Option<PeerId> = None;
        loop {
            match server.poll(Some(TICK)).expect("poll") {
                Event::Connected { peer, .. } => {
                    if first.is_none() {
                        first = Some(peer);
                        server.send_large(peer, &payload).expect("send_large");
                        let _ = ready.send(());
                    }
                }
                // The second peer's ping, answered while the first peer's
                // large message is still going out. This is the whole point of
                // queuing rather than waiting.
                Event::Message { peer, data } if Some(peer) != first => {
                    server.send(peer, &data).expect("echo");
                    return true;
                }
                _ => {}
            }
        }
    });

    let _first = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
    started.recv_timeout(TIMEOUT).expect("large send started");

    let mut second =
        Connection::connect(addr, &public, &Identity::generate()).expect("connect");
    second.set_read_timeout(Some(TIMEOUT)).expect("timeout");
    second.send(b"are you still there").expect("send");

    let mut buf = [0u8; 128];
    let n = second.recv(&mut buf).expect("the endpoint must still answer");
    assert_eq!(&buf[..n], b"are you still there");

    assert!(handle.join().expect("server thread"));
}

#[test]
fn queueing_more_than_the_limit_is_refused() {
    let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let addr = server.local_addr().expect("addr");
    let public = *server.public_key().expect("identity");

    let handle = thread::spawn(move || {
        loop {
            if let Event::Connected { peer, .. } = server.poll(Some(TICK)).expect("poll") {
                let payload = incompressible(40_000);
                // Each queued message holds its payload until acknowledged, so
                // the queue has to be bounded or one peer could make the
                // endpoint keep any amount of memory.
                for _ in 0..fectp::MAX_QUEUED_LARGE {
                    server.send_large(peer, &payload).expect("within the limit");
                }
                return server.send_large(peer, &payload).is_err();
            }
        }
    });

    let _client = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
    assert!(
        handle.join().expect("server thread"),
        "one past the queue limit must be refused, not queued anyway"
    );
}

#[test]
fn two_queued_messages_both_arrive_in_order() {
    let mut server = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let addr = server.local_addr().expect("addr");
    let public = *server.public_key().expect("identity");

    let first = incompressible(9_000);
    let second: Vec<u8> = incompressible(9_000).into_iter().map(|b| !b).collect();
    let (a, b) = (first.clone(), second.clone());

    let handle = thread::spawn(move || {
        let mut sent = 0;
        loop {
            match server.poll(Some(TICK)).expect("poll") {
                Event::Connected { peer, .. } => {
                    server.send_large(peer, &a).expect("first");
                    server.send_large(peer, &b).expect("second");
                }
                Event::Sent { delivered, .. } => {
                    assert!(delivered);
                    sent += 1;
                    if sent == 2 {
                        return;
                    }
                }
                _ => {}
            }
        }
    });

    let mut client =
        Connection::connect(addr, &public, &Identity::generate()).expect("connect");
    client.set_read_timeout(Some(TIMEOUT)).expect("timeout");

    let mut buf = vec![0u8; 9_000];
    let n = client.recv(&mut buf).expect("first");
    assert_eq!(&buf[..n], &first[..]);
    let n = client.recv(&mut buf).expect("second");
    assert_eq!(&buf[..n], &second[..], "the queue must not reorder");

    handle.join().expect("server thread");
}
