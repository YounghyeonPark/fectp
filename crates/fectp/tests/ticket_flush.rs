//! What a stranger can do to a responder's resumption tickets.
//!
//! Reaching the handshake in public-key mode needs the responder's public key
//! and nothing else, which is the point — it is public. Every completed
//! handshake issues the ticket for the next one, and the store that holds them
//! is bounded, so a party with no standing relationship can fill it and push
//! everyone else's out.
//!
//! Nothing is broken by that. SPEC §4.6 says a responder MAY forget tickets at
//! any time and that an initiator whose ticket is refused falls back to a full
//! handshake, which it must be able to do in any case. What it costs is the
//! thing resumption exists to save: four Diffie-Hellman operations instead of
//! one, which on a Cortex-M4 is the largest latency this protocol has.
//!
//! This measures it rather than reasoning from `MAX_TICKETS` and the eviction
//! order, because reading the eviction order wrongly is a mistake already made
//! once in this repository (D73).

use std::time::{Duration, Instant};

use fectp::{Endpoint, Event, Identity, MAX_TICKETS};

/// Drives both sides until the client's handshake completes.
fn connect(client: &mut Endpoint, server: &mut Endpoint, addr: std::net::SocketAddr, key: &fectp::PeerKey) {
    client.connect(addr, Some(key)).expect("connect starts");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let _ = server.poll(Some(Duration::from_millis(1)));
        if let Ok(Event::Connected { .. }) = client.poll(Some(Duration::from_millis(1))) {
            return;
        }
    }
    panic!("the handshake never completed");
}

/// A stranger's handshakes push an established peer's ticket out of the store.
///
/// The arithmetic is what makes this airtight rather than an assumption about
/// eviction order: the store holds at most `MAX_TICKETS`, the stranger inserts
/// `MAX_TICKETS` of them *after* the legitimate one, so whatever order the
/// store evicts in, the legitimate ticket cannot still be there.
#[test]
fn a_stranger_can_flush_the_ticket_store() {
    let identity = Identity::generate();
    let key = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("server");
    let addr = server.local_addr().expect("addr");

    let mut honest = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("honest");
    connect(&mut honest, &mut server, addr, &key);
    assert_eq!(
        server.outstanding_tickets(),
        1,
        "the honest peer's handshake issued a ticket"
    );

    // One endpoint standing in for the stranger. Each connect is a separate
    // handshake with a resumption key of its own, so it costs one ticket.
    let mut stranger = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("stranger");
    for _ in 0..MAX_TICKETS {
        connect(&mut stranger, &mut server, addr, &key);
    }

    assert_eq!(
        server.outstanding_tickets(),
        MAX_TICKETS,
        "the store is bounded at MAX_TICKETS"
    );
}

/// The bound holds however far past it the stranger goes.
///
/// Separate from the test above because "it is capped" and "it is capped at the
/// documented number" are different claims, and a store that grew slowly would
/// pass the first one for a long time.
#[test]
fn the_ticket_store_does_not_grow_past_its_bound() {
    let identity = Identity::generate();
    let key = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("server");
    let addr = server.local_addr().expect("addr");

    let mut stranger = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("stranger");
    for _ in 0..(MAX_TICKETS + 64) {
        connect(&mut stranger, &mut server, addr, &key);
        assert!(
            server.outstanding_tickets() <= MAX_TICKETS,
            "the store reached {} against a bound of {MAX_TICKETS}",
            server.outstanding_tickets()
        );
    }
}
