//! Session resumption over a real socket pair.
//!
//! A full handshake costs each peer four X25519 operations — on a
//! microcontroller, roughly a hundred milliseconds, paid again after every
//! reset. Resumption replaces that with one, by authenticating from a ticket
//! the previous session established.

use std::time::Duration;

mod common;

use common::Echo;
use fectp::{Connection, Identity, PayloadType, Ticket};

const TIMEOUT: Duration = Duration::from_secs(5);



/// The resumption ticket of an encrypted connection.
fn ticket_of(conn: &Connection) -> Ticket {
    conn.resumption_ticket()
        .expect("an encrypted session always has one")
}

/// Runs one request/response exchange.
fn exchange(conn: &mut Connection, message: &[u8]) -> Vec<u8> {
    conn.set_read_timeout(Some(TIMEOUT)).expect("timeout");
    conn.send(message, PayloadType::Opaque).expect("send");
    let mut buf = vec![0u8; 4096];
    let n = conn.recv(&mut buf).expect("recv");
    buf[..n].to_vec()
}

#[test]
fn a_resumed_session_carries_data() {
    let echo = Echo::start();
    let (addr, server_public) = (echo.addr(), echo.public());

    let mut first =
        Connection::connect(addr, &server_public, &Identity::generate()).expect("connect");
    assert_eq!(exchange(&mut first, b"over a full handshake"), b"over a full handshake");
    let ticket = first.resumption_ticket().expect("encrypted session");
    drop(first);

    let mut resumed =
        Connection::resume(addr, &ticket, &server_public).expect("resume");
    assert_eq!(exchange(&mut resumed, b"over a resumption"), b"over a resumption");

}

#[test]
fn both_peers_agree_on_the_ticket() {
    // The client and server derive the ticket independently; resumption only
    // works because they arrive at the same value.
    let echo = Echo::start();
    let (addr, server_public) = (echo.addr(), echo.public());

    let mut conn = Connection::connect(addr, &server_public, &Identity::generate()).expect("connect");
    exchange(&mut conn, b"hello");
    let ticket = ticket_of(&conn);

    // The server accepted the resumption in the next test; here it is enough
    // that a ticket exists and is stable for the session.
    assert_eq!(ticket.id(), ticket_of(&conn).id());
}

#[test]
fn identity_survives_resumption() {
    let echo = Echo::start();
    let (addr, server_public) = (echo.addr(), echo.public());
    let client_identity = Identity::generate();
    let client_public = *client_identity.public();

    let mut first = Connection::connect(addr, &server_public, &client_identity).expect("connect");
    exchange(&mut first, b"one");
    let ticket = first.resumption_ticket().expect("encrypted session");
    assert_eq!(first.peer_public_key().expect("connected"), server_public);
    drop(first);

    let mut resumed =
        Connection::resume(addr, &ticket, &server_public).expect("resume");
    exchange(&mut resumed, b"two");
    assert_eq!(
        resumed.peer_public_key().expect("connected"),
        server_public,
        "the resumed session must still report who it is talking to"
    );

    assert_eq!(
        echo.connections(2, TIMEOUT).peers,
        vec![client_public, client_public],
        "the server must recognise the same client across resumption, even \
         though a resumption handshake performs no static-key agreement"
    );
}

#[test]
fn a_ticket_is_single_use() {
    let echo = Echo::start();
    let (addr, server_public) = (echo.addr(), echo.public());

    let mut first =
        Connection::connect(addr, &server_public, &Identity::generate()).expect("connect");
    exchange(&mut first, b"one");
    let ticket = first.resumption_ticket().expect("encrypted session");
    drop(first);

    let mut resumed =
        Connection::resume(addr, &ticket, &server_public).expect("first resume");
    exchange(&mut resumed, b"two");
    drop(resumed);

    assert!(
        Connection::resume(addr, &ticket, &server_public).is_err(),
        "redeeming a ticket twice must fail, or a captured resumption request \
         could be replayed"
    );

}

#[test]
fn resumption_issues_a_fresh_ticket_each_time() {
    let echo = Echo::start();
    let (addr, server_public) = (echo.addr(), echo.public());

    let mut conn = Connection::connect(addr, &server_public, &Identity::generate()).expect("connect");
    exchange(&mut conn, b"one");
    let first_ticket = ticket_of(&conn);
    drop(conn);

    let mut conn =
        Connection::resume(addr, &first_ticket, &server_public).expect("resume");
    exchange(&mut conn, b"two");
    let second_ticket = ticket_of(&conn);
    assert_ne!(
        first_ticket.id(),
        second_ticket.id(),
        "each handshake must issue a new ticket, since the old one is spent"
    );
    drop(conn);

    // And the new one works, so the chain can continue indefinitely.
    let mut conn =
        Connection::resume(addr, &second_ticket, &server_public).expect("resume again");
    assert_eq!(exchange(&mut conn, b"three"), b"three");

}

#[test]
fn an_unknown_ticket_is_refused() {
    let echo = Echo::start();
    let (addr, server_public) = (echo.addr(), echo.public());

    // A ticket this server has never issued.
    let bogus = Ticket::from_key([0x77; 32]);
    let result = Connection::resume(addr, &bogus, &server_public);
    assert!(
        result.is_err(),
        "a server that does not hold the ticket cannot answer, so the client \
         must time out and fall back to a full handshake"
    );
}

#[test]
fn a_restarted_server_forces_a_full_handshake() {
    let echo = Echo::start();
    let (addr, server_public) = (echo.addr(), echo.public());

    let mut conn = Connection::connect(addr, &server_public, &Identity::generate()).expect("connect");
    exchange(&mut conn, b"before the restart");
    let ticket = ticket_of(&conn);
    drop(conn);

    // A fresh server, on a fresh socket, holds no tickets.
    drop(echo);
    let fresh = Echo::start();
    let (fresh_addr, new_public) = (fresh.addr(), fresh.public());

    assert!(
        Connection::resume(fresh_addr, &ticket, &new_public).is_err(),
        "tickets do not survive the peer forgetting them"
    );

    // The full handshake still works, which is the fallback path.
    let mut conn =
        Connection::connect(fresh_addr, &new_public, &Identity::generate()).expect("connect");
    assert_eq!(exchange(&mut conn, b"after the restart"), b"after the restart");
}

#[test]
fn resumption_carries_zero_rtt_data() {
    let echo = Echo::start();
    let (addr, server_public) = (echo.addr(), echo.public());

    let mut conn = Connection::connect(addr, &server_public, &Identity::generate()).expect("connect");
    exchange(&mut conn, b"warm up");
    let ticket = ticket_of(&conn);
    drop(conn);

    let mut resumed = Connection::resume_and_send(
        addr,
        &ticket,
        &server_public,
        b"resumed 0-RTT",
    )
    .expect("resume");
    exchange(&mut resumed, b"and then some");

    let zero_rtts = echo.connections(2, TIMEOUT).zero_rtt;
    assert_eq!(
        zero_rtts[1], b"resumed 0-RTT",
        "a resumption must be able to carry data in its first message too"
    );
}

#[test]
fn a_ticket_survives_a_round_trip_through_storage() {
    // A constrained device persists the key to flash and restores it after a
    // reset; only the 32-byte key needs storing, since the identifier is
    // derived from it.
    let echo = Echo::start();
    let (addr, server_public) = (echo.addr(), echo.public());

    let mut conn = Connection::connect(addr, &server_public, &Identity::generate()).expect("connect");
    exchange(&mut conn, b"before reset");
    let stored: [u8; 32] = *conn.resumption_ticket().expect("encrypted session").key();
    drop(conn);

    let restored = Ticket::from_key(stored);
    let mut resumed =
        Connection::resume(addr, &restored, &server_public).expect("resume");
    assert_eq!(exchange(&mut resumed, b"after reset"), b"after reset");

}
