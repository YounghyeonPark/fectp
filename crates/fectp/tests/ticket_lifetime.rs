//! A resumption ticket stops being redeemable.
//!
//! Tickets were bounded in number and not in time. A ticket is single use, but
//! until it is used it is enough on its own to impersonate the peer it was
//! issued to — so bounding the count is not bounding that. A responder that
//! sees one peer keeps its ticket until 256 more arrive, which on a quiet
//! device is for ever: a ticket captured today would still work next year.
//!
//! The lifetime here is set to a few milliseconds so the test does not take an
//! hour. That is the same setter a deployment uses, so the path under test is
//! the real one.

mod common;

use std::thread::sleep;
use std::time::Duration;

use fectp::{Connection, Endpoint, Event, Identity, PayloadType, Ticket};

/// Runs a server in this thread for `window`, answering whatever arrives.
fn serve(server: &mut Endpoint, window: Duration) {
    let started = std::time::Instant::now();
    while started.elapsed() < window {
        if let Ok(Event::Message { peer, data }) = server.poll(Some(Duration::from_millis(5))) {
            let _ = server.send(peer, &data, PayloadType::Opaque);
        }
    }
}

#[test]
fn a_ticket_stops_being_redeemable_once_it_has_expired() {
    let identity = Identity::generate();
    let public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity).expect("bind");
    let addr = server.local_addr().expect("addr");

    // Long enough to survive the first exchange and short enough to expire
    // during a deliberate wait. Set through the same setter a deployment uses
    // rather than a back door.
    //
    // The first version of this used 150 ms, which the ticket outlived before
    // the control could redeem it — the control failed, which is what it is
    // for. Without it the assertion at the end would have passed for the wrong
    // reason.
    const LIFETIME: Duration = Duration::from_secs(3);
    server.set_ticket_lifetime(LIFETIME);

    // A first connection, purely to be issued a ticket.
    let client = std::thread::spawn(move || {
        let conn = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
        let key = *conn
            .resumption_ticket()
            .expect("an encrypted session issues one")
            .key();
        drop(conn);
        key
    });
    serve(&mut server, Duration::from_millis(300));
    let key = client.join().expect("client");

    // Redeemed immediately, it works — the control, without which the
    // assertion below could be about anything at all.
    let fresh = std::thread::spawn(move || {
        Connection::resume(addr, &Ticket::from_key(key), &public).is_ok()
    });
    serve(&mut server, Duration::from_millis(300));
    assert!(
        fresh.join().expect("client"),
        "a ticket must be redeemable while it is still alive, or this test is \
         measuring something else"
    );

    // A second ticket, then left to go stale.
    let client = std::thread::spawn(move || {
        let conn = Connection::connect(addr, &public, &Identity::generate()).expect("connect");
        *conn
            .resumption_ticket()
            .expect("encrypted")
            .key()
    });
    serve(&mut server, Duration::from_millis(300));
    let stale = client.join().expect("client");

    // Past the lifetime, with room for scheduling.
    sleep(LIFETIME + Duration::from_millis(300));

    let refused = std::thread::spawn(move || {
        Connection::resume(addr, &Ticket::from_key(stale), &public).is_err()
    });
    serve(&mut server, Duration::from_millis(6_500));
    assert!(
        refused.join().expect("client"),
        "a ticket past its lifetime must not be redeemable: until it is spent \
         it is enough on its own to impersonate the peer it was issued to"
    );
}

/// The default is the documented one, and nothing here leaves it changed.
#[test]
fn the_default_lifetime_is_the_documented_one() {
    assert_eq!(
        fectp::TICKET_LIFETIME,
        Duration::from_secs(3600),
        "an hour: short enough that a stolen ticket is worth little, long \
         enough for a device that reboots and reconnects"
    );
}
