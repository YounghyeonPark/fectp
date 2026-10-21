//! The frame ceiling, and what raising it is worth.
//!
//! Its own file because the ceiling is process-wide, and each integration test
//! file is its own binary: setting it here cannot disturb anything else. Within
//! this file it is one test for the same reason — two would race each other.
//!
//! Why process-wide at all: the path MTU is a property of the network this
//! process sits on, not of any one connection, and the value has to be known
//! before a handshake because it is sent to the peer inside one.

mod common;

use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use common::Echo;
use fectp::{Connection, Identity, PayloadType};

/// Serialises the tests in this file.
///
/// Cargo runs the tests within one binary on threads, and the ceiling is one
/// value shared by all of them: without this, one test's clamping happens
/// inside another's raised window and which of them notices is a matter of
/// timing. It passed five runs in a row that way, which is not the same as
/// being correct.
static CEILING: Mutex<()> = Mutex::new(());

/// Bytes that will not compress.
///
/// `vec![0u8; n]` was the first version of this, and it made the test fail
/// under `--features compress` for a reason that had nothing to do with frame
/// sizes: it coded down to nothing and fitted in a frame it should have
/// overflowed. That is the first entry in docs/FIXING-A-BUG.md, written the
/// same day.
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

fn exclusive() -> MutexGuard<'static, ()> {
    // A test that panics while holding it should not make every later test
    // fail for a different reason than the one that broke.
    CEILING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A default frame gives up a fifth of what ethernet would have carried, and
/// until now there was no way to take it back — the peer's advertised limit
/// could only lower the ceiling, never raise it.
#[test]
fn raising_the_ceiling_puts_more_in_every_frame() {
    let _guard = exclusive();

    // ---- as shipped ------------------------------------------------------
    assert_eq!(
        fectp::max_datagram(),
        fectp::DEFAULT_MAX_DATAGRAM,
        "the default has to be the conservative one"
    );

    let echo = Echo::start();
    let conn =
        Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let small = conn.max_payload();
    assert!(
        small < fectp::DEFAULT_MAX_DATAGRAM,
        "a frame is its payload plus overhead"
    );

    // One byte past it is refused, which is what makes the limit the limit.
    assert!(
        conn.send(&incompressible(small + 1), PayloadType::Opaque)
            .is_err(),
        "the frame limit must actually bound an unreliable send"
    );
    drop(conn);
    drop(echo);

    // ---- told what the path can carry ------------------------------------
    //
    // 1500 of ethernet, less 20 bytes of IPv4 and 8 of UDP.
    const ETHERNET: usize = 1472;
    fectp::set_max_datagram(ETHERNET);
    assert_eq!(fectp::max_datagram(), ETHERNET);
    // Told, not searched for: with discovery on, a session would start at
    // 1200 and probe its way up, which `path_mtu.rs` tests. This is the mode
    // for a path the operator already knows.
    fectp::set_path_mtu_discovery(false);

    // A fresh endpoint, because the value travels in the handshake: a peer
    // already told 1200 goes on believing it.
    let echo = Echo::start();
    let conn =
        Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let large = conn.max_payload();

    assert!(
        large > small,
        "raising the ceiling changed nothing: {large} bytes against {small}. \
         The peer's advertised limit is still only able to lower it."
    );
    assert_eq!(
        large - small,
        ETHERNET - fectp::DEFAULT_MAX_DATAGRAM,
        "the gain should be exactly the extra room on the wire"
    );

    // And it is real: a payload that did not fit before now travels in one
    // frame, unreliably, which is the path with no retransmission to hide a
    // frame that was silently too big.
    let payload = incompressible(large);
    conn.send(&payload, PayloadType::Opaque)
        .expect("a payload the raised ceiling should carry");

    let mut buf = vec![0u8; ETHERNET * 2];
    let n = conn.recv(&mut buf).expect("the echo must come back whole");
    assert_eq!(n, payload.len(), "a larger frame arrived truncated");
    assert_eq!(&buf[..n], &payload[..], "and it must be unchanged");

    // Restore, so that anything added to this file later starts from the
    // default rather than from whatever the previous test left behind.
    fectp::set_max_datagram(fectp::DEFAULT_MAX_DATAGRAM);
    fectp::set_path_mtu_discovery(true);
}

/// The ceiling is clamped, because both ends of the range break something.
///
/// Too small and a handshake cannot fit, so nothing connects at all. Too large
/// and the capability field cannot carry the value, so the peer would be told
/// something other than the truth.
#[test]
fn the_ceiling_is_clamped_at_both_ends() {
    let _guard = exclusive();
    let original = fectp::max_datagram();

    fectp::set_max_datagram(0);
    assert_eq!(
        fectp::max_datagram(),
        fectp::MIN_MAX_DATAGRAM,
        "a ceiling below a handshake would mean nothing can ever connect"
    );

    fectp::set_max_datagram(usize::MAX);
    assert_eq!(
        fectp::max_datagram(),
        u16::MAX as usize,
        "the capability field is a u16; a larger value could not be advertised"
    );

    fectp::set_max_datagram(original);
    assert_eq!(fectp::max_datagram(), original);
}

/// Raising the ceiling raises what a session sends once it exists, not what a
/// handshake sends. A handshake happens before anything is known about the
/// path, which is the one moment a frame sized for it cannot be justified —
/// and path MTU discovery, which is what makes a raised ceiling safe to use,
/// cannot have run yet.
#[test]
fn a_raised_ceiling_does_not_raise_a_handshake() {
    let _guard = exclusive();
    let original = fectp::max_datagram();
    fectp::set_max_datagram(1472);

    // Fits 1472, not 1200.
    let large = vec![0x5a; 1250];
    // Fits 1200 with room for any handshake's overhead.
    let small = vec![0x5a; 900];

    let mut server = fectp::Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let reply_refused = server.set_handshake_reply(&large).is_err();
    let reply_accepted = server.set_handshake_reply(&small).is_ok();

    // The opening frame. An endpoint sends it without waiting for an answer,
    // so nothing has to be listening.
    let mut client = fectp::Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let target = server.local_addr().expect("addr");
    let public = *server.public_key().expect("identity");
    let opening_refused = client
        .connect_and_send(target, Some(&public), &large)
        .is_err();
    let opening_accepted = client
        .connect_and_send(target, Some(&public), &small)
        .is_ok();

    // A connection waits for the answer, so this one has a peer that gives
    // it: refusing for the size has to be told apart from failing to connect.
    let echo = Echo::start();
    let connection_refused =
        Connection::connect_and_send(echo.addr(), &echo.public(), &Identity::generate(), &large)
            .is_err();
    let connection_accepted =
        Connection::connect_and_send(echo.addr(), &echo.public(), &Identity::generate(), &small)
            .is_ok();

    fectp::set_max_datagram(original);

    assert!(reply_accepted, "a handshake reply that fits 1200 bytes");
    assert!(
        reply_refused,
        "a handshake reply that only fits a raised ceiling must be refused"
    );
    assert!(opening_accepted, "an opening frame that fits 1200 bytes");
    assert!(
        opening_refused,
        "an endpoint's opening frame must not grow with the ceiling"
    );
    assert!(
        connection_accepted,
        "a connection whose opening fits 1200 bytes"
    );
    assert!(
        connection_refused,
        "a connection's opening frame must not grow with the ceiling"
    );
}

/// The largest payload `connect_and_send` accepts, and the datagram it makes.
///
/// Found by trying downwards from well past any limit, so the test does not
/// need to know the handshake's overhead to check what it adds up to.
fn largest_opening(
    client: &mut fectp::Endpoint,
    sink: &std::net::UdpSocket,
    public: Option<&[u8; 32]>,
) -> (usize, usize, fectp::Error) {
    let to = sink.local_addr().expect("addr");
    let mut refused = None;
    for len in (0..=1400).rev() {
        match client.connect_and_send(to, public, &incompressible(len)) {
            Ok(_) => {
                let mut buf = [0u8; 65535];
                let (n, _) = sink.recv_from(&mut buf).expect("the opening frame");
                return (len, n, refused.expect("1400 bytes cannot have fitted"));
            }
            Err(e) => refused = Some(e),
        }
    }
    panic!("not even an empty payload was accepted");
}

/// An opening frame carrying data fits in 1200 bytes, all of it.
///
/// It used to be the payload that had to fit, with the handshake's 118 bytes
/// added on top: a 1200-byte payload went out as a 1318-byte datagram at the
/// default ceiling, past the 1200 the default exists for and past the 1280 an
/// IPv6 link need carry. And the payload one byte too large was refused only
/// by a buffer running out, as "output buffer too small".
#[test]
fn an_opening_frame_with_data_fits_in_what_any_path_carries() {
    let _guard = exclusive();
    assert_eq!(fectp::max_datagram(), fectp::DEFAULT_MAX_DATAGRAM);
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    sink.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");

    let server = fectp::Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let public = *server.public_key().expect("identity");
    let mut keyed = fectp::Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("bind");
    let mut shared = fectp::Endpoint::bind_psk("127.0.0.1:0", b"a group secret").expect("bind");

    for (mode, client, key) in [
        ("public-key", &mut keyed, Some(&public)),
        ("pre-shared-key", &mut shared, None),
    ] {
        let (largest, datagram, refused) = largest_opening(client, &sink, key);
        assert!(
            datagram <= 1200,
            "{mode}: a {largest}-byte payload went out as a {datagram}-byte datagram"
        );
        assert!(
            matches!(refused, fectp::Error::PayloadTooLarge { len, limit }
                if len == largest + 1 && limit == largest),
            "{mode}: one byte more must be refused saying what fits, not {refused:?}"
        );

        // A connection has the same limit, and says so the same way. Refused
        // before anything is sent, so nothing has to be listening.
        let too_large = incompressible(largest + 1);
        let to = sink.local_addr().expect("addr");
        let refused = match key {
            Some(key) => Connection::connect_and_send(to, key, &Identity::generate(), &too_large),
            None => Connection::connect_psk_and_send(to, b"a group secret", &too_large),
        }
        .expect_err("refused");
        assert!(
            matches!(refused, fectp::Error::PayloadTooLarge { limit, .. } if limit == largest),
            "{mode}: a connection must refuse the same payload the same way, not {refused:?}"
        );
    }

    // The control: a connection carrying the largest payload does connect.
    let echo = Echo::start();
    let (largest, _, _) = largest_opening(&mut keyed, &sink, Some(&public));
    Connection::connect_and_send(
        echo.addr(),
        &echo.public(),
        &Identity::generate(),
        &incompressible(largest),
    )
    .expect("the largest payload that fits is still accepted");
}
