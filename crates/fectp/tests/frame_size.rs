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
    CEILING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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
    let conn = Connection::connect(echo.addr(), &echo.public(), &Identity::generate())
        .expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let small = conn.max_payload();
    assert!(
        small < fectp::DEFAULT_MAX_DATAGRAM,
        "a frame is its payload plus overhead"
    );

    // One byte past it is refused, which is what makes the limit the limit.
    assert!(
        conn.send(&incompressible(small + 1), PayloadType::Opaque).is_err(),
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

    // A fresh endpoint, because the value travels in the handshake: a peer
    // already told 1200 goes on believing it.
    let echo = Echo::start();
    let conn = Connection::connect(echo.addr(), &echo.public(), &Identity::generate())
        .expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
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
