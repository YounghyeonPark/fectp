//! An `Endpoint` whose long-term key is not in this process.
//!
//! [D76](../../../docs/DECISIONS.md) gave `fectp-core` a `StaticKey` seam so a
//! secure element or HSM can perform the Diffie-Hellman without releasing the
//! key. It reached the core and stopped there: `Endpoint` and `Connection`
//! still took an `Identity`, which is thirty-two bytes in this process's
//! memory. The case that motivated D76 — a constrained device linking the core
//! directly — was served; a server holding its identity in an HSM was not, and
//! that is the commoner deployment of the two.
//!
//! The element here is deliberately awkward, as the core's is: it counts calls,
//! can refuse, and has no method that returns the key.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fectp::{Endpoint, Event, Identity, PayloadType};
use fectp_core::keys::{Keypair, PublicKey, StaticKey, DHLEN};

/// A stand-in for a secure element, shareable and thread-safe because an
/// `Endpoint` is sent to a thread in every server this repository has.
struct Element {
    inner: Keypair,
    calls: AtomicUsize,
    locked: AtomicBool,
}

impl Element {
    fn holding(secret: [u8; DHLEN]) -> Self {
        Self {
            inner: Keypair::from_secret(secret),
            calls: AtomicUsize::new(0),
            locked: AtomicBool::new(false),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl StaticKey for Element {
    fn public(&self) -> PublicKey {
        *self.inner.public()
    }

    fn dh(&self, peer: &PublicKey) -> fectp_core::Result<[u8; DHLEN]> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.locked.load(Ordering::Relaxed) {
            return Err(fectp_core::Error::KeyUnavailable);
        }
        Ok(self.inner.dh(peer))
    }
}

/// A server whose identity lives in an element answers an ordinary client.
#[test]
fn an_endpoint_can_hold_its_identity_in_an_element() {
    let element = std::sync::Arc::new(Element::holding([0x22; 32]));
    let public = element.public();

    let mut server = Endpoint::bind_with_key("127.0.0.1:0", element.clone()).expect("server binds");
    let addr = server.local_addr().expect("addr");
    assert_eq!(
        server.public_key(),
        Some(&public),
        "an endpoint must report the element's public key as its own"
    );

    // An ordinary client, which cannot tell the difference and should not.
    let mut client = Endpoint::bind("127.0.0.1:0", Identity::generate()).expect("client binds");
    let peer = client
        .connect_and_send(addr, Some(&public), b"a reading")
        .expect("connect");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut zero_rtt = None;
    let mut ready = false;
    while Instant::now() < deadline && (zero_rtt.is_none() || !ready) {
        if let Ok(Event::Connected { zero_rtt: data, .. }) =
            server.poll(Some(Duration::from_millis(1)))
        {
            zero_rtt = Some(data);
        }
        if let Ok(Event::Connected { .. }) = client.poll(Some(Duration::from_millis(1))) {
            ready = true;
        }
    }
    assert_eq!(
        zero_rtt.as_deref(),
        Some(&b"a reading"[..]),
        "the handshake must complete and carry its 0-RTT payload"
    );
    assert!(ready, "the client's side must complete too");

    // Data both ways, so this shows the keys agree rather than one side
    // talking to itself.
    client.send(peer, b"up", PayloadType::Opaque).expect("send");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut heard = false;
    while Instant::now() < deadline && !heard {
        if let Ok(Event::Message { data, .. }) = server.poll(Some(Duration::from_millis(1))) {
            assert_eq!(data, b"up");
            heard = true;
        }
        let _ = client.poll(Some(Duration::from_millis(1)));
    }
    assert!(
        heard,
        "data must flow after a handshake done through an element"
    );

    // Twice per handshake, not once: `IK` uses the responder's static key for
    // both `es` and `ss` while reading message 1. Worth pinning rather than
    // assuming — this assertion was written expecting one — because on a
    // device where each call is a round trip to a chip the count is the cost,
    // and a change that added a third would otherwise go unnoticed.
    assert_eq!(
        element.calls(),
        2,
        "a responder uses its static key for `es` and `ss`, and nothing else"
    );
}

/// The element is shared, not given away, so an application keeps its device.
#[test]
fn the_application_keeps_the_element_the_endpoint_uses() {
    let element = std::sync::Arc::new(Element::holding([0x33; 32]));
    let endpoint = Endpoint::bind_with_key("127.0.0.1:0", element.clone()).expect("binds");

    // Still reachable for everything an element offers besides the handshake —
    // a health check, an unlock, a call count. An `Endpoint` that took
    // ownership would make that impossible.
    assert_eq!(element.calls(), 0, "nothing has handshaked yet");
    drop(endpoint);
    assert_eq!(
        element.public().len(),
        32,
        "and the element outlives the endpoint that borrowed it"
    );
}

/// A blocking `Connection` can authenticate from an element too.
///
/// The other front end, and the easier half: a connection handshakes once, so
/// the key is used and released rather than held for the object's life.
#[test]
fn a_connection_can_authenticate_from_an_element() {
    use fectp::Connection;

    let server_element = std::sync::Arc::new(Element::holding([0x44; 32]));
    let server_public = server_element.public();
    let mut server =
        Endpoint::bind_with_key("127.0.0.1:0", server_element.clone()).expect("server binds");
    let addr = server.local_addr().expect("addr");

    // Both ends behind an element: the client's identity is one too.
    let client_element = std::sync::Arc::new(Element::holding([0x55; 32]));
    let client_key = client_element.clone();

    let done = std::thread::spawn(move || {
        Connection::connect_with_key(addr, &server_public, client_key, b"from an element")
            .expect("connect")
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut zero_rtt = None;
    while Instant::now() < deadline && zero_rtt.is_none() {
        if let Ok(Event::Connected { zero_rtt: data, .. }) =
            server.poll(Some(Duration::from_millis(1)))
        {
            zero_rtt = Some(data);
        }
    }
    let conn = done.join().expect("the client thread");
    drop(conn);

    assert_eq!(
        zero_rtt.as_deref(),
        Some(&b"from an element"[..]),
        "a connection whose key is in an element must complete the handshake"
    );
    assert_eq!(
        client_element.calls(),
        2,
        "an initiator uses its static key for `ss` and `se`"
    );
    assert_eq!(
        server_element.calls(),
        2,
        "and the responder for `es` and `ss`"
    );
}

/// Both doors take the same things, so neither has to be discovered separately.
///
/// Worth a test rather than trust: the two entry points were written a few
/// minutes apart and took different types — an `Arc` and a `&SharedKey` — for
/// the same idea. That compiles. It is only wrong to read.
#[test]
fn the_two_entry_points_accept_the_same_keys() {
    use fectp::{Connection, SharedKey};

    let element = std::sync::Arc::new(Element::holding([0x66; 32]));
    let peer = Identity::generate();
    let peer_public = *peer.public();

    // An `Arc` of a concrete element, which is what an application holds.
    Endpoint::bind_with_key("127.0.0.1:0", element.clone()).expect("arc binds");
    // A `SharedKey`, for a handle already erased or built once and reused.
    let shared = SharedKey::new(element.clone());
    Endpoint::bind_with_key("127.0.0.1:0", shared.clone()).expect("shared key binds");
    // And an ordinary in-memory identity, since it is a `StaticKey` too.
    Endpoint::bind_with_key("127.0.0.1:0", Identity::generate()).expect("identity binds");

    // The same three on the other door. Nothing answers at this address, so
    // each one fails on the network rather than on its type — which is the
    // property under test: they compile.
    let dead = "127.0.0.1:1";
    for outcome in [
        Connection::connect_with_key(dead, &peer_public, element, b""),
        Connection::connect_with_key(dead, &peer_public, shared, b""),
        Connection::connect_with_key(dead, &peer_public, Identity::generate(), b""),
    ] {
        assert!(
            outcome.is_err(),
            "nothing is listening there, so this must not report a connection"
        );
    }
}

/// An endpoint still crosses to a thread, which is why the bound is what it is.
///
/// Every server in this repository binds on one thread and polls on another, so
/// an `Endpoint` must be `Send`. It now holds its key behind a trait object,
/// and a trait object is `Send` only if it was declared so: dropping the
/// `+ Send + Sync` from `SharedKey` compiles, and breaks every such server at
/// the call site rather than here. This is the cheaper place to find out.
#[test]
fn an_endpoint_still_crosses_to_another_thread() {
    fn assert_send<T: Send>() {}
    assert_send::<Endpoint>();
    assert_send::<fectp::SharedKey>();

    // And exercised, not only asserted: a bound nothing uses is a bound that
    // can be relaxed without anything noticing.
    let element = std::sync::Arc::new(Element::holding([0x77; 32]));
    let endpoint = Endpoint::bind_with_key("127.0.0.1:0", element.clone()).expect("binds");
    let public = std::thread::spawn(move || {
        let mut endpoint = endpoint;
        let _ = endpoint.poll(Some(Duration::from_millis(1)));
        *endpoint
            .public_key()
            .expect("a public-key endpoint has one")
    })
    .join()
    .expect("the thread");
    assert_eq!(
        public,
        element.public(),
        "the key goes with it and is still the element's"
    );
}
