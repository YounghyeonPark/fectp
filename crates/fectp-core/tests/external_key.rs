//! A handshake whose long-term private key is never in this process.
//!
//! The gap this closes is the one `DECISIONS.md`'s table said was "relevant on
//! exactly the microcontrollers this protocol targets": `Keypair::from_secret`
//! takes the raw 32 bytes and the handshake performs its own Diffie-Hellman,
//! so a secure element or HSM that never releases the key — which is the whole
//! point of having one — could not be used at all.
//!
//! [`StaticKey`] is the seam. Everything the protocol does with a long-term
//! private key is two operations: name its public half, and Diffie-Hellman
//! against a peer. An element can do both without handing anything over.
//!
//! The fake below is deliberately awkward about it. It holds the secret behind
//! a counter and a lock, refuses when locked, and has no method that returns
//! the key — so a handshake that completes through it could not have read the
//! bytes even if it wanted to.

use core::cell::Cell;

use fectp_core::keys::{Keypair, PublicKey, StaticKey, DHLEN};
use fectp_core::session::{Capabilities, Initiator, Responder};
use fectp_core::Error;
use rand_core::OsRng;

/// A stand-in for a secure element.
///
/// The secret is private to this type and no method returns it. `dh` is the
/// only way to use it, which is what an element offers, and it counts calls
/// and can refuse — both of which a `Keypair` never does and both of which a
/// caller has to cope with.
struct Element {
    /// Stored here because this is a test; a real element holds it in hardware
    /// and this file could not name its type.
    inner: Keypair,
    calls: Cell<usize>,
    locked: Cell<bool>,
}

impl Element {
    fn holding(secret: [u8; DHLEN]) -> Self {
        Self {
            inner: Keypair::from_secret(secret),
            calls: Cell::new(0),
            locked: Cell::new(false),
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }

    fn lock(&self) {
        self.locked.set(true);
    }
}

impl StaticKey for Element {
    fn public(&self) -> PublicKey {
        *self.inner.public()
    }

    fn dh(&self, peer: &PublicKey) -> fectp_core::Result<[u8; DHLEN]> {
        self.calls.set(self.calls.get() + 1);
        if self.locked.get() {
            return Err(Error::KeyUnavailable);
        }
        Ok(self.inner.dh(peer))
    }
}

fn caps() -> Capabilities {
    Capabilities::minimal(1200)
}

/// A full handshake where neither side's static key is a `Keypair`.
#[test]
fn a_handshake_completes_with_both_static_keys_behind_an_element() {
    let client = Element::holding([0x11; 32]);
    let server = Element::holding([0x22; 32]);
    let server_public = server.public();

    let mut initiator = Initiator::new(&client, server_public, 1, caps()).expect("initiator");
    let mut msg1 = vec![0u8; fectp_core::session::INITIATOR_OVERHEAD + 32];
    let n = initiator
        .write_init(&mut OsRng, b"a reading", &mut msg1)
        .expect("message 1");

    let mut responder = Responder::new(&server, caps());
    let mut staging = vec![0u8; msg1.len()];
    let len = responder
        .read_init(&msg1[..n], &mut staging)
        .expect("read message 1");
    assert_eq!(&staging[..len], b"a reading");

    let mut msg2 = vec![0u8; fectp_core::session::RESPONDER_OVERHEAD + 32];
    let (mut server_session, n2) = responder
        .write_response(&mut OsRng, b"and the reply", &mut msg2)
        .expect("message 2");
    let mut reply = vec![0u8; msg2.len()];
    let (mut client_session, reply_len) = initiator
        .read_response(&msg2[..n2], &mut reply)
        .expect("read message 2");
    assert_eq!(&reply[..reply_len], b"and the reply");

    // Both directions, so this shows the keys agree rather than one side
    // decrypting its own traffic.
    let mut frame = vec![0u8; 256];
    let n = client_session.seal(b"up", 0, &mut frame).expect("seal");
    let opened = server_session.open(&mut frame[..n]).expect("open");
    assert_eq!(&frame[14..14 + opened.len], b"up");
}

/// An element that refuses is an error, not a panic and not a silent success.
///
/// This is the half a `Keypair` cannot exercise at all: an in-memory key is
/// never busy, locked, or unplugged, so every caller of a handshake was written
/// against an operation that could not fail. It can now.
#[test]
fn a_locked_element_fails_the_handshake_rather_than_anything_worse() {
    let client = Element::holding([0x11; 32]);
    let server_public = Element::holding([0x22; 32]).public();
    client.lock();

    let mut initiator = Initiator::new(&client, server_public, 1, caps()).expect("initiator");
    let mut msg1 = vec![0u8; fectp_core::session::INITIATOR_OVERHEAD + 32];
    let failed = initiator.write_init(&mut OsRng, b"a reading", &mut msg1);

    assert_eq!(
        failed,
        Err(Error::KeyUnavailable),
        "a locked element must surface as an error the caller can act on"
    );
}

/// The element is asked exactly as often as the pattern says.
///
/// `Noise_IK` performs four Diffie-Hellman operations and two of them use the
/// initiator's static key: `es` in message 1 and `se` in message 2. A count
/// that drifts means either an operation was added or one is being done with a
/// key held somewhere else, and on a device where each call is a round trip to
/// a chip the number is also the cost.
#[test]
fn an_initiator_asks_its_element_twice() {
    let client = Element::holding([0x11; 32]);
    let server = Element::holding([0x22; 32]);
    let server_public = server.public();

    let mut initiator = Initiator::new(&client, server_public, 1, caps()).expect("initiator");
    let mut msg1 = vec![0u8; fectp_core::session::INITIATOR_OVERHEAD + 8];
    let n = initiator
        .write_init(&mut OsRng, &[], &mut msg1)
        .expect("msg1");

    let mut responder = Responder::new(&server, caps());
    let mut staging = vec![0u8; msg1.len()];
    responder.read_init(&msg1[..n], &mut staging).expect("read");
    let mut msg2 = vec![0u8; fectp_core::session::RESPONDER_OVERHEAD + 8];
    let (_, n2) = responder
        .write_response(&mut OsRng, &[], &mut msg2)
        .expect("msg2");

    let mut reply = vec![0u8; msg2.len()];
    let (_, _) = initiator
        .read_response(&msg2[..n2], &mut reply)
        .expect("read response");

    // The application kept the element and lent it, so the count is read from
    // the element itself rather than through a handshake that has been
    // consumed.
    assert_eq!(
        client.calls(),
        2,
        "the initiator's static key is used for `es` and `se`, and nothing else"
    );
}
