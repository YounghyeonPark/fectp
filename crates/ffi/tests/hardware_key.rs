//! A long-term key the library never sees, through the C ABI.
//!
//! `fectp_identity_from_key` takes a public key and a function that performs
//! X25519 with the private half, which is how a secure element, an HSM or a
//! TPM is reached from C, Python or JavaScript. The element here is Rust
//! pretending to be one: a keypair behind `extern "C"` functions, which count
//! their calls, can be locked, and record when they are released.
//!
//! Driven through the exported functions and raw pointers only, as the rest of
//! this crate's tests are, and run under Miri in CI — the callback boundary is
//! exactly the kind of place a fault changes no answer.

use core::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fectp::*;
use fectp_core::keys::{Keypair, PublicKey};

const KEYLEN: usize = 32;
const FRAME: u16 = 1200;

/// What the host keeps: a key it can use and cannot hand over.
struct Element {
    keypair: Keypair,
    calls: AtomicUsize,
    released: AtomicUsize,
    locked: AtomicBool,
}

impl Element {
    fn holding(secret: u8) -> Self {
        Self {
            keypair: Keypair::from_secret([secret; KEYLEN]),
            calls: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
            locked: AtomicBool::new(false),
        }
    }

    fn public(&self) -> PublicKey {
        *self.keypair.public()
    }

    fn context(&self) -> *mut c_void {
        self as *const Element as *mut c_void
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn released(&self) -> usize {
        self.released.load(Ordering::SeqCst)
    }
}

/// The host's Diffie-Hellman, as a C function.
///
/// # Safety
///
/// `context` is an `Element` that outlives every call, as the tests arrange;
/// `peer` and `shared` are 32 bytes each, as the library promises.
unsafe extern "C" fn element_dh(context: *mut c_void, peer: *const u8, shared: *mut u8) -> i32 {
    // SAFETY: as above.
    let element = unsafe { &*(context as *const Element) };
    element.calls.fetch_add(1, Ordering::SeqCst);
    if element.locked.load(Ordering::SeqCst) {
        return 1;
    }
    let mut remote = [0u8; KEYLEN];
    // SAFETY: the library promises 32 readable bytes at `peer`.
    remote.copy_from_slice(unsafe { std::slice::from_raw_parts(peer, KEYLEN) });
    let result = element.keypair.dh(&remote);
    // SAFETY: the library promises 32 writable bytes at `shared`.
    unsafe { std::slice::from_raw_parts_mut(shared, KEYLEN) }.copy_from_slice(&result);
    0
}

/// The host being told its key is no longer referenced.
///
/// # Safety
///
/// As `element_dh`.
unsafe extern "C" fn element_release(context: *mut c_void) {
    // SAFETY: as above.
    let element = unsafe { &*(context as *const Element) };
    element.released.fetch_add(1, Ordering::SeqCst);
}

/// An identity reaching `element`.
///
/// # Safety
///
/// `element` must outlive the identity and every handshake begun from it.
unsafe fn identity_for(element: &Element) -> *mut fectp_identity {
    let public = element.public();
    let identity = unsafe {
        fectp_identity_from_key(
            public.as_ptr(),
            Some(element_dh),
            element.context(),
            Some(element_release),
        )
    };
    assert!(!identity.is_null(), "an element identity");
    identity
}

/// A whole handshake between two identities, then one message each way.
///
/// Returns the codes from the four handshake calls if any fails, so a test
/// can assert on where a locked key surfaces.
///
/// # Safety
///
/// Both identities must be live.
unsafe fn handshake(
    client: *const fectp_identity,
    server: *const fectp_identity,
) -> Result<(), (&'static str, isize)> {
    let mut server_public = [0u8; KEYLEN];
    assert_eq!(
        unsafe { fectp_identity_public(server, server_public.as_mut_ptr()) },
        FECTP_OK
    );
    let mut initiator =
        unsafe { fectp_initiator_new(client, server_public.as_ptr(), 0x0E1E_0E1E, FRAME) };
    let mut responder = unsafe { fectp_responder_new(server, FRAME) };
    assert!(!initiator.is_null() && !responder.is_null(), "setup");

    let finish = |initiator: *mut fectp_initiator, responder: *mut fectp_responder| {
        // SAFETY: each is live or null, and null is accepted.
        unsafe {
            fectp_initiator_free(initiator);
            fectp_responder_free(responder);
        }
    };

    let mut frame = vec![0u8; 4096];
    let n = unsafe {
        fectp_initiator_write_init(initiator, ptr::null(), 0, frame.as_mut_ptr(), frame.len())
    };
    if n < 0 {
        finish(initiator, responder);
        return Err(("write_init", n));
    }
    frame.truncate(n as usize);

    let mut scratch = vec![0u8; 4096];
    let n = unsafe {
        fectp_responder_read_init(
            responder,
            frame.as_ptr(),
            frame.len(),
            scratch.as_mut_ptr(),
            scratch.len(),
        )
    };
    if n < 0 {
        finish(initiator, responder);
        return Err(("read_init", n));
    }

    let mut reply = vec![0u8; 4096];
    let mut server_session: *mut fectp_session = ptr::null_mut();
    let n = unsafe {
        fectp_responder_write_response(
            &mut responder,
            ptr::null(),
            0,
            reply.as_mut_ptr(),
            reply.len(),
            &mut server_session,
        )
    };
    if n < 0 {
        finish(initiator, responder);
        return Err(("write_response", n));
    }
    reply.truncate(n as usize);

    let mut client_session: *mut fectp_session = ptr::null_mut();
    let n = unsafe {
        fectp_initiator_read_response(
            &mut initiator,
            reply.as_ptr(),
            reply.len(),
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut client_session,
        )
    };
    if n < 0 {
        unsafe { fectp_session_free(server_session) };
        finish(initiator, responder);
        return Err(("read_response", n));
    }

    // One message each way: the two sessions agree on keys or they do not.
    for (from, to, words) in [
        (client_session, server_session, &b"up"[..]),
        (server_session, client_session, &b"down"[..]),
    ] {
        let mut sealed = vec![0u8; 4096];
        let n = unsafe {
            fectp_session_seal(
                from,
                words.as_ptr(),
                words.len(),
                sealed.as_mut_ptr(),
                sealed.len(),
            )
        };
        assert!(n > 0, "seal returned {n}");
        let mut opened = vec![0u8; 4096];
        let m = unsafe {
            fectp_session_open(
                to,
                sealed.as_ptr(),
                n as usize,
                opened.as_mut_ptr(),
                opened.len(),
            )
        };
        assert!(m >= 0, "open returned {m}: the sessions do not agree");
        assert_eq!(&opened[..m as usize], words);
    }

    unsafe {
        fectp_session_free(client_session);
        fectp_session_free(server_session);
    }
    Ok(())
}

#[test]
fn an_element_can_be_either_side_of_a_handshake() {
    let element = Element::holding(0x21);
    let element_identity = unsafe { identity_for(&element) };
    let ordinary = fectp_identity_generate();

    unsafe { handshake(element_identity, ordinary) }.expect("element as initiator");
    // `IK` uses the initiator's static key for `ss` and `se`.
    assert_eq!(element.calls(), 2, "an initiator calls its key twice");

    unsafe { handshake(ordinary, element_identity) }.expect("element as responder");
    // And the responder's for `es` and `ss`.
    assert_eq!(element.calls(), 4, "a responder calls its key twice");

    unsafe {
        fectp_identity_free(element_identity);
        fectp_identity_free(ordinary);
    }
    assert_eq!(element.released(), 1, "released once, after the last use");
}

#[test]
fn the_public_key_is_the_one_given() {
    let element = Element::holding(0x22);
    let identity = unsafe { identity_for(&element) };
    let mut public = [0u8; KEYLEN];
    assert_eq!(
        unsafe { fectp_identity_public(identity, public.as_mut_ptr()) },
        FECTP_OK
    );
    assert_eq!(public, element.public());
    assert_eq!(element.calls(), 0, "reading the public key costs no call");
    unsafe { fectp_identity_free(identity) };
}

#[test]
fn a_locked_key_is_reported_as_a_key_error_on_either_side() {
    let element = Element::holding(0x23);
    let identity = unsafe { identity_for(&element) };
    let ordinary = fectp_identity_generate();
    element.locked.store(true, Ordering::SeqCst);

    // As the initiator, the first use is in message 1.
    assert_eq!(
        unsafe { handshake(identity, ordinary) },
        Err(("write_init", FECTP_ERR_KEY))
    );
    // As the responder, the first use is reading message 1.
    assert_eq!(
        unsafe { handshake(ordinary, identity) },
        Err(("read_init", FECTP_ERR_KEY))
    );

    // Unlocked, the same identity works: a refusal is not a broken handle.
    element.locked.store(false, Ordering::SeqCst);
    unsafe { handshake(identity, ordinary) }.expect("after unlocking");

    unsafe {
        fectp_identity_free(identity);
        fectp_identity_free(ordinary);
    }
    assert_eq!(element.released(), 1);
}

#[test]
fn a_handshake_keeps_the_key_after_its_identity_is_freed() {
    // The initiator uses its key in message 1 and again reading message 2, and
    // a host may free the identity handle in between. If the key went with the
    // handle, the second call would reach a context the host had let go.
    let element = Element::holding(0x24);
    let identity = unsafe { identity_for(&element) };
    let peer = Element::holding(0x25);
    let peer_public = peer.public();

    let initiator =
        unsafe { fectp_initiator_new(identity, peer_public.as_ptr(), 0x0E1E_0E1F, FRAME) };
    assert!(!initiator.is_null());
    unsafe { fectp_identity_free(identity) };
    assert_eq!(
        element.released(),
        0,
        "a handshake still holds the key, so it must not be released"
    );

    let mut frame = vec![0u8; 4096];
    let n = unsafe {
        fectp_initiator_write_init(initiator, ptr::null(), 0, frame.as_mut_ptr(), frame.len())
    };
    assert!(
        n > 0,
        "write_init after the identity was freed returned {n}"
    );
    assert_eq!(element.calls(), 1);

    unsafe { fectp_initiator_free(initiator) };
    assert_eq!(element.released(), 1, "released when the handshake went");
}

#[test]
fn a_rejected_identity_is_not_released() {
    let element = Element::holding(0x26);
    let public = element.public();

    let no_function = unsafe {
        fectp_identity_from_key(
            public.as_ptr(),
            None,
            element.context(),
            Some(element_release),
        )
    };
    assert!(no_function.is_null(), "a key with no function is refused");

    let no_public = unsafe {
        fectp_identity_from_key(
            ptr::null(),
            Some(element_dh),
            element.context(),
            Some(element_release),
        )
    };
    assert!(no_public.is_null(), "a key with no public half is refused");

    assert_eq!(
        element.released(),
        0,
        "the context is still the caller's when creation fails"
    );
}

#[test]
fn a_null_release_is_accepted() {
    let element = Element::holding(0x27);
    let public = element.public();
    let identity = unsafe {
        fectp_identity_from_key(public.as_ptr(), Some(element_dh), element.context(), None)
    };
    assert!(!identity.is_null());
    let ordinary = fectp_identity_generate();
    unsafe { handshake(identity, ordinary) }.expect("handshake");
    unsafe {
        fectp_identity_free(identity);
        fectp_identity_free(ordinary);
    }
}
