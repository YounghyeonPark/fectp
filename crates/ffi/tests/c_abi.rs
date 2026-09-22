//! The C ABI exercised the way a C caller would.
//!
//! Through the exported functions and raw pointers only, never the Rust types
//! behind them — a test that reached past the boundary would pass whatever the
//! boundary did, which is the whole thing being checked here.
//!
//! There is no drift guard for a C header the way `api_reference.rs` pins the
//! Rust API, so these tests are the only thing holding the two together. That
//! gap is named in `docs/OTHER-LANGUAGES.md`.

use std::ptr;

use fectp::*;

const KEYLEN: usize = 32;
const FRAME: u16 = 1200;

/// A complete handshake and one message each way, through the ABI.
///
/// # Safety
///
/// Every pointer below points at a local of this function.
unsafe fn round_trip(initiator_payload: &[u8], responder_payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let server = fectp_identity_generate();
    let client = fectp_identity_generate();
    assert!(
        !server.is_null() && !client.is_null(),
        "identity generation"
    );

    let mut server_public = [0u8; KEYLEN];
    assert_eq!(
        unsafe { fectp_identity_public(server, server_public.as_mut_ptr()) },
        FECTP_OK
    );

    let mut initiator =
        unsafe { fectp_initiator_new(client, server_public.as_ptr(), 0x1234_5678, FRAME) };
    let responder = unsafe { fectp_responder_new(server, FRAME) };
    assert!(
        !initiator.is_null() && !responder.is_null(),
        "handshake setup"
    );

    // Message 1.
    let mut init_frame = vec![0u8; 4096];
    let n = unsafe {
        fectp_initiator_write_init(
            initiator,
            initiator_payload.as_ptr(),
            initiator_payload.len(),
            init_frame.as_mut_ptr(),
            init_frame.len(),
        )
    };
    assert!(n > 0, "write_init returned {n}");
    init_frame.truncate(n as usize);

    let mut got_from_client = vec![0u8; 4096];
    let mut responder_slot = responder;
    let n = unsafe {
        fectp_responder_read_init(
            responder_slot,
            init_frame.as_ptr(),
            init_frame.len(),
            got_from_client.as_mut_ptr(),
            got_from_client.len(),
        )
    };
    assert!(n >= 0, "read_init returned {n}");
    got_from_client.truncate(n as usize);
    assert_eq!(got_from_client, initiator_payload, "0-RTT payload");

    // Message 2, which consumes the responder.
    let mut response = vec![0u8; 4096];
    let mut server_session: *mut fectp_session = ptr::null_mut();
    let n = unsafe {
        fectp_responder_write_response(
            &mut responder_slot,
            responder_payload.as_ptr(),
            responder_payload.len(),
            response.as_mut_ptr(),
            response.len(),
            &mut server_session,
        )
    };
    assert!(n > 0, "write_response returned {n}");
    assert!(responder_slot.is_null(), "the responder must be consumed");
    assert!(!server_session.is_null(), "no session came back");
    response.truncate(n as usize);

    let mut got_from_server = vec![0u8; 4096];
    let mut client_session: *mut fectp_session = ptr::null_mut();
    let n = unsafe {
        fectp_initiator_read_response(
            &mut initiator,
            response.as_ptr(),
            response.len(),
            got_from_server.as_mut_ptr(),
            got_from_server.len(),
            &mut client_session,
        )
    };
    assert!(n >= 0, "read_response returned {n}");
    assert!(initiator.is_null(), "the initiator must be consumed");
    assert!(!client_session.is_null(), "no session came back");
    got_from_server.truncate(n as usize);

    // One data frame each way, to prove the sessions agree on keys.
    let mut sealed = vec![0u8; 4096];
    let n = unsafe {
        fectp_session_seal(
            client_session,
            b"from the client".as_ptr(),
            b"from the client".len(),
            sealed.as_mut_ptr(),
            sealed.len(),
        )
    };
    assert!(n > 0, "seal returned {n}");
    let mut opened = vec![0u8; 4096];
    let n = unsafe {
        fectp_session_open(
            server_session,
            sealed.as_ptr(),
            n as usize,
            opened.as_mut_ptr(),
            opened.len(),
        )
    };
    assert!(n >= 0, "open returned {n}");
    assert_eq!(&opened[..n as usize], b"from the client");

    unsafe {
        fectp_session_free(client_session);
        fectp_session_free(server_session);
        fectp_initiator_free(initiator);
        fectp_responder_free(responder_slot);
        fectp_identity_free(client);
        fectp_identity_free(server);
    }

    (got_from_client, got_from_server)
}

#[test]
fn a_handshake_and_a_message_cross_the_boundary() {
    let (from_client, from_server) =
        unsafe { round_trip(b"hello from the opening frame", b"and from the reply") };
    assert_eq!(from_client, b"hello from the opening frame");
    assert_eq!(from_server, b"and from the reply");
}

#[test]
fn an_empty_payload_is_allowed_on_both_flights() {
    // A null pointer with a zero length is the ordinary way a C caller says
    // "nothing", and must not be mistaken for a missing argument.
    let server = fectp_identity_generate();
    let client = fectp_identity_generate();
    let mut public = [0u8; KEYLEN];
    unsafe { fectp_identity_public(server, public.as_mut_ptr()) };

    let initiator = unsafe { fectp_initiator_new(client, public.as_ptr(), 1, FRAME) };
    let mut frame = vec![0u8; 4096];
    let n = unsafe {
        fectp_initiator_write_init(initiator, ptr::null(), 0, frame.as_mut_ptr(), frame.len())
    };
    assert!(n > 0, "a null, zero-length payload must be accepted: {n}");

    unsafe {
        fectp_initiator_free(initiator);
        fectp_identity_free(client);
        fectp_identity_free(server);
    }
}

#[test]
fn every_entry_point_refuses_null_rather_than_crashing() {
    // The first thing any binding does wrong. None of these may dereference.
    let mut out = [0u8; 64];
    assert_eq!(
        unsafe { fectp_identity_public(ptr::null(), out.as_mut_ptr()) },
        FECTP_ERR_NULL
    );
    let id = fectp_identity_generate();
    assert_eq!(
        unsafe { fectp_identity_public(id, ptr::null_mut()) },
        FECTP_ERR_NULL
    );
    assert!(unsafe { fectp_initiator_new(ptr::null(), out.as_ptr(), 0, FRAME) }.is_null());
    assert!(unsafe { fectp_initiator_new(id, ptr::null(), 0, FRAME) }.is_null());
    assert!(unsafe { fectp_responder_new(ptr::null(), FRAME) }.is_null());
    assert_eq!(
        unsafe {
            fectp_initiator_write_init(ptr::null_mut(), out.as_ptr(), 1, out.as_mut_ptr(), 64)
        },
        FECTP_ERR_NULL
    );
    assert_eq!(
        unsafe { fectp_session_seal(ptr::null_mut(), out.as_ptr(), 1, out.as_mut_ptr(), 64) },
        FECTP_ERR_NULL
    );
    assert_eq!(
        unsafe { fectp_session_open(ptr::null_mut(), out.as_ptr(), 1, out.as_mut_ptr(), 64) },
        FECTP_ERR_NULL
    );
    assert_eq!(
        unsafe {
            fectp_initiator_read_response(
                ptr::null_mut(),
                out.as_ptr(),
                1,
                out.as_mut_ptr(),
                64,
                ptr::null_mut(),
            )
        },
        FECTP_ERR_NULL
    );

    // Freeing null is what `free(NULL)` does: nothing.
    unsafe {
        fectp_identity_free(ptr::null_mut());
        fectp_initiator_free(ptr::null_mut());
        fectp_responder_free(ptr::null_mut());
        fectp_session_free(ptr::null_mut());
        fectp_identity_free(id);
    }
}

#[test]
fn a_short_output_buffer_is_an_error_and_not_a_truncation() {
    let server = fectp_identity_generate();
    let client = fectp_identity_generate();
    let mut public = [0u8; KEYLEN];
    unsafe { fectp_identity_public(server, public.as_mut_ptr()) };
    let initiator = unsafe { fectp_initiator_new(client, public.as_ptr(), 1, FRAME) };

    let mut tiny = [0u8; 8];
    let n = unsafe {
        fectp_initiator_write_init(initiator, ptr::null(), 0, tiny.as_mut_ptr(), tiny.len())
    };
    assert_eq!(
        n, FECTP_ERR_BUFFER,
        "a buffer too small must be refused, not filled as far as it goes"
    );
    assert_eq!(tiny, [0u8; 8], "nothing may be written to a refused buffer");

    unsafe {
        fectp_initiator_free(initiator);
        fectp_identity_free(client);
        fectp_identity_free(server);
    }
}

#[test]
fn a_consumed_handle_cannot_be_used_twice() {
    // The shape that turns into a double free in every C binding ever written.
    // The slot is nulled when the handle is taken, so a second call sees null
    // and refuses rather than freeing the same box again.
    let server = fectp_identity_generate();
    let client = fectp_identity_generate();
    let mut public = [0u8; KEYLEN];
    unsafe { fectp_identity_public(server, public.as_mut_ptr()) };

    let mut initiator = unsafe { fectp_initiator_new(client, public.as_ptr(), 1, FRAME) };
    let mut frame = vec![0u8; 4096];
    let n = unsafe {
        fectp_initiator_write_init(initiator, ptr::null(), 0, frame.as_mut_ptr(), frame.len())
    };
    assert!(n > 0);

    // Garbage, so the call fails — the handle must still be consumed, because
    // the handshake cannot continue from a half-read state.
    let junk = [0u8; 64];
    let mut session: *mut fectp_session = ptr::null_mut();
    let mut out = vec![0u8; 256];
    let first = unsafe {
        fectp_initiator_read_response(
            &mut initiator,
            junk.as_ptr(),
            junk.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut session,
        )
    };
    assert!(first < 0, "garbage must not produce a session: {first}");
    assert!(initiator.is_null(), "a failed read must still consume it");
    assert!(session.is_null(), "no session on failure");

    let second = unsafe {
        fectp_initiator_read_response(
            &mut initiator,
            junk.as_ptr(),
            junk.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut session,
        )
    };
    assert_eq!(
        second, FECTP_ERR_NULL,
        "the second call must refuse rather than free the same handle again"
    );

    unsafe {
        fectp_identity_free(client);
        fectp_identity_free(server);
    }
}

#[test]
fn a_forged_frame_is_refused_rather_than_delivered() {
    let server = fectp_identity_generate();
    let client = fectp_identity_generate();
    let mut public = [0u8; KEYLEN];
    unsafe { fectp_identity_public(server, public.as_mut_ptr()) };

    let mut initiator = unsafe { fectp_initiator_new(client, public.as_ptr(), 7, FRAME) };
    let responder = unsafe { fectp_responder_new(server, FRAME) };
    let mut frame = vec![0u8; 4096];
    let n = unsafe {
        fectp_initiator_write_init(initiator, ptr::null(), 0, frame.as_mut_ptr(), frame.len())
    } as usize;

    let mut scratch = vec![0u8; 4096];
    unsafe { fectp_responder_read_init(responder, frame.as_ptr(), n, scratch.as_mut_ptr(), 4096) };
    let mut responder_slot = responder;
    let mut server_session: *mut fectp_session = ptr::null_mut();
    let mut reply = vec![0u8; 4096];
    let n = unsafe {
        fectp_responder_write_response(
            &mut responder_slot,
            ptr::null(),
            0,
            reply.as_mut_ptr(),
            reply.len(),
            &mut server_session,
        )
    } as usize;
    let mut client_session: *mut fectp_session = ptr::null_mut();
    unsafe {
        fectp_initiator_read_response(
            &mut initiator,
            reply.as_ptr(),
            n,
            scratch.as_mut_ptr(),
            4096,
            &mut client_session,
        )
    };

    let mut sealed = vec![0u8; 4096];
    let n = unsafe {
        fectp_session_seal(
            client_session,
            b"genuine".as_ptr(),
            7,
            sealed.as_mut_ptr(),
            sealed.len(),
        )
    } as usize;

    // Flip a byte in the ciphertext. The tag must catch it.
    sealed[n - 1] ^= 0x01;
    let mut out = vec![0u8; 4096];
    let opened = unsafe {
        fectp_session_open(
            server_session,
            sealed.as_ptr(),
            n,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(
        opened, FECTP_ERR_PROTOCOL,
        "a tampered frame must be refused across the boundary too"
    );

    unsafe {
        fectp_session_free(client_session);
        fectp_session_free(server_session);
        fectp_identity_free(client);
        fectp_identity_free(server);
    }
}
