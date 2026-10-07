//! FECTP over a C ABI.
//!
//! This is the doorway every other language goes through — Python by `cffi`,
//! Java by the FFM API, C and C++ directly. [`docs/OTHER-LANGUAGES.md`] sets
//! out why it binds `fectp-core` rather than `fectp`: the core is defined over
//! buffers and never touches a socket, so nothing here blocks a caller's event
//! loop, owns a thread, or allocates memory the caller has to free through a
//! function it must remember to call.
//!
//! The host does its own I/O. This turns bytes into frames and frames back
//! into bytes, and that is all it does.
//!
//! [`docs/OTHER-LANGUAGES.md`]: https://github.com/YounghyeonPark/fectp/blob/main/docs/OTHER-LANGUAGES.md
//!
//! # What this crate is careful about
//!
//! The rest of the workspace carries `#![forbid(unsafe_code)]`. This crate
//! cannot: raw pointers, lengths chosen by the caller and lifetimes the
//! compiler cannot see are what a C ABI *is*. So the safety argument stops
//! being "the compiler proved it" and starts being "this file is short, every
//! `unsafe` block is one of four shapes, each says what it assumes, and Miri
//! runs the tests in CI".
//!
//! That last part is not decoration. The tests here cannot see a fault that
//! does not change an answer: a slice built one byte too long and then trimmed
//! passes all six of them, and is undefined behaviour. Miri names the line.
//!
//! **The secret never crosses.** [`fectp_identity`] is opaque and has no
//! accessor for the private key — not a discouraged one, an absent one. The
//! core's `Keypair` does not expose it either, so there is no path from here
//! to those bytes. A `bytes` object in Python or a `byte[]` in Java is immortal
//! and copied by its runtime, and D67 is what happens when a secret outlives
//! the thing that was supposed to wipe it.
//!
//! **Or never exists here at all.** [`fectp_identity_from_key`] takes a key
//! that lives somewhere this library cannot read — a secure element, an HSM, a
//! TPM — as a public key and a function that performs the Diffie-Hellman. The
//! host's function is called with the peer's public key and writes the shared
//! secret; the private key stays wherever the host keeps it.
//!
//! **No panic escapes.** Unwinding out of an `extern "C"` function aborts the
//! process, which for a host language means the interpreter dies rather than
//! an exception being raised. Every entry point below is wrapped, and returns
//! [`FECTP_ERR_PANIC`] instead.
//!
//! **The caller owns every buffer.** Output goes where the caller says, with a
//! length it supplied; a buffer too small is an error and not a truncation.
//! The only things this crate allocates are the four opaque handles, each
//! freed by its own function.
//!
//! # Lifetime and threads
//!
//! A handle is owned by whoever created it and must be freed exactly once.
//! Passing a freed handle, or the same handle to two threads at once, is
//! undefined — these are ordinary Rust objects behind a pointer and carry no
//! lock. One session per thread, or a lock in the host.
//!
//! `fectp_initiator_read_response` and `fectp_responder_write_response`
//! **consume** their handle: they take a pointer to it, free it, and write
//! null back, so a caller cannot use it again by accident.

// This is the one crate in the workspace that cannot forbid `unsafe`, so it
// keeps the surface small enough to read instead. Every block below is one of
// four shapes — borrow an input, borrow an output, take or give a handle, call
// the host's key — and each states what it assumes of the caller.
#![deny(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]
// The names are what a C caller types. Rust's conventions do not apply to an
// ABI that another language reads from a header.
#![allow(non_camel_case_types)]

use core::ffi::c_void;
use core::panic::AssertUnwindSafe;
use core::slice;
use std::sync::Arc;

use fectp_core::frame::HEADER_LEN;
use fectp_core::keys::{Keypair, PublicKey, StaticKey, DHLEN};
use fectp_core::session::{Capabilities, Initiator, Responder, Session};
use rand_core::OsRng;
use zeroize::Zeroize;

/// The call succeeded. Calls that report a length return a non-negative one.
pub const FECTP_OK: isize = 0;
/// A pointer argument was null, or a handle had already been consumed.
pub const FECTP_ERR_NULL: isize = -1;
/// An output buffer was too small. Nothing was written to it.
pub const FECTP_ERR_BUFFER: isize = -2;
/// The protocol rejected the input: a malformed frame, a failed
/// authentication, a handshake step out of order.
pub const FECTP_ERR_PROTOCOL: isize = -3;
/// A panic was caught at the boundary. That is a bug in FECTP, and the handle
/// it happened on should be treated as unusable.
pub const FECTP_ERR_PANIC: isize = -4;
/// A length did not fit this platform's `isize` and so could not be reported.
/// Nothing was read or written.
pub const FECTP_ERR_TOO_LARGE: isize = -5;
/// The host's key function reported a failure — the device was busy, locked or
/// absent. The handshake it happened in is over, as with any other error.
pub const FECTP_ERR_KEY: isize = -6;

/// A long-term identity.
///
/// Opaque, and with no call that reads the private key back out — absent
/// rather than discouraged. Either it holds the secret, or it holds a way to
/// reach a key held elsewhere ([`fectp_identity_from_key`]).
pub struct fectp_identity {
    key: Held,
    public: PublicKey,
}

/// What an identity holds.
enum Held {
    /// The secret itself. Kept because the core's `Keypair` is consumed by a
    /// handshake and cannot be cloned, so one is built per handshake from
    /// these; they are wiped when the handle is freed.
    Secret([u8; DHLEN]),
    /// A key held by the host. Shared, not copied: each handshake begun from
    /// this identity holds a reference, so the host's context outlives the
    /// handle when a handshake is still using it.
    Element(Arc<Element>),
}

impl fectp_identity {
    /// The key one handshake will use.
    fn key(&self) -> IdentityKey {
        match &self.key {
            // The copy `from_secret` makes wipes itself on drop.
            Held::Secret(secret) => IdentityKey::Secret(Keypair::from_secret(*secret)),
            Held::Element(element) => IdentityKey::Element(Arc::clone(element)),
        }
    }
}

impl Drop for fectp_identity {
    fn drop(&mut self) {
        if let Held::Secret(secret) = &mut self.key {
            secret.zeroize();
        }
    }
}

/// Performs X25519 with a key this library never sees.
///
/// Called with the `context` the host registered, the peer's 32-byte public
/// key, and 32 writable bytes for the shared secret. Returns 0 on success;
/// anything else is reported as [`FECTP_ERR_KEY`] and ends the handshake.
pub type fectp_dh_fn =
    unsafe extern "C" fn(context: *mut c_void, peer_public: *const u8, shared: *mut u8) -> i32;

/// Tells the host its key is no longer referenced.
pub type fectp_release_fn = unsafe extern "C" fn(context: *mut c_void);

/// A key held by the host, reached through its function.
struct Element {
    dh: fectp_dh_fn,
    context: *mut c_void,
    release: Option<fectp_release_fn>,
    public: PublicKey,
}

// SAFETY: `context` is the host's, and what crossing threads means for it is
// the host's to say. The contract on `fectp_identity_from_key` states it: the
// function may be called on whatever thread drives a handshake begun from the
// identity, so a host that drives several at once on several threads must be
// able to serve them, or lock. Nothing in this library touches `context`
// except to pass it back.
unsafe impl Send for Element {}
// SAFETY: as above; `Element` has no interior mutability of its own.
unsafe impl Sync for Element {}

impl Element {
    fn dh(&self, peer: &PublicKey) -> fectp_core::Result<[u8; DHLEN]> {
        let mut shared = [0u8; DHLEN];
        // SAFETY: the host's function, under the contract it registered with:
        // `peer` is 32 readable bytes and `shared` 32 writable ones, both
        // live for the call, and `context` is exactly what it handed over.
        let status = unsafe { (self.dh)(self.context, peer.as_ptr(), shared.as_mut_ptr()) };
        if status != 0 {
            shared.zeroize();
            return Err(fectp_core::Error::KeyUnavailable);
        }
        Ok(shared)
    }
}

impl Drop for Element {
    /// The last reference has gone — the identity and every handshake begun
    /// from it — so the host may let its key go.
    fn drop(&mut self) {
        if let Some(release) = self.release {
            // SAFETY: the host's function, called once, with its own context,
            // after which nothing here can reach that context again.
            unsafe { release(self.context) };
        }
    }
}

/// The key one handshake holds.
enum IdentityKey {
    Secret(Keypair),
    Element(Arc<Element>),
}

impl StaticKey for IdentityKey {
    fn public(&self) -> PublicKey {
        match self {
            IdentityKey::Secret(keypair) => *keypair.public(),
            IdentityKey::Element(element) => element.public,
        }
    }

    fn dh(&self, peer: &PublicKey) -> fectp_core::Result<[u8; DHLEN]> {
        match self {
            IdentityKey::Secret(keypair) => Ok(keypair.dh(peer)),
            IdentityKey::Element(element) => element.dh(peer),
        }
    }
}

/// A handshake in progress, from the side that started it.
pub struct fectp_initiator {
    inner: Initiator<IdentityKey>,
}

/// A handshake in progress, from the side that answered.
pub struct fectp_responder {
    inner: Responder<IdentityKey>,
}

/// An established session: payloads in, frames out, and back again.
pub struct fectp_session {
    inner: Session,
}

/// Runs `body`, turning a panic into [`FECTP_ERR_PANIC`] rather than an abort.
///
/// Unwinding across an `extern "C"` boundary aborts the process from Rust 1.81
/// on. To a host language that is the interpreter dying with no traceback,
/// which is far worse than an error code — so every entry point goes through
/// here, including those that look as though they cannot fail.
fn guard<F: FnOnce() -> isize>(body: F) -> isize {
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => FECTP_ERR_PANIC,
    }
}

/// As [`guard`], for a call that returns a handle rather than a code.
fn guard_ptr<T, F: FnOnce() -> *mut T>(body: F) -> *mut T {
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => core::ptr::null_mut(),
    }
}

/// A length as `isize`, or [`FECTP_ERR_TOO_LARGE`] if it will not fit.
///
/// A negative return means an error here, so a length large enough to alias
/// one cannot be reported. Unreachable on a 64-bit host; present because
/// "unreachable" and "unchecked" are different things at an ABI boundary.
fn length(n: usize) -> isize {
    isize::try_from(n).unwrap_or(FECTP_ERR_TOO_LARGE)
}

/// Maps a core error onto the codes above.
fn code(e: &fectp_core::Error) -> isize {
    match e {
        fectp_core::Error::BufferTooSmall => FECTP_ERR_BUFFER,
        fectp_core::Error::KeyUnavailable => FECTP_ERR_KEY,
        _ => FECTP_ERR_PROTOCOL,
    }
}

/// Borrows `len` bytes at `ptr`, or `None` if it is null.
///
/// A null pointer with a zero length is an empty slice, which is what a caller
/// with no payload passes.
///
/// # Safety
///
/// `ptr` must be valid for reads of `len` bytes, or null when `len` is zero.
unsafe fn input<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `len` readable bytes at `ptr`, and `len`
    // is non-zero so this is not the empty-slice sentinel.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Borrows `len` writable bytes at `ptr`, or `None` if it is null.
///
/// # Safety
///
/// `ptr` must be valid for writes of `len` bytes, or null when `len` is zero,
/// and must not alias anything else borrowed at the same time.
unsafe fn output<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        return Some(&mut []);
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: as `input`, plus the caller's guarantee of no aliasing.
    Some(unsafe { slice::from_raw_parts_mut(ptr, len) })
}

// ──────────────────────────────────────────────────────────── identity ────

/// Generates an identity from the operating system's randomness.
///
/// Returns null if it cannot. Free it with [`fectp_identity_free`].
#[no_mangle]
pub extern "C" fn fectp_identity_generate() -> *mut fectp_identity {
    guard_ptr(|| {
        let mut secret = [0u8; DHLEN];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut secret);
        let public = *Keypair::from_secret(secret).public();
        let handle = Box::into_raw(Box::new(fectp_identity {
            key: Held::Secret(secret),
            public,
        }));
        secret.zeroize();
        handle
    })
}

/// Rebuilds an identity from 32 stored secret bytes.
///
/// This direction exists and the other does not. Nothing here hands the secret
/// back: a host that must persist one should keep the bytes it was given at
/// generation, and better still should keep this handle and never let them
/// into its own memory — a `bytes` in Python or a `byte[]` in Java cannot be
/// wiped, is copied by its runtime, and may reach swap.
///
/// The copy this call makes is wiped before it returns. The caller's own bytes
/// are the caller's to erase.
///
/// # Safety
///
/// `secret` must be valid for reads of 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fectp_identity_from_secret(secret: *const u8) -> *mut fectp_identity {
    guard_ptr(|| {
        // SAFETY: the caller guarantees 32 readable bytes at `secret`.
        let Some(bytes) = (unsafe { input(secret, DHLEN) }) else {
            return core::ptr::null_mut();
        };
        let mut fixed = [0u8; DHLEN];
        fixed.copy_from_slice(bytes);
        let public = *Keypair::from_secret(fixed).public();
        let handle = Box::into_raw(Box::new(fectp_identity {
            key: Held::Secret(fixed),
            public,
        }));
        fixed.zeroize();
        handle
    })
}

/// An identity whose private key is held by the host and never seen here.
///
/// For a secure element, an HSM or a TPM: `public_key` is the key's 32-byte
/// public half, read once now, and `dh` performs X25519 with the private half
/// whenever a handshake needs it — twice per handshake on each side. `context`
/// is passed back to `dh` and `release` unchanged; this library never reads
/// it.
///
/// `release`, which may be null, is called exactly once, when nothing here can
/// call `dh` again: after this identity is freed *and* every initiator and
/// responder begun from it has been consumed or freed. A handshake may outlive
/// the identity handle it began from, and its key goes with it.
///
/// Returns null if `public_key` or `dh` is null, in which case `release` is
/// not called and `context` remains the host's.
///
/// # Contract on `dh`
///
/// - It is called synchronously, from inside [`fectp_initiator_write_init`],
///   [`fectp_initiator_read_response`] and [`fectp_responder_read_init`], on
///   the thread that called them. A host driving several handshakes from this
///   identity on several threads at once must serve concurrent calls or lock.
/// - It must write all 32 bytes and return 0, or return non-zero. A non-zero
///   return is [`FECTP_ERR_KEY`] from the call that made it.
/// - It must not unwind: no C++ exception, no `longjmp` across this library.
///   A host language's exception must be caught in the host's wrapper and
///   turned into a non-zero return.
///
/// # Safety
///
/// `public_key` must be valid for reads of 32 bytes. `dh` and `release` must
/// remain callable with `context` until `release` has been called.
#[no_mangle]
pub unsafe extern "C" fn fectp_identity_from_key(
    public_key: *const u8,
    dh: Option<fectp_dh_fn>,
    context: *mut c_void,
    release: Option<fectp_release_fn>,
) -> *mut fectp_identity {
    guard_ptr(|| {
        let Some(dh) = dh else {
            return core::ptr::null_mut();
        };
        // SAFETY: the caller guarantees 32 readable bytes at `public_key`.
        let Some(bytes) = (unsafe { input(public_key, DHLEN) }) else {
            return core::ptr::null_mut();
        };
        let mut public = [0u8; DHLEN];
        public.copy_from_slice(bytes);
        let element = Arc::new(Element {
            dh,
            context,
            release,
            public,
        });
        Box::into_raw(Box::new(fectp_identity {
            key: Held::Element(element),
            public,
        }))
    })
}

/// Writes this identity's 32-byte public key to `out`.
///
/// # Safety
///
/// `identity` must be a live handle, `out` valid for writes of 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fectp_identity_public(
    identity: *const fectp_identity,
    out: *mut u8,
) -> isize {
    guard(|| {
        if identity.is_null() {
            return FECTP_ERR_NULL;
        }
        // SAFETY: the caller guarantees a live handle.
        let identity = unsafe { &*identity };
        // SAFETY: the caller guarantees 32 writable bytes.
        let Some(out) = (unsafe { output(out, DHLEN) }) else {
            return FECTP_ERR_NULL;
        };
        out.copy_from_slice(&identity.public);
        FECTP_OK
    })
}

/// Frees an identity, wiping its secret. Null is accepted and does nothing.
///
/// # Safety
///
/// `identity` must have come from this library and not been freed already.
#[no_mangle]
pub unsafe extern "C" fn fectp_identity_free(identity: *mut fectp_identity) {
    if identity.is_null() {
        return;
    }
    let _ = guard(|| {
        // SAFETY: the caller guarantees this came from `Box::into_raw` in this
        // library and has not been freed. `Drop` wipes the secret.
        drop(unsafe { Box::from_raw(identity) });
        FECTP_OK
    });
}

// ─────────────────────────────────────────────────────────── initiator ────

/// Begins a handshake with the peer whose public key is `peer_public`.
///
/// `session_id` names this session to the peer; it is the caller's to choose
/// and must not collide with another live session to the same address.
/// `max_frame` is the largest frame this side will accept.
///
/// # Safety
///
/// `identity` must be live and `peer_public` valid for reads of 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fectp_initiator_new(
    identity: *const fectp_identity,
    peer_public: *const u8,
    session_id: u32,
    max_frame: u16,
) -> *mut fectp_initiator {
    guard_ptr(|| {
        if identity.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: the caller guarantees a live handle.
        let identity = unsafe { &*identity };
        // SAFETY: the caller guarantees 32 readable bytes.
        let Some(peer) = (unsafe { input(peer_public, DHLEN) }) else {
            return core::ptr::null_mut();
        };
        let mut remote = [0u8; DHLEN];
        remote.copy_from_slice(peer);
        match Initiator::new(
            identity.key(),
            remote,
            session_id,
            Capabilities::minimal(max_frame),
        ) {
            Ok(inner) => Box::into_raw(Box::new(fectp_initiator { inner })),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Writes the opening frame, with `payload` carried inside it, to `out`.
///
/// Returns the number of bytes written, or a negative code.
///
/// # Safety
///
/// `initiator` must be live; `payload` and `out` valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn fectp_initiator_write_init(
    initiator: *mut fectp_initiator,
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_len: usize,
) -> isize {
    guard(|| {
        if initiator.is_null() {
            return FECTP_ERR_NULL;
        }
        // SAFETY: the caller guarantees a live handle, used only here.
        let initiator = unsafe { &mut *initiator };
        // SAFETY: the caller guarantees the buffers; they do not alias, being
        // one read-only and one write-only argument.
        let (Some(payload), Some(out)) = (unsafe { input(payload, payload_len) }, unsafe {
            output(out, out_len)
        }) else {
            return FECTP_ERR_NULL;
        };
        match initiator.inner.write_init(&mut OsRng, payload, out) {
            Ok(n) => length(n),
            Err(e) => code(&e),
        }
    })
}

/// Reads the peer's reply, producing a session.
///
/// **Consumes the initiator** either way: the handshake cannot be retried from
/// this state, so `*initiator` is freed and set to null whether this succeeds
/// or fails. On success `*session` receives a handle to free with
/// [`fectp_session_free`], and the return value is the length of any payload
/// the peer sent with its reply, written to `out`.
///
/// # Safety
///
/// `initiator` must point at a live handle produced here, `session` at a
/// writable pointer, and the buffers must be valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn fectp_initiator_read_response(
    initiator: *mut *mut fectp_initiator,
    frame: *const u8,
    frame_len: usize,
    out: *mut u8,
    out_len: usize,
    session: *mut *mut fectp_session,
) -> isize {
    guard(|| {
        if initiator.is_null() || session.is_null() {
            return FECTP_ERR_NULL;
        }
        // SAFETY: the caller guarantees a writable pointer-to-pointer.
        let slot = unsafe { &mut *initiator };
        if slot.is_null() {
            return FECTP_ERR_NULL;
        }
        // SAFETY: the handle came from `Box::into_raw` here; taking it back
        // is what makes this call consume it. The slot is nulled immediately
        // so a second call cannot reach the same box.
        let owned = unsafe { Box::from_raw(*slot) };
        *slot = core::ptr::null_mut();

        // SAFETY: the caller guarantees the buffers, which do not alias.
        let (Some(frame), Some(out)) = (unsafe { input(frame, frame_len) }, unsafe {
            output(out, out_len)
        }) else {
            return FECTP_ERR_NULL;
        };
        match owned.inner.read_response(frame, out) {
            Ok((established, n)) => {
                let handle = Box::into_raw(Box::new(fectp_session { inner: established }));
                // SAFETY: the caller guarantees `session` is writable.
                unsafe { *session = handle };
                length(n)
            }
            Err(e) => code(&e),
        }
    })
}

/// Frees an initiator abandoned before the handshake finished.
///
/// Null is accepted, which is what a consumed handle has been set to.
///
/// # Safety
///
/// `initiator` must have come from this library and not been freed already.
#[no_mangle]
pub unsafe extern "C" fn fectp_initiator_free(initiator: *mut fectp_initiator) {
    if initiator.is_null() {
        return;
    }
    let _ = guard(|| {
        // SAFETY: the caller guarantees provenance and that it is unfreed.
        drop(unsafe { Box::from_raw(initiator) });
        FECTP_OK
    });
}

// ─────────────────────────────────────────────────────────── responder ────

/// Prepares to answer handshakes aimed at `identity`.
///
/// # Safety
///
/// `identity` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn fectp_responder_new(
    identity: *const fectp_identity,
    max_frame: u16,
) -> *mut fectp_responder {
    guard_ptr(|| {
        if identity.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: the caller guarantees a live handle.
        let identity = unsafe { &*identity };
        Box::into_raw(Box::new(fectp_responder {
            inner: Responder::new(identity.key(), Capabilities::minimal(max_frame)),
        }))
    })
}

/// Reads an opening frame, writing any payload it carried to `out`.
///
/// Returns that payload's length, or a negative code.
///
/// # Safety
///
/// `responder` must be live; the buffers valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn fectp_responder_read_init(
    responder: *mut fectp_responder,
    frame: *const u8,
    frame_len: usize,
    out: *mut u8,
    out_len: usize,
) -> isize {
    guard(|| {
        if responder.is_null() {
            return FECTP_ERR_NULL;
        }
        // SAFETY: the caller guarantees a live handle, borrowed only here.
        let responder = unsafe { &mut *responder };
        // SAFETY: the caller guarantees the buffers, which do not alias.
        let (Some(frame), Some(out)) = (unsafe { input(frame, frame_len) }, unsafe {
            output(out, out_len)
        }) else {
            return FECTP_ERR_NULL;
        };
        match responder.inner.read_init(frame, out) {
            Ok(n) => length(n),
            Err(e) => code(&e),
        }
    })
}

/// Writes the reply, with `payload` inside it, producing a session.
///
/// **Consumes the responder** either way, for the same reason
/// [`fectp_initiator_read_response`] does: `*responder` is freed and set to
/// null. On success `*session` receives a handle and the return value is the
/// length written to `out`.
///
/// # Safety
///
/// `responder` must point at a live handle produced here, `session` at a
/// writable pointer, and the buffers must be valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn fectp_responder_write_response(
    responder: *mut *mut fectp_responder,
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_len: usize,
    session: *mut *mut fectp_session,
) -> isize {
    guard(|| {
        if responder.is_null() || session.is_null() {
            return FECTP_ERR_NULL;
        }
        // SAFETY: the caller guarantees a writable pointer-to-pointer.
        let slot = unsafe { &mut *responder };
        if slot.is_null() {
            return FECTP_ERR_NULL;
        }
        // SAFETY: as in `read_response` — taken back to consume it, and the
        // slot nulled at once so no second call can reach the same box.
        let owned = unsafe { Box::from_raw(*slot) };
        *slot = core::ptr::null_mut();

        // SAFETY: the caller guarantees the buffers, which do not alias.
        let (Some(payload), Some(out)) = (unsafe { input(payload, payload_len) }, unsafe {
            output(out, out_len)
        }) else {
            return FECTP_ERR_NULL;
        };
        match owned.inner.write_response(&mut OsRng, payload, out) {
            Ok((established, n)) => {
                let handle = Box::into_raw(Box::new(fectp_session { inner: established }));
                // SAFETY: the caller guarantees `session` is writable.
                unsafe { *session = handle };
                length(n)
            }
            Err(e) => code(&e),
        }
    })
}

/// Frees a responder abandoned before the handshake finished.
///
/// # Safety
///
/// `responder` must have come from this library and not been freed already.
#[no_mangle]
pub unsafe extern "C" fn fectp_responder_free(responder: *mut fectp_responder) {
    if responder.is_null() {
        return;
    }
    let _ = guard(|| {
        // SAFETY: the caller guarantees provenance and that it is unfreed.
        drop(unsafe { Box::from_raw(responder) });
        FECTP_OK
    });
}

// ───────────────────────────────────────────────────────────── session ────

/// Encrypts `payload` into a data frame, written to `out`.
///
/// Returns the frame's length, or a negative code.
///
/// # Safety
///
/// `session` must be live; the buffers valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn fectp_session_seal(
    session: *mut fectp_session,
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_len: usize,
) -> isize {
    guard(|| {
        if session.is_null() {
            return FECTP_ERR_NULL;
        }
        // SAFETY: the caller guarantees a live handle, borrowed only here.
        let session = unsafe { &mut *session };
        // SAFETY: the caller guarantees the buffers, which do not alias.
        let (Some(payload), Some(out)) = (unsafe { input(payload, payload_len) }, unsafe {
            output(out, out_len)
        }) else {
            return FECTP_ERR_NULL;
        };
        match session.inner.seal(payload, 0, out) {
            Ok(n) => length(n),
            Err(e) => code(&e),
        }
    })
}

/// Decrypts `frame`, writing its payload to `out`.
///
/// Returns the payload's length, or a negative code. A frame that fails to
/// authenticate is [`FECTP_ERR_PROTOCOL`] and must be discarded: anyone can
/// send bytes to a socket, so this is an ordinary event and not a fault.
///
/// The frame is copied before being decrypted, so the caller's buffer is left
/// as it was and may be `const`.
///
/// # Safety
///
/// `session` must be live; the buffers valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn fectp_session_open(
    session: *mut fectp_session,
    frame: *const u8,
    frame_len: usize,
    out: *mut u8,
    out_len: usize,
) -> isize {
    guard(|| {
        if session.is_null() {
            return FECTP_ERR_NULL;
        }
        // SAFETY: the caller guarantees a live handle, borrowed only here.
        let session = unsafe { &mut *session };
        // SAFETY: the caller guarantees the buffers, which do not alias.
        let (Some(frame), Some(out)) = (unsafe { input(frame, frame_len) }, unsafe {
            output(out, out_len)
        }) else {
            return FECTP_ERR_NULL;
        };
        // The core decrypts in place; the caller's frame is not ours to write
        // to, so it is copied first.
        let mut scratch = frame.to_vec();
        match session.inner.open(&mut scratch) {
            Ok(opened) => {
                let plaintext = &scratch[HEADER_LEN..][..opened.len];
                if out.len() < plaintext.len() {
                    return FECTP_ERR_BUFFER;
                }
                out[..plaintext.len()].copy_from_slice(plaintext);
                length(plaintext.len())
            }
            Err(e) => code(&e),
        }
    })
}

/// Frees a session. Null is accepted and does nothing.
///
/// # Safety
///
/// `session` must have come from this library and not been freed already.
#[no_mangle]
pub unsafe extern "C" fn fectp_session_free(session: *mut fectp_session) {
    if session.is_null() {
        return;
    }
    let _ = guard(|| {
        // SAFETY: the caller guarantees provenance and that it is unfreed.
        drop(unsafe { Box::from_raw(session) });
        FECTP_OK
    });
}
