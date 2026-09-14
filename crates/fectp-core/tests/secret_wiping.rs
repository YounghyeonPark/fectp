//! Whether a long-term secret is still in memory after it is dropped.
//!
//! The session keys are wiped — `CipherState` carries a `Drop` that does it,
//! and the buffer `Keypair::generate` fills is wiped before it goes out of
//! scope. The long-term X25519 secret is the one that matters most, because it
//! lives for the process rather than for a session and because recovering it
//! forges every future handshake, and it was the one not covered.
//!
//! `x25519-dalek` wipes `StaticSecret` on drop, but only under its `zeroize`
//! feature, which is on by default and was switched off here by
//! `default-features = false` without being listed again. Nothing said so: the
//! type compiles either way and behaves identically until someone reads the
//! freed memory.
//!
//! These tests read the bytes of a value after dropping it, which needs
//! `unsafe` and is why they are here rather than in the library — the crate
//! itself carries `#![forbid(unsafe_code)]`. The memory is still owned by this
//! stack frame, never freed and never reused; only the value in it has been
//! dropped. That is the one way to observe this property at runtime rather
//! than asserting a trait bound and hoping it means what it says.

use core::mem::{size_of, ManuallyDrop};

use fectp_core::keys::Keypair;

/// The bytes of `value`, then the bytes of the same memory after dropping it.
///
/// `ManuallyDrop` keeps the value in a local this frame owns, so the storage
/// outlives the drop and can be read back.
fn bytes_around_drop<T>(value: T) -> (Vec<u8>, Vec<u8>) {
    let mut holder = ManuallyDrop::new(value);
    let at = (&*holder as *const T).cast::<u8>();
    let size = size_of::<T>();

    // SAFETY: `at` points at the live value inside `holder`, which is on this
    // frame, and `size` is its exact size.
    let before = unsafe { core::slice::from_raw_parts(at, size) }.to_vec();

    // SAFETY: `holder` is dropped exactly once, here, and never used as a
    // value again — only its storage is read.
    unsafe { ManuallyDrop::drop(&mut holder) };

    // SAFETY: the storage is still this frame's and has not been freed or
    // written since. Reading a dropped value's bytes is the property under
    // test; nothing is interpreted as a `T`.
    let after = unsafe { core::slice::from_raw_parts(at, size) }.to_vec();

    (before, after)
}

/// Where `needle` sits inside `haystack`, if it does.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[test]
fn a_long_term_secret_is_wiped_when_its_keypair_is_dropped() {
    // Distinctive enough that finding it is not a coincidence, and shaped so
    // X25519's clamping leaves it recognisable: clamping only clears the low
    // three bits of the first byte and rewrites the top two of the last, so a
    // pattern in between survives it.
    let mut secret = [0u8; 32];
    for (i, b) in secret.iter_mut().enumerate() {
        *b = 0xA0 ^ (i as u8);
    }

    let (before, after) = bytes_around_drop(Keypair::from_secret(secret));

    // Clamped or not, the middle of the pattern is untouched by clamping and
    // is what is searched for.
    let middle = &secret[1..31];
    let at = find(&before, middle).expect(
        "the secret is not in the keypair's own bytes, so this test is looking \
         in the wrong place and would pass whatever happened on drop",
    );

    assert!(
        after[at..at + middle.len()].iter().all(|&b| b == 0),
        "the long-term X25519 secret survived the drop of its keypair. It is \
         still readable in memory that will be reused, swapped, or written to \
         a core dump, and recovering it forges every future handshake. Found \
         at offset {at}: {:02x?}",
        &after[at..at + middle.len()]
    );
}

#[test]
fn a_generated_secret_is_wiped_too() {
    // The same for a key that was never handled as bytes by the caller, which
    // is the ordinary case: `generate` wipes its own temporary buffer, and the
    // question here is whether the copy it handed to `StaticSecret` is wiped
    // as well.
    use rand_core::OsRng;

    let keypair = Keypair::generate(&mut OsRng);
    let public = *keypair.public();
    let (before, after) = bytes_around_drop(keypair);

    // The public key is not secret and is derived, not stored raw in every
    // build — so it anchors nothing. What must go is everything that was not
    // zero and is not the public key.
    let public_at = find(&before, &public);
    let mut checked = 0usize;
    for (i, (&b, &a)) in before.iter().zip(after.iter()).enumerate() {
        let in_public = public_at.is_some_and(|p| i >= p && i < p + public.len());
        if in_public || b == 0 {
            continue;
        }
        checked += 1;
        assert_eq!(
            a, 0,
            "byte {i} of a dropped keypair still holds {b:02x}; only the \
             public key may survive, and this is not inside it"
        );
    }
    assert!(
        checked > 16,
        "only {checked} secret bytes were examined, which is too few for this \
         to be testing anything — the layout assumption is wrong"
    );
}
