//! Whether `Identity` leaves its secret in memory after it is dropped.
//!
//! The companion to `fectp-core/tests/secret_wiping.rs`, which covers the
//! keypair inside the session layer. This one covers the type a caller
//! actually holds: `Identity` keeps the long-term secret as a plain `[u8; 32]`
//! of its own, and a plain array has no destructor to wipe it.
//!
//! Reading the bytes of a dropped value needs `unsafe`, which is why this is a
//! test rather than an assertion inside the library. The memory belongs to
//! this stack frame throughout — it is never freed and never reused; only the
//! value occupying it has been dropped.

use core::mem::{size_of, ManuallyDrop};

use fectp::Identity;

/// The bytes of `value`, then the bytes of the same memory after dropping it.
fn bytes_around_drop<T>(value: T) -> (Vec<u8>, Vec<u8>) {
    let mut holder = ManuallyDrop::new(value);
    let at = (&*holder as *const T).cast::<u8>();
    let size = size_of::<T>();

    // SAFETY: `at` points at the live value inside `holder`, on this frame,
    // and `size` is exactly its size.
    let before = unsafe { core::slice::from_raw_parts(at, size) }.to_vec();

    // SAFETY: dropped exactly once, here, and never used as a value again.
    unsafe { ManuallyDrop::drop(&mut holder) };

    // SAFETY: the storage is still this frame's, unfreed and unwritten since.
    // Reading the dropped value's bytes is the property under test.
    let after = unsafe { core::slice::from_raw_parts(at, size) }.to_vec();

    (before, after)
}

#[test]
fn an_identity_wipes_its_secret_when_dropped() {
    let identity = Identity::generate();
    let public = *identity.public();
    let (before, after) = bytes_around_drop(identity);

    let public_at = before.windows(public.len()).position(|w| w == public);
    let mut checked = 0usize;
    for (i, (&b, &a)) in before.iter().zip(after.iter()).enumerate() {
        let in_public = public_at.is_some_and(|p| i >= p && i < p + public.len());
        if in_public || b == 0 {
            continue;
        }
        checked += 1;
        assert_eq!(
            a, 0,
            "byte {i} of a dropped Identity still holds {b:02x}. The long-term \
             secret outlives the value that owned it, in memory that will be \
             reused, swapped, or written to a core dump — and recovering it \
             forges every future handshake to this endpoint."
        );
    }
    assert!(
        checked > 16,
        "only {checked} bytes were examined, too few for this to be testing \
         anything: the layout assumption is wrong"
    );
}
