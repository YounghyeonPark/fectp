//! The crate root re-exports the names a caller reaches for together.
//!
//! `StaticKey` was added in D76 and left in `keys` while `Keypair`,
//! `PublicKey`, `ANONYMOUS` and `DHLEN` were all at the root — so somebody who
//! wrote `use fectp_core::Keypair` and then wanted the trait it implements had
//! to reach two module paths deep for one of the pair. That shipped in 0.2.0
//! before it was noticed.
//!
//! This file is the guard: it uses every key name through the *root* path, so
//! a name that stops being re-exported fails to compile here rather than in
//! somebody's crate.

use fectp_core::{Keypair, PublicKey, StaticKey, ANONYMOUS, DHLEN};

#[test]
fn every_key_name_is_reachable_from_the_root() {
    let keypair = Keypair::from_secret([3u8; DHLEN]);
    let public: PublicKey = *keypair.public();
    assert_eq!(public.len(), DHLEN);

    // Through the trait, not the inherent method, so the trait itself has to
    // be in scope from the root for this to build.
    let shared = StaticKey::dh(&keypair, &public).expect("an in-memory key never fails");
    assert_eq!(shared.len(), DHLEN);

    // And `StaticKey::public`, which returns by value where the inherent one
    // borrows — the difference an element needs.
    let by_value: PublicKey = StaticKey::public(&keypair);
    assert_eq!(by_value, public);

    assert_eq!(ANONYMOUS, [0u8; DHLEN]);
}
