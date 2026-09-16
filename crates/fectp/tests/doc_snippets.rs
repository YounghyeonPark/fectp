//! Compiles every Rust snippet in `README.md` and `docs/USAGE.md`.
//!
//! The snippets are extracted by `build.rs` and included here, so this file
//! failing to build *is* the failure: a snippet that no longer matches the API
//! stops the test suite rather than misleading a reader. See `build.rs` for
//! how a block opts out.
//!
//! This complements `examples/tour.rs`, which proves the documented flows
//! actually work at run time. This one proves the documents say what the code
//! does.

// The snippets are compiled, never called: unreachable tails and unused
// bindings are the point, not a defect.
#![allow(unused, unreachable_code, non_snake_case, clippy::all)]

include!(concat!(env!("OUT_DIR"), "/doc_snippets.rs"));

/// An extractor that silently matched nothing would pass by doing nothing.
///
/// Skipped when there were no documents to extract from, which is the case for
/// a crate unpacked from the index: they live two directories up and are not
/// in the package. `DOCUMENTS_FOUND` separates that from an extractor that has
/// stopped matching, and only the second is a failure.
#[test]
fn the_documentation_still_has_snippets_to_check() {
    if !DOCUMENTS_FOUND {
        eprintln!("skipped: no README.md or docs/USAGE.md beside this crate");
        return;
    }
    assert!(
        SNIPPETS_CHECKED >= 25,
        "only {SNIPPETS_CHECKED} snippets extracted from README.md and docs/USAGE.md \
         — the extractor has probably stopped matching"
    );
}
