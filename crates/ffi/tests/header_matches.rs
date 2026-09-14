//! The C header and the Rust exports, held to each other.
//!
//! `docs/OTHER-LANGUAGES.md` lists "nothing that keeps this honest extends" as
//! one of the things a binding breaks: `doc_snippets.rs`, `api_reference.rs`
//! and `spec_conformance.rs` are all Rust and none of them reads a `.h`. That
//! is true of the semantics and cannot be fixed from here — no test in this
//! language can check that the header's prose describes what the function
//! does.
//!
//! What *can* be checked is the part that drifts first and silently: a
//! function added to one side and not the other. A caller compiling against a
//! header that promises a symbol the library does not export gets a link
//! error, which is survivable. A caller reading a header that omits a function
//! never finds it, and one reading a stale signature gets undefined behaviour.
//!
//! So this pins the set of names. It does not pin the signatures, and saying
//! so is the point: this closes the cheap half of the gap and leaves the
//! expensive half open and named.

use std::collections::BTreeSet;

/// Every `#[no_mangle] pub extern "C"` function name in the crate source.
fn exported_from_rust() -> BTreeSet<String> {
    let source = include_str!("../src/lib.rs");
    let mut names = BTreeSet::new();
    let mut previous_was_no_mangle = false;
    for line in source.lines() {
        let line = line.trim();
        if line == "#[no_mangle]" {
            previous_was_no_mangle = true;
            continue;
        }
        if previous_was_no_mangle {
            if let Some(rest) = line.split("fn ").nth(1) {
                if let Some(name) = rest.split('(').next() {
                    names.insert(name.trim().to_string());
                }
            }
            previous_was_no_mangle = false;
        }
    }
    names
}

/// Every `fectp_*` function the header declares.
fn declared_in_header() -> BTreeSet<String> {
    let header = include_str!("../include/fectp.h");
    let mut names = BTreeSet::new();
    for line in header.lines() {
        let line = line.trim();
        // Declarations only: a comment mentioning a name is not a promise, and
        // the prose above mentions several.
        if line.starts_with('*') || line.starts_with("/*") || line.starts_with("//") {
            continue;
        }
        // The name is the identifier immediately before the parameter list,
        // read backwards from the bracket. Reading forwards finds the return
        // type first — `fectp_identity *fectp_identity_generate(void)` starts
        // with a name that is not the function's.
        let Some(open) = line.find('(') else { continue };
        let before = &line[..open];
        let start = before
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |i| i + 1);
        let name = &before[start..];
        if name.starts_with("fectp_") {
            names.insert(name.to_string());
        }
    }
    names
}

#[test]
fn the_header_declares_exactly_what_the_library_exports() {
    let rust = exported_from_rust();
    let header = declared_in_header();

    assert!(
        !rust.is_empty() && !header.is_empty(),
        "one side parsed to nothing, so this test would pass against any \
         drift at all: {} from Rust, {} from the header",
        rust.len(),
        header.len()
    );

    let missing_from_header: Vec<_> = rust.difference(&header).collect();
    assert!(
        missing_from_header.is_empty(),
        "exported but not declared in include/fectp.h, so a C caller cannot \
         reach it: {missing_from_header:?}"
    );

    let missing_from_rust: Vec<_> = header.difference(&rust).collect();
    assert!(
        missing_from_rust.is_empty(),
        "declared in include/fectp.h but not exported, so a C caller that \
         compiles will fail to link: {missing_from_rust:?}"
    );
}

#[test]
fn the_header_states_that_no_call_returns_the_secret() {
    // The one property worth pinning in prose, because it is the one a future
    // change would quietly break by adding a convenience accessor. If someone
    // adds `fectp_identity_secret`, the name assertion above stays green — the
    // header would simply gain a line — and this is what notices.
    let rust = exported_from_rust();
    let offenders: Vec<_> = rust
        .iter()
        .filter(|name| name.contains("secret"))
        .filter(|name| *name != "fectp_identity_from_secret")
        .collect();
    assert!(
        offenders.is_empty(),
        "a call that names the secret and is not the one that takes it in: \
         {offenders:?}. Nothing may hand a private key to a host language — \
         the bytes cannot be wiped there, are copied by its runtime, and may \
         reach swap. See D67 for what happens when a secret outlives the thing \
         meant to wipe it, and docs/OTHER-LANGUAGES.md for why this boundary \
         is where it is."
    );
}
