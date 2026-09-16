# Releasing

Two crates are publishable, and when they go they have to go in order.
`fectp-bench` and `fectp-footprint` carry `publish = false` and never do.

---

## Published unaudited, on purpose

**No audit is coming.** Not deferred and not being sought — decided against, in
[D74](DECISIONS.md#d74--published-unaudited-with-the-disclosure-moved-to-where-it-is-read),
which reversed [D65](DECISIONS.md#d65--publishable-and-not-published-until-it-has-been-audited).
D65's argument against publishing is still in the record and has not weakened;
the decision went the other way with that argument written beside it.

What replaces the gate is where the disclosure sits. D65 refused because "the
disclosure in a README is read by a fraction of the people who will run it",
which was an argument about placement. So it is now in the two places a reader
meets first:

- the **crate description**, which crates.io shows in search results and at the
  top of the crate page — both end "Not security-audited";
- the **crate-level documentation**, which is the first thing on docs.rs,
  rendered as a warning block.

Keeping those accurate is part of releasing, not decoration. Before each
publish, check that both still say what is true.

A version on crates.io is **permanent**. `0.1.0` cannot be re-uploaded, only
yanked, and yanking does not remove it — a yanked version still resolves for
anyone with it in a lockfile. Publishing also claims the name for good, which
is the one thing here that cannot be undone at all.

---

## The order

```bash
cargo publish -p fectp-core     # first
cargo publish -p fectp          # then this
```

`fectp` depends on `fectp-core`, so the dependency has to exist on the index
before the dependent can be verified. Until `fectp-core` is actually published,
`cargo publish --dry-run -p fectp` fails with *"no matching package named
`fectp-core` found"* — which is expected and not a fault in the manifest.
`--dry-run -p fectp-core` does work, and is worth running first.

## What was needed to make it publishable

Recorded because each one was a separate failure of `--dry-run`, and none of
them is obvious from the workspace layout.

**A version on the path dependency.** `fectp-core = { path = "..." }` builds
fine in a workspace and is refused on publish: *"all dependencies must have a
version requirement specified when publishing"*. Both are needed — the path is
what this workspace builds against, the version is what a published crate
depends on. **This has to be bumped with the version**, and nothing checks it.

**A README inside each crate.** The `readme` field has to point at a file
within the package directory, so the workspace README at the root cannot serve
— it would not be included. Each crate has its own, and they are the crates.io
front page.

**`all-features = true` for docs.rs.** Both crates have their interesting
feature off by default — `compress` on `fectp`, `std` on `fectp-core` — so
docs.rs would otherwise document them with that API simply absent.

**Keywords and categories**, which are how anyone finds the crate at all.

## The build script is already handled

`crates/fectp/build.rs` extracts the Rust snippets from `README.md`,
`docs/USAGE.md` and `crates/fectp/README.md` so the test suite compiles them.
Two of those are outside the crate directory and none of them is in the
published package. It skips a document it cannot read, so a packaged crate
builds with nothing to check — which is the right answer, because the snippets
were checked before the package was made.

If that skip is ever removed, publishing breaks, and it breaks on docs.rs
rather than locally.

## Afterwards

- Tag the commit, and make the tag match the published version.
- Check docs.rs built both crates. It builds with `--all-features` because the
  manifests now ask it to; if a feature fails to compile there it fails
  silently from the publisher's point of view.
- The version in `Cargo.toml` is `version.workspace = true`, so both crates
  move together. That is deliberate: they are one protocol, and a `fectp` that
  can pair with two different `fectp-core` versions is a support question
  nobody wants.
