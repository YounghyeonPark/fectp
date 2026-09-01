# Fixing a bug

Seven steps. Step 2 is the one that matters, and it is the one that gets
skipped.

Every example here is from this repository. None of it is general advice.

---

## 1. Reproduce it as a test that fails

Before the fix. A bug you cannot reproduce is a bug you cannot know you fixed.

Read the failure message and check it is failing for the reason you think. A
test can fail for the wrong reason as easily as it can pass for one.

Where the bug is a *sequence* rather than an input, build the sequence
deliberately. `a_sender_may_not_outrun_what_the_receiver_can_still_name`
constructs one stuck message with ordinary traffic cycling around it, because
generated orderings do not reach that state — measured, they get 32 identifiers
ahead where the failure begins at 64.

## 2. Prove the test would fail without the fix

**Remove the thing you are about to add, and watch the test fail.** Then put it
back and confirm `git status --short` is clean.

This step exists because tests here have passed without testing anything at
least five separate times, and every one was found by accident. If you do only
one thing on this page, do this one.

The ways they failed, each from this repository:

| Trap | What happened |
|---|---|
| **Compressible filler** | `vec![0x7E; n]` codes to nothing with the `compress` feature on, so a test about a fragmented payload silently tested one small frame. Three separate tests. Use an xorshift fill and assert the size exceeds the limit first. |
| **Stopping at the limit** | A loop breaking when a counter *reaches* a bound, then asserting the bound was not exceeded, is true by construction. Run past it, then assert. |
| **Counting instead of surviving** | "Served *n* times" is satisfied by a peer evicted a second in, from before it happened. Assert the final state. |
| **Asserting what was already true** | "An established peer still works after a flood" held before the bound existed. `a_flood_does_not_evict_an_established_peer` was deleted for this: 200 connections never reached the default `MAX_PEERS` of 1024, so nothing was ever evicted. |
| **A generator that never arrives** | A property test whose inputs stop short of the interesting region cannot fail. Measure the reach — `report_how_far_the_generator_reaches` exists for exactly this. |
| **Racing the harness** | A peer waiting in `recv` while the loop that answers it has stopped times out and looks evicted. Drain before joining. |

If the test still passes with the fix removed, you have not found the bug's
cause, or the test is not aimed at it. Both are worth knowing before you commit.

## 3. Fix it

Prefer the change that makes the failure impossible over the one that makes
this instance go away. The ACK-window bug was a slot count that could not bound
an identifier distance; adding slots would have moved it, not removed it.

If the fix reveals the code was inconsistent with itself, say so in the comment
where it lives. The sender had used wrapping arithmetic all along and only the
receiver compared numerically — that sentence belongs next to the fix.

## 4. Verify in every configuration, not just the convenient one

```bash
cargo test -p fectp-core
cargo test -p fectp                       # no features
cargo test -p fectp --features compress
cargo test --workspace
```

`cargo test --workspace` unifies features across the graph, and the bench crate
enables `fectp/compress`. That hid a suite failing under `-p fectp` entirely.
Run them separately.

`#[cfg(unix)]` code does not compile on Windows at all:

```bash
cargo check --workspace --all-targets --target x86_64-unknown-linux-gnu
```

And the bounds these tests set are not the shipped ones. `set_max_peers(32)`
makes a bound reachable in seconds where the default would take a minute — but
a number measured in a debug build says nothing about a release one. Measured:
X25519 takes 181 µs unoptimised against 30 µs optimised, six times, so the four
operations of a handshake are 725 µs rather than 121 µs. That is why a flood
measurement in a test could not tell a limit of 64 a second from no limit at
all — the harness topped out below both.

(Six times, not "orders of magnitude", which is what this paragraph said until
it was measured. The habit this page is about applies to the page.)

## 5. Fix what the bug proved wrong

A bug is evidence that something else was also wrong. Usually at least one of:

- **A document.** SPEC.md said identifiers were "a u32 assigned by the sender,
  starting at 0 and increasing by one" and stopped, so it never said what
  happens at the wrap. The code was wrong *and* the specification was silent.
- **A guard.** If a constant changed, `api_reference.rs` or
  `spec_conformance.rs` pins it and must be updated — that is what they are
  for.
- **A claim in prose.** Nothing checks the sentences. `.github/check-links.py`
  resolves links, `doc_snippets.rs` compiles code blocks, and neither reads the
  paragraph in between.

## 6. Write it down

Add a numbered entry to [DECISIONS.md](DECISIONS.md). Not a changelog line —
the reasoning, in this shape:

- **Problem**: what was wrong, and how it was found.
- **Decision**: what changed, and why this rather than the alternative.
- **What it costs**: every fix costs something. Name it.
- **What is still open**: the part you did not fix. Say it here rather than
  leaving it to be discovered.

Where a number is involved, measure it. `MAX_HANDSHAKES_PER_SECOND` shipped at
64 against a capacity of a few thousand because it was chosen by feel, and it
would have throttled this protocol's own traffic before inconveniencing anyone
hostile.

## 7. Commit the reasoning, not the diff

The diff is in the commit. The message says what was wrong, why it happened,
and what it means — including the parts that reflect badly on the previous
attempt. Several messages in this history record a test that was written three
times before it discriminated, because that is more useful to the next person
than a clean story.

---

## Who to ask

Four agents in [`.claude/agents/`](../.claude/agents/), each from something that
has gone wrong here more than once:

| | |
|---|---|
| `test-adversary` | Step 2, performed by someone other than the author — which is the only reason it works |
| `claim-auditor` | Step 5, for the sentences no guard reads |
| `measurement-critic` | Step 4 and step 6, when a number is involved |
| `protocol-adversary` | Before touching the handshake, session table, replay window or reassembly |

## What none of this catches

It is not a security audit. Injecting packet loss found a bug that lost
messages while 179 tests passed; writing the specification a second time found
another that had been there since the reliability layer was written. Both were
found by doing something new, not by doing this list again.
