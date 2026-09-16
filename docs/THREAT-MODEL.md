# Threat model

Who this protocol assumes is attacking it, what it claims against them, and
what it does not claim at all.

**Not audited** ([D74](DECISIONS.md#d74--published-unaudited-with-the-disclosure-moved-to-where-it-is-read)).
No cryptographer has reviewed any of this and none is going to. Everything
below is a claim with evidence beside it, and the evidence is tests, models and
specification text — not review. Read the *Not claimed* and *Known weaknesses*
sections before the others: a threat model that is read top-down is a list of
reassurances, and the parts that matter are the ones that say no.

[SPEC.md §7](SPEC.md) is a different document from this one. That is a
conformance list — what an implementation MUST do. This is what an attacker
gets to do, and what happens when they do it.

---

## What is being protected

In order of how much it costs to lose:

1. **The long-term static key.** Identifies a peer. Compromise is
   impersonation, and for a responder it is impersonation to everyone.
2. **The configured pre-shared key**, in the mode that has one (§1.2.1). It is
   symmetric, so every holder can impersonate every other holder.
3. **Resumption keys.** Each authenticates one later handshake, and stealing
   one does not give the next (D73).
4. **Application payloads in flight.** Confidentiality and integrity.
5. **The responder's availability.** Memory and the session table are finite
   and a stranger can reach them.

Not protected, and never claimed to be: **who is talking to whom, how often,
and roughly how much**. See *Traffic analysis* below.

---

## The attacker

Assumed able to:

- **read every datagram**, in full, and keep them indefinitely;
- **drop, delay, reorder and duplicate** anything;
- **inject datagrams with any source address**, including one it does not
  control, because UDP source addresses are not verified by anything;
- **replay** any datagram it has seen, from any address, at any time;
- **connect legitimately** in public-key mode, because reaching the handshake
  needs only the responder's public key, which is public;
- **run for as long as it likes**, and come back later with keys it has since
  stolen.

Assumed **not** able to:

- break X25519, ChaCha20-Poly1305 or BLAKE2s;
- read memory on either peer, or run code there;
- obtain a static key, except where a section below says otherwise;
- observe timing at a granularity this document does not claim to defend
  against — see *Known weaknesses*.

---

## Claimed

Each row names what stops the attack and what shows it does.

| Claim | Mechanism | Evidence |
|---|---|---|
| Payloads are confidential and authenticated | `Noise_IK` and ChaCha20-Poly1305 over the whole frame header as associated data | `interop.rs` against `snow` in both roles; the `Session::open` tests in `fectp-core/src/session.rs`; SPEC §5 |
| An altered data frame is refused, and an altered handshake frame is refused except in a reply's sequence field and its known flag bits | The full header is AEAD associated data on data frames; message 1's header is the Noise prologue. A *reply's* header is neither — see below | `handshake_mutation.rs`; `malformed_input.rs` |
| A recorded session stays shut when a long-term key is later stolen | Ephemeral-ephemeral exchange in both the full and resumed handshakes | D73's model, `confidentiality? transport_msg` passing with the key leaked in phase 1 |
| Stealing one resumption key does not give the next | The next key is derived from a chaining key that absorbed a fresh `ee` | D73, `confidentiality? next_rk_c` |
| A replayed data frame is refused | 64-frame replay window, advanced only after authentication | `replay_model.rs`; SPEC §5.1 |
| A replayed resumption request is refused | Tickets are single use | `resumption.rs::a_ticket_is_single_use`; SPEC §4.6. **Not in pre-shared-key mode** — see below |
| A session is never *moved* to an address that has not answered | Path challenge and response before anything but the challenge goes to a new address | `migration.rs::an_address_that_never_answers_does_not_get_the_session` and `::a_replayed_frame_cannot_move_a_session`; SPEC §5.8. This is about address **changes**; first contact is not validated — see below |
| A stranger cannot exhaust the session table by flooding | 512 handshakes answered per second and 1024 peers **by default** — both are raised or lowered by `set_max_handshakes_per_second` and `set_max_peers`, and a deployment that raises them has less of this — plus an eviction order that prefers sessions which never sent an authenticated frame | `handshake_flood.rs`; `resumption_replay.rs::replays_evict_each_other_and_not_a_peer_that_has_spoken` |
| A peer cannot force unbounded memory | What a *peer* can make a receiver hold is bounded: 4 reassemblies at once, each at most 1 MiB and 4096 fragments, and 256 tickets | `MAX_REASSEMBLIES`, `MAX_MESSAGE_LEN`, `MAX_FRAGMENTS`, `MAX_TICKETS`; SPEC §5.6 for the fragment count, the rest code-only; `endpoint_large.rs`, `ticket_flush.rs` |
| The two security modes cannot be mixed or downgraded | No wire field selects a mode; a peer in the wrong one sends frame types the responder has no arm for | `modes.rs`; SPEC §1.2 |
| Every long-lived secret is wiped when dropped | `zeroize` on the keypair, the identity, the resumption ticket and the session's copy of its resumption key | `secret_wiping.rs`, which reads a dropped value's bytes; D67 and D75 |
| No binding can leak a private key | The C ABI exports no accessor, and `fectp-core`'s keypair has none | D68, D69; the bindings' tests assert the absence. The **Rust** front end does have `Identity::secret`, documented as the one way the key leaves memory that gets wiped — this row is about bindings, not about Rust callers |
| The C ABI does not corrupt memory | `catch_unwind` at every entry, caller-owned buffers, consuming handles nulled | D68; Miri in CI (D72) |

---

## Not claimed

These are not weaknesses to be fixed. They are outside what the protocol is
for, and something else has to provide them if they are needed.

- **Anonymity or unlinkability.** A session identifier is in the clear on every
  frame, by design, so one socket can serve many peers. Frames of one session
  are trivially linkable.
- **Protection against a compromised endpoint.** If an attacker runs code on
  either peer, everything above is void.
- **Key distribution.** How an initiator learns the responder's public key is
  out of scope (SPEC §10), and so is distributing the first ticket.
- **Post-quantum security.** X25519 is not.
- **Denial of service by volume.** Nothing here stops a flood large enough to
  fill the link. The bounds above stop a *cheap* attacker from costing the
  responder more than it costs them; they do not stop a large one.
- **Ordering.** Deliberately absent (SPEC §5.5, D12). An attacker reordering
  frames is doing something the protocol permits a network to do.
- **Close semantics.** The `Close` frame type is assigned and its state machine
  is not defined (SPEC §10), so an attacker cannot be prevented from
  withholding one.

---

## Known weaknesses

True, and bad, and stated here so that nobody has to derive them.

### 0-RTT data is replayable and has no forward secrecy

Data carried with a handshake's first flight is encrypted before any ephemeral
of the *responder's* has been mixed in, so it is protected by the responder's
static key alone. Whoever later obtains that key and has a recorded frame can
read it, and anyone who captured the frame can send it again.

D73's model demonstrates this for the *resumed* handshake, where the key in
question is the resumption key: `confidentiality? zero_rtt` fails the moment it
leaks, in four steps. The full handshake's 0-RTT has the same shape with the
responder's static key in that role, and is not separately modelled. SPEC
§4.4.1 requires an implementation to treat it as replayable.
**Send only what is safe to replay, or nothing.**

### A handshake reply's sequence and flag bytes are not authenticated

Message 1's header is the Noise prologue, so all fourteen bytes are bound into
the transcript. The reply's is not, and cannot be: there is nothing the
responder could bind that the initiator does not already hold. An initiator
compares the frame type and the session identifier and leaves the rest, so an
attacker on the path can change the eight sequence bytes, and the four known
flag bits of a ninth, and the handshake still completes. An unknown flag bit is
refused, by `Header::decode`, for every frame type.

That costs nothing today — the only code that reads `flags` or `sequence` is
`Session::open`, where the whole header is the AEAD's associated data — and
`handshake_mutation.rs::a_reply_does_not_authenticate_its_sequence_or_its_known_flag_bits`
pins the exact set, so a change that gave those bytes a meaning during a
handshake fails there first.

### In pre-shared-key mode, the opening frame has no replay protection

Resumption answers replay with a rule rather than a construction — a ticket is
spent when redeemed — and §1.2.1 exempts the configured pre-shared key from it,
because a responder that spent the key would refuse its peer's next connection.
Nothing replaces it.

Measured ([`resumption_replay.rs`](../crates/fectp/tests/resumption_replay.rs)):
a captured opening frame replayed from an address the responder has not already
filed a session against is accepted, its 0-RTT payload reaches the application
again, and each copy takes a session slot — so a party that does **not** hold
the key can make a responder allocate them, which it otherwise cannot do at all.

It stops there: eviction prefers sessions that have never sent an authenticated
frame, and a session conjured from a replay never sends one, so the replays
displace each other rather than working peers. SPEC §1.2.1 states both halves
normatively, and §4.9 says why the handshake cannot answer this itself.

### A first contact's address is never validated, and a reply goes there

Path validation (SPEC §5.8) applies to a session that *moves*. It does not
apply to where a session starts. `accept_full` reads message 1, sends the reply
to the source address on it, files the session against that address, and hands
any 0-RTT payload to the application — none of which waits for the address to
prove it can receive. A UDP source address is whatever the sender wrote, so
that address can be a third party's.

[D57](DECISIONS.md) settled the neighbouring case with the words "one datagram
in must not buy a stream out", and stopped keep-alives going to an address
nothing authenticated had been heard from. `Endpoint::send` was not part of
that decision and has no such check.

What the *protocol* emits there is small and bounded: one 70-byte handshake
reply, resent at most three times (D33). What the *application* emits is not
bounded by anything here. Measured
([`unproved_address.rs`](../crates/fectp/tests/unproved_address.rs) and a
throwaway probe beside it): a single unreliable `send` is capped at one frame
by what the peer advertised, so it cannot amplify past one datagram — but a
`send_reliable` of 64 KiB to an address that never acknowledges turned **136
bytes in into 28,870 bytes out over twelve seconds**, a factor of 212, because
retransmission keeps trying.

So the exposure is the application's shape rather than the protocol's:
answering 0-RTT data with a large reliable message makes this endpoint a
reflector. **Answer 0-RTT with a small unreliable reply, or wait for the peer
to say something authenticated first** — `Event::Message` from that peer is
that proof, and it is the same signal the eviction order already relies on.

The counterweight, measured in the same file: a session that has authenticated
nothing is the first thing evicted, so this does not also buy table space.

### A stranger can flush the responder's resumption tickets

Reaching the handshake in public-key mode needs the responder's public key and
nothing else — that is the point of it being public — and every completed
handshake issues the ticket for the next one. The store that holds them is
bounded at 256, so 256 handshakes from a party with no standing relationship
push every legitimate peer's ticket out.

Measured ([`ticket_flush.rs`](../crates/fectp/tests/ticket_flush.rs)), and the
arithmetic rather than the eviction order is what settles it: the store holds at
most 256 and the stranger inserts 256 *after* the honest one, so whatever order
it evicts in, the honest ticket cannot still be there.

Nothing breaks. SPEC §4.6 allows a responder to forget tickets at any time and
an initiator whose ticket is refused falls back to a full handshake, which it
must be able to do regardless. What it costs is exactly what resumption exists
to save: four Diffie-Hellman operations instead of one, which on a Cortex-M4 is
the largest latency this protocol has. It is a cheap, repeatable performance
denial against the devices the protocol is written for, bounded by the
handshake rate limit and by nothing else.

`set_ticket_lifetime` and the `MAX_TICKETS` bound are the knobs; neither
removes the attack, and a larger store makes it more expensive rather than
impossible.

### Nothing here is constant-time, and nothing checks that it is

The constant-time properties this protocol needs come entirely from its
dependencies — `chacha20poly1305` for tag comparison, `x25519-dalek` for scalar
multiplication. **No code in this repository does a constant-time comparison,
and no test measures timing.** `fectp-core` declared `subtle` as a dependency
and never called it, which read as a claim to do such work; that declaration
has been removed rather than left to mislead.

An attacker who can measure this implementation's timing precisely is outside
what is defended against. Whether that matters depends on where it runs, and
this document cannot answer that for you.

### Traffic analysis, and the compression side channel

Frame lengths follow payload lengths unless padding is switched on, and it is
off by default — padding to 64-byte blocks costs bandwidth that the devices
this protocol targets often cannot spare, so it is the caller's decision.
Timing between frames is not shaped at all. Anyone watching the wire learns who
talks to whom, when, how often, and approximately how much.

Worse than that, and not mentioned above because it is a different mechanism:
**with coding on, a frame's length follows the payload's *content*, not its
length.** The structural transforms run by default at 32 bytes and up, and
Zstandard at 1024 and up with the `compress` feature. Compressing attacker-
influenced data alongside secret data is the shape of CRIME and BREACH, and
SPEC §6.5 and D6 both treat this as a security property rather than a
performance one: each payload is coded independently, so a compression ratio
says something about one message and not about the relationship between two.
That bounds it; it does not remove it. A caller mixing its own secrets with
attacker-chosen bytes in one payload is outside what this protects.

### The C ABI is the one place without `#![forbid(unsafe_code)]`

`fectp-core` and `fectp` carry it. `crates/ffi` cannot: raw pointers,
caller-chosen lengths and lifetimes the compiler cannot see are what a C ABI
is. It is 673 lines with 34 `unsafe` blocks and 16 `unsafe fn` items, every
entry point wrapped in
`catch_unwind`, and CI runs its tests under Miri (D72) — which sees undefined
behaviour the tests cannot, because a fault that changes no answer passes all
of them.

A hand-written binding in another language has none of that. That is the
argument for going through this crate rather than around it.

### Abandonment reporting is not observable on the wire

SPEC §5.5 notes that a conforming receiver cannot tell whether a sender gave up
on a reliable message. This project got that logic wrong twice (D63), and no
test vector or interoperability test can catch that class of fault, because the
traffic is byte-identical either way. It is not an attack — it is a place where
the usual defences do not reach, and a caller who relies on delivery reports is
relying on something only the sender's own tests check.

---

## Assumptions

If any of these does not hold, the claims above do not either.

- **The random number generator is sound.** Every ephemeral and every identity
  comes from the operating system's. A predictable one loses everything.
- **The monotonic clock tracks elapsed time.** Nothing here reads a wall
  clock: ticket lifetimes and every timer use `Instant`, which cannot step
  backwards. What it can do is stop advancing while a device is suspended, so
  a ticket given an hour may outlive an hour of real time by however long the
  host slept.
- **The dependencies are correct.** The whole cryptographic argument rests on
  five crates this project did not write — x25519-dalek, chacha20poly1305,
  blake2, zeroize, rand_core. `audit.yml` watches the advisory
  database weekly, which catches what RustSec knows about and nothing else — it
  found `RUSTSEC-2026-0285` in a benchmark dependency the day after it was
  published.
- **Peers store key material as key material.** A resumption ticket written to
  flash unprotected is a static key written to flash unprotected.

---

## Reporting something

Open an issue at <https://github.com/YounghyeonPark/fectp/issues>. There is no
embargo process and no security contact separate from the tracker, which is
itself worth knowing: this is a `0.x` project with no audit behind it, and
treating it as though it had a disclosure pipeline would overstate what is here.
