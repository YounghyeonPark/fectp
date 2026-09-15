# Formal models

Symbolic models of the parts of FECTP that a published analysis does not
already cover, with the tool that checks them and what came out.

**This is not an audit**, and it is not a substitute for one. It is one class
of question — what an attacker who controls the network can compute — asked of
one handshake, by a tool with known limits, in a model this project wrote about
its own protocol. An auditor's value is partly that none of those things are
true of them.

## Why this handshake and not the others

The full handshake is `Noise_IK_25519_ChaChaPoly_BLAKE2s`, a standard Noise
pattern. Every fundamental Noise pattern has been analysed symbolically in the
literature, `IK` among them, and [`interop.rs`](../../crates/fectp-core/tests/interop.rs)
already checks that this implementation agrees with
[`snow`](https://docs.rs/snow) in both roles. Modelling `IK` again would be
re-deriving somebody else's result about somebody else's protocol.

Resumption is `Noise_NNpsk0`, also standard. What is **not** standard is how
FECTP arrives at it:

- the pre-shared key is not configured by an operator, it is the resumption key
  derived from the chaining key of an earlier `IK` handshake,
- it is named on the wire by an 8-byte ticket identifier that is a hash of the
  key itself,
- it is replaced by a fresh one, derived from the resumed handshake's own
  chaining key, every time a session resumes,
- and the same pattern doubles as the pre-shared-key mode (SPEC §1.2.1), where
  the key is configured and long-lived instead.

That composition is this project's own, so it is the part worth modelling.

## Running it

```bash
verifpal verify docs/formal/resumption.vp
```

[Verifpal](https://verifpal.com) 1.4.10, a single binary with no toolchain
behind it. It is a lighter tool than ProVerif or Tamarin and says less: it
searches a bounded number of sessions rather than proving a property for
unboundedly many, and its attacker model is its own rather than the applied pi
calculus. Where it is strong is that the model reads like the protocol, which
matters more than it sounds — a model nobody can check against the code is a
model nobody should believe. Every derivation in
[`resumption.vp`](resumption.vp) names the line of
[`resume.rs`](../../crates/fectp-core/src/noise/resume.rs) or
[`symmetric.rs`](../../crates/fectp-core/src/noise/symmetric.rs) it came from.

This does not run in CI. It is a 10 MB third-party binary that is not on the
runners, and the model changes only when the handshake does.

## What came out

Seven queries, five pass, two fail. Both failures are interesting and neither
is a surprise to the specification.

| Query | Result | |
|---|---|---|
| `confidentiality? handshake_reply` | **pass** | |
| `confidentiality? transport_msg` | **pass** | Forward secrecy: the resumption key leaks in phase 1 and the recorded session stays shut |
| `confidentiality? next_rk_c` | **pass** | Stealing one resumption key does not give the next one |
| `authentication? Server -> Client: c1` | **pass** | |
| `authentication? Client -> Server: t0` | **pass** | |
| `confidentiality? zero_rtt` | **fail** | Expected. 0-RTT data has no forward secrecy, by construction |
| `authentication? Client -> Server: c0` | **fail** | Message 1 has no replay protection of its own |

### The forward secrecy claim holds

`resume.rs` claims that an attacker who later steals the stored resumption key
cannot decrypt a recorded resumed session, because both peers contribute an
ephemeral and the `ee` operation mixes them. The model leaks the resumption key
in phase 1 — after the exchange, so it cannot be used to interfere with it —
and both the handshake reply and the transport message stay confidential. The
next resumption key stays confidential too, which is what stops one theft from
unrolling the whole chain.

That is the headline property of the design, and it is the one the model
confirms.

### The 0-RTT payload does not, and is not meant to

`zero_rtt` falls the moment the resumption key leaks, by a four-step trace: the
attacker reconstructs the chaining key from the leaked key and the ephemeral
public key it watched go past, and opens the frame. That is correct behaviour.
The payload of message 1 is encrypted before any ephemeral of the *responder's*
has been mixed in, so it is protected by the pre-shared key alone;
`write_message_1` says so and SPEC §4.8 says so. The query is here so that the
caveat is checked rather than remembered.

### Message 1 has no replay protection of its own — and that led somewhere

Verifpal reports non-injective agreement: the responder contributes nothing to
message 1 before accepting it, so the same frame is accepted twice. It is not a
forgery — the attacker cannot author a frame — it is a replay.

The specification already answers this, in SPEC §4.6: a resumption ticket MUST
be spent when redeemed. So the model did not find a gap; it derived
independently *why* that rule is load-bearing, which is worth having, because a
MUST whose reason is only in a comment is a MUST somebody eventually relaxes.

But SPEC §1.2.1 exempts the configured pre-shared key from that rule, and it
has to: a responder that spent the key would refuse the peer's next connection.
So in pre-shared-key mode the rule that answers the replay is not in force, and
nothing replaces it. That is not stated anywhere, and chasing it produced
[`resumption_replay.rs`](../../crates/fectp/tests/resumption_replay.rs) and
[D73](../DECISIONS.md).

Measured, in pre-shared-key mode:

- a captured opening frame replayed **from another source address** is accepted,
  and its 0-RTT payload is delivered to the application a second time;
- each replay takes a session slot, so an attacker that does **not** hold the
  key can make the responder allocate sessions, which it otherwise cannot do at
  all;
- but it cannot evict a peer that has spoken. `make_room` drops the oldest peer
  that has never sent an authenticated frame, and a session conjured from a
  replay never sends one, so the replays evict each other.

The source address matters and finding that out is why these are tests and not
an argument. Replaying from the *same* address gets nowhere: `repeat_handshake`
finds the route the first handshake left and resends the cached response
instead of building a second session. The first version of the test replayed
from the same address, concluded the frame was refused, and was measuring the
wrong thing.

## What the model cannot say

- **Bounded search.** Verifpal exhausted its search at two sessions. A property
  that holds there may fail at three; ProVerif and Tamarin are the tools that
  answer that, and neither is run here.
- **Nothing about state.** The single-use ticket rule is a property of a table
  in memory, not of the cryptography. No symbolic model of the handshake can
  express it, which is precisely why the replay query fails against a protocol
  that is not in fact replayable in its default mode.
- **Nothing about the implementation.** A model checks a design. That the code
  computes what the model says it computes is the job of `interop.rs`,
  `spec_conformance.rs`, the test vectors, and reading.
- **Nothing about timing, memory, or side channels.** Symbolic analysis assumes
  perfect cryptography and leaks nothing but what it is told to send.
- **`IK` is not modelled here**, so the resumption model begins with a shared
  resumption key rather than deriving one. The claim that an `IK` handshake
  delivers such a key to both peers and nobody else is assumed, not checked.
