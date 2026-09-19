# Changelog

`fectp` and `fectp-core` carry the same version and move together. What a
version number promises — and the difference between the crate version and the
wire version, which is 1 and has not moved — is in
[RELEASING.md](docs/RELEASING.md).

The reasoning behind anything here is in [DECISIONS.md](docs/DECISIONS.md),
which is the long form: this file says what changed, that one says why.

## Unreleased

**A long-term key can live in a secure element.** `fectp-core` takes a
`StaticKey` — `public()` and a fallible `dh()`, which is everything the protocol
does with a static private key — so an element or HSM that never releases the
key can be used. `Keypair` implements it and so does `&T`, because a device is
owned by the application and lent to a handshake rather than given away. New
`Error::KeyUnavailable` for a device that is busy, locked or absent, which an
in-memory key never is. Costs 50 bytes of flash. See D76.

`Endpoint` and `Connection` still require a `Keypair`; the case this closes is
the constrained one, which uses the core directly.

**Breaking:** `Initiator` and `Responder` are generic over the key type with a
default, so `Initiator` still means `Initiator<Keypair>` — but
`Initiator::OVERHEAD` no longer infers. Use `INITIATOR_OVERHEAD` and
`RESPONDER_OVERHEAD`, which are free constants with the same values, or name
the parameter. The wire format is unchanged: the test vectors pass untouched
and the handshake still agrees with `snow` in both roles.

## 0.1.0 — 2026-09-16

First published version. Wire version 1.

**What it is.** A UDP transport with a `Noise_IK_25519_ChaChaPoly_BLAKE2s`
handshake, an `NNpsk0` resumption that costs one Diffie-Hellman instead of
four, reliable and unreliable delivery, fragmentation, a replay window, address
migration behind a path challenge, and typed payload transforms. `fectp-core`
is `no_std` and allocation-free. Linked for `thumbv7em-none-eabihf` the whole
protocol costs **23,896 bytes of flash**; session state is 358 bytes, or 1,414
with the reliable-delivery queue, measured as `size_of` on the host by
`cargo run -p fectp-core --example sizes` rather than on the target — a 32-bit
target differs only trivially, and the example says so.

**Not audited, and no audit is coming.** That is a decision (D74), not a
backlog item. [THREAT-MODEL.md](docs/THREAT-MODEL.md) is what stands in its
place: what is claimed, with the test or model behind each claim, and — the
part worth reading first — what is not claimed and what is known to be weak.

**Interoperating from another language.** The C ABI is `crates/ffi`, which is
not published; build it from the repository. Python and TypeScript bindings sit
on it. [test-vectors.txt](docs/test-vectors.txt) is fixed inputs and expected
bytes for an independent implementation, and [SPEC.md](docs/SPEC.md) is written
to be implemented from rather than read alongside the code.

**Known weaknesses at this version.** Each is in
[THREAT-MODEL.md](docs/THREAT-MODEL.md) with whatever evidence there is, and
that differs by item: some are pinned by committed tests, one rests on a
throwaway probe, and two are stated because there is nothing to measure. Each
bullet says which.

- 0-RTT data is replayable and has no forward secrecy.
- In pre-shared-key mode nothing answers replay of an opening frame, because
  the configured key is not consumed the way a resumption ticket is.
- A first contact's address is never validated, so an application that answers
  0-RTT with a large reliable message reflects. A throwaway probe turned 136
  bytes in into 28,870 out over twelve seconds; `unproved_address.rs` pins that
  the reply goes out at all and that an unreliable send is capped at one frame,
  but nothing in the suite reproduces the ratio.
- A stranger can flush the resumption ticket store, costing every peer a full
  handshake on its next reconnect.
- Nothing in this repository is constant-time and no test measures timing;
  what constant-time behaviour exists comes from `chacha20poly1305` and
  `x25519-dalek`.
- Frame length follows payload *content* whenever coding runs, which it does by
  default from 32 bytes up — Zstandard from 1024 with the `compress` feature.
  That is a compression side channel and nothing measures it. Padding is
  available and off by default.
- A handshake reply's eight sequence bytes and four known flag bits are neither
  compared nor authenticated. Nothing reads them today, and
  `handshake_mutation.rs` pins the exact set so that a change which gave them a
  meaning fails there first.
