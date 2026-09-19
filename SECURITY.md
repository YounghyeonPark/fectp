# Security

## What this is, before anything else

**FECTP has not been security-audited, and it is not going to be.** No
cryptographer has reviewed the handshake, the key schedule or the replay
window. That is a decision, recorded with its counter-argument in
[D74](docs/DECISIONS.md), not a gap waiting to be filled.

[THREAT-MODEL.md](docs/THREAT-MODEL.md) is the honest version of what that
leaves: who the attacker is assumed to be, what is claimed against them with
the test or model behind each claim, what is deliberately **not** claimed, and
the weaknesses that are known and measured. Read its *Not claimed* and *Known
weaknesses* sections before deciding to depend on this.

Use it where being wrong is survivable.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

`0.1.0` is the first release. A `0.x` crate may break its Rust API on any minor
version; the *wire* version is 1 and moves separately and rarely, and
[RELEASING.md](docs/RELEASING.md) says what each promises.

## Reporting a vulnerability

Open an issue: <https://github.com/YounghyeonPark/fectp/issues>

**There is no embargo process and no private channel**, and that is worth
knowing rather than discovering. A disclosure pipeline implies a response
capability — a triage rota, a patch-and-release path, downstream notification —
and this is a `0.x` project with no audit behind it. Setting one up would
overstate what is here.

So: if you find something, please just say so in the open. If you would rather
not publish a working exploit, a description of the class and the file is
enough to act on.

## What is already known

These are known. The threat model has each one with whatever evidence exists,
which varies — some are pinned by tests, some are stated because there is
nothing to measure.

- 0-RTT data is replayable and has no forward secrecy (SPEC §4.4.1).
- Pre-shared-key mode does not answer replay of an opening frame (SPEC §1.2.1).
- A first contact's address is not validated, so an application that answers
  0-RTT with a large reliable message becomes a reflector.
- A stranger can flush the resumption ticket store.
- Nothing here is constant-time, and no test measures timing.
- Traffic analysis is not defended against at all: who talks to whom, when and
  roughly how much is visible, and frame timing is not shaped. On top of that,
  frame length follows payload *content* whenever compression or a transform
  runs, which is by default from 32 bytes up — a compression side channel.
- A handshake reply's sequence bytes and known flag bits are not authenticated
  (nothing reads them; the set is pinned by a test).

## What is checked mechanically

Not a substitute for review, and listed so that the shape of the gap is clear
rather than the size of the effort:

- `#![forbid(unsafe_code)]` on `fectp-core` and `fectp`; `crates/ffi` cannot
  carry it and runs under Miri in CI instead.
- The handshake is cross-validated against [`snow`](https://docs.rs/snow) in
  both roles.
- The resumption handshake has a symbolic model in
  [`docs/formal/`](docs/formal/).
- Generated and mutation-based tests over every parser an unauthenticated
  stranger reaches, plus libFuzzer targets run weekly.
- `cargo audit` against the RustSec database, weekly and on every dependency
  change.
