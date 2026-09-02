# Using FECTP from another language

Written because the question keeps coming and the answer is not "write a
binding". One part of it is decided by physics, one by what this project claims
about itself, and one by where the safety guarantees stop.

---

## What is possible

| | How | |
|---|---|---|
| **C, C++** | A `cdylib` and a C header. Everything below is built on this. | possible |
| **Python** | PyO3 as a native extension, or `cffi` over the C ABI. | possible |
| **Java** | The FFM API (JDK 22+), or JNI. | possible |
| **Node.js** | N-API, or `napi-rs`. | possible |
| **Browser JavaScript** | — | **not possible** |

**A browser cannot speak FECTP.** There is no API for sending a UDP datagram
from a page. WebRTC data channels are SCTP over DTLS and WebTransport is
HTTP/3 — both are different protocols, not transports this could sit on.
Compiling the core to WebAssembly changes nothing, because the missing piece is
the socket rather than the code. Anything browser-facing needs a gateway that
speaks FECTP on one side and something a browser has on the other.

---

## Bind the core, not the convenience layer

The obvious binding wraps `fectp` — `Connection`, `Endpoint`, sockets, threads.
It is the wrong half.

`fectp-core` is defined over a `Transport` trait and never touches a socket:
`Session::seal` and `Session::open` take buffers. `crates/footprint` already
uses it that way, running a complete handshake and a sealed frame with no I/O
anywhere. A binding shaped the same way takes bytes and returns bytes.

What that avoids:

- **No blocking calls**, so no releasing the GIL around a five-second handshake
  and no blocking Node's event loop.
- **No threads owned by the library**, so the host does its own I/O in its own
  idiom — `asyncio`, NIO, `libuv`.
- **No owned memory crossing the boundary**: the caller supplies the buffers,
  so there is nothing to free from the wrong side.
- **A much smaller `unsafe` surface**, which matters for the reason below.

What it costs: retransmission, congestion control and fragmentation are things
`fectp` drives. A sans-IO binding has to drive them, or do without.

---

## What a wrapper breaks

### The safety claim stops at the boundary

`fectp-core` carries `#![forbid(unsafe_code)]`, and that is the strongest thing
this project says about itself. **Every FFI layer needs `unsafe`** — raw
pointers, lengths from the caller, lifetimes the compiler cannot see. A binding
reintroduces exactly what the core excludes, and the memory-safety argument
covers the protocol but not the doorway.

Unavoidable. Worth stating rather than discovering.

### Panics become process aborts

Inside Rust an invariant violation is a panic: catchable, or at worst one
thread's problem. Unwinding out of an `extern "C"` function **aborts the
process** (Rust 1.81 and later; the minimum here is 1.85).

`fectp` has twelve `expect` sites. All are invariant assertions rather than
input-driven, but a binding turns any future regression at one of them from "a
Rust error" into "the interpreter died". Wrapping every entry point in
`catch_unwind` and converting to an error code is mandatory, not tidiness.

### Key material escapes `zeroize`

`Identity::secret()` returns the raw 32 bytes. In Rust they are wiped when
dropped. As a Python `bytes`, a Java `byte[]` or a JavaScript `Buffer` they are
immortal, copied by the garbage collector, and may reach swap. Nothing the Rust
side does about it survives the crossing.

A binding should never expose the secret. Load and store it behind an opaque
handle, and let the host name a file rather than hold the bytes.

### Nothing that keeps this honest extends

`doc_snippets.rs`, `api_reference.rs`, `spec_conformance.rs`, and the models in
`reliability_model.rs`, `replay_model.rs`, `prefix_model.rs` and
`congestion_model.rs` are all Rust. A binding's API has no drift protection at
all, and this repository's own history is a long argument for why that matters.

### Owned memory crosses, in the convenience layer

`Event::Message { data: Vec<u8> }` is Rust-allocated. Across FFI it must be
copied out or freed through a function the library provides — the classic
double-free and leak surface. A sans-IO binding does not have this problem,
which is half the reason to prefer one.

---

## A wrapper is not an implementation

A wrapper makes other languages **consumers of this implementation**. It tests
the specification not at all, and every language inherits this codebase's bugs —
of which this repository has found several, including one that lost messages
outright while 179 tests passed.

`project_description.md` calls FECTP "an open, royalty-free standard" aiming at
"industry-wide standardization". What serves that is a **second independent
implementation**, written from [SPEC.md](SPEC.md). `spec_independent.rs` is a
shadow of one, and writing even that much found the two disagreeing about
identifiers at the wrap — a real bug and a silent specification.

A standard whose only usable form is "link this library" is a library with a
specification-shaped README.

---

## Before any of it

In order, because each one makes the next worth doing:

1. **An audit.** Binding an unaudited core into five languages spreads it
   further, not thinner.
2. **Versioning and a release.** Not on crates.io, no version policy. A binding
   pinned to an unversioned dependency has nothing to pin to.
3. **Test vectors** — frames built from fixed keys, with expected bytes — so an
   independent implementer can check their work without reading this code.
   Cheap, and it is what makes SPEC.md usable by somebody else.
4. **Then bindings**, sans-IO, over the C ABI, with `catch_unwind` at every
   entry point and the secret never crossing.
