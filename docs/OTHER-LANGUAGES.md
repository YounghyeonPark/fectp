# Using FECTP from another language

Written because the question keeps coming and the answer is not "write a
binding". One part of it is decided by physics, one by what this project claims
about itself, and one by where the safety guarantees stop.

---

## What is possible

| | How | |
|---|---|---|
| **C, C++** | A `cdylib` and a C header. Everything below is built on this. | **built** |
| **Python** | `ctypes` over the C ABI, in `bindings/python`. | **built** |
| **Java** | The FFM API (JDK 22+), or JNI. | possible |
| **Node.js** | `koffi` over the C ABI, in `bindings/typescript`. | **built** |
| **Deno, Bun** | The same binding; `Deno.dlopen` or `bun:ffi` in place of `koffi`. | possible |
| **TypeScript** | Not a separate question — see below. | **built**, on Node |
| **Browser JavaScript** | — | **not possible** |

**A browser cannot speak FECTP.** There is no API for sending a UDP datagram
from a page. WebRTC data channels are SCTP over DTLS and WebTransport is
HTTP/3 — both are different protocols, not transports this could sit on.
Compiling the core to WebAssembly changes nothing, because the missing piece is
the socket rather than the code. Anything browser-facing needs a gateway that
speaks FECTP on one side and something a browser has on the other.

**TypeScript is not the constraint; the runtime under it is.** The types are
compiled away, and what decides the question is whether the host can open a UDP
socket. Node has had `dgram` since the beginning, Deno has
`Deno.listenDatagram`, and Bun has `Bun.udpSocket`. A browser has none of them,
so the same TypeScript is fine in one place and impossible in another — the
line is drawn by the host, not the language.

The sans-IO shape below is what makes this bind well: bytes in, bytes out
leaves the socket in TypeScript, using `dgram` directly, so nothing in the
binding is `async` and there is no event loop to block. That is the property
worth protecting, and it is the reason the binding is small.

`napi-rs` was the obvious route — it emits a `.d.ts` from the Rust signatures,
so the types cannot drift from the implementation, and one Node-API addon may
serve all three runtimes because Deno and Bun implement it too. What was built
instead is the C ABI again, through `koffi`: it reuses the boundary the Python
binding already exercises rather than adding a second one to audit, and it
needs no compiler at the far end. The cost is that the `.d.ts` is hand-written
and the signatures are declared by hand, which is a real cost — a wrong one is
wrong silently. A published package would be a good reason to revisit it; there
is nothing published until the audit (D65).

---

## What exists

`crates/ffi` is the C ABI; `bindings/python` and `bindings/typescript` sit on
it. It exports
fifteen functions over `fectp-core`: an identity, the two sides of a handshake,
and `seal`/`open` on the session that comes out. `include/fectp.h` is the
header, and a test holds the two to each other — a function on one side and not
the other fails the build rather than a caller's link step.

The Python side is `ctypes` and nothing else — the standard library against
the shared object cargo builds — so there is no package to install and no
compiler needed at the far end. `cffi` and PyO3 would both be better company
for a published wheel; neither is worth a dependency for a binding that is not
published, and nothing is published until the audit (D65).

The TypeScript side is `koffi` and nothing else, and Node runs the `.ts` files
directly, so there is no build step either. Only `load()` is runtime-specific:
Deno and Bun have FFI of their own and would replace that one function without
touching the rest.

Those two are the only tests in the repository that cross the boundary from
outside Rust. `crates/ffi/tests/c_abi.rs` calls the same functions through the
compiler that built them, which cannot catch a wrong calling convention, a
mistaken pointer width, or a signature a foreign caller has to guess — the
faults a binding meets first. Two callers rather than one is the point: the
`void **` out-parameters worked from `ctypes` and silently returned nothing
from `koffi` until their direction was declared, which is exactly the class of
fault a single foreign caller does not find. CI runs both on every push.

What it does **not** do is everything `fectp` does above the session: no
retransmission, no congestion control, no fragmentation, no keep-alive. That is
the trade this page argues for and it is worth restating now that the code
exists — see "what it costs" below, and D68 for what a caller has to build to
get those back.

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

Unavoidable. What narrows it is that `crates/ffi` is the only place in this
workspace where that happens, it is 673 lines with 34 `unsafe` blocks, and CI runs its tests under Miri
— which sees undefined behaviour the tests cannot, because a fault that changes
no answer passes every one of them (D72). A hand-written binding in another
language has none of that, which is the argument for going through this crate
rather than around it.

### Panics become process aborts

Inside Rust an invariant violation is a panic: catchable, or at worst one
thread's problem. Unwinding out of an `extern "C"` function **aborts the
process** (Rust 1.81 and later; the minimum here is 1.85).

`fectp` has eight `expect` sites outside its tests, and `fectp-core` one. All
are invariant assertions rather than input-driven, but a binding turns any
future regression at one of them from "a Rust error" into "the interpreter
died". Wrapping every entry point in `catch_unwind` and converting to an error
code is mandatory, not tidiness — which is what `crates/ffi` does, at every
entry including the ones that cannot fail.

### A key held in hardware does not cross either

`fectp-core` takes a `StaticKey` so that a secure element can perform the
Diffie-Hellman without releasing the key (D76). **The C ABI does not expose
that**, and neither do the bindings on it: a trait crosses as a struct of
function pointers the caller fills in, with a lifetime the C side has to
honour and a failure path in both directions. `fectp_identity_from_secret` is
what exists, and it takes the bytes.

Not a gap so much as a different problem. The case D76 closes is a constrained
device linking `fectp-core` directly, in Rust, where there is no boundary to
cross; a C caller with an element is a second design, not the same one wearing
a header.

### Key material escapes `zeroize`

`fectp::Identity::secret()` returns the raw 32 bytes. In Rust they are wiped
when dropped. As a Python `bytes`, a Java `byte[]` or a JavaScript `Buffer`
they are immortal, copied freely by the runtime, and may reach swap. Nothing
the Rust side does about it survives the crossing.

This one is answered rather than mitigated: `crates/ffi` binds `fectp-core`,
whose `Keypair` has no such accessor, so there is no path from the boundary to
those bytes and nothing for a binding to expose. Both bindings assert the
absence rather than trusting it (D68, D69).

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
   further, not thinner. **Decided against** (D74), which is not the same as
   done: what stands in its place is a disclosure where it is read, a threat
   model, a symbolic model of the resumption handshake, and Miri over the C ABI.
2. **Versioning and a release.** **Done**: `fectp` and `fectp-core` are on
   crates.io at `0.1.0`, so a binding now has a version to pin to.
3. **Test vectors** — frames built from fixed keys, with expected bytes — so an
   independent implementer can check their work without reading this code.
   **Built**: [test-vectors.txt](test-vectors.txt), SPEC §9.2.
4. **Then bindings**, sans-IO, over the C ABI, with `catch_unwind` at every
   entry point and the secret never crossing. **Built**, out of order: C ABI,
   Python and TypeScript exist and the two above them do not. Worth admitting
   rather than quietly renumbering — the bindings were the interesting problem
   and the ordering was the honest one.
