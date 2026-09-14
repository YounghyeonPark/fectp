# FECTP from TypeScript

The sans-IO session layer, over the C ABI in [`crates/ffi`](../../crates/ffi).
Payloads in, frames out, and back again — **you** own the socket, the thread
and the event loop. Nothing here is `async`, because nothing here blocks.

**Not audited.** Nothing in this project has been reviewed by someone who
breaks protocols for a living.

## Running it

```bash
cargo build -p fectp-ffi --release
cd bindings/typescript && npm ci && npm test
```

Node 22.6 or newer runs the `.ts` files directly, so there is no build step and
nothing compiled to go stale. The shared library is found under `target/`, or
named through `FECTP_LIBRARY`.

## What it looks like

```typescript
import { Identity, Initiator, Responder } from "./fectp.ts";

const server = Identity.generate();
const client = Identity.generate();

const initiator = new Initiator(client, server.publicKey, 1);
const responder = new Responder(server);

responder.readInit(initiator.writeInit(bytes));   // -> what the client sent
const { session: s, frame: reply } = responder.writeResponse();
const { session: c } = initiator.readResponse(reply);

s.open(c.seal(payload));                          // -> payload
```

`Initiator.readResponse` and `Responder.writeResponse` **consume** the handle
they are called on, success or failure — a handshake cannot be retried from a
half-read state. Using one again throws rather than corrupting memory, and that
check is load-bearing: with the give-up in `Handle.take` removed, the second
call kills the process (exit 127) instead of throwing.

## Which runtime

TypeScript does not decide where this runs; the runtime under it does. The one
thing that differs is loading the library, and it is isolated in `load()`:

| Runtime | FFI                | Needs a dependency |
| ------- | ------------------ | ------------------ |
| Node    | `koffi`            | yes — the only one |
| Deno    | `Deno.dlopen`      | no                 |
| Bun     | `bun:ffi`          | no                 |
| Browser | none               | — no socket either |

Node is what is written and tested here because Node is what this repository
has. A browser is ruled out by the missing UDP socket rather than by the code,
so WebAssembly would not change it.

## The secret key

**There is no way to read a private key out of an `Identity`,** and the C ABI
exports no such call for this to wrap.

That is the shape of the binding rather than an oversight. Bytes handed to a
JavaScript runtime cannot be wiped: a moving collector may relocate a `Buffer`
and does not clear what it copied from, and the memory may reach swap. Rust
wipes its own copy when the identity is dropped; nothing it does survives the
crossing.

`Identity.fromSecret` restores a key stored elsewhere, and FECTP wipes the copy
it makes. What you pass in stays yours, and you cannot wipe it — which is the
argument for keeping the handle and never having the bytes here at all.

## What this does not do

The session layer only. **Retransmission, congestion control, fragmentation and
keep-alive are not here** — they live in the `fectp` crate, above the layer this
binds. A caller who needs reliable delivery builds it or does without.

That trade is why the binding is this shape at all
([OTHER-LANGUAGES.md](../../docs/OTHER-LANGUAGES.md)): binding the layer above
would mean blocking calls in an event loop that must not block, threads the
library owns, and memory crossing the boundary in both directions.

One warning worth repeating from D63: the abandonment reporting such a caller
would rebuild is the logic this project got wrong twice, and §5.5 of the
specification notes that a conforming receiver cannot observe it — so wire-level
test vectors cannot catch that class of mistake either.
