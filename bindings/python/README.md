# FECTP from Python

The sans-IO session layer, over the C ABI in [`crates/ffi`](../../crates/ffi).
Payloads in, frames out, and back again — **you** own the socket, the thread
and the event loop.

**Not audited.** Nothing in this project has been reviewed by someone who
breaks protocols for a living.

## Running it

```bash
cargo build -p fectp-ffi --release
python3 bindings/python/test_fectp.py
```

`ctypes`, so there is nothing to install: the standard library and the shared
library cargo just built. It is found under `target/`, or named through
`FECTP_LIBRARY`.

## What it looks like

```python
import fectp

server = fectp.Identity.generate()
client = fectp.Identity.generate()

initiator = fectp.Initiator(client, server.public, session_id=1)
responder = fectp.Responder(server)

opening = initiator.write_init(b"data sent with the handshake")
responder.read_init(opening)                      # -> b"data sent with the handshake"

server_session, reply = responder.write_response()
client_session, _ = initiator.read_response(reply)

frame = client_session.seal(b"hello")             # put this on a socket
server_session.open(frame)                        # -> b"hello"
```

`Initiator.read_response` and `Responder.write_response` **consume** the handle
they are called on, success or failure — a handshake cannot be retried from a
half-read state. Using one again raises rather than corrupting memory, which is
[what happens](../../docs/DECISIONS.md) without that check: removing it takes
this test suite from passing to the interpreter dying.

## The secret key

**There is no way to read a private key out of an `Identity`,** and the C ABI
exports no such call for this to wrap.

That is the shape of the whole binding rather than an oversight. Bytes handed
to Python cannot be wiped: `bytes` is immutable so nothing can overwrite it,
the interpreter copies freely, and the memory may reach swap. Rust wipes its
copy when the identity is dropped; nothing it does survives the crossing.

`Identity.from_secret` restores a key you stored elsewhere, and FECTP wipes the
copy it makes. What you passed in is yours — use a `bytearray` and overwrite it
afterwards, because a `bytes` cannot be.

## What this does not do

The session layer only. **Retransmission, congestion control, fragmentation and
keep-alive are not here** — they live in the `fectp` crate, above the layer this
binds. A caller who needs reliable delivery builds it or does without.

That trade is why the binding is this shape at all
([OTHER-LANGUAGES.md](../../docs/OTHER-LANGUAGES.md)): binding the layer above
would mean blocking calls to hold the GIL over, threads the library owns, and
memory crossing the boundary in both directions.

One warning worth repeating from D63: the abandonment reporting such a caller
would rebuild is the logic this project got wrong twice, and §5.5 of the
specification notes that a conforming receiver cannot observe it — so wire-level
test vectors cannot catch that class of mistake either.
