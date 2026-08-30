# FECTP

Fast Encrypted Compressed Transport Protocol — an implementation.

Send bytes, get bytes. Encryption, framing, and the decision of whether
compression is even worth attempting are handled underneath the API.

```rust
use std::time::Duration;
use fectp::{Connection, Event, Identity, Endpoint};

// Endpoint
let identity = Identity::generate();
let server_public = *identity.public();
let mut server = Endpoint::bind("0.0.0.0:4433", identity)?;

// Client — the server's public key must already be known.
let mut client = Connection::connect("server:4433", &server_public, &Identity::generate())?;
client.send(b"hello")?;
```

## What it is

- `Noise_IK_25519_ChaChaPoly_BLAKE2s` over UDP datagrams.
- **0-RTT on first contact.** The IK pattern lets the initiator put real
  application data in the very first message, because it already knows the
  responder's static key. No prior session and no certificate authority are
  needed. QUIC with TLS 1.3 cannot do this on a first connection.
- **`no_std`, allocation-free core.** Builds for `thumbv7em-none-eabihf`.
  The core owns no buffers; every operation writes into a caller-provided
  slice.
- **No coalescing on send.** `send` hands the datagram to the kernel and
  returns. It does not wait for an acknowledgement and never batches payloads
  the way a stream protocol would.
- `#![forbid(unsafe_code)]`, and a fixed-size header with no variable-length
  parsing before authentication.

## Three modes, one API

Not every deployment needs the same protection, and the friction is never the
encryption — it is distributing keys. So the modes differ in what must be
shared beforehand, not in how you use them:

```rust
Connection::connect(addr, &server_public, &identity)?   // public key: 4 DH
Connection::connect_psk(addr, b"shared-secret", t)?     // one secret:  1 DH
Connection::connect_plain(addr, t)?                     // trusted link, no crypto
```

Everything after the constructor is identical. Modes never interoperate: their
frame types are disjoint, so there is nothing on the wire to negotiate and
nothing to downgrade.

## Peers, not clients and servers

An `Endpoint` binds one socket and uses it both to accept connections and to
start them. Whoever spoke first stops mattering once the handshake is done —
the session is symmetric.

```rust
let mut node = Endpoint::bind_psk("0.0.0.0:4433", b"mesh-secret")?;
let peer = node.connect("other-node:4433", None)?;   // same socket
```

Sharing the socket is the precondition for NAT hole punching: a NAT maps a
local port, so a node that dials from one port and listens on another cannot be
reached on the mapping its own traffic created.

## Serving many peers

`Endpoint` owns the socket, routes each datagram by the header's session
identifier, and reports what happened — one thread, no locks, no socket per
peer. One server type handles one peer or a thousand:

```rust
let mut server = Endpoint::bind("0.0.0.0:4433", Identity::generate())?;
loop {
    match server.poll(Some(Duration::from_millis(100)))? {
        Event::Connected { peer, .. } => println!("{peer:?} arrived"),
        Event::Message { peer, data } => server.send(peer, &data)?,
        Event::Idle => {}
    }
}
```

Each peer gets its own reliability state, codec negotiation, and resumption
ticket. Sessions are keyed on `(address, session_id)`, so two clients that pick
the same identifier cannot collide.

## Resumption

A full handshake costs each peer four X25519 operations — on a microcontroller
roughly a hundred millisecond, paid again after every reset. Resumption costs
**one**:

```rust
let ticket = conn.resumption_ticket();      // persist *ticket.key(), 32 bytes
// ... after a reset ...
let conn = Connection::resume(addr, &ticket, &server_public, timeout)?;
```

Authentication comes from the ticket, which an earlier authenticated handshake
established, so identities stay bound. Fresh ephemerals are still exchanged, so
a resumed session keeps forward secrecy. Tickets are single use — each
handshake issues the next one — which is what stops a captured resumption
request being replayed.

## Reliability, per message

```rust
conn.send(b"telemetry")?;             // fire and forget
conn.send_reliable(b"command")?;      // retransmitted until acknowledged
conn.flush(Duration::from_secs(2))?;  // wait for outstanding acknowledgements
```

Reliable, but deliberately **not ordered**: a message that arrives is delivered
at once rather than waiting for an earlier one, because holding it back is
head-of-line blocking. Acknowledgements are selective, so one gap does not
stall everything behind it, and a retransmission goes out under a fresh
sequence number — the frame's nonce can never repeat — with a message
identifier inside letting the receiver recognise the duplicate.

## Typed payloads

A generic compressor sees only bytes. Telling it the shape lets a transform run
first:

```rust
conn.send_typed(&samples, PayloadType::I16 { channels: 4 })?;

// Or, for a stream that is always the same shape:
conn.set_default_payload_type(PayloadType::I16 { channels: 4 });
conn.send(&samples)?;
```

All codecs are lossless: a payload comes back byte for byte, and samples one
least significant bit apart stay distinct. On a 4-channel block of slowly
varying `i16`, Zstandard on the raw bytes saves nothing at all (interleaving
hides the redundancy) while the typed path reaches **1.99x**. Transforms are pure integer code in the `no_std` core, so a peer with
no room for a Zstandard decoder still gets that. A wrong declaration costs
compression, never correctness, and a transform the peer cannot reverse is
never used.

Codecs are a registry, not a fixed set: adding support for a new data type
means writing one transform and registering it, and negotiation, fallback,
framing, and composition with Zstandard come for free. See
[`docs/ADDING-A-CODEC.md`](docs/ADDING-A-CODEC.md).

## Layout

| Crate | |
|---|---|
| `fectp-core` | `no_std` handshake, wire format, session, `Transport` trait |
| `fectp` | `std` API: `Connection`, `Endpoint`, UDP backend, compression |

The core is defined over a datagram `Transport` trait rather than over QUIC,
because UDP is the only transport every target shares. QUIC fits behind the
same trait on platforms that can afford it.

## Status

Working: handshake, 0-RTT, authenticated framing, replay protection, reorder
tolerance, capability negotiation, per-message reliable delivery, session
resumption, multi-peer serving, outbound dialling on the same socket,
three security modes, optional
length-masking padding, typed payload codecs, optional Zstandard compression.

Not yet built: congestion control, ordering, address migration, ticket
expiry, a QUIC backend, bit-packed deltas.

## Documentation

| | |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | How to use it. Every snippet is compiled by `examples/tour.rs`. |
| [`docs/SPEC.md`](docs/SPEC.md) | Normative wire specification. Everything an independent implementation needs. |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Why the protocol is shaped this way, and where it departs from the original design note. |
| [`docs/ADDING-A-CODEC.md`](docs/ADDING-A-CODEC.md) | How to support a new data type. |

## Interoperating

FECTP is an open format, not just this implementation. The handshake is
standard Noise — `Noise_IK_25519_ChaChaPoly_BLAKE2s` for the full handshake and
`Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` for resumption, for which libraries
exist in C, Go, Python, Java, and JavaScript — so a new implementation writes only
the framing: three fixed-size binary layouts and the transforms, all specified
in [`docs/SPEC.md`](docs/SPEC.md). Every normative constant in that document is
pinned by `crates/fectp-core/tests/spec_conformance.rs`, so the specification
cannot drift away from the code.

See [`docs/DECISIONS.md`](docs/DECISIONS.md) for where this deviates from
`project_description.md` and why — including the BLAKE2b→BLAKE2s change, why
compression had to become negotiable, and why the padding is off by default.

## Examples

```bash
cargo run -p fectp --example tour          --features compress   # every documented snippet
cargo run -p fectp --example echo          --features compress   # one client, round-trip timings
cargo run -p fectp --example multi_client  --features compress   # six clients on one socket
cargo run -p fectp --example mesh          --features compress   # three peers, all dialling each other
```

## Building

```bash
cargo test --workspace --features fectp/compress
```

Compression needs a C toolchain for `zstd` and is therefore opt-in:

```bash
cargo build -p fectp --features compress
```

Embedded target check:

```bash
cargo build -p fectp-core --target thumbv7em-none-eabihf --release
```

## Verification

The Noise implementation is validated against [`snow`](https://docs.rs/snow),
an independent implementation, in both roles — see
`crates/fectp-core/tests/interop.rs`. Any divergence in the key schedule,
transcript hash, HMAC, or HKDF would make the peer's decryption fail, so a
passing run exercises the whole handshake.

## Licence

BSD 3-Clause.
