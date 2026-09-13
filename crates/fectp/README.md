# fectp

Fast Encrypted Compressed Transport Protocol — an encrypted, compressed
datagram transport over UDP, with optional per-message reliability.

**Not audited.** This is `#![forbid(unsafe_code)]`, cross-validated against an
independent Noise implementation, and has a conformance suite pinning every
normative constant — none of which is a substitute for review by someone who
breaks protocols for a living. Do not put it in front of an adversary yet.

## What it does

- **Noise_IK** handshake, with data sendable on the first flight
- **Authenticated framing** with replay protection and reorder tolerance
- **Per-message reliability**, opt-in per send, unordered by design — a frame
  is delivered on arrival rather than held for the one before it
- **Typed compression**: tell it the payload's shape and a transform suited to
  it runs before the generic compressor
- **Many peers on one socket**, address migration, optional NAT keep-alive

## Two front ends

`Connection` is one peer, blocking, with `send` / `recv` / `flush`.
`Endpoint` is many peers over one socket, driven by `poll`.

```rust
use std::time::Duration;
use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

// ── Listening side ────────────────────────────────────────────────
let identity = Identity::generate();
let public_key = *identity.public();          // give this to the other side
let mut node = Endpoint::bind("0.0.0.0:4433", identity)?;

loop {
    match node.poll(Some(Duration::from_millis(100)))? {
        Event::Message { peer, data } =>
            node.send(peer, &data, PayloadType::Opaque)?,   // echo
        _ => {}
    }
}
```

## Features

`compress` pulls in Zstandard. Without it the typed transforms still run, and
the ones that only rearrange bytes are skipped because there would be no
entropy coder behind them to gain from it.

## Where the rest is

This crate is the `std` half. [`fectp-core`](https://crates.io/crates/fectp-core)
is the `no_std`, allocation-free session layer and wire format, defined over
buffers rather than sockets — which is what to bind from another language.

Full documentation, the specification, the measured comparison against raw UDP
and TCP+TLS, and the numbered record of every design decision are in the
[repository](https://github.com/YounghyeonPark/fectp).

## Licence

BSD 3-Clause.
