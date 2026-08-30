# Using FECTP

Every snippet here is compiled as part of `crates/fectp/examples/tour.rs`, so
none of it can go stale.

## Adding the dependency

```toml
[dependencies]
fectp = { path = "crates/fectp" }
```

Zstandard compression is opt-in, because it needs a C toolchain to build:

```toml
fectp = { path = "crates/fectp", features = ["compress"] }
```

Without it everything still works — payloads simply go uncompressed, and the
built-in integer transforms (see [Typed payloads](#typed-payloads)) still apply.

## Choosing a mode

A connection runs in one of three modes. Everything after the constructor —
`send`, `recv`, `send_reliable`, codecs, `poll` — is identical in all three, so
this is a one-line decision, not a different way of working.

| | pre-shared | encrypted | handshake | use it for |
|---|---|---|---|---|
| Public key | server's public key | yes | 4 DH | the internet, several organisations |
| Pre-shared key | one secret | yes | **1 DH** | one closed system, a lab network |
| Plaintext | nothing | no | none | a physically trusted link, development |

```rust
// Public key
let conn = Connection::connect(addr, &server_public, &Identity::generate())?;
let server = Endpoint::bind("0.0.0.0:4433", Identity::generate())?;

// Pre-shared key
let conn = Connection::connect_psk(addr, b"lab-instrument-7", timeout)?;
let server = Endpoint::bind_psk("0.0.0.0:4433", b"lab-instrument-7")?;

// Plaintext
let conn = Connection::connect_plain(addr, timeout)?;
let server = Endpoint::bind_plain("0.0.0.0:4433")?;
```

**Encryption is not what costs you anything.** Encrypting a frame takes about a
microsecond; distributing keys is what takes effort. So if public-key mode
feels heavy, the answer is usually a pre-shared key — one secret both sides
configure, no public keys to ship — rather than turning encryption off.

**A pre-shared key is symmetric.** Everyone holding it can impersonate everyone
else holding it. Right for one closed system, wrong across organisations.

**Plaintext authenticates nothing.** Anyone on the path can read, forge, or
alter every byte. Two situations justify it: a link that is already physically
trusted, and development, where a readable packet capture is worth more than
confidentiality.

**Modes never mix.** A peer in one mode cannot talk to a peer in another — the
frame types are disjoint, so there is nothing to negotiate and nothing to
downgrade. Mismatched peers simply fail to connect.

## Identities and keys

A peer is identified by an X25519 keypair.

```rust
use fectp::Identity;

let identity = Identity::generate();
let public = *identity.public();     // [u8; 32] — hand this to peers
let secret = *identity.secret();     // [u8; 32] — persist this, keep it secret
let restored = Identity::from_secret(secret);
```

**A client must know the server's public key before connecting.** FECTP has no
certificate authority and does no key discovery: distributing that key is your
problem, the same way an SSH host key is. Ship it with the firmware, put it in a
config file, print it on a label — but it has to arrive out of band.

## The shortest working pair

Endpoint:

```rust
use fectp::{Event, Identity, Endpoint};

let identity = Identity::generate();
println!("public key: {:?}", identity.public());
let mut server = Endpoint::bind("0.0.0.0:4433", identity)?;

loop {
    match server.poll(Some(Duration::from_millis(100)))? {
        Event::Message { peer, data } => server.send(peer, &data)?,   // echo
        _ => {}
    }
}
```

Client:

```rust
use fectp::{Connection, Identity};

let mut conn = Connection::connect("server:4433", &server_public, &Identity::generate())?;
conn.send(b"hello")?;

let mut buf = vec![0u8; 2048];
let n = conn.recv(&mut buf)?;
```

> One `Endpoint` handles one peer or a thousand, and dials as well as
> listens — see [Peers, not clients and servers](#peers-not-clients-and-servers).

## Timeouts

`recv` blocks forever unless a timeout is set. Set one:

```rust
use std::time::Duration;

conn.set_read_timeout(Some(Duration::from_secs(5)))?;
match conn.recv(&mut buf) {
    Ok(n) => { /* ... */ }
    Err(fectp::Error::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => { /* ... */ }
    Err(e) => return Err(e),
}
```

`connect` blocks until the server answers. If the server is unreachable, or you
have the wrong public key, it never will — the server cannot authenticate the
frame, so it simply drops it. Use the timeout variant when that matters:

```rust
let conn = Connection::connect_with_timeout(
    addr, &server_public, &identity, Duration::from_secs(2),
)?;
```

## Sending data

```rust
conn.send(b"fire and forget")?;      // no acknowledgement, no retransmission
```

`send` returns once the datagram is handed to the kernel. It does not wait for
anything, and it never batches payloads.

Payloads are bounded by one datagram:

```rust
let limit = conn.max_payload();      // typically 1170 bytes
```

A larger payload is refused with `Error::PayloadTooLarge` — *unless* it
compresses under the limit, in which case it goes through. What has to fit is
the frame on the wire.

A reliable send carries a message identifier as well, so its ceiling is a few
bytes lower:

```rust
let limit = conn.max_reliable_payload();   // typically 1166 bytes
```

For anything above either limit, see [Large messages](#large-messages).

## Zero-RTT

The first handshake message can already carry data, so a request reaches the
server in one flight:

```rust
let (conn, reply) = Connection::connect_with_zero_rtt(
    addr, &server_public, &identity, b"GET /status",
)?;
```

The server receives it as the second element of `accept()`, or as
`Event::Connected { zero_rtt, .. }`.

**This data is replayable.** It is encrypted, but an attacker who captures the
frame can resend it, and it has no forward secrecy. Put only idempotent
requests here.

## Reliable delivery

```rust
conn.send_reliable(b"this must arrive")?;
conn.flush(Duration::from_secs(2))?;     // wait for acknowledgement
```

Three things to know:

**Retransmission needs to be driven.** `send_reliable` returns immediately;
progress happens inside `recv` and `flush`. A program that sends reliably and
then does neither will never retransmit.

**Delivery is unordered.** A message that arrives is delivered at once, even if
an earlier one is still in flight. Holding it back would be head-of-line
blocking. If you need order, put a sequence number in your own payload.

**The window is bounded** at 32 unacknowledged messages (`fectp::MAX_UNACKED`).
Past that, `send_reliable` fails with `Error::Protocol(WindowFull)`; call
`flush`, or send that message unreliably.

```rust
println!("{} still in flight", conn.unacknowledged());
println!("retransmit timeout now {} ms", conn.rto_ms());
```

`flush` fails with `Error::Unacknowledged { count }` if messages were abandoned
after exhausting their retries, or if the timeout expires first.

## Large messages

`send` and `send_reliable` both refuse a payload larger than one frame. A
datagram above the path MTU is cut up by IP, and an IP-fragmented datagram is
lost entire if any piece of it goes missing — so FECTP never emits one.

`send_large` splits the message at the protocol layer instead, where a lost
piece is retransmitted on its own:

```rust
conn.send_large(&recording, Duration::from_secs(10))?;
```

It arrives as **one** message, not as pieces:

```rust
let n = conn.recv(&mut buf)?;    // the whole thing, reassembled
```

Four things to know:

**It waits.** Unlike the other send methods, this returns only once the peer
has acknowledged every fragment, which is why it takes a timeout. There is no
useful sense in which a large message has been sent while most of it is still
queued behind a send window.

**Every fragment is reliable**, so the peer must support the reliability layer.
Without that, one lost fragment would lose the whole message with no way to
repair it.

**There is a ceiling.** `fectp::MAX_MESSAGE_LEN` (1 MiB) and
`fectp::MAX_FRAGMENTS` (4096) bound what a receiver will reassemble, because a
receiver commits memory on the strength of the sender's own fragment count.
Above that, `send_large` fails with `Error::PayloadTooLarge`.

**Compression is per fragment.** Each frame is coded on its own so that it is
self-describing, which costs ratio — the compressor sees one fragment of
context rather than the whole message. For data that compresses well, sending
it pre-compressed by your own code will beat this.

### From an endpoint

`Endpoint::send_large` cannot wait — an event loop serving many peers must not
stall on one of them — so it **queues** the message and returns immediately.
`poll` feeds it out as the send window frees:

```rust
server.send_large(peer, &recording)?;      // returns at once
loop {
    match server.poll(Some(Duration::from_millis(50)))? {
        Event::Sent { peer, delivered } => {
            println!("{peer:?}: {}", if delivered { "arrived" } else { "lost" });
            break;
        }
        _ => {}
    }
}
```

`Event::Sent` reports the outcome. `delivered` is false if any fragment was
abandoned after exhausting its retries — a fragmented message missing a piece
is not partially delivered, it is not delivered.

Progress happens only inside `poll`. An endpoint that queues a message and
never polls sends nothing. The queue is bounded at `fectp::MAX_QUEUED_LARGE`
messages per peer, since each holds its payload until acknowledged.

## Typed payloads

A generic compressor sees only bytes. Telling it the shape lets a transform run
first — on interleaved `i16` sensor data this is the difference between no
saving at all and about 2x.

```rust
use fectp::PayloadType;

conn.send_typed(&samples, PayloadType::I16 { channels: 4 })?;
```

If the connection always carries one shape, say so once:

```rust
conn.set_default_payload_type(PayloadType::I16 { channels: 4 });
conn.send(&samples)?;                                  // uses the default
conn.send_typed(&status, PayloadType::Opaque)?;        // override for one message
```

Available shapes:

| | for |
|---|---|
| `PayloadType::Opaque` | unknown structure (the default) |
| `PayloadType::I16 { channels }` | interleaved little-endian `i16` samples |
| `PayloadType::I32 { channels }` | interleaved little-endian `i32` samples |
| `PayloadType::Elements { size }` | `f32`/`f64` arrays, fixed-layout records |

Declaring the wrong shape is safe: the payload still round-trips, it just
compresses badly. If the peer cannot reverse the transform, or coding does not
shrink the payload, the original bytes are sent.

To support a new data shape, see [`ADDING-A-CODEC.md`](ADDING-A-CODEC.md).

## Resumption

A full handshake costs each peer four X25519 operations — on a microcontroller
roughly a hundred milliseconds, paid again after every reset. Resumption costs
one.

```rust
// After any connection, take the ticket and persist the 32-byte key.
// `None` in plaintext mode, which has nothing to resume.
let key: [u8; 32] = *conn.resumption_ticket().expect("encrypted").key();
save_to_flash(&key);

// Later, instead of connect():
use fectp::Ticket;
let conn = Connection::resume(
    addr, &Ticket::from_key(load_from_flash()), &server_public,
    Duration::from_secs(1),
)?;
```

**Tickets are single use.** Each handshake issues the next one, so store the
new ticket after every connection, resumed ones included. Redeeming a spent
ticket fails — that is what stops a captured resumption request being replayed.

**Always keep the full-handshake path.** A server that restarted, or evicted
the ticket, cannot answer; the resume times out. Fall back:

```rust
let conn = match Connection::resume(addr, &ticket, &server_public, timeout) {
    Ok(conn) => conn,
    Err(_) => Connection::connect(addr, &server_public, &identity)?,
};
```

Resumption keeps forward secrecy — fresh ephemerals are still exchanged — but
the ticket is key material. Store it as carefully as the identity secret.

## Peers, not clients and servers

`Endpoint` binds one socket and uses it **both** to accept connections and to
start them. "Initiator" and "responder" are roles a connection has, not
properties a node has; once a handshake finishes the session is symmetric and
neither side is privileged.

```rust
let mut node = Endpoint::bind_psk("0.0.0.0:4433", b"mesh-secret")?;

// Dial another node — from this same socket.
let peer = node.connect("other-node:4433", None)?;

loop {
    match node.poll(Some(Duration::from_millis(100)))? {
        Event::Connected { peer, initiated, .. } => {
            println!("{peer:?} ({})", if initiated { "we dialled" } else { "they dialled" });
        }
        Event::Message { peer, data } => node.send(peer, &data)?,
        Event::ConnectFailed { peer } => println!("{peer:?} never answered"),
        _ => {}
    }
}
```

Sharing the socket is not tidiness. A NAT maps a *local port*, so a node that
dials out from one port and listens on another cannot be reached through the
mapping its own traffic created. One socket is what makes hole punching
possible at all.

`connect` does **not** block. It sends the opening frame and hands back a
`PeerId`; the handshake finishes when the reply arrives, surfacing as
`Event::Connected { initiated: true }`. Nothing may be sent to that handle
before then. A peer that never answers becomes `Event::ConnectFailed` after a
few retries — silence is reported, not waited on forever.

In public-key mode `connect` needs the peer's key; in the other two it does not:

```rust
node.connect(addr, Some(&their_public))?;   // public-key mode
node.connect(addr, None)?;                  // pre-shared key, or plaintext
```

`Connection` remains the simpler blocking client for code that only ever dials
and never listens.

## Serving many peers

`Endpoint` owns the socket and routes each datagram by session identifier. One
thread, no locks, no socket per peer.

```rust
use fectp::{Event, Identity, Endpoint};

let mut server = Endpoint::bind("0.0.0.0:4433", Identity::generate())?;
loop {
    match server.poll(Some(Duration::from_millis(100)))? {
        Event::Connected { peer, zero_rtt, resumed } => {
            println!("{peer:?} connected (resumed: {resumed}), 0-RTT: {zero_rtt:?}");
        }
        Event::Message { peer, data } => {
            server.send(peer, &data)?;              // echo
        }
        Event::Idle => {}
        _ => {}                                     // `Event` is non-exhaustive
    }
}
```

`poll` also drives retransmission for every peer, so call it regularly even
when idle.

Per-peer operations take the `PeerId`:

```rust
server.send_reliable(peer, b"command")?;
server.send_typed(peer, &samples, PayloadType::I16 { channels: 4 })?;
server.set_default_payload_type(peer, PayloadType::I16 { channels: 4 });

let who = server.peer_public_key(peer);      // Option<&[u8; 32]>
let outstanding = server.unacknowledged(peer);
server.disconnect(peer);
```

`PeerId` handles are never reused, so one belonging to a departed peer stops
resolving rather than addressing whoever took its place.

**Sessions are bound to the peer's address.** A peer that changes address (a
phone moving between networks) loses its session and must reconnect — or
resume, which is cheap.

## Length masking

Frame sizes reveal payload lengths. If the lengths themselves are sensitive:

```rust
conn.set_padding(true);      // pad to a 64-byte boundary
```

Off by default, because a 10-byte message becomes a 64-byte one — a steep price
for the small messages this protocol targets. It is per-frame and per-direction;
the peer follows the flag.

This narrows length leakage; it does not defeat CRIME-style attacks. The
defence against those is that FECTP compresses every message independently.

## Errors

```rust
pub enum Error {
    Io(std::io::Error),          // socket failure, or a read timeout
    Protocol(fectp_core::Error), // protocol-level failure
    Decompress,                  // a compressed payload could not be decoded
    PayloadTooLarge { len, limit },
    Handshake,
    Unacknowledged { count },    // reliable messages were abandoned
    ReliabilityUnsupported,      // the peer does not implement it
    UnknownTicket,               // stale or already-redeemed resumption ticket
    UnknownPeer,                 // no such connected peer (server only)
}
```

Note what is **not** an error: a forged, replayed, or misdirected frame. Those
are silently discarded and the call keeps waiting. Anyone can send bytes to a
UDP port; surfacing that as an error would hand an off-path attacker a denial
of service.

## On a microcontroller

`fectp-core` is `no_std` and allocation-free. It has no socket, no clock, and
no threads — you supply all three.

```toml
[dependencies]
fectp-core = { path = "crates/fectp-core", default-features = false }
```

Implement `Transport` over whatever link you have, then drive `Initiator` /
`Responder` and `Session` directly. Every operation writes into a buffer you
provide, and the reliability layer takes `now_ms` as a parameter rather than
reading a clock.

Advertise honest capabilities — a device with no Zstandard decoder must not
claim one:

```rust
use fectp_core::Capabilities;
let caps = Capabilities::minimal(256);   // small frames, core transforms only
```

Build check:

```bash
cargo build -p fectp-core --target thumbv7em-none-eabihf --release
```

## Common mistakes

| | |
|---|---|
| Reliable messages never arrive | Nothing is calling `recv` or `flush` to drive retransmission. |
| `recv` hangs forever | No read timeout set. |
| Resumption always fails | The ticket was already used — store the new one after every connection. |
| `connect` hangs | Wrong server public key: the server cannot authenticate the frame, so it drops it silently. Use `connect_with_timeout`. |
| Compression saves nothing | The payload is small, already compressed, or the peer never advertised `CAP_ZSTD`. Declare a `PayloadType` if the data is structured. |
| `match` on `Event` will not compile | `Event` is `#[non_exhaustive]`; add a `_` arm. |
| Client and server never connect | They are in different modes. Modes do not interoperate, by design. |
| `send` after `connect` fails | An `Endpoint` dial is not finished until `Event::Connected` arrives; poll first. |
| `resumption_ticket()` is `None` | Plaintext sessions have nothing to resume. |

## Further reading

| | |
|---|---|
| [`SPEC.md`](SPEC.md) | The normative wire format. |
| [`DECISIONS.md`](DECISIONS.md) | Why the protocol is shaped this way. |
| [`ADDING-A-CODEC.md`](ADDING-A-CODEC.md) | Supporting a new data shape. |
