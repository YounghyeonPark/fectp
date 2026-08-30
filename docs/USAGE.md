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

Opening a connection needs none of your attention: every way of doing it gives
up after `fectp::HANDSHAKE_TIMEOUT` (5 seconds). That is not a convenience —
a responder that cannot authenticate a frame drops it silently, so a handshake
aimed at an unreachable peer or the wrong key has nothing to wait for and would
otherwise wait for ever.

`set_read_timeout` is a separate thing: it bounds `recv` on an established
connection, and defaults to blocking.


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

## Sending with the handshake

Opening a connection normally costs a round trip before any data moves. If you
have data ready, it can ride along in the very first packet:

```rust
let conn = Connection::connect_and_send(
    addr, &server_public, &identity, &reading,
)?;
```

The peer receives it as `Event::Connected { zero_rtt, .. }`, or as the second
element of `accept()`. Anything it sends back arrives through `recv` like any
other message.

**When this is worth using.** It saves exactly one round trip, once, per
connection. On a connection that stays open and carries thousands of messages
that is nothing. It matters when connections are short:

- a battery-powered sensor that wakes, reports one reading, and sleeps
- reconnecting after a NAT mapping expires, which ends a session
- anywhere the very first answer's latency is what somebody notices

If your program connects once and streams, use plain `connect` and ignore this.

**What it costs.** That first payload is encrypted, but:

- **replayable** — an attacker who captures the packet can send it again, and
  the peer cannot tell
- **no forward secrecy** — it is protected only by the peer's static key, so a
  later key compromise exposes it

Send only what is safe to repeat. A sensor reading is; "open the valve" is not.
`SPEC.md` §4.4.1 states this normatively.

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

**The window is bounded, and it moves.** Two limits apply: `fectp::MAX_UNACKED`
(32) bounds memory and never changes, and a congestion window bounds what the
path has shown it can carry. The second is the tighter one — it opens at
`fectp::INITIAL_CWND` (4) on a new connection, widens as acknowledgements
arrive, and collapses when a message times out.

So `send_reliable` fails with `Error::Protocol(WindowFull)` sooner than the
memory bound suggests, and how soon depends on the path. Handle it:

```rust
while conn.send_reliable(&payload).is_err() {
    conn.flush(Duration::from_secs(2))?;   // wait for room
}
```

A sender that must sometimes wait is what congestion control is. Without it,
against a 1 Mbit/s link, 46% of what this protocol sent was dropped by a full
queue before it reached the far side.

```rust
println!("{} still in flight", conn.unacknowledged());
println!("retransmit timeout now {} ms", conn.rto_ms());
```

`flush` fails with `Error::Unacknowledged { count }` if messages were abandoned
after exhausting their retries, or if the timeout expires first.

## Large messages

There is no separate call and no size to check:

```rust
conn.send_reliable(&recording)?;      // any size
conn.flush(Duration::from_secs(10))?; // wait for it to arrive
```

A payload larger than one frame is split across several, each acknowledged and
retransmitted on its own, and it arrives as **one** message:

```rust
let n = conn.recv(&mut buf)?;    // the whole thing, reassembled
```

Why there is no size to check: the frame limit depends on what the peer
advertised at handshake, so it differs per connection and a microcontroller
peer will advertise less. Asking the caller to compare against a number they
cannot know in advance was the wrong shape.

Three things to know:

**`send_reliable` does not wait.** A split message will not fit in the
congestion window, so the rest is queued and fed out by `recv`, `flush` and
later sends. `flush` is how you wait for it, and it fails with
`Error::Unacknowledged` if any fragment was abandoned — a message missing one
piece is not partly delivered, it is not delivered.

**`send` is still one frame only.** Splitting a payload that cannot be
retransmitted would fail whenever any one piece went missing: for 200 fragments
at 1% loss, nine times out of ten. It is refused rather than offered.

**There is a ceiling.** `fectp::MAX_MESSAGE_LEN` (1 MiB) and
`fectp::MAX_FRAGMENTS` (4096) bound what a receiver will reassemble, because a
receiver commits memory on the strength of the sender's own fragment count.
Above that, `send_reliable` fails with `Error::PayloadTooLarge`.

Compression is per fragment, so each frame is self-describing. That costs ratio
— the compressor sees one fragment of context rather than the whole message —
so data that compresses well is better compressed by your own code first.

On an `Endpoint` it is the same call. There is nothing to block on there, so a
message that had to be split reports its outcome as `Event::Sent { delivered }`.

## Typed payloads

A generic compressor sees only bytes. Telling it the shape lets a transform run
first — interleaved sensor samples are split by channel and delta-coded, which
a byte-oriented compressor cannot do for itself.

Every send names the shape:

```rust
let shape = PayloadType::I16 { channels: 4 };   // 4 channels of 16-bit ADC
conn.send(&samples, shape)?;
conn.send(&more, shape)?;

conn.send(b"a status line", PayloadType::Opaque)?;   // just bytes
```

| | |
|---|---|
| `Opaque` | Just bytes. Always correct; the compressor is on its own. |
| `I16 { channels }` | Interleaved 16-bit samples. |
| `I32 { channels }` | Interleaved 32-bit samples or counters. |
| `Elements { size }` | Fixed-size elements, byte-transposed. `4` for `f32`, `8` for `f64`. |

What it is worth, measured on 8 KiB:

| | as `Opaque` | declared |
|---|---|---|
| sensor i16 ×4, slow | 1.12x | **3.46x** |
| counter i32 ×2 | 1.67x | **292.57x** |
| f32 array | 1.14x | **8.21x** |
| JSON text | 126.03x | 126.03x |
| random bytes | 1.00x | 1.00x |

Structured binary gains a lot; text and random bytes gain nothing.

**A wrong declaration is safe.** The payload still round-trips — it just
compresses badly, and the peer reverses whatever was applied.

**Why it is named every time and not set once.** A setting would mean this
line's behaviour depended on a call made somewhere else, and forgetting it
would cost compression with no error and no warning. Repeating a shape costs
nothing: `PayloadType` is two bytes and `Copy`, so bind it to a local and pass
it. Changing the channel count then means changing one line.

**Below 32 bytes no transform runs at all**, and a stream that repeatedly fails
to compress stops being asked — so a wrong shape on incompressible data costs a
few microseconds at the start and almost nothing after that.

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

### What it costs

Measured on a linked image rather than estimated — `crates/footprint` builds
one for `thumbv7em-none-eabihf` with LTO and `--gc-sections`:

| | |
|---|---|
| flash | **22.0 KiB**, handshake, session and codec included |
| RAM, session state | 294 bytes, or 1,334 with reliable delivery |
| RAM, buffers | the caller's — 2,400 bytes for send and receive at the default frame size |

```bash
cd crates/footprint && cargo build --release && python size.py
cargo run -p fectp-core --example sizes
```

The core allocates nothing, so those numbers are the whole answer. On a
Cortex-M4 with 256 KiB of flash that is 9% of it.

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

## The whole list

[API.md](API.md) has every public method grouped by task, the constants with
their values, and an honest note about the two places the list is untidy. This
document explains *when* to reach for each; that one is the index.

## Further reading

| | |
|---|---|
| [`SPEC.md`](SPEC.md) | The normative wire format. |
| [`DECISIONS.md`](DECISIONS.md) | Why the protocol is shaped this way. |
| [`ADDING-A-CODEC.md`](ADDING-A-CODEC.md) | Supporting a new data shape. |
