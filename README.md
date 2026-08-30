# FECTP

**An encrypted transport that gets your data moving with as little delay as
possible — small enough for a microcontroller, identical code on a server.**

You hand it bytes, the peer gets those bytes. Encryption, framing, and the
decision of whether compressing is even worth the CPU all happen underneath.

```rust
conn.send(b"hello")?;
let n = conn.recv(&mut buf)?;
```

---

## What it is for

Most encrypted transports make you choose. TLS over TCP is everywhere but costs
two round trips before the first byte moves, and its stack is far too large for
a microcontroller. Raw UDP is small and immediate but gives you nothing —
no encryption, no framing, no way to know a message arrived.

FECTP is for the middle: **an instrument, a sensor, or a service that needs to
send data encrypted, right now, and may be running on 32 KiB of RAM.**

- Data travels in the **very first packet** — no waiting for a handshake.
- The core is `no_std` and allocates nothing. Roughly **29 KiB** of code.
- Delivery is per-message: fire-and-forget by default, guaranteed on request.
- It knows what your data *is*, so it can compress it properly.

### Not what it is for

Talking to a web browser, or anything that expects HTTP. This is a transport for
software you control on both ends. It is also **not** a general P2P stack —
there is no peer discovery and no NAT traversal, only the socket property those
would build on.

---

## Why it's fast

The usual cost of encryption is not the maths — encrypting a 1200-byte packet
takes about a microsecond. The cost is the **round trips spent agreeing on keys
before any real data may move**.

```mermaid
sequenceDiagram
    participant A as Your app
    participant B as Peer
    Note over A,B: once per session
    A->>B: handshake + request
    B->>A: handshake + answer
    Note over A,B: every message after — no handshake
    A->>B: data
```

**The handshake happens once per session, not per message.** Afterwards each
`send` is one symmetric encryption — about a microsecond — and a 14-byte
header. No key agreement, ever again, until the session ends.

| Before your first byte can be sent | Round trips |
|---|---|
| **FECTP**, first ever contact | **0** |
| QUIC + TLS 1.3, first ever contact | 1 |
| QUIC + TLS 1.3, reconnecting to a known peer | 0 |
| TCP + TLS 1.3 | 2 |

FECTP manages this on *first* contact because of one trade: the caller must
already know the peer's public key. Nothing has to be negotiated, so the first
packet can carry both the handshake and the payload. That key has to reach you
some other way — the same bargain as an SSH host key.

A session lasts until you drop it. The only thing that costs another handshake
is losing the session — a restart, a reboot, a new peer — and
[resumption](#session-resumption) cuts even that to a single X25519 operation.

> 0-RTT data is encrypted but **replayable** by anyone who captures the packet.
> Put idempotent requests there, or none.

### Measured

Against raw UDP and TCP + TLS 1.3, on loopback:

| | median | vs raw UDP |
|---|---|---|
| raw UDP, no encryption | 31.6 µs | — |
| **FECTP, encrypted** | **35.8 µs** | **+13%** |
| TCP + TLS 1.3 | 64.4 µs | +104% |

But the round-trip table above is what actually decides anything: at 150 ms of
path latency, FECTP answers a first request 300 ms sooner than TCP + TLS, and
every microsecond in this table put together is a rounding error beside that.

[**BENCHMARKS.md**](docs/BENCHMARKS.md) has the full comparison — setup cost,
per-message overhead, compression against gzip and Zstandard, and an honest
account of the encryption trade-offs. It has also changed the implementation
twice: it is why the default compression level moved from −4 to 1, and why the
send path stopped trying to compress data that has already refused to.

---

## Where it sits

Two crates. The lower one has no operating system in it at all, which is what
lets the same protocol run on a microcontroller and a server.

```mermaid
flowchart TB
    A["Your application"]
    B["fectp · needs std<br/>Connection · Endpoint<br/>codecs · Zstandard"]
    C["fectp-core · no_std<br/>~29 KiB of code<br/>Noise handshake · framing<br/>replay window · reliability"]
    D["Transport trait<br/>UDP, or a link you supply"]
    A --> B --> C --> D
```

A constrained device uses `fectp-core` alone and supplies its own socket, clock
and buffers. A server uses both crates. They speak the same protocol:

```mermaid
flowchart LR
    subgraph big["Server"]
        s1["fectp"] --> s2["fectp-core"]
    end
    subgraph small["Microcontroller"]
        m["fectp-core"]
    end
    big <--> small
```

Same wire format on both sides.

---

## Getting started

```toml
[dependencies]
fectp = { git = "https://github.com/younghyeonpark/fectp" }
```

The simplest pair — one peer listens, one dials:

```rust
use std::time::Duration;
use fectp::{Connection, Endpoint, Event, Identity};

// ── Listening side ────────────────────────────────────────────────
let identity = Identity::generate();
let public_key = *identity.public();          // give this to the other side
let mut node = Endpoint::bind("0.0.0.0:4433", identity)?;

loop {
    match node.poll(Some(Duration::from_millis(100)))? {
        Event::Message { peer, data } => node.send(peer, &data)?,   // echo
        _ => {}
    }
}

// ── Dialling side ─────────────────────────────────────────────────
let mut conn = Connection::connect("host:4433", &public_key, &Identity::generate())?;
conn.send(b"hello")?;

let mut buf = vec![0u8; 2048];
let n = conn.recv(&mut buf)?;
```

Full walkthrough, with every snippet compiled and run by
[`examples/tour.rs`](crates/fectp/examples/tour.rs):
**[docs/USAGE.md](docs/USAGE.md)**.

---

## What happens to a message

`send` is not a thin wrapper around `sendto`. Each payload takes this path, and
every branch that costs anything is skipped when it would not pay:

```mermaid
flowchart LR
    P["your bytes"] --> TR["transform<br/>if shape declared"]
    TR --> Z["compress<br/>if worth it"]
    Z --> E["encrypt and<br/>authenticate"]
    E --> S(["UDP datagram<br/>+ 14-byte header"])
```

Both middle steps are skipped when they would not pay, and the payload goes
straight through.

The "worth it?" test is real: a payload under 1 KiB, one that already looks
compressed, or one the peer cannot decompress goes straight through. If
compression runs and fails to shrink the payload, the original is sent. **A bad
guess costs CPU, never bytes.**

`send` returns as soon as the datagram reaches the kernel. It never waits for an
acknowledgement and never batches payloads the way a stream protocol does.

### On the wire

```
 byte  0        1          2 – 5              6 – 13          14 –
     ┌─────────┬─────────┬──────────────┬──────────────────┬───────────┐
     │ ver·type│  flags  │  session id  │ sequence number  │  payload  │
     └─────────┴─────────┴──────────────┴──────────────────┴───────────┘
     └──────────────── 14 bytes, always ─────────────────────┘
```

Fixed size, no length fields. Parsing a hostile packet involves no arithmetic
before it is authenticated — deliberate, because a microcontroller has no ASLR,
no NX bit and no MMU to contain a mistake there. The whole header is
authenticated along with the payload, so changing any byte of it makes
decryption fail.

The core carries `#![forbid(unsafe_code)]`, so none of this parsing can reach
for a raw pointer even by accident.

Overhead is **30 bytes** per frame (14 header + 16 authentication tag), or 14 in
plaintext mode, which has no tag because it has nothing to authenticate.

---

## Three security modes

Not every deployment faces the same threat, and the friction is never the
encryption — it is getting keys to where they need to be. So the modes differ in
**what has to be shared beforehand**, not in how you use them.

| Mode | You must share | Encrypted | Handshake cost | Suits |
|---|---|---|---|---|
| **Public key** | the peer's public key | yes | 4 × X25519 | the internet, several organisations |
| **Pre-shared key** | one secret | yes | 1 × X25519 | a lab network, one closed system |
| **Plaintext** | nothing | **no** | none | a cable you already trust, debugging |

```rust
Connection::connect(addr, &peer_public, &identity)?     // public key
Connection::connect_psk(addr, b"shared-secret", t)?     // one secret
Connection::connect_plain(addr, t)?                     // no crypto
```

**Everything after the constructor is identical** — same `send`, same `recv`,
same codecs, same reliability.

If public-key mode feels heavy, the answer is usually a pre-shared key rather
than turning encryption off: it removes key distribution entirely and keeps
both encryption and forward secrecy.

> **Modes never interoperate.** Their frame types do not overlap, so a peer in
> one mode simply does not understand a peer in another. There is nothing on the
> wire to negotiate, and therefore nothing to downgrade.

---

## Peers, not clients and servers

"Initiator" and "responder" describe a *connection*, not a node. An `Endpoint`
binds one socket and uses it **both** to accept connections and to start them;
once the handshake finishes the session is symmetric and neither side is
privileged.

```mermaid
flowchart LR
    A(["Node A"]) <--> B(["Node B"])
    B <--> C(["Node C"])
    A <--> C
```

Each node binds one port. Every link was dialled by one side and accepted by
the other, and after the handshake it makes no difference which.

```rust
let mut node = Endpoint::bind_psk("0.0.0.0:4433", b"mesh-secret")?;
let peer = node.connect("other-node:4433", None)?;   // the same socket
```

Sharing the socket is not tidiness. A NAT maps a **local port**, so a node that
dials out from one port and listens on another cannot be reached through the
mapping its own traffic just created. One socket is the precondition for hole
punching.

`connect` does not block: it sends the opening packet and returns a handle. The
handshake completes during `poll`, as `Event::Connected { initiated: true }`, or
gives up as `Event::ConnectFailed`.

One `Endpoint` serves one peer or a thousand, on one thread, with no locks and
no socket per peer. Try it:
`cargo run -p fectp --example mesh --features compress`.

---

## Messages larger than a frame

`send` refuses a payload above about 1170 bytes, because a datagram past the
path MTU is cut up by IP — and an IP-fragmented datagram is lost entire if any
one piece goes missing.

`send_large` cuts the message at the protocol layer instead, where a lost piece
is retransmitted on its own:

```rust
conn.send_large(&recording, Duration::from_secs(10))?;
```

It arrives as one message. Every fragment is reliable, and the send waits for
acknowledgements — so this returns when the peer actually has the whole thing,
not when the bytes left the kernel. The ceiling is 1 MiB, because a receiver
commits memory on the strength of the sender's own fragment count.

## Reliability, per message

```rust
conn.send(b"telemetry")?;             // fire and forget
conn.send_reliable(b"command")?;      // resent until acknowledged
conn.flush(Duration::from_secs(2))?;  // wait for what is outstanding
```

Reliable but deliberately **not ordered**. A message that arrives is delivered
at once rather than being held back for an earlier one — holding it back is
head-of-line blocking, the exact cost this protocol exists to avoid. If you need
order, put a sequence number in your own payload.

Acknowledgements are selective, so one gap does not stall everything behind it.
A retransmission goes out under a fresh sequence number, because that number is
the encryption nonce and can never repeat; a message identifier inside the
encrypted payload is what lets the receiver recognise the duplicate.

---

## Typed payloads

A general-purpose compressor sees only bytes. Tell it the shape and a transform
can run first:

```rust
conn.send_typed(&samples, PayloadType::I16 { channels: 4 })?;

// Or, if the connection always carries the same shape:
conn.set_default_payload_type(PayloadType::I16 { channels: 4 });
conn.send(&samples)?;
```

On a 4-channel block of slowly varying `i16` — ordinary instrument data:

| | Bytes on the wire |
|---|---|
| Zstandard on the raw bytes | 4096 — **no saving at all** |
| Declared as `I16 { channels: 4 }` | 2055 — **2x** |

Interleaving is why: consecutive bytes come from different channels, so a
byte-oriented compressor finds nothing. Splitting by channel first exposes the
redundancy that was there all along.

Every codec is **lossless** — a payload comes back byte for byte, and samples
one bit apart stay distinct. The transforms are plain integer code in the
`no_std` core, so a peer with no room for a Zstandard decoder still gets that
2x. Declaring the wrong shape costs compression, never correctness.

Codecs are a registry, not a fixed set: supporting a new data type means writing
one transform — see [docs/ADDING-A-CODEC.md](docs/ADDING-A-CODEC.md).

---

## Session resumption

A full handshake is four X25519 operations per side. On a microcontroller that
is roughly a hundred milliseconds, paid again after **every reset**. Resumption
costs one:

```rust
let key = *conn.resumption_ticket().expect("encrypted").key();   // 32 bytes
save_to_flash(&key);

// after a reset
let conn = Connection::resume(addr, &Ticket::from_key(key), &peer_public, timeout)?;
```

Authentication comes from the ticket, which an earlier authenticated handshake
established, so identities stay bound. Fresh ephemeral keys are still exchanged,
so a resumed session keeps forward secrecy. Tickets are single use — each
handshake issues the next — which is what stops a captured resumption request
being replayed. Always keep the full-handshake path as a fallback.

---

## Status

**Working:** handshake, 0-RTT, authenticated framing, replay protection,
reorder tolerance, capability negotiation, per-message reliable delivery,
session resumption, many peers on one socket, outbound dialling on that same
socket, three security modes, optional length-masking padding, typed payload
codecs, optional Zstandard compression.

**Not built:** congestion control, ordered delivery, address migration, ticket
expiry, peer discovery and NAT traversal, a QUIC backend, bit-packed deltas.

141 tests pass; the crate builds for `thumbv7em-none-eabihf`.

---

## Verification

The handshake is validated against [`snow`](https://docs.rs/snow), an
independent Noise implementation, **in both roles** — see
[`tests/interop.rs`](crates/fectp-core/tests/interop.rs). Any divergence in the
key schedule, transcript hash, HMAC or HKDF would make the other side's
decryption fail, so a passing run exercises the entire handshake.

[docs/SPEC.md](docs/SPEC.md) is a normative wire specification. Every constant
in it is pinned by
[`tests/spec_conformance.rs`](crates/fectp-core/tests/spec_conformance.rs), so
the specification cannot quietly drift away from the code.

An independent implementation needs an off-the-shelf Noise library — the two
patterns used, `Noise_IK_25519_ChaChaPoly_BLAKE2s` and
`Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`, exist for C, Go, Python, Java and
JavaScript — plus the framing: three fixed-size binary layouts and the
transforms.

---

## Building

```bash
cargo test --workspace --features fectp/compress
```

Zstandard needs a C toolchain, so it is opt-in. Without it everything still
works; payloads simply go uncompressed, and the built-in integer transforms
still apply.

```bash
cargo build -p fectp-core --target thumbv7em-none-eabihf --release   # embedded check
```

### Examples

```bash
cargo run -p fectp --example tour          --features compress   # every documented snippet
cargo run -p fectp --example echo          --features compress   # one peer, round-trip timings
cargo run -p fectp --example multi_client  --features compress   # six clients, one socket
cargo run -p fectp --example mesh          --features compress   # three peers, all dialling
```

---

## Documentation

| | |
|---|---|
| [USAGE.md](docs/USAGE.md) | How to use it. Every snippet is compiled by `examples/tour.rs`. |
| [SPEC.md](docs/SPEC.md) | Normative wire format — everything an independent implementation needs. |
| [DECISIONS.md](docs/DECISIONS.md) | Why the protocol is shaped this way, and where it departs from the original design note. |
| [ADDING-A-CODEC.md](docs/ADDING-A-CODEC.md) | Supporting a new data type. |
| [BENCHMARKS.md](docs/BENCHMARKS.md) | Measured against UDP, TLS, gzip and Zstandard — including where it loses. |

---

## Licence

BSD 3-Clause. See [LICENSE](LICENSE).
