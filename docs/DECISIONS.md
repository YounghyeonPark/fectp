# FECTP implementation decisions

This records where the implementation deviates from `project_description.md`,
and why. Each entry states the original position, the problem with it, and what
was done instead.

The governing constraints, agreed before implementation:

- **Goal**: fast encrypted transport. The caller sends bytes through an API and
  should experience something close to sending raw packets.
- **Reach**: one codebase from a 32-bit microcontroller to a server.
- **Language**: Rust, `no_std` core. Memory-safety risk in a pre-authentication
  network parser is the deciding factor, and it is worse on an MCU, which has
  no ASLR, no NX, no MMU, and no easy patch path.
- **Floor**: 32-bit MCU. 8/16-bit targets were considered and dropped; see D7.
- **Lossless only**: every codec reproduces its input byte for byte. Lossy
  coding is a non-goal, so where compression is bounded by the data's own
  entropy the bound is accepted rather than worked around. Enforced by
  `every_transform_reproduces_its_input_exactly` in
  `crates/fectp-core/tests/codec.rs`.

---

## D1 — BLAKE2b replaced by BLAKE2s

**Original**: `Noise_IK_25519_ChaChaPoly_BLAKE2b`.

**Problem**: BLAKE2b operates on 64-bit words and loses a large constant factor
on 32-bit microcontrollers. BLAKE2s is the variant designed for 32-bit words.

This is not a per-profile choice. Both peers must use the same hash for the
handshake transcript to agree, so a server on BLAKE2b could never talk to an
MCU on BLAKE2s. The suite has to be fixed protocol-wide.

**Decision**: the suite is `Noise_IK_25519_ChaChaPoly_BLAKE2s` everywhere.
Verified byte-compatible with the `snow` implementation in
`crates/fectp-core/tests/interop.rs`.

## D2 — Zstandard is a negotiated capability, not a mandatory stage

**Original**: compression is stage 1 of a fixed 5-stage pipeline, with a
1-byte header flag choosing the path per payload.

**Problem**: the flag says whether *this frame* is compressed. It does not say
whether the *receiver* can decompress. A Zstandard decoder does not fit on the
smallest supported targets, so a server that compresses toward an MCU produces
a frame the MCU can never decode. The original design has no way to prevent
this, which breaks the stated goal of one protocol across all environments.

**Decision**: peers exchange a capability block during the handshake
(`Capabilities` in `session.rs`). A sender consults
`Session::peer_capabilities()` before compressing.

The capability block travels **inside the encrypted handshake payload**, not in
the header. Putting negotiable parameters in a cleartext header would allow an
attacker to force a downgrade by rewriting bytes. Encrypted, the worst an
attacker can do by tampering is cause a decryption failure.

## D3 — Compression bypass is size-aware, not just type-aware

**Original**: bypass is chosen by payload type — text/JSON compressed,
JPEG/MP4/ZIP bypassed.

**Problem**: incomplete. The original document itself notes Zstandard struggles
below 64 KiB, yet the mapping would compress a 200-byte JSON message. At that
size there is too little context to find redundancy, and any saving is swamped
by the frame's own overhead. The API this protocol exposes carries mostly small
messages, so this is the common case, not an edge case.

**Decision**: four checks in order (`crates/fectp/src/compress.rs`):

1. Can the peer decompress at all? (D2)
2. Is the payload at least `MIN_COMPRESS_SIZE` (1024 bytes)?
3. Does it already look compressed? (magic-number check, as originally
   specified)
4. Did compression actually shrink it? If not, send the original.

Check 4 means a wrong guess costs CPU but never bytes.

## D4 — QUIC is an optional backend, not the base layer

**Original**: stage 3 is "integration with RFC 9000 (QUIC)".

**Problem**: two independent objections.

*Reach*: QUIC cannot run on the smallest supported targets. A full QUIC stack
needs on the order of 100 KB of flash and tens of KB of RAM per connection.
Making it the base layer excludes every constrained device.

*Latency*: QUIC already performs its own TLS 1.3 handshake and its own AEAD.
Layering Noise on top means two serial handshakes and two encryption passes.
The double AEAD costs little in absolute latency, but the extra handshake round
trip is exactly the cost this project exists to avoid.

**Decision**: the core is defined over a datagram `Transport` trait. Plain UDP
is the base backend, because it is the only one every profile shares. QUIC
becomes an optional backend behind the same trait for platforms that want its
congestion control and migration. This also let the transport-layer question
stay open without blocking the core.

## D5 — The frame header carries no negotiable state

**Original**: a 1-byte flag field selects processing behaviour.

**Decision**: the header carries routing and framing only — version, frame
type, session id, sequence number, and per-frame markers describing what the
sender already did (compressed, padded). Anything negotiable lives in the
encrypted handshake payload.

The entire header is the AEAD's associated data, so any modification is a
decryption failure. `every_header_byte_is_authenticated` in
`tests/session.rs` flips every bit of every header byte and asserts each one is
caught.

For handshake frames, message 1's header is used as the Noise prologue, which
binds it into the transcript on both sides.

## D6 — Length-masking padding is implemented but off by default

**Original**: "64-byte block alignment padding" applied unconditionally, framed
as mitigating CRIME and BREACH.

**Two corrections.**

*It cannot be unconditional.* Padding a 10-byte message to 64 bytes is a 6x
expansion. For a protocol whose purpose is low-latency small messages, forcing
that on every frame is the wrong default.

*It does not mitigate CRIME/BREACH.* Those attacks work by having the attacker
influence plaintext that is compressed **together with** a secret, then
observing how the compressed size changes across many probes. Rounding to 64
bytes coarsens the signal and raises the probe count; it does not remove the
signal. The real defence is not to compress attacker-influenced data in the
same context as secrets. FECTP compresses each message independently, with no
shared dictionary across messages, which is what actually limits the exposure —
that property, not the padding, is what should be relied on.

**Decision**: implemented as `Session::set_padding()`, off by default. When on,
the plaintext becomes `u16 length | payload | zeros`, rounded to a 64-byte
boundary. The receiver follows the per-frame flag, so the two directions are
independent and either side may change mid-session. Padding narrows length
leakage from 1 byte to 64 bytes; the documentation says exactly that and no
more.

## D7 — Minimum target is a 32-bit MCU

**Original**: no stated floor.

**Considered**: 8/16-bit (AVR, MSP430). Rejected on two grounds.

*Performance*: X25519 on an 8-bit AVR at 16 MHz takes roughly a second per
scalar multiplication. The IK initiator performs four DH operations, so the
handshake would take several seconds. A device with 2 KB of SRAM also cannot
hold a full-MTU frame buffer. The protocol's defining goal is not achievable
there.

*Toolchain*: Rust's AVR support is nightly-only with known LLVM code-generation
bugs, and MSP430 is tier 3. Supporting those targets means C, which means
giving up memory safety in the pre-authentication parser — on precisely the
class of device where a memory-safety bug is least contained.

**Decision**: 32-bit MCU, at least ~32 KiB RAM. Verified by building
`fectp-core` for `thumbv7em-none-eabihf`.

## D8 — Structural mitigations for parser risk

Beyond choosing Rust:

- `#![forbid(unsafe_code)]` in the core.
- The header is **fixed-size with no variable-length fields**, so parsing an
  attacker-controlled frame involves no length arithmetic before
  authentication.
- Undefined flag bits and unknown versions are rejected rather than ignored.
- The core performs **no heap allocation** and owns no buffers; every operation
  writes into a caller-provided slice.
- Error variants carry no payload, so a rejection reason cannot leak to an
  attacker.
- `curve25519-dalek` uses `fiat-crypto`, whose field arithmetic is formally
  verified.

## D9 — Replay window, because datagrams reorder

Not addressed in the original document, but forced by D4: a datagram transport
drops, duplicates, and reorders, so an implicit monotonic nonce counter is not
usable.

**Decision**: the sequence number travels in the (authenticated) header and
serves as the AEAD nonce. A 64-entry sliding bitmap tracks which sequence
numbers have been accepted. The window is checked before decryption as a cheap
filter but **only updated after the frame authenticates**, so a forged sequence
number cannot advance it and lock out legitimate traffic.

## D10 — Forged frames are dropped, not surfaced as errors

Anyone can send bytes to a UDP port. `Connection::recv` silently discards
frames that fail to authenticate, replay a sequence number, or belong to
another session, and keeps waiting. Surfacing them as application errors would
hand an off-path attacker a denial of service.

## D11 — Typed payload codecs

**Original**: one generic compressor for everything, selected by payload type
only to decide *whether* to compress.

**Problem**: a general-purpose compressor sees only bytes. Multi-channel `i16`
sensor data is the clearest case — in an interleaved buffer, consecutive bytes
come from different channels, which have no reason to resemble each other, so
byte-oriented matching finds almost nothing. Measured on a 4-channel, 512-sample
block of slowly varying `i16`:

| | wire bytes | ratio |
|---|---|---|
| Zstandard on the raw bytes | 4096 | **1.00x** — no saving at all |
| Declared as `i16 x4`, transform then Zstandard | 2055 | **1.99x** |
| Same block delta-coded as if it were one channel | 4092 | 1.00x |

The third row is the point: the win comes from knowing the *channel layout*,
not from delta coding alone.

**Decision**: a codec *registry* rather than a fixed set of codecs. The caller
declares a payload's shape on every send (`Connection::send`) and that selects
a transform.
Adding a new data type later means writing one transform and registering it —
see [`ADDING-A-CODEC.md`](ADDING-A-CODEC.md). Shapes implemented today: Shapes implemented:
interleaved `i16`/`i32` (de-interleave, delta, zigzag, varint) and fixed-size
elements (byte transposition, which is what works for `f32`/`f64` arrays and
fixed-layout records).

Three properties make this safe to expose on a simple API:

- **A wrong declaration costs compression, never correctness.** The payload
  still round-trips.
- **Transforms are negotiated.** `Capabilities.codecs` advertises what a peer
  can reverse; a transform the receiver does not have is never used.
- **Coding is skipped whenever it does not pay.** The codec header counts
  against the saving, and the original bytes are sent if the coded form is not
  smaller.

### Transform and entropy stage are separate

A codec is a transform (pure integer rearrangement) optionally followed by
Zstandard. The transforms need no allocator and no tables, so they live in the
`no_std` core, and **a peer with no room for a Zstandard decoder still gets real
compression** — measured at 1.99x on the block above with no entropy stage at
all. On a full profile the two compose.

### Why there is no cross-message prediction

The obvious extension — first frame plus residuals, as a video codec does — was
considered and deliberately not built. Every codec here works within a single
message.

For actual video the answer is to use a real codec (H.264/AV1) and let FECTP
bypass the result. Most of a real codec's advantage comes from being lossy,
which this protocol is not, so trying to compete inside FECTP is the wrong
trade twice over — naive frame differencing also has no motion compensation,
and sensor noise fills the residual.

That leaves one case where lossless temporal differencing genuinely works:
fixed-camera scientific imaging with a static background, where only a small
fraction of pixels change between frames and the residual really is sparse.
Since lossy coding is off the table, this is *the* case worth revisiting, not
one exception among several.

But cross-message state carries two costs that have to be paid first:

1. **Loss amplification.** One dropped datagram corrupts every message after
   it, on a transport that drops datagrams by design. This needs periodic
   keyframes and reliable delivery of reference messages — which means the
   reliability layer has to exist first.
2. **Compression side channel.** D6 notes that compressing each message
   independently is what actually limits CRIME/BREACH exposure. Sharing a
   compression context across messages removes that defence: attacker-influenced
   data compressed alongside a secret is precisely the CRIME condition. A
   predictive codec would need strict context separation per logical stream.

### Known limitation of the current transform

Varint granularity makes the win a step function. A delta that fits in 7 bits
costs one byte; anything larger costs two, which for `i16` input is no saving
at all. Measured across signal speeds:

| sample-to-sample change | ratio |
|---|---|
| slow | 2.00x |
| medium | 1.44x |
| fast | 1.03x |

Bit-packing — coding a block of deltas at the minimum width they all fit in,
as dedicated time-series codecs do — would turn that step into a curve. It is
the obvious next improvement, not a limit of the approach.

And there is a floor nothing can cross: noise. A 16-bit sample with three bits
of sensor noise carries at least thirteen bits of entropy, and lossless coding
cannot go below it. Crossing it would mean discarding low bits, which is ruled
out — see the lossless-only constraint above. Bit-packing is therefore the
main remaining lossless lever, which is what raises its priority.

## D12 — Reliability is per message, and unordered

**Original**: not addressed. The five-stage pipeline assumes delivery happens.

**Decision**: `Connection::send_reliable` retransmits until acknowledged;
`send` stays fire and forget. Reliability is chosen per message, and both kinds
share one session.

Three points where the obvious design would have been wrong:

**Delivery is unordered.** Guaranteeing order means holding an arrived message
back until its predecessors turn up — head-of-line blocking, the cost this
protocol exists to avoid. An application needing order can sequence its own
payloads; one that does not should not pay for it. Acknowledgements are
therefore selective rather than cumulative, so one gap does not stall
everything behind it.

**A retransmission cannot reuse the frame sequence number**, because that is
the AEAD nonce. So a resent message goes out under a fresh sequence number,
which means the receiver cannot recognise it from the header — the replay
window sees a perfectly good new frame. Reliable messages therefore carry a
`message_id` inside the encrypted plaintext, and the receiver deduplicates on
that. A receiver must acknowledge duplicates too: the sender is resending
precisely because it has not heard back.

**The core reads no clock.** Every entry point in `reliability.rs` takes
`now_ms` from the caller. That keeps the module usable on a microcontroller
with no clock abstraction, and it makes the retransmission tests deterministic
and instant — a test that slept could not probe the exact millisecond a
deadline falls on.

Timeouts follow RFC 6298 with Karn's algorithm (no round-trip sample from a
retransmitted message, whose acknowledgement is ambiguous). The initial timeout
is 200 ms rather than TCP's one second: a second of silence after a dropped
datagram would undo the point of the protocol. The window is capped at 32
outstanding messages, which bounds memory without an allocator and doubles as
crude flow control.

## D13 — Resumption uses a second Noise pattern

**Original**: not addressed.

**Problem**: the `IK` handshake performs four Diffie-Hellman operations per
peer. On a 32-bit microcontroller that is on the order of a hundred
milliseconds, and a device that reboots pays it again every time. It is the
single largest latency cost the protocol has on constrained hardware — larger
than everything the original document's compression discussion addresses, by
orders of magnitude.

**Considered**: caching the static-static (`ss`) Diffie-Hellman, which is
constant for a given peer pair. That is safe and needs no protocol change, but
saves only one operation of four.

**Decision**: a second handshake, `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`,
authenticated by a ticket the previous session established. It performs **one**
Diffie-Hellman instead of four.

Three properties made this the right trade:

**Forward secrecy is retained.** Both peers still contribute fresh ephemerals,
and `ee` mixes them. An attacker who later steals a stored ticket cannot
decrypt a recorded resumed session without an ephemeral private key, and those
are discarded. This is why `NNpsk0` was chosen over a pattern with no
Diffie-Hellman at all, which would have been faster still and much weaker.

**Identity stays bound**, transitively: the ticket comes from an authenticated
`IK` handshake, the same way TLS 1.3 resumption works. The resumed session
still reports the peer's public key even though it performed no static-key
agreement.

**Tickets are single use.** Each handshake, full or resumed, issues the next
ticket, and a responder removes one when redeemed. Without that, a captured
resumption request could be replayed. The cost is that a lost response strands
the client, which then falls back to a full handshake — one wasted round trip,
not a failure.

The ticket identifier is derived from the key (`BLAKE2s("fectp/1 ticket-id" ||
key)[0..8]`) rather than assigned, so the two cannot drift apart and the
responder needs no separate index. It travels in the clear because a responder
must know which key to try before decrypting anything; being a one-way function
of the key, it discloses nothing, and the prologue binds it into the transcript.

The resumption key itself is domain-separated from the transport keys —
`HKDF(ck, "fectp/1 resumption", 2)` against `Split`'s empty input — so
recovering one tells an attacker nothing about the other.

**The subtle part**: in a pre-shared-key pattern the Noise specification
requires that ephemeral public keys be mixed into the chaining key as well as
the transcript. Omitting that `MixKey` yields an implementation that is
self-consistent and interoperates with nothing. The cross-implementation tests
against `snow` cover the resumption pattern in both roles for exactly this
reason.

## D14 — Many peers share one socket, through an event loop

**Original**: not addressed.

**Problem**: the obvious design gives each accepted peer its own `Connection`
holding a clone of the listening socket, filtering out datagrams from other
addresses. That works for exactly one peer. With two, each connection reads
datagrams meant for the other and discards them — traffic vanishes silently,
which is the worst way for it to fail.

**Considered**: a thread and socket per peer. Rejected — a stack and a kernel
object per peer is a strange price for a protocol whose whole argument is
efficiency, and it would need locking around the shared ticket store anyway.

**Decision**: `Endpoint` owns the socket and routes. The frame header already
carries `session_id` for precisely this. `poll` returns an `Event`; one thread,
no locks, no per-peer socket.

**Sessions are keyed on `(address, session_id)`, not the identifier alone.**
The initiator chooses that identifier, and two initiators can choose the same
one — with 32 bits and random selection, a collision is not a remote
possibility at scale. The pair cannot collide. The cost is that a peer changing
address loses its session, so address migration is not supported; a moved peer
resumes instead, which is cheap.

`PeerId` handles are never reused. A handle for a departed peer stops
resolving rather than silently addressing whoever took its place.

`Listener`, the single-peer type this replaced, was subsequently removed: it
duplicated `Endpoint`, worked in only one mode, and carried a trap — while
servicing a connection it was not in `accept()`, so a second connection, a
reconnect included, was silently dropped. An API that needs a warning label is
usually one that should not exist.

### One implementation, two front ends

`Connection` and a `Endpoint` peer run identical sealing, coding, and
reliability logic. Having written it twice, the duplication was removed into
`pipeline::Peer`, which both use. Two copies of security-relevant code drift,
and reliability code drifts silently: a divergence would show up as a rare
retransmission bug, not a compile error.

`Peer` holds no transport. It writes acknowledgements into a caller-supplied
buffer and reports how many bytes to send, so the same code serves an owned
UDP socket and a shared routed one. Like the core reliability layer, it takes
`now_ms` as a parameter rather than reading a clock.

## D15 — Three security modes, chosen and never negotiated

**Original**: one mode, public-key only.

**Problem**: public-key mode requires distributing the responder's key out of
band before anything works. For an instrument wired to its host, or a lab
network, that is a deployment procedure invented to solve a threat that is not
present. The friction was real.

**The reframing that mattered**: the cost is *key distribution*, not
encryption. Encrypting a 1200-byte frame takes about a microsecond, against
~100 ms for one IK handshake on a microcontroller and an unbounded amount of
human effort to get a key to a field site. Turning encryption off would save
the microsecond and leave the actual problem untouched.

**Decision**: three modes, differing in what must be shared beforehand.

| | pre-shared | encrypted | handshake |
|---|---|---|---|
| Public key | responder's public key | yes | `IK`, 4 DH |
| Pre-shared key | one secret | yes | `NNpsk0`, 1 DH |
| Plaintext | nothing | no | capability exchange |

**Pre-shared-key mode carries the weight.** It removes public-key distribution
entirely — both sides configure one secret — while keeping encryption and
forward secrecy, and it cost no new cryptography: it is `NNpsk0`, already built
and already validated against `snow` for resumption. Only the provenance of the
key differs, and one rule follows from that: a configured key is long-lived and
must not be consumed on redemption, where an earned resumption ticket must be.

**Plaintext mode is deliberately narrow.** Two defensible uses: a physically
trusted link, and development, where a readable capture beats confidentiality.
It is documented as *not* the answer to awkward key distribution, because
reaching for it on those grounds gives up authentication to solve a problem
pre-shared keys solve without.

### The property that makes this safe

**Modes are chosen at construction and never appear on the wire as a choice.**
The encrypted and plaintext framings use disjoint frame types, so a peer in one
mode receiving the other's opening frame sees a type it does not accept. There
is no mode field to rewrite and no negotiation to influence — an attacker
cannot talk two encrypted peers down to plaintext, because neither ever
considers it.

A server likewise runs one mode. One that accepted several would let the
client, or anyone impersonating it, pick the weakest on offer.

`tests/modes.rs` asserts every crossing fails: plaintext to encrypted,
encrypted to plaintext, public-key client to pre-shared-key server, wrong
secret. It also checks that codecs and reliable delivery behave identically in
all three, which is the point of the `Link` abstraction beneath them.

## D16 — One socket, both directions

**Original**: the document calls FECTP a peer-to-peer protocol; the
implementation had grown a `Server` that only accepted, and a `Connection` that
only dialled.

**Problem**: a node that wanted both had to hold two sockets — a bound one for
inbound, an ephemeral one per outbound connection. On a LAN that is merely
untidy. Behind a NAT it does not work: **a NAT maps a local port**, so a node
dialling out from one port cannot be reached on the mapping that traffic
created if it listens on another. One socket is the precondition for hole
punching, and therefore for internet peer-to-peer at all.

**Decision**: `Server` became `Endpoint`, and gained `connect`. It binds one
socket and uses it for both directions.

The naming mattered more than it looks. "Server" suggested a property of the
node; the asymmetry is only ever a property of a *connection* — who spoke
first. After `Split` the two sides hold mirror-image cipher states and every
operation is available to both, which `tests/peer_to_peer.rs` asserts by having
the responder send reliably and typed to the initiator.

### `connect` does not block

It sends the opening frame and returns a `PeerId`; the handshake completes when
the reply arrives, as `Event::Connected { initiated: true }`. A blocking dial
would stall an event loop that is also serving other peers, which is precisely
the situation an endpoint is in.

The consequence is that a handshake needs its own retransmission — a lost
opening frame would otherwise strand the attempt silently. Four attempts with
linear backoff, then `Event::ConnectFailed`. Silence is reported rather than
waited on.

### What a forged reply can do

A reply is matched on (source address, session id) and then fed to the pending
handshake, which consumes it. If it fails to authenticate the attempt ends with
`ConnectFailed` rather than being retried, because the handshake state is gone
either way.

Reaching that deliberately means guessing a random 32-bit session identifier
*and* spoofing the peer's source address, and the cost of success is one failed
connection the caller can retry. That is an acceptable trade against holding
half-open handshake state for anyone who sends a plausible-looking datagram.

### Still missing for internet peer-to-peer

One socket is necessary but not sufficient. Peer discovery, STUN-style address
reflection, and the hole-punching handshake itself are all absent; what exists
is the property they depend on.

---

## Known gaps

These are unimplemented, not overlooked.

| Gap | Consequence | Notes |
|---|---|---|
| **Ordering** | Reliable delivery is unordered by design (D12). | Not a gap so much as a decision; an application needing order sequences its own payloads. Measured against a same-delay control, reordering costs nothing (BENCHMARKS.md §10). |
| **Ticket expiry** | Tickets are bounded in number but have no lifetime. | A responder evicts oldest-first at 256; time-based expiry is unspecified. |
| **Plaintext mode misuse** | Nothing stops an operator choosing plaintext where it is inappropriate. | The API and documentation steer towards pre-shared keys; a protocol cannot enforce judgement. |
| **NAT traversal** | One socket serves both directions (D16), but there is no discovery, address reflection, or hole-punching coordination. | Those are separable problems built on the socket property, not changes to it. |
| **Address migration** | A session is bound to its peer's address. | Keying on the pair is what avoids session-id collisions (D14); supporting migration would need a different scheme. Measured: a peer reappearing on a new source port is a stranger and the session ends (BENCHMARKS.md §10). |
| **Answering inside the handshake** | An `Endpoint` receives data sent with a handshake but always replies with an empty payload, so the responder's half of 0-RTT is unreachable through the public API. | The protocol supports it — `Responder::write_response` takes a payload — and `Connection` delivers it through `recv` (D27). Only the endpoint has no way to supply one. |
| **Path MTU discovery** | Frame size is fixed at 1200 bytes or the peer's advertised limit. | Fine on a LAN; a real network path may be smaller. |
| **Tail latency under load** | One socket and one loop serve every peer, so a request arriving behind a burst waits for it. | Measured with 23 busy peers, the median is unchanged and p95 grows about fivefold (BENCHMARKS.md §11). A consequence of D14, not a defect in it. |
| **Rekeying** | A session ends after 2^64 frames. | Not reachable in practice, but the error path exists (`Error::NonceExhausted`). |
| **QUIC backend** | Only UDP exists. | The `Transport` trait is the seam. |
| **Bit-packed deltas** | Delta coding only pays when deltas fit in 7 bits (see D11). | Block-wise bit-packing would make the ratio track the signal smoothly instead of stepping. |
| **Cross-message prediction** | No temporal/residual codec. | Needs the reliability layer plus keyframes first; see D11. |
| **Post-quantum** | X25519 only. | The original document's versioning plan still holds: the suite name is fixed per version, so a PQC suite becomes a new version rather than a negotiation. |

## D17 — The compression level was raised after measuring it

**Original**: the document recommends Zstandard at `--fast=4` (level −4), on the
reasoning that a latency-sensitive transport cannot afford a slow compressor.
The implementation took that as `compress::LEVEL`.

**Problem**: measured, level −4 does not compress structured binary data at
all. On the four binary datasets in `BENCHMARKS.md` §7 it produces *more* bytes
than it is given — 8202 from 8192 — so the payload goes out raw. Level 1 gets
1.67x on the same input.

The reasoning that picked −4 counts only half the clock. A send costs encode
time **plus** bytes over the link, so a level costing `dt` more and saving `db`
bytes is the faster choice on any link slower than `db / dt`. For this data
that threshold is 437 Mbps to 2.6 Gbps — above every real network it will run
on. Declaring a payload type does not rescue the low level either: sensor data
goes from 2.00x to 3.46x and an `f32` table from 5.43x to 8.21x.

**Decision**: `LEVEL` is 1. Nothing on the wire depends on it — SPEC §7 already
required a receiver to accept any level, so this is a sender-side default that
any implementation may set differently.

The one case the old level suited is a link fast enough that bytes are cheaper
than cycles. That is not the case this protocol is for, and a sender that finds
itself in it can change the constant without coordinating with anyone.

## D18 — Compression stops being attempted when it stops working

**Problem**: coding cost a few microseconds per send whether or not it
achieved anything, and the send path paid it on every message. For a stream
that never compresses — encrypted blobs, random telemetry, anything already
packed — that is a pure loss repeated forever, and it is 21% of a plaintext
send.

**Decision**: the send path counts consecutive attempts that did not shrink the
payload. After four it stops attempting, and retries once every 32 sends.
Plaintext sends fell from 9.41 µs to 7.45 µs, encrypted from 10.83 µs to
9.21 µs. Compressible streams are untouched: the counter never advances.

Two properties keep this from being a trap. It is invisible on the wire, since
an uncompressed frame is a valid frame and a flag says which one arrived. And a
payload too large to send raw is *always* coded regardless of the counter,
because for those, coding is the only thing that makes the send legal at all —
an optimisation must never be the reason a correct call fails.

Retrying periodically rather than giving up matters for the same reason the
codec registry exists: what a connection carries can change. A channel of
opaque bytes that starts carrying text should start compressing again, and 32
sends bounds how long it takes to notice.

## D19 — Messages larger than a frame are cut at the protocol layer

**Problem**: a payload above `max_payload` could not be sent at all. That is a
hard ceiling of about 1170 bytes on a general-purpose transport, and it has
nothing to do with the protocol's purpose — it is the path MTU showing through.

The reason FECTP never emits an oversized datagram is sound: IP fragments it,
and an IP-fragmented datagram is lost entire if any one of its pieces goes
missing, so the loss probability multiplies by the number of pieces.

**Decision**: cut the message at the protocol layer instead, where each piece
is a frame in its own right. A fragment descriptor — logical message, index,
count — rides inside the encrypted plaintext, gated by `FLAG_FRAGMENT`, so an
unfragmented message pays nothing for the feature.

Three consequences worth stating rather than discovering:

**Fragments are always reliable.** A message missing one fragment is entirely
undeliverable, so fragments that could vanish without recovery would make the
whole thing pointless. This is the first place the coding layer depends on the
reliability layer.

**The in-flight bound doubles as the send window.** A split message waits when
the window is full rather than queueing the lot. That is what keeps a
burst from outrunning the receiver's socket buffer — a 6 MB message emitted at
line rate would overflow a default 64 KB buffer many times over and lose most
of itself. It also caps throughput at one window per round trip, which is the
honest limit of doing this without congestion control.

**Coding is per fragment, not per message.** Each frame stays self-describing,
which a receiver can act on without waiting for the rest, at the cost of the
compressor seeing one fragment of context instead of the whole message.

**Neither side waits.** Both types queue what will not fit and feed it out —
`Connection` from `recv`, `flush` and later sends, `Endpoint` from `poll`. On an
endpoint the outcome arrives as `Event::Sent { delivered }`, since there is
nothing there to block on; on a connection `flush` reports it. The queue is
bounded per peer either way, because each entry holds its payload until
acknowledged.

See D25 for why this ended up as one method rather than two.

## D20 — A sender may not outrun the acknowledgement window

**Problem**: found by injecting packet loss into the benchmark. A 256 KiB
fragmented message did not merely slow down at 1% loss — it failed, every time.
Dropping exactly one fragment of a 199-fragment message showed why: dropping
fragment 6, 20, 60 or 100 lost the message; dropping 140, 180 or 195 recovered
it in about 215 ms. The boundary sits where the remaining stream is 64 long.

An acknowledgement names a highest identifier plus a bitmap of the 64 below it
(D12). Once the sender has issued more than that many identifiers past a stuck
message, no acknowledgement can name it, and its retransmissions arrive outside
the receiver's replay window and are discarded as stale. It is lost however many
retries remain.

**The trap** is that bounding how many messages are unacknowledged *at once*
looks like it prevents this, and does not. The stuck message holds one of 32
slots while the other 31 keep cycling, so the identifier space runs hundreds
past it. `MAX_IN_FLIGHT` is a memory bound; it is not a window.

**Decision**: `register` refuses an identifier more than `ACK_WINDOW` ahead of
the oldest unacknowledged one, so the sender stalls until that message is
resolved one way or the other. `SPEC.md` §5.5 states it as a sender MUST rather
than as quality of implementation, because a receiver conforming to the
deduplication rules will silently fail to deliver what a violating sender
sends — the failure is invisible on the receiving side.

This was never specific to fragmentation. Any reliable stream that keeps sending
while one message is stuck would lose it; `send_large` merely reaches the
condition easily, because it feeds the window rather than waiting on it.

## D21 — The first retransmission uses the measured timeout

**Problem**: with D20 fixed, a single loss still cost about 200 ms where the
measured round trip justified 20 ms.

A message's first timeout was `max(INITIAL_RTO_MS, current)`. But `current`
already answers `INITIAL_RTO_MS` while no round trip has been measured, so the
maximum did nothing except pin the first timeout at 200 ms for the life of the
session — making `MIN_RTO_MS` unreachable exactly where it decides how fast a
loss is noticed. Retransmissions after the first used the measured value, so the
backoff was not even monotonic: 200 ms, then 40 ms.

**Decision**: use `current` alone. Measured over the loss benchmark, 100
messages at 1% loss went from 463 ms to 279 ms, and a 256 KiB fragmented message
at 1% loss from 419 ms to 62 ms.

The conservatism this removes is real but misplaced. Guarding against spurious
retransmission is what the round-trip estimate is *for*; refusing to use it
below 200 ms discards the measurement rather than acting on it.

## D22 — Both directions on one shared reference

**Problem**: `Connection::send` and `recv` both took `&mut self`, so a program
could not have one thread reading while another wrote. That was an API limit
rather than a protocol one: after the Noise split the two directions hold
separate cipher states, and one UDP socket may be sent on and received on at
once.

Three shapes were tried before the right one, and the two that were discarded
are worth recording because each looked reasonable.

**`split()` into two halves** fails on acknowledgements. An acknowledgement is
an encrypted frame in the send direction, so the receiving half has to send;
and retransmission has to happen whether or not the application is asking for
anything. Split the connection and both stay on the receiving half, so the
halves are not peers — the sender's reliability silently depends on someone
draining the receiver, and nothing in the types says so.

**`into_duplex()` onto a background thread** removes that contract but adds a
concept. The caller has to know the conversion exists, decide when to use it,
and learn two more types; and every connection that wants both directions pays
a thread and an allocation per received message. It was built, measured, and
removed.

**Decision**: the methods take `&self`. A shared `&Connection` is then all
either thread needs — scoped threads work directly, and an `Arc` is available
to anyone who wants `'static` ones without the API insisting on it. There is no
second type, no conversion, and nothing to remember.

Internally the receive path holds its own lock — a second handle on the same
socket, plus its buffers — so a blocking read never holds the lock a send
takes. The shared state is the reliability layer, held for microseconds.
Measured idle, the lock costs less than the send-path benchmark can resolve.

What this does **not** change is where retransmission is driven: still inside
`recv`, `flush` and the send calls, as before. A program that sends reliably
and then calls none of them will not retransmit. That is the same contract
`Connection` has always had, and `flush` is the answer to it — but it is the
one thing the discarded thread-based version did better, and the trade was
made deliberately for an API with fewer parts.

## D23 — The microcontroller premise, measured

**Problem**: the project was scoped around running on a 32-bit microcontroller,
and that premise had never been checked. What `DECISIONS.md` carried was a
pre-link upper bound — the core's own code at about 21 KiB, plus roughly 95 KiB
of crypto dependencies *before* dead-code elimination. Read together that is
about 116 KiB, which is enough to rule the protocol out on a lot of parts. It
is also not a number anyone can plan with, because most of `curve25519-dalek`
is never reached and the linker discards it.

**Measured**: `crates/footprint` links a real image for `thumbv7em-none-eabihf`
with fat LTO, `opt-level = "z"` and `--gc-sections`, driving a full public-key
handshake in both roles, a sealed and opened data frame, and the codec path so
nothing that matters is discarded.

| | flash |
|---|---|
| full protocol | 22,572 bytes |
| the same image with the protocol removed | 36 bytes |
| **FECTP** | **22,536 bytes (22.0 KiB)** |

The estimate was five times too pessimistic. RAM is smaller still: 294 bytes of
session state, or 1,334 with the reliable-delivery queue, plus whatever buffers
the caller supplies — about 3.7 KiB for a full-duplex reliable session at the
default frame size (`cargo run -p fectp-core --example sizes`).

**Decision**: the premise holds, and the estimate is replaced by the
measurement. On a Cortex-M4 with 256 KiB of flash and 64 KiB of RAM — a small
part by current standards — this is 9% of the flash and 6% of the RAM.

The footprint crate sits outside the workspace deliberately: it only links for
a bare-metal target, and its profile differs from the workspace's because the
numbers mean nothing without LTO, size optimisation and section garbage
collection all on. A conformance test pins the structure sizes, so a change
that quietly doubles what a constrained peer must hold fails a test rather than
someone's board.

## D24 — The send window answers to the path, not just to memory

**Problem**: `MAX_IN_FLIGHT` bounded how many messages could be outstanding, and
it was described as "crude flow control". Measured, it was not flow control at
all. Against a 1 Mbit/s link with an 8 KiB queue, **46.5% of everything the
sender offered was dropped by the full queue** and then recovered by a
retransmission timer (BENCHMARKS.md §10). The sender had no way to learn that
the path could not take what it was giving it.

The gap is easy to mistake for a small one, because the bound *looks* like a
window. It is not: it bounds memory, which is a property of this host, and says
nothing about the path.

**Decision**: a congestion window sits in front of the slot count, and
`register` refuses when it is full. It opens at 4 messages, doubles per round
trip while below a threshold, then grows by one message per round trip; a
retransmission timer firing halves the threshold and collapses the window to 2.

Two details are forced by what this protocol already is.

**The loss signal is the timer alone.** There is no duplicate-acknowledgement
path, because an acknowledgement here reports the whole receive window rather
than repeating the last in-order identifier — the same property that makes
losing an acknowledgement nearly free (BENCHMARKS.md §11). So the only signal
available is the severe one, and the response is the severe one to match.

**The window is fixed-point, not floating.** Congestion avoidance grows by a
fraction of a message per acknowledgement, and the core targets
microcontrollers that may have no FPU. One counter is not worth a soft-float
dependency.

Measured, the 1 Mbit/s row falls from 46.5% to 2.4-4.7% across runs, and the
sender offers 257 datagrams where it used to offer 469.

**What it costs**: a loss-free path is about 12% slower on a large transfer,
because the window ramps from 4 rather than starting at 32. And
`send_reliable` now fails with `WindowFull` sooner and less predictably — after
four messages on a new connection rather than thirty-two. That is not a
regression to hide: a sender that must sometimes wait is what congestion
control *is*, and `flush` is how it waits.

This is one algorithm, not the right one for every path. It is loss-based, so
it fills a bottleneck queue before it backs off — which adds the queueing delay
this protocol otherwise works to avoid. A delay-based controller would suit the
latency argument better and is the obvious next thing to try; it is also much
harder to validate without real paths, and this one is measurably better than
nothing.

## D25 — One reliable send, whatever the size

**Problem**: `send_reliable` refused anything above one frame and `send_large`
existed beside it, so the caller had to choose. Choosing meant comparing their
payload against `max_reliable_payload()` — a number that **depends on what the
peer advertised at handshake** and therefore differs per connection. A
microcontroller peer advertises less than a desktop one.

Asking an application to branch on a number it cannot know in advance is the
wrong shape, and it is exactly the kind of thing this protocol set out not to
make people think about.

**Decision**: `send_reliable` takes any size and splits when it has to.
`send_large` is gone.

Two consequences worth stating.

**`send_reliable` returns `()` rather than a `MessageId`.** A split message is
many reliable messages, so there is no single identifier to hand back. Nothing
was lost: no API ever accepted a `MessageId`, so it was a value nobody could
act on. `flush` is how delivery is observed, as it always was.

**`send` still refuses anything larger than a frame.** Splitting a payload that
cannot be retransmitted fails whenever any one piece goes missing — for 200
fragments at 1% loss, nine times out of ten. Unreliable fragmentation is a trap
rather than a feature, so the unreliable call keeps the limit and the reliable
one does not. That also answers the question the old API left open: for a large
payload there is only one call that accepts it.

The queue that feeds fragments out moved from `Endpoint` into `Peer`, so both
types share it rather than growing two of them.

## D26 — Every way of connecting has the same timeout

**Problem**: writing the API reference made the constructors' shape visible.
Nine of them, and the timeout argument applied unevenly: `connect` took none
while `connect_with_timeout` sat beside it, and `connect_psk`, `connect_plain`
and `resume` all required one.

Looking for the reason turned up something worse than untidiness. `connect` did
not have a *default* timeout — it had **none**, and `connect_with_timeout`
existed as the way around that. Measured against a bound port that accepted
datagrams and answered nothing, `Connection::connect` blocked for ever.

That is not a hang anyone would notice in testing, because a responder that
cannot authenticate a frame **drops it silently**: there is no reply and no
error, so a handshake aimed at an unreachable peer or the wrong static key has
nothing at all to wait for.

**Decision**: `HANDSHAKE_TIMEOUT` applies to every constructor, and none of them
takes a timeout argument. `connect_with_timeout` is gone. Nine constructors
become eight, all the same shape: four modes, each with a variant that carries
0-RTT data.

Five seconds is generous for a satellite path and short enough that an
unreachable peer is reported rather than waited on. It is fixed rather than
configurable, because nothing so far needs a different value and a parameter
that exists "just in case" is how the inconsistency started.

Two tests pin it: one connects to a silent port and requires the call to
return, and one does the same for every mode whose argument was removed.

## D27 — Data sent with the handshake is data, not a request

**Problem**: two things, found by being asked what `zero_rtt` was by the person
who commissioned the protocol.

The first is naming. The constructors were `connect_with_zero_rtt` and friends,
and the documentation described the payload as a "request" with `GET /status`
for an example. That framed a **data transport** as an RPC. This protocol was
built to move sensor readings and streams; a stream has no requests in it. The
vocabulary came from TLS and HTTP and did not belong.

The second is shape. Those constructors returned `(Connection, Vec<u8>)` — the
connection and whatever the peer said back — so half the ways of connecting
returned a tuple and half did not, and a caller had to learn that before using
any of them.

**Decision**: the payload is the first data, so it is named for that and it
travels the way data travels.

- `connect_and_send(addr, key, identity, first)`, `resume_and_send`,
  `connect_psk_and_send`. The verb matches the rest of the API.
- Every constructor returns `Result<Self>`. What the peer sends back goes into
  the same queue `recv` reads from, because it *is* the peer's first message,
  not a different kind of thing.
- Plaintext loses its variant entirely. It is for loopback and trusted links,
  where saving one round trip does not justify a way of connecting.

Eight constructors become seven, all the same shape.

**A thing worth recording**: the `Vec<u8>` that was removed was *always empty*.
`Endpoint` answers every handshake with `&[]`, so nothing in this codebase
could ever put anything there. It was API surface for a value no caller could
receive. The protocol supports it — `Responder::write_response` takes a
payload — so the gap is on the endpoint side and is now listed as one.

**And a correction to the benchmark.** `BENCHMARKS.md` §3 said its round-trip
table was "the entire argument for FECTP" without saying that the saving is
*once per connection*. Spread over ten thousand messages it is 30 µs each,
comparable to the protocol differences §2 measures; over a million it is
nothing. The table is decisive for short connections — a sensor that wakes,
reports and sleeps — and close to meaningless for one that stays open and
streams. The condition is now stated, with the arithmetic.

## D28 — The payload's shape is an argument, not a setting

**Problem**: there were two ways to declare a shape and four ways to send. A
setter fixed a default for the connection, `send` used it, and `send_typed`
overrode it for one message — the same again for reliable sends, and the same
again on `Endpoint`. Eight methods where two would do.

The count was the smaller half. The setter meant this line:

```rust
conn.send(&data)?;
```

did something different depending on a call made somewhere else, possibly in
another function. Forgetting the setter cost compression **silently** — no
error, no warning, just a worse ratio nobody would notice. That is a bad shape
for a knob whose only effect is invisible.

**Decision**: `send(data, shape)` and `send_reliable(data, shape)`. The setter
and the `_typed` twins are gone; 50 public methods become 43.

Naming a shape at every call is not the burden it looks like. `PayloadType` is
two bytes and `Copy`, so a stream binds it once to a local and passes it:

```rust
let shape = PayloadType::I16 { channels: 4 };
conn.send(&samples, shape)?;
```

That gives what the setter was for — one place to change the channel count —
without letting a send inherit a shape from a call it cannot see.

**What it costs**: a program that never compresses anything must still write
`PayloadType::Opaque` on every send. That is a real tax on the simplest case,
and it was weighed against keeping `send(data)` as an opaque-only shortcut. The
argument that settled it is that two calls with one obvious rule beat four
calls with a rule about which is which.

## D29 — The documentation is compiled, not transcribed

**Problem**: the examples in `README.md` and `docs/USAGE.md` had drifted from
the API and nothing noticed.

Six calls still passed a timeout argument that [D26](#d26--every-way-of-connecting-has-the-same-timeout)
had removed three commits earlier. One `match` arm was a field short of the
`Event` it destructured, so a reader who pasted it got a compile error. The
import list in the front-page example omitted a type the example used.

This was not for want of testing. `examples/tour.rs` exists precisely to keep
the guide honest, 189 tests passed throughout, and a documentation pass had
just been made over these files. The reason it missed is structural: the tour
is a **transcription**. It reimplements what the guide describes in a separate
file, so the two are copies, and a copy compiles perfectly well after the
original goes stale. It proves the API works. It cannot prove the guide
describes it.

**Decision**: `build.rs` extracts every ```` ```rust ```` block from those two
documents and `tests/doc_snippets.rs` compiles them. The document is the input,
so a snippet that no longer matches the API is a build failure.

A fragment is written for a reader — `conn.send(..)` with no twenty lines
above it — so each block is wrapped in a function with a prelude supplying the
usual bindings. The functions are compiled and never called, so the prelude may
bind a socket without cost, and an unreachable tail is expected rather than a
defect.

A block that illustrates rather than runs — a list of signatures, an enum's
variants — opts out with `<!-- doc-check: skip -->` above its fence. An HTML
comment because it is invisible on GitHub, where these files are read.

**What it costs**: the prelude is a maintained list of names. A snippet that
introduces a new variable needs a line added, and the failure mode is a build
break on an unrelated change. That is the price of the check being a real
compile rather than a pattern match, and a pattern match would not have caught
the arity change, which is the bug that motivated this.

**What it does not cover**: prose. "Not built: congestion control" survived
three commits after congestion control was built, and no extractor catches
that. `docs/API.md` has its own guard for the constants it quotes; the claims
in between are still held by nothing but reading them.

## D30 — Every parser is driven with input nobody wrote

**Problem**: every decoder in the protocol reads bytes chosen by someone else,
and every test of them used bytes a person thought to write.

That is the gap the ACK-window bug went through: it lost messages outright
while 179 example-based tests passed. Example tests check the cases their
author imagined. A parser's interesting inputs are the ones nobody imagined.

**Decision**: `crates/fectp-core/tests/malformed_input.rs` drives every decoder
with generated input — `proptest`, on stable, because `cargo-fuzz` needs
nightly and libFuzzer and this project builds on Windows.

`#![forbid(unsafe_code)]` already rules out memory corruption, so the two
failures worth hunting are narrower than "a crash":

- **A panic** is a remote denial of service. One socket and one loop serve
  every peer ([D14](#d14--many-peers-share-one-socket-through-an-event-loop)), so a
  datagram that panics the loop takes every other peer down with it.
- **A wrong accept** is quieter and worse: a decoder returning `Ok` for bytes
  its own encoder could not have produced hands the layer above a value it
  will trust.

So each property is one of three: it terminates without panicking on any input;
what it accepts re-encodes to the same bytes, so no value has two spellings;
what it accepts satisfies the invariant the next layer assumes. Frames get two
more — a real frame with one byte flipped, and a real frame truncated — because
those reach the arithmetic that peels the optional prefixes, which the header
checks pass rather than reject.

**What it found**: the varint decoder accepted overlong encodings. `[0x80,
0x00]` decoded to zero, which the encoder writes as `[0x00]` — two spellings of
one value, and it took both.

The honest severity is low. The codec runs on plaintext `Session::open` has
already authenticated, so reaching it needs the session key; this was
malleability between implementations, not a way in. It is fixed because the
encoder never emitted the longer form, so accepting it bought nothing, and
because the same principle already governs the frame header, which rejects
undefined flag bits rather than ignoring them
([SPEC §4](SPEC.md)). Tightening now is easy; tightening after another
implementation depends on the laxity is not.

`docs/SPEC.md` §6.2.2 states the rule normatively and
`tests/spec_conformance.rs` pins it, which it did not before — the section had
a MUST and no test.

**What it costs**: `proptest` as a dev-dependency, and a suite whose failures
are random rather than reproducible. The second is handled: proptest records a
failing seed in `tests/malformed_input.proptest-regressions`, which is checked
in, and the case it found is also pinned as a named test so it does not depend
on the seed file surviving.

**What it does not cover**: the state machines. These properties are about
parsers — one input, one output. The bug that motivated the file was in the
retransmit queue's *sequence* of operations, which needs a stateful model to
find. That is [D34](#d34--the-sequence-a-bug-needs-is-not-always-one-a-generator-finds).
Nor is any of this a security audit; it is the part of one that can be
automated.

## D31 — The handshake is retransmitted, like everything else

**Problem**: `Connection` sent its opening frame once. If that datagram or its
reply went missing, `connect` waited the full `HANDSHAKE_TIMEOUT` and failed.

The protocol has retransmitted data frames since [D12](#d12--reliability-is-per-message-and-unordered),
and `Endpoint` resent the handshakes *it* started — four attempts, 250 ms
linear backoff — from the moment outbound dialling was built. Only the blocking
client did not, which left the simpler of the two APIs the less robust one, and
that is the wrong way round: `Connection` is what a first program uses.

The consequence was not subtle. One lost packet in either direction meant a
five-second stall and a failed connection, on a protocol whose stated purpose
is a device that wakes, sends one reading, and sleeps. A 1% loss path fails
about 2% of connections outright.

**How it surfaced**: as a flaky test. The `modes` suite failed roughly one run
in six, on a different test each time, always with a handshake timeout.
Diagnosing it as "the test machine is loaded" would have been true and useless:
Windows loopback UDP does drop datagrams under load, and the protocol had no
answer for that anywhere a handshake was involved.

**Decision**: `Connection` retransmits on the schedule `Endpoint` already used,
bounded by the same `HANDSHAKE_TIMEOUT`, so a peer that is genuinely absent is
still reported in five seconds — it now costs about six datagrams to establish
that rather than one.

`tests/handshake_loss.rs` puts a relay in the path and drops specific frames:
the opening one, the reply, and three in a row. All three fail without the
retransmission and pass with it, which is the only thing that makes them worth
having. A fourth test pins the other direction — that retrying has not turned
"nobody is there" into an unbounded wait.

**What it does not fix**: the responder still keeps no state for a handshake it
has answered, so a repeated message 1 is answered afresh. That is correct for
`IK` — the reply is deterministic given the same message — but it does mean a
replayed opening frame costs the responder four X25519 operations. Bounding
that is unsolved and belongs with the rest of the denial-of-service surface.

## D32 — A stranger's handshake is bounded, in memory and in work

**Problem**: reaching the handshake needs nothing but the endpoint's public
key, which is public by design. Anyone can complete one, and the peer was filed
before the application heard about it — which is the first point at which it
could have said no.

`examples/keys.rs` demonstrates the path on purpose: its "stranger" holds a
perfectly valid key, connects, and is refused *afterwards*. The four X25519
operations and the table entry are spent either way.

Measured rather than assumed: a single-threaded attacker on loopback files
**34 sessions a second** and never sends a byte. That is a floor — it politely
waits for each reply, where a real flood would not. Nothing bounded the table,
and nothing expired an idle session, so at 294 bytes of state each this fills
the 32 KiB of the microcontroller this protocol is for in about four seconds.

**Decision**: two bounds, because one is not enough.

[`MAX_PEERS`] caps the table. When it is full the peer dropped is the one that
has been there longest **and never sent anything** — falling back to plain
oldest only when every peer has spoken. That distinction is the whole point:
completing a handshake costs an attacker nothing and proves nothing, while
sending an authenticated frame afterwards is the first thing that does. Plain
oldest-first would evict the established session and keep the flood.

[`MAX_HANDSHAKES_PER_SECOND`] caps the work — at 512 a second, which is not
the number this shipped with. It was 64, chosen by feel rather than from the
0.66 ms a handshake actually costs, and 64 would have throttled a fleet of
devices that wake, report and sleep to a small fraction of what one core can
serve. That is this protocol's own traffic, refused to protect it. Both bounds
are settable now, for the same reason `MAX_PEERS` was. The table bound alone would leave
an attacker buying four X25519 operations for the price of a datagram
indefinitely, since evicting always makes room. The limit is on *new* sessions
only — established peers are routed without passing through it, so a flood
slows connection setup and leaves everything already connected alone.

**What it costs**: during a flood, a legitimate new peer competes for the same
budget and may have to retry. That is unavoidable without a cookie exchange,
and a cookie costs the round trip that carrying data in the first packet
exists to save. The trade taken here is that setting up a new connection
degrades while established ones do not.

`MAX_PEERS` is a default rather than a fixed value — `set_max_peers` overrides
it. A microcontroller wants far fewer and a large server may want more, and
neither is served by one number compiled in.

**How the tests were wrong first**, twice, because it is the same mistake both
times. The first version asserted only that an established peer still worked
after a flood — true before any of this existed. The second stopped the flood
on reaching the limit and then asserted the limit had not been exceeded, which
is true by construction. The third counted how often the honest peer was
served, which a peer evicted one second in still satisfies from before it
happened. Only the fourth — does the honest peer survive to the *end* — fails
against plain oldest-first eviction, which is the thing it is meant to
discriminate.

And then the fourth was flaky, about one run in six, for a reason that had
nothing to do with the code under test: the honest peer sits in `recv` while
the loop that answers it has already stopped, times out, and reports being
evicted when it was only abandoned. The loop now drains before joining. A test
that fails at random is worse than no test, because what it teaches is to
ignore a red run.

**What was left, and is now done**: see [D33](#d33--a-repeated-opening-frame-is-answered-from-what-was-kept).
The responder answered a repeated opening frame afresh, which turned out to be
worse than the wasted arithmetic it looked like.

## D33 — A repeated opening frame is answered from what was kept

**Problem**: the responder handshaked again every time it saw message 1.
[D32](#d32--a-strangers-handshake-is-bounded-in-memory-and-in-work) recorded
this as the arithmetic being paid twice. It is worse than that.

Sessions are filed by address and identifier (D14), and filing a new one
**replaces** what that pair already had. A replayed opening frame carries a
specific peer's identifier, so answering it afresh destroys the session it
names. One captured packet, sent again, cuts off one chosen peer — a good deal
more pointed than making a server do arithmetic, and it was reachable by anyone
who could capture a datagram.

Measured by doing it: a relay keeps the first frame it forwards and sends it
again later. Before the change the client's next message went unanswered and
`recv` timed out; the test that does this is `handshake_flood.rs`.

The same path is now ordinary rather than hostile, which is what brought it to
attention. Since [D31](#d31--the-handshake-is-retransmitted-like-everything-else)
the client resends its opening frame whenever a reply goes missing, so a
responder sees message 1 twice as a matter of course.

**Decision**: never handshake twice for the same pair. The response is kept
with the session and sent again if the frame repeats; once the peer sends an
authenticated frame it has evidently received the response, so the copy is
dropped and any further repeat is ignored.

Resending is safe in a way that answering afresh is not: the bytes are ones the
attacker already has, so nothing is disclosed, and no session is created or
replaced.

**What it costs**: the response is held per session until the peer speaks —
about a hundred bytes each, and only for peers that have not yet said anything.
Resends are capped per session, because a cheap answer to a cheap frame is a
reflector otherwise: an attacker spoofing an address it does not control could
have one datagram sent for each one it sends. A client resends its opening
frame a handful of times at most within the handshake timeout, so a small
allowance covers every honest case and nothing else.

**What is still open**: a replay from a *different* source address is a new
pair, so it is a new handshake and costs the four operations. That is bounded
only by the rate limit of D32. Distinguishing it would need a cookie exchange,
and a cookie costs the round trip that carrying data in the first packet exists
to save.

## D34 — The sequence a bug needs is not always one a generator finds

**Problem**: [D30](#d30--every-parser-is-driven-with-input-nobody-wrote) said
what it did not cover — the state machines — and named the ACK-window bug as
the thing that got through because of it. This is that gap.

`tests/reliability_model.rs` drives the sender and receiver against each other
through generated orderings: send, lose selectively, deliver, acknowledge, lose
the acknowledgement, let time pass. It checks that nothing is delivered twice,
that nothing is acknowledged that never arrived, and that nothing is discarded
as a duplicate that was not one.

**The generated sequences do not find the original bug.** That is worth saying
plainly, because four versions of this file were written on the assumption that
they would.

- The first modelled loss per *step* — "this round arrives" — which cannot
  express one message failing while everything around it succeeds, since the
  moment a round succeeds the stuck message is delivered with the rest. Loss is
  per message now.
- The second asserted "every message is delivered or explicitly given up on".
  Being given up on is the *visible half* of the failure, not an acceptable
  outcome, so the property tolerated exactly what it was meant to catch. The
  precise claim is that a message discarded as a duplicate must actually be
  one.
- The third had the right property and still passed, so the state was measured
  rather than reasoned about: the sequences run **32** identifiers past an
  outstanding message, the slot count, where the failure begins at **64**. A
  throwaway harness reached it, at two orders of magnitude more steps than a
  test suite can afford.

**Decision**: keep the properties, and add a directed test beside them.
Random search is good at states nobody thought of and bad at deep ones. The
ACK-window failure has a known shape — one message that never arrives while
ordinary traffic keeps cycling around it — so
`a_sender_may_not_outrun_what_the_receiver_can_still_name` constructs it. With
the guard removed it fails, reporting the sender 192 identifiers ahead of a
message the receiver could reach back only 64 for. With the guard it passes.
That is the discrimination the properties do not provide.

The diagnostic that measured the reach is checked in, ignored by default. A
generator that stops short of the state it is aimed at cannot fail however
correct its properties are, and there is no way to tell by reading it.

**What it costs**: the properties are worth less than they look. They are
genuine coverage of ordering, duplication and acknowledgement, and they are not
a substitute for knowing where the hard states are. The honest summary is that
the directed test is what protects this particular bug and the properties
protect the ordinary cases around it.

**What it does not cover**: the fragment reassembly and congestion windows have
their own sequences and no model of either. Nothing here is a security audit.

## Not carried over

**Thread pinning to performance cores.** The original document specifies
limiting worker threads to P-cores to avoid fork-join tails. There is no thread
pool to pin: the current implementation is single-threaded and synchronous, and
per-frame crypto is microseconds. This becomes relevant only if a multiplexed,
multi-threaded server backend is built, and it should be measured before being
assumed.
