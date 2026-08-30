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
declares a payload's shape (`Connection::send_typed`, or
`set_default_payload_type` once per connection) and that selects a transform.
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
| **Congestion control** | A sender may saturate a path. | The in-flight bound (D12) caps memory, not send rate. It does pace `send_large` (D19), but as a fixed window, not a response to loss. |
| **Ordering** | Reliable delivery is unordered by design (D12). | Not a gap so much as a decision; an application needing order sequences its own payloads. |
| **Ticket expiry** | Tickets are bounded in number but have no lifetime. | A responder evicts oldest-first at 256; time-based expiry is unspecified. |
| **Plaintext mode misuse** | Nothing stops an operator choosing plaintext where it is inappropriate. | The API and documentation steer towards pre-shared keys; a protocol cannot enforce judgement. |
| **NAT traversal** | One socket serves both directions (D16), but there is no discovery, address reflection, or hole-punching coordination. | Those are separable problems built on the socket property, not changes to it. |
| **Address migration** | A session is bound to its peer's address. | Keying on the pair is what avoids session-id collisions (D14); supporting migration would need a different scheme. |
| **Path MTU discovery** | Frame size is fixed at 1200 bytes or the peer's advertised limit. | Fine on a LAN; a real network path may be smaller. |
| **Rekeying** | A session ends after 2^64 frames. | Not reachable in practice, but the error path exists (`Error::NonceExhausted`). |
| **Linked footprint figure** | Only a pre-link upper bound has been measured. | `fectp-core`'s own code is ~21 KiB for `thumbv7em-none-eabihf`; the crypto dependencies add roughly 95 KiB before dead-code elimination, dominated by `curve25519-dalek`. A real figure needs a firmware image linked with LTO and `--gc-sections`. |
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

**The in-flight bound doubles as the send window.** `send_large` waits when 32
fragments are outstanding rather than queueing the lot. That is what keeps a
burst from outrunning the receiver's socket buffer — a 6 MB message emitted at
line rate would overflow a default 64 KB buffer many times over and lose most
of itself. It also caps throughput at one window per round trip, which is the
honest limit of doing this without congestion control.

**Coding is per fragment, not per message.** Each frame stays self-describing,
which a receiver can act on without waiting for the rest, at the cost of the
compressor seeing one fragment of context instead of the whole message.

**On an endpoint the waiting is not available.** `Connection::send_large` can
block; an event loop serving many peers cannot, so `Endpoint::send_large`
queues the message and `poll` feeds it out as the window frees. The outcome
arrives as `Event::Sent { delivered }` rather than as a return value, and the
queue is bounded per peer because each entry holds its payload until
acknowledged.

That difference is deliberate rather than an oversight of symmetry: the two
types have different obligations. A `Connection` owes its caller one answer; an
`Endpoint` owes every peer forward progress, and the fastest way to break that
promise is to let one slow peer own the loop.

## Not carried over

**Thread pinning to performance cores.** The original document specifies
limiting worker threads to P-cores to avoid fork-join tails. There is no thread
pool to pin: the current implementation is single-threaded and synchronous, and
per-frame crypto is microseconds. This becomes relevant only if a multiplexed,
multi-threaded server backend is built, and it should be measured before being
assumed.
