# How FECTP compares

Measured against raw UDP, TCP + TLS 1.3, gzip and plain Zstandard.

```bash
cargo run -p fectp-bench --release
```

The numbers below are from one desktop (Windows 11, release build, loopback).
Yours will differ. What should survive the change of machine is the *shape* of
the results, and the places where FECTP is worse than the alternatives — those
are called out rather than buried.

Everything runs over loopback. That deliberately removes the network, so what
is left is each protocol's own cost. It also flatters every protocol that needs
extra round trips, which is why those are counted separately in §3 — on a real
path they are the only thing that matters.

**Read §3 first.** Sections 1, 2, 4 and 5 measure things that turn out not to
decide anything.

This benchmark has changed the implementation four times. §7 is why the default
compression level moved from −4 to 1, §8 is why the send path stopped
attempting compression on data that has already refused to compress, and §9 is
where injecting packet loss found a bug that lost messages outright.

It has also had to correct itself repeatedly, and those corrections are left in
rather than tidied away: §2, §5, §9 and §10 each record a measurement that was
wrong before it was right. A benchmark that only ever confirms what its author
expected is not measuring anything.

---

## 1. Opening a connection

| | median | p95 | X25519 operations |
|---|---|---|---|
| FECTP, public key | 0.66 ms | 0.80 ms | 4 |
| FECTP, resumed | 0.36 ms | 0.45 ms | 1 |
| FECTP, pre-shared key | 0.34 ms | 0.46 ms | 1 |
| FECTP, plaintext | 0.18 ms | 0.25 ms | 0 |
| TCP + TLS 1.3 (rustls) | 1.53 ms | 1.72 ms | 1 + certificate chain |

TLS is doing more work than FECTP here: it verifies a certificate chain, and
FECTP has no chain to verify. That is not a free win — it is the trade in §6.

## 2. Request and response, connection already open

One 256-byte message out, the same back.

| | median | p95 | vs raw UDP |
|---|---|---|---|
| raw UDP (no encryption) | 31.6 µs | 54.0 µs | — |
| FECTP, plaintext | 31.3 µs | 49.9 µs | −1% |
| FECTP, encrypted | 35.8 µs | 57.4 µs | +13% |
| TCP + TLS 1.3 | 64.4 µs | 103.9 µs | +104% |
| **raw UDP again (control)** | **30.6 µs** | **49.5 µs** | **−3%** |

The last row is the first row's measurement repeated at the end of the run,
with nothing changed. It moved 3%, which is this host's noise floor on this
run — on a busier run it has been 8%. **Treat any difference smaller than the
control as noise.** That covers the plaintext row entirely.

An earlier draft reported FECTP plaintext as 11–15% *faster* than raw UDP,
which is impossible — it is raw UDP plus a 14-byte header. The control row
exists so that kind of artifact stays visible instead of quotable.

## 3. Round trips before a request is answered

Counted from each protocol's handshake, then priced at three real path
latencies. These are properties of the protocols, not measurements.

| | round trips | LAN 0.2 ms | regional 20 ms | distant 150 ms |
|---|---|---|---|---|
| FECTP, first ever contact | 1 | 0.20 ms | 20 ms | 150 ms |
| FECTP, resumed | 1 | 0.20 ms | 20 ms | 150 ms |
| QUIC + TLS 1.3, first contact | 2 | 0.40 ms | 40 ms | 300 ms |
| QUIC + TLS 1.3, resumed (0-RTT) | 1 | 0.20 ms | 20 ms | 150 ms |
| TCP + TLS 1.3, first contact | 3 | 0.60 ms | 60 ms | 450 ms |

TCP + TLS spends one round trip on the TCP handshake, one on TLS, and one on
the exchange itself.

The README's table counts the same thing one round trip lower, because it asks
what must happen *before the first byte can be sent* and this one counts
through to the answer arriving. FECTP is 0 handshake round trips and 1 total;
TCP + TLS is 2 and 3.

**This table is the entire argument for FECTP.** At 150 ms of path latency the
difference between FECTP and TCP + TLS on first contact is 300 ms. Every
microsecond in sections 1, 2, 4 and 5 put together is a rounding error against
that.

FECTP reaches one round trip on *first* contact because the Noise `IK` pattern
carries the initiator's payload in message 1. QUIC needs a prior session to
match it. The cost is in §6 — that payload is replayable and has no forward
secrecy.

## 4. Bytes added to a 256-byte message

| | protocol | IP + transport | total |
|---|---|---|---|
| raw UDP | 0 | 28 | 28 |
| FECTP, plaintext | 14 | 28 | 42 |
| FECTP, encrypted | 30 | 28 | 58 |
| TCP + TLS 1.3 | 48 | 40 | 88 |

TLS was measured at the socket; FECTP's is fixed by its frame format. The
4-byte length prefix this benchmark adds to TLS is counted against it — a
datagram protocol gets message boundaries for free. TCP headers are 40 bytes
against UDP's 28, before any retransmission.

## 5. What one send actually costs

1024 incompressible bytes, against the same `sendto` with no protocol on it.

| | per send | over raw sendto | throughput |
|---|---|---|---|
| raw UDP sendto (no protocol) | 8.3 µs | — | 117 MiB/s |
| FECTP plaintext: + framing | 8.5 µs | +0.2 µs | 115 MiB/s |
| FECTP encrypted: + framing + AEAD | 10.7 µs | +2.4 µs | 91 MiB/s |

**Framing is below what this can resolve** — repeated runs put it between −0.3
and +0.2 µs, which means it costs something smaller than the measurement noise.
Encryption costs about 2 µs. The syscall, at 8.3 µs, is the largest single item
by a wide margin.

Two things about this table are worth more than the numbers in it.

The payload is deliberately incompressible. An earlier version of this section
sent 1200 constant bytes, which code down to almost nothing — so the syscall
was moving about 30 bytes rather than 1200, and the section was measuring the
wrong thing. It also only fitted in a frame *because* it compressed; the same
1200 bytes of real data are refused, as `max_payload` is 1186.

It also needs a harness that can resolve a microsecond. Timing one 8 µs send at
a time cannot: the scheduler noise around it is the same order as the thing
being measured, and it will cheerfully report that adding work made the send
faster. These figures time batches of 500 and divide.

---

## 6. Encryption strength

This section is not benchmarkable — "how secure" has no microsecond figure — so
it is a comparison of properties and of what each protocol asks you to trust.

### Primitives

FECTP uses the same primitives as WireGuard: X25519, ChaCha20-Poly1305,
BLAKE2s, via the Noise Protocol Framework. Specifically
`Noise_IK_25519_ChaChaPoly_BLAKE2s`, with `Noise_NNpsk0_...` for pre-shared-key
mode and resumption. Handshake output is validated against
[snow](https://github.com/mcginty/snow), an independent Noise implementation,
in both roles.

Against TLS 1.3 the primitives are equivalent in strength. The differences are
architectural.

### What FECTP does differently

**No cipher negotiation.** The suite is fixed by the frame type. There is no
negotiation to downgrade, and the three security modes use disjoint frame types
so an attacker cannot talk a peer down from encrypted to plaintext. The cost is
that there is no in-band migration path if ChaCha20-Poly1305 is ever broken —
that would need a new protocol version.

**No PKI.** Peers are identified by raw X25519 public keys. This removes
certificate authorities, expiry, and revocation from the trust model, and it is
why §1 shows FECTP opening faster than TLS. It also means **FECTP gives you no
way to answer "is this the right peer?" — you must already know the key.** TLS
solves a problem FECTP declines to solve. For a fleet of devices you control,
that is a simplification; for talking to arbitrary internet hosts, it is
disqualifying.

**Forward secrecy** holds for steady-state data in all encrypted modes: both
peers contribute fresh ephemerals. It does **not** hold for 0-RTT data.

### The two real weaknesses

**0-RTT data is replayable and has no forward secrecy.** The payload in
handshake message 1 is protected only by the responder's static key, and
nothing prevents an attacker who captured it from sending it again. This is the
price of the §3 result and it is inherent to `IK`, not an implementation gap.
TLS 1.3 and QUIC have the same exposure on *their* 0-RTT, but they only offer
0-RTT on a resumed session, whereas FECTP offers it on first contact — so the
window is wider. `SPEC.md` §4.4.1 requires that applications not put
non-idempotent requests in 0-RTT data, and that a responder which cannot
tolerate replay ignore it.

**Pre-shared-key mode has shared-fate compromise.** Every peer holds the same
secret, so extracting it from any one device compromises all sessions using it,
including recorded past ones for that mode's handshake. It exists because
distributing one secret to a fleet of microcontrollers is operationally far
easier than per-device keypairs, and that convenience is the whole of its
security cost. Public-key mode is the default for a reason.

Plaintext mode has no security whatsoever; it is for loopback and trusted
links, and it is a separate frame type so it can never be reached by accident.

### What has not been done

**This implementation has not been audited.** It is `#![forbid(unsafe_code)]`,
allocation-free in the core, cross-validated against snow, and has a
conformance suite pinning every normative constant — none of which is a
substitute for review by someone who breaks protocols for a living. Do not put
it in front of anything valuable on the strength of this document.

The protocol design leans on Noise, which *is* formally analysed. The
implementation of it here is not.

---

## 7. Compression, and why the level changed

Bytes on the wire for one 8 KiB payload. Ratios are raw ÷ coded, so higher is
better, and FECTP's figures include its 4-byte codec header.

| dataset | raw | gzip | zstd only | **FECTP typed** | typed, no zstd | encode |
|---|---|---|---|---|---|---|
| sensor i16 ×4, slow | 8192 | 1.19x | 1.12x | **3.46x** | 2.00x | 16.7 µs |
| sensor i16 ×4, fast | 8192 | 1.18x | 1.07x | **1.34x** | 1.03x | 29.8 µs |
| counter i32 ×2 | 8192 | 2.77x | 1.67x | **292.57x** | 3.99x | 6.3 µs |
| f32 array | 8192 | 1.56x | 1.14x | **8.21x** | 1.00x | 13.3 µs |
| JSON log lines | 8192 | 78.77x | **126.03x** | 126.03x | 1.00x | 3.8 µs |
| random bytes | 8192 | 1.00x | 1.00x | 1.00x | 1.00x | 6.4 µs |

- **sensor i16 ×4** — 4 channels of 16-bit ADC, one slowly varying and one not
- **counter i32 ×2** — 2 channels of monotonic 32-bit counters
- **f32 array** — floats of similar magnitude, a calibration table
- **JSON log lines** — repetitive structured text
- **random bytes** — incompressible, the floor nothing can beat

The "typed, no zstd" column is what a microcontroller peer gets. Those
transforms are plain integer code in the `no_std` core — de-interleave, delta,
zigzag, varint — so a device with no room for a Zstandard decoder still gets
2.00x on telemetry and 3.99x on counters.

**The fast sensor row is the honest limit of the approach.** Delta coding only
wins when successive samples are close, and a varint only saves a byte when the
delta crosses a 7-bit boundary. A fast-moving signal defeats both, and 1.34x is
what is left. That is a property of the transform, not a tuning problem.

### Why the default level is now 1

The level is a sender-side choice — `SPEC.md` §7 requires a receiver to accept
any valid frame — so this is an implementation default, not a wire question.
It was −4, the design note's `--fast=4`, chosen on the reasoning that a
latency-sensitive transport cannot afford a slow compressor.

| dataset | **−4 (was)** | −1 | **1 (now)** | 3 | 9 |
|---|---|---|---|---|---|
| sensor i16 ×4, slow | 1.00x | 1.00x | 1.12x | 1.12x | 1.13x |
| sensor i16 ×4, fast | 1.00x | 1.00x | 1.07x | 1.10x | 1.10x |
| counter i32 ×2 | 1.00x | 1.00x | 1.67x | 1.67x | 1.67x |
| f32 array | 1.00x | 1.00x | 1.14x | 1.14x | 1.14x |
| JSON log lines | 78.77x | 134.30x | 134.30x | 134.30x | 134.30x |
| random bytes | 1.00x | 1.00x | 1.00x | 1.00x | 1.00x |
| **encode 8 KiB** | **3.3 µs** | 3.7 µs | **13.7 µs** | 18.0 µs | 56.4 µs |

**At level −4, Zstandard does not merely fail on structured binary data — it
emits more bytes than it was given** (8202 from 8192), so FECTP falls back to
sending the payload unchanged. The 1.00x row is a real result, not a benchmark
that failed to run.

The reasoning that picked −4 counts only half the clock. A send costs encode
time *plus* bytes over the link, so a level that spends `dt` more and saves
`db` bytes wins on every link slower than `db / dt`:

| dataset | bytes at −4 | bytes at 1 | level 1 wins below |
|---|---|---|---|
| sensor i16 ×4, slow | 8192 | 7296 | 710 Mbps |
| sensor i16 ×4, fast | 8192 | 7640 | 437 Mbps |
| counter i32 ×2 | 8192 | 4902 | **2.6 Gbps** |
| f32 array | 8192 | 7184 | 798 Mbps |
| JSON log lines | 104 | 61 | 34 Mbps |
| random bytes | 8192 | 8192 | never |

Every real network is below those thresholds, so on this data level 1 is the
faster choice *end to end*, not the slower one. The JSON row is the exception
worth noting: −4 already found nearly everything, and the extra saving is 43
bytes, so above 34 Mbps the lower level was right there.

**The stronger half of the case is the typed column in the table above**, and
it corrects something an earlier draft of this document got wrong. That draft
argued the default was fine for declared types, on the grounds that the
transform exposes the redundancy before Zstandard sees it — but it generalised
from the one dataset where that holds. Running the transform first does not
make the level irrelevant:

| declared type | at −4 | at 1 |
|---|---|---|
| sensor i16 ×4, slow | 2.00x | **3.46x** |
| f32 array | 5.43x | **8.21x** |
| JSON log lines | 75.85x | **126.03x** |
| counter i32 ×2 | 248.24x | 292.57x |

Only the i32 counters were already fine at −4.

## 8. Not compressing what will not compress

Attempting compression costs a few microseconds whether or not it works, and
before this change the send path paid it on **every** message — including on a
stream of encrypted blobs or random telemetry that had never once compressed.

The send path now counts consecutive failures. After four, it stops attempting
and retries once every 32 sends, so a stream whose content changes is picked up
again within a bounded delay. Measured on 1024 incompressible bytes, three runs
each:

| | before | after |
|---|---|---|
| `Connection::send`, plaintext | 9.41 µs | **7.45 µs** (−21%) |
| `Connection::send`, encrypted | 10.83 µs | **9.21 µs** (−15%) |

Compressible payloads are unaffected: the counter never advances, so coding is
attempted every time exactly as before.

This is invisible on the wire — an uncompressed frame is a valid frame and the
receiver is told which it got by a flag — with one exception that matters. A
payload too large to send raw only fits *because* it codes down, so coding is
always attempted for those regardless of what the stream has done before.
Without that carve-out the optimisation silently breaks large sends;
`a_payload_that_only_fits_when_coded_is_still_coded` fails without it, which is
how it is kept honest.

The two changes also support each other. Raising the level (§7) makes a failed
attempt more expensive, and skipping makes the failed attempts rare — the case
where a higher level costs more and returns nothing is now the one case that
stops being paid for on every message.

## 9. Under packet loss

Everything above runs over loopback, which never drops anything — so it
exercises the parts of the protocol that are cheap and leaves the reliability
layer, the only part with a hard job, untested. Loss here is injected by a
relay from a seeded generator, so a run is reproducible. The handshake is
exempt: this measures data delivery, not connection setup.

**100 reliable 256-byte messages, sent and acknowledged:**

| loss | time | vs no loss | per lost message |
|---|---|---|---|
| 0% | 3.02 ms | — | — |
| 1% | 278.66 ms | 92x | 276 ms |
| 5% | 232.77 ms | 77x | 46 ms |
| 10% | 297.19 ms | 98x | 29 ms |

**A 256 KiB message, fragmented across 226 frames:**

| loss | time | vs no loss | throughput |
|---|---|---|---|
| 0% | 3.69 ms | — | 67.7 MiB/s |
| 1% | 61.80 ms | 17x | 4.0 MiB/s |
| 5% | 261.89 ms | 71x | 1.0 MiB/s |
| 10% | 357.04 ms | 97x | 0.7 MiB/s |

**1% loss costs an order of magnitude.** Nothing is resent until a
retransmission timer fires, and that timer has a 20 ms floor against a loopback
round trip of about 30 µs — so a single loss costs on the order of a thousand
round trips. No protocol tuning changes that; only a faster loss signal would,
and there is none here. There is no congestion response either: the send window
is 32 whether the path is dropping everything or nothing.

### The bug this found

At 1% loss a 256 KiB message did not merely slow down — it **failed**, every
time, after exhausting its retries. That is not a probabilistic outcome for a
fragment with five retries at 1% loss, so it was worth chasing.

Dropping exactly one fragment of a 199-fragment message, varying which:

| fragment dropped | outcome |
|---|---|
| 6, 20, 60, 100 | **message lost** |
| 140, 180, 195 | recovered in ~215 ms |

The boundary sits between 100 and 140, and 199 − 140 = 59, just under 64.

An acknowledgement names a highest identifier plus a bitmap of the 64 below it.
Once the sender has run further ahead than that, the stuck message cannot be
named by any acknowledgement — and its retransmission now falls outside the
receiver's replay window, so it is discarded as stale rather than delivered.
The message is lost however many retries remain.

**Bounding how many messages are unacknowledged at once does not prevent this**,
which is what made it easy to miss: the stuck message holds one of 32 slots
while the other 31 keep cycling, and the identifier space runs hundreds past
it. The bound has to be on the distance between identifiers. `SPEC.md` §5.5
now requires that as a sender MUST, and says why the obvious alternative reading
is wrong.

It was not specific to fragmentation — any reliable stream that keeps sending
while one message is stuck would lose it. Fragmentation just made it easy to
reach, because `send_large` keeps feeding the window rather than waiting.

### And a second one

With that fixed, every loss still cost about 200 ms rather than the 20 ms the
measured round trip justified. The first transmission's timeout was computed as
`max(INITIAL_RTO_MS, current)` — but `current` already answers `INITIAL_RTO_MS`
while no round trip has been measured, so the maximum only pinned the first
timeout at 200 ms for the life of the session and made the 20 ms floor
unreachable exactly where it mattered.

Removing it is the difference between the tables above and these:

| | before | after |
|---|---|---|
| 100 messages, 1% loss | 463 ms | **279 ms** |
| 100 messages, 10% loss | 808 ms | **297 ms** |
| 256 KiB fragmented, 1% loss | 419 ms | **62 ms** |

## 10. Reordering, a bottleneck, and a rebinding NAT

The parts of a real path that are not loss. Each is separated because a
protocol can be right about one and wrong about another — and two of these
three are known gaps rather than results.

### Reordering costs nothing

200 reliable 256-byte messages through a relay that holds some datagrams back.

| | time | vs in order | arrived |
|---|---|---|---|
| none | 4.94 ms | — | all |
| **every one by 2 ms (control)** | **106.20 ms** | 21.5x | all |
| 1 in 10 by 2 ms | 106.85 ms | 21.6x | all |
| **every one by 5 ms (control)** | **185.61 ms** | 37.6x | all |
| 1 in 5 by 5 ms | 104.89 ms | 21.3x | all |

**The controls are the measurement.** Delaying a datagram slows any protocol
down, so a reordering run on its own says nothing. Each control applies the
same delay to *every* datagram, which reorders nothing; the difference between
a pair is what reordering itself costs.

Both reordering rows sit at or below their control, so **reordering costs
nothing measurable here** and the whole slowdown is latency. That is the design
working as intended: delivery is unordered, so a frame is handed up on arrival
rather than held for the one before it, and nothing is left to go wrong when
they arrive in a different order. (The 5 ms pair is inverted — the reordered run
came out faster than its control — which is the run-to-run spread, not a
result.)

### A bottleneck is where the missing congestion control shows

A 256 KiB message through a rate-limited link with a finite queue.

| bottleneck | time | queue overflow | goodput |
|---|---|---|---|
| 10 Mbit/s, 64 KiB queue | 307.24 ms | 2.5% (8/324) | 0.81 MiB/s |
| 10 Mbit/s, 32 KiB queue | 227.84 ms | 2.5% (6/236) | 1.10 MiB/s |
| 10 Mbit/s, 8 KiB queue | 279.13 ms | 10.2% (26/255) | 0.90 MiB/s |
| 1 Mbit/s, 8 KiB queue | 2443.81 ms | 46.5% (218/469) | 0.10 MiB/s |

There is no congestion control: the send window stays at 32 whatever the path
is doing, so the sender keeps offering frames that a full queue then drops.
**Those drops are the sender's own doing**, and each is paid for afterwards by a
retransmission timer. At 1 Mbit/s nearly half of everything sent is discarded
before it reaches the far side.

A first draft of this section reasoned that a queue larger than one window —
32 frames, about 38 KiB — could not be made to overflow. The 64 KiB row
disproves it: retransmissions are offered *on top of* the window, so the burst
is not bounded by it. The run-to-run spread on the middle two rows is wide;
only the 1 Mbit/s row is far enough outside it to lean on.

### A rebinding NAT ends the session

| | after the rebind | expected |
|---|---|---|
| session survives a new source port | no | no |

A session is keyed on the peer's address *and* its session identifier, so a
peer that reappears on a new port is a stranger. This is a consequence of the
keying choice rather than an oversight — keying on the pair is what stops one
client's chosen identifier colliding with another's (D14) — but it does mean a
NAT whose mapping expires ends the session, and the peers must handshake again.

The relay here forwards from a second source port part-way through, which is
what a NAT does when its mapping is re-created. The exchange before the rebind
is the control: it must succeed, or the test proves nothing. An earlier version
rebound after the third datagram, by which point the test had already finished —
so it reported the session surviving something that never happened.

## 11. Jitter, an asymmetric path, and a crowded endpoint

### Jitter does not fool the retransmission timer

200 reliable messages through a relay that delays each datagram by a random
amount. **Nothing is dropped**, so every datagram past 201 is one the sender
resent while the first copy was still in flight.

| jitter | time | datagrams sent | spurious |
|---|---|---|---|
| none | 5.10 ms | 201 | 0 (0.0%) |
| 0–2 ms | 109.90 ms | 201 | 0 (0.0%) |
| 0–10 ms | 109.19 ms | 201 | 0 (0.0%) |
| 0–40 ms | 525.73 ms | 204 | 3 (1.5%) |

There are no spurious retransmissions until the jitter reaches twice the
initial timeout, and three even then. The estimator carries a variation term
(RFC 6298's RTTVAR) and is evidently using it — one that averaged round trips
without it would retransmit every time a datagram took longer than usual, which
under this much jitter is constantly.

### Losing an acknowledgement is nearly free; losing data is not

| loss | time | vs no loss | delivered |
|---|---|---|---|
| none | 5.57 ms | — | all |
| 2% on data only | 121.33 ms | 21.8x | all |
| **2% on acks only** | **5.65 ms** | **1.0x** | all |
| 2% both ways | 170.97 ms | 30.7x | all |
| **none again (control)** | **5.39 ms** | **1.0x** | all |

The control puts the noise floor at about 1.0x on this run, and the ack-loss
row sits inside it. That asymmetry is a property of the design rather than
luck: **each acknowledgement reports the whole receive window**, so a lost one
is repaired by the next to arrive, while lost data has to be sent again and
waits for a timer before anyone notices.

It is worth knowing which direction of a path matters. A link that is lossy
only on the return leg costs this protocol almost nothing.

### A crowded endpoint spares the median and not the tail

One connection's round trip, measured while other peers work the same endpoint.

| other peers busy | round trip | vs idle | p95 |
|---|---|---|---|
| 0 | 30.0 µs | — | 43.6 µs |
| 7 | 31.6 µs | 1.05x | 107.6 µs |
| 23 | 30.5 µs | 1.02x | **232.0 µs** |

**Read the p95 column.** The median barely moves, so a typical request is
unaffected by two dozen busy neighbours — but the tail grows about fivefold,
because one socket and one event loop serve everyone and a request arriving
behind a burst waits for it. That is the shape of a single-threaded loop, and
it is the price of the one-socket design (D14) rather than a defect in it.

Client and server share this machine's cores here, so the load threads compete
for CPU as well as for the endpoint. Treat the figures as an upper bound.

An earlier version of this table sent to every peer and then read from every
peer, and reported per-peer latency *falling* as peers were added — which was
the batching amortising the syscall, not the endpoint getting faster. It could
not have answered the question, which is what one peer waits for.

---

## What this measured, and what it did not

Loopback removes the network. Loss (§9), reordering, bottlenecks and rebinding
(§10), jitter, path asymmetry and multi-peer contention (§11) are now injected.
What remains unmeasured is a real path: none of this involves a second machine,
a switch, a wireless link, or a middlebox with opinions.

**There is still no comparison against TCP under loss.** Dropping datagrams at a
relay is fair to a datagram protocol and meaningless for a stream — the same
relay corrupts a TCP connection rather than exercising its recovery. Doing it
fairly needs loss injected below the transport, which is not portable, so §9 and
§10 are FECTP measured against itself and against controls, never against an
alternative. Read them as "what this costs", not as "what this beats".

The TLS figures use rustls with a self-signed certificate and `TCP_NODELAY`. A
production TLS deployment with session tickets and a warm connection pool would
close most of the §1 and §3 gaps — the honest comparison there is FECTP against
*resumed* TLS, not against a cold handshake.

The break-even figures in §7 model a link as pure bandwidth. They ignore
serialisation across multiple frames, congestion response, and the fact that a
smaller payload can be the difference between one datagram and two — which is
worth far more than the microseconds either way.
