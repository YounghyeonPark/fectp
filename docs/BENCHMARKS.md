# How FECTP compares

Measured against raw UDP, TCP + TLS 1.3, gzip and plain Zstandard.

```bash
cargo run -p fectp-bench --release
```

The numbers below are from one desktop (Windows 11, release build, loopback).
Yours will differ. What should survive the change of machine is the *shape* of
the results, and the two places where FECTP is worse than the alternatives —
both of which are called out rather than buried.

Everything runs over loopback. That deliberately removes the network, so what
is left is each protocol's own cost. It also flatters every protocol that needs
extra round trips, which is why those are counted separately in §3 — on a real
path they are the only thing that matters.

**Read §3 first.** Sections 1, 2, 4 and 5 measure things that turn out not to
decide anything.

---

## 1. Opening a connection

| | median | p95 | X25519 operations |
|---|---|---|---|
| FECTP, public key | 0.61 ms | 0.76 ms | 4 |
| FECTP, resumed | 0.36 ms | 0.49 ms | 1 |
| FECTP, pre-shared key | 0.32 ms | 0.47 ms | 1 |
| FECTP, plaintext | 0.16 ms | 0.26 ms | 0 |
| TCP + TLS 1.3 (rustls) | 1.62 ms | 1.80 ms | 1 + certificate chain |

TLS is doing more work than FECTP here: it verifies a certificate chain, and
FECTP has no chain to verify. That is not a free win — it is the trade in §6.

## 2. Request and response, connection already open

One 256-byte message out, the same back.

| | median | p95 | vs raw UDP |
|---|---|---|---|
| raw UDP (no encryption) | 26.2 µs | 57.5 µs | — |
| FECTP, plaintext | 26.2 µs | 34.5 µs | +0% |
| FECTP, encrypted | 30.7 µs | 37.8 µs | +17% |
| TCP + TLS 1.3 | 59.0 µs | 90.6 µs | +125% |
| **raw UDP again (control)** | **28.0 µs** | **39.7 µs** | **+7%** |

The last row is the first row's measurement repeated at the end of the run. It
moved 7% without anything changing, which is the noise floor of this host.
**Treat any difference smaller than 7% as noise.** That covers the plaintext
row entirely; the encrypted row is marginal; only TLS clearly clears the bar.

An earlier draft of this benchmark reported FECTP plaintext as 11–15% *faster*
than raw UDP, which is impossible — it is raw UDP plus a 14-byte header. The
control row exists so that kind of artifact is visible instead of quotable.

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

## 5. Encrypting a frame

| | per frame | throughput |
|---|---|---|
| seal 1200 bytes and hand to the kernel | 31.8 µs | 36 MiB/s |

This includes the `sendto` syscall, which dominates it. The AEAD is a small
fraction. **Encryption is not what costs anything in this protocol** — which is
the finding that shaped the design: if crypto is ~1 µs and a round trip is
20 ms, the thing worth optimising is round trips.

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

## 7. Compression

Bytes on the wire for one 8 KiB payload. Ratios are raw ÷ coded, so higher is
better, and FECTP's figures include its 4-byte codec header.

| dataset | raw | gzip | zstd −4 | FECTP typed | FECTP typed, no zstd |
|---|---|---|---|---|---|
| sensor i16 ×4, slow | 8192 | 1.19x | 1.00x | **2.00x** | 2.00x |
| sensor i16 ×4, fast | 8192 | 1.18x | 1.00x | 1.04x | 1.03x |
| counter i32 ×2 | 8192 | 2.77x | 1.00x | **248.24x** | 3.99x |
| f32 array | 8192 | 1.56x | 1.00x | **5.43x** | 1.00x |
| JSON log lines | 8192 | **78.77x** | 75.85x | 75.85x | 1.00x |
| random bytes | 8192 | 1.00x | 1.00x | 1.00x | 1.00x |

- **sensor i16 ×4** — 4 channels of 16-bit ADC, one slowly varying and one not
- **counter i32 ×2** — 2 channels of monotonic 32-bit counters
- **f32 array** — floats of similar magnitude, a calibration table
- **JSON log lines** — repetitive structured text
- **random bytes** — incompressible, the floor nothing can beat

The point of the last column is that it is what a microcontroller peer gets.
The transforms are plain integer code in the `no_std` core — de-interleave,
delta, zigzag, varint — so a device with no room for a Zstandard decoder still
gets 2.00x on telemetry and 3.99x on counters.

Two honest caveats:

- **On text, FECTP loses to gzip** (75.85x vs 78.77x). Declaring a shape buys
  nothing there; the entropy stage does all the work, and see §8 for why it is
  not doing as much of it as it could.
- **The "fast" sensor row barely compresses** (1.04x). Delta coding only wins
  when successive samples are close, and varint only saves a byte when the
  delta crosses a 7-bit boundary. Fast-changing signals defeat both. This is a
  real limit of the approach, not a tuning problem.

## 8. The Zstandard level, and a defect in the default

The level is a sender-side choice — `SPEC.md` §7 requires a receiver to accept
any valid frame — so this is an implementation default, not a wire question.

| dataset | **−4 (default)** | −1 | 1 | 3 | 9 |
|---|---|---|---|---|---|
| sensor i16 ×4, slow | 1.00x | 1.00x | 1.12x | 1.12x | 1.13x |
| sensor i16 ×4, fast | 1.00x | 1.00x | 1.07x | 1.10x | 1.10x |
| counter i32 ×2 | 1.00x | 1.00x | 1.67x | 1.67x | 1.67x |
| f32 array | 1.00x | 1.00x | 1.14x | 1.14x | 1.14x |
| JSON log lines | 78.77x | **134.30x** | 134.30x | 134.30x | 134.30x |
| random bytes | 1.00x | 1.00x | 1.00x | 1.00x | 1.00x |

Encode time for 8 KiB:

| | −4 (default) | −1 | 1 | 3 | 9 |
|---|---|---|---|---|---|
| counter i32 ×2 | 3.4 µs | 3.7 µs | 13.6 µs | 18.6 µs | 70.0 µs |

**At level −4, Zstandard does not merely fail to compress structured binary
data — it emits more bytes than it was given** (8202 from 8192), so FECTP
correctly falls back to sending the payload unchanged. The 1.00x column is a
real result, not a benchmark that failed to run. Level 1 gets 1.67x on the same
input for about 10 µs more per 8 KiB.

`compress::LEVEL = -4` was inherited from the original design note's
`--fast=4` recommendation, on the reasoning that a latency-sensitive transport
cannot afford a slow compressor. Measured, that reasoning does not hold: 10 µs
against the 20 ms round trip of §3 is not a trade worth making.

**But read it against §7 before concluding the default is simply wrong.** When
a payload's type is declared, the transform runs first and leaves something
repetitive enough that even level −4 finds it — the i32 counters still reach
248x. The gap is on *opaque* payloads, where nothing has exposed the structure
and −4 is all that stands between the data and the wire. On the JSON row that
costs a real 1.7x in final size.

So the defect is narrow but genuine: **the default is well chosen for typed
payloads and poorly chosen for opaque ones.** The obvious fix is to raise the
default to 1, or to pick the level from whether a transform ran. Changing it is
a judgement call about which payloads matter more, so it is recorded here
rather than made silently.

---

## What this measured, and what it did not

Loopback removes the network. It says nothing about behaviour under loss,
reordering, congestion, or NAT rebinding — FECTP's selective-repeat ARQ and RTO
are exercised by the test suite but not by this benchmark. A comparison under
real packet loss would be a more demanding test than any table above, and it
has not been run.

The TLS figures use rustls with a self-signed certificate and `TCP_NODELAY`. A
production TLS deployment with session tickets and a warm connection pool would
close most of the §1 and §3 gaps — the honest comparison there is FECTP against
*resumed* TLS, not against a cold handshake.
