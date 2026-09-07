# How FECTP compares

Measured against raw UDP, TCP + TLS 1.3, gzip and plain Zstandard.

```bash
cargo run -p fectp-bench --release          # everything
cargo run -p fectp-bench --release -- 8     # one section, by its own number
```

A full run takes several minutes, most of it in two rows of §11 that wait a
minute each by construction, so re-measuring one section is worth doing on its
own. The argument is the number the **harness** prints, which is one less than
this document's from §9 onwards: §7b and §8 here have no counterpart in the
harness, so `-- 8` runs what this document calls §9, `-- 9` runs §10 and
`-- 10` runs §11.

The numbers below are from one desktop (Windows 11, release build, loopback).
Yours will differ, and so will these: re-running §5 on the same machine on one
afternoon moved its baseline 32%, with nothing changed but how busy the machine
was. **Read each section against its own control, measured in the same run —
not against an absolute figure from a different one.** Sections that have such
a control say so; several do not, and those are the ones to trust least. The
places where FECTP is worse than the alternatives are called out rather than
buried.

Everything runs over loopback. That deliberately removes the network, so what
is left is each protocol's own cost. It also flatters every protocol that needs
extra round trips, which is why those are counted separately in §3 — on a real
path they are the only thing that matters.

**Read §3 first.** Sections 1, 2, 4 and 5 measure things that turn out not to
decide anything.

This benchmark has changed the implementation five times. §7 is why the default
compression level moved from −4 to 1, §8 is why the send path stopped attempting
compression on data that has already refused to compress, §9 is where injecting
packet loss found two bugs that lost messages outright, and §10 is why there is
congestion control at all.

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
| TCP + TLS 1.3 (rustls) | 1.53 ms | 1.72 ms | 1 + certificate chain |

TLS is doing more work than FECTP here: it verifies a certificate chain, and
FECTP has no chain to verify. That is not a free win — it is the trade in §6.

## 2. Request and response, connection already open

One 256-byte message out, the same back.

| | median | p95 | vs raw UDP |
|---|---|---|---|
| raw UDP (no encryption) | 31.6 µs | 54.0 µs | — |
| FECTP | 35.8 µs | 57.4 µs | +13% |
| TCP + TLS 1.3 | 64.4 µs | 103.9 µs | +104% |
| **raw UDP again (control)** | **30.6 µs** | **49.5 µs** | **−3%** |

The last row is the first row's measurement repeated at the end of the run,
with nothing changed. It moved 3%, which is this host's noise floor on this
run — on a busier run it has been 8%. **Treat any difference smaller than the
control as noise.**

The control row is here because of a specific escape. An earlier draft carried
a fourth row, an unencrypted mode, and reported it as 11–15% *faster* than raw
UDP — impossible, since it was raw UDP plus a 14-byte header. The row is gone
with the mode, but the control that exposed it stays: it is what keeps that
kind of artifact visible instead of quotable.

Seven further runs put the control anywhere from −10% to +6% and FECTP from
−7% to +24%. **In one of them FECTP measured faster than unencrypted UDP**,
which is the same impossible signature the removed plaintext row had. So the
overhead is usually positive and usually larger than the control, and it is not
reliably separable from it on this host. Anyone quoting a single figure from
this table is quoting one run.

The bar itself is one sample — a single difference of two medians — and it
ranged 4% to 10% across three runs today. A verdict that flips with it deserves
more than one degree of freedom behind it.

**The harness used to disagree with its own numbers here.** It printed, as
fixed text beside a computed control, that "most of the gap between raw UDP and
FECTP" was noise and that TLS was the only row clearing the bar. That was true
when it was written, with the control drifting 11%. On a quiet machine the
control drifts 2% and the sentence is simply false — and it printed anyway. The
note is now derived from the run: it compares each row against the control and
says which clear it. A benchmark that states its conclusion regardless of what
it measured is worse than one that states none.

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

**This is the argument for FECTP, and it has a condition on it.** At 150 ms of
path latency the difference between FECTP and TCP + TLS on first contact is
300 ms — but it is 300 ms *once per connection*, so what it is worth depends
entirely on how many messages that connection then carries:

| messages per connection | saved per message | against §2's protocol difference |
|---|---|---|
| 1 | 300 ms | decisive |
| 100 | 3 ms | still decisive |
| 10,000 | 30 µs | comparable |
| 1,000,000 | 0.3 µs | irrelevant |

So this table is decisive for short connections — a sensor that wakes, reports
and sleeps; a peer reconnecting after a NAT mapping expired (§10) — and close to
meaningless for a connection that stays open and streams. An earlier draft of
this section said the table was the whole argument and left that condition out,
which flattered the result on exactly the workload where it does not apply.

FECTP reaches one round trip on *first* contact because the Noise `IK` pattern
carries the initiator's payload in message 1. QUIC needs a prior session to
match it. The cost is in §6 — that payload is replayable and has no forward
secrecy.

## 4. Bytes added to a 256-byte message

| | protocol | IP + transport | total |
|---|---|---|---|
| raw UDP | 0 | 28 | 28 |
| FECTP | 30 | 28 | 58 |
| TCP + TLS 1.3 | 26 | 40 | 66 |

TLS was measured at the socket; FECTP's is fixed by its frame format. The
4-byte length prefix this benchmark adds to TLS is counted against it — a
datagram protocol gets message boundaries for free. TCP headers are 40 bytes
against UDP's 28, before any retransmission.

**The gap is eight bytes, and it used to read thirty.** The harness wrote the
length prefix and the body as two calls, and each becomes its own TLS record —
a 5-byte header, a content-type byte and a 16-byte tag apiece. So 22 of the 48
bytes this row charged TLS were the measurement, not the protocol. One write
now, on both sides, as any real sender would do.

That is worth more than the correction. This section is the one place FECTP
looked clearly better on a number, and most of the margin was ours.

## 5. What one send actually costs

1024 incompressible bytes, against the same `sendto` with no protocol on it.

| | per send | over raw sendto | throughput |
|---|---|---|---|
| raw UDP sendto (no protocol) | 10.1 µs | — | 97 MiB/s |
| FECTP send | 11.4 µs | +1.3 µs | 85 MiB/s |

**This section is under correction. Read the caveats before the table.** An
earlier version of it — one commit old at the time of writing — drew
conclusions its own measurement could not support, and the corrections are left
here rather than tidied away.

### What the row actually contains

Not "framing + AEAD", which is what it used to say. Three things are in it that
the label did not admit:

- **A failed compression attempt.** The payload is 1024 bytes and
  `MIN_COMPRESS_SIZE` is 1024, so `should_compress` passes and a Zstandard
  attempt runs on incompressible data and is discarded. It does not run on
  every send — the coding path backs off — but it runs **4 times in every 36**,
  measured at 2.86 µs each, so about **0.32 µs per send**, a quarter of the
  1.3 µs in the table.
- **The other side's decryption.** The raw arm sends to a socket that discards;
  the FECTP arm sends to a peer that opens the frame and advances a replay
  window, on the same cores. Stopping both receivers moves the difference from
  7.6 µs to 3.9 µs — more than half of it was a thread that is not part of a
  send.
- **Nothing that could be called throughput.** The last column is
  1024 ÷ send-call latency with nothing confirmed to have arrived.

### What it can support

The noise floor, measured by interleaving the two arms in alternating batches
rather than running them one after the other:

```
paired delta   median 2.31 µs   p05 0.88 µs   p95 3.54 µs
```

The quantity being reported is about the size of its own spread. **Nothing
below roughly 1 µs per send is resolvable here.** What survives is: a FECTP
send costs on the order of 1–3 µs more than a bare `sendto` on this host,
compression probe included.

### The rule this section reached, and how far it goes

Five runs at different machine loads:

| run | raw sendto | FECTP | over raw |
|---|---|---|---|
| 1 | 12.6 µs | 14.4 µs | +14% |
| 2 | 12.8 µs | 14.7 µs | +15% |
| 3 | 10.1 µs | 11.4 µs | +13% |
| 4 | 9.7 µs | 11.1 µs | +14% |
| an earlier session, different build | 7.6 µs | 8.8 µs | +16% |

The baseline moved 32% across the four same-day runs — nothing changed but how
busy the machine was. That much holds, and it is why an absolute figure in
microseconds from this file describes a machine on a day.

**The ratio is not the stable quantity the previous version claimed.** Seven
replications on one build put it between +13% and +27%, with one outlier past
+100%; the four values above are four draws from that, not a constant. And the
stability such as it is cannot mean what it was used for: when the host slows,
the syscall and the userspace work dilate together, so the ratio is insensitive
to load *by construction* — it would sit still whether the protocol's fixed
cost were 0 or 0.5 µs.

The rule that survives is narrower, and is still worth having: **compare
against a control measured in the same run, not against a figure from another
one.** §2, §10's asymmetry table and §10's rebinding row do that; most of this
file does not.

### A claim that was withdrawn

The previous version said the unchanged ratio showed that replacing session
keys ([D50](DECISIONS.md#d50--one-key-does-not-last-a-whole-session)) costs
less than this harness can see. That does not follow, for a reason that is easy
to check and was not: this section sends **20,050 frames**, and `REKEY_INTERVAL`
is **65,536**. The replacement is never executed once. What is exercised is the
divide-and-compare on every frame, and nothing else.

D50's per-frame claim — a shift and a comparison, on the order of a nanosecond
— is four orders of magnitude below what this resolves. It remains unmeasured,
and saying so is the only honest position. Settling it needs two builds
alternating inside one run, one of them with the interval set out of reach.

### Two things that are right about the table

The payload is deliberately incompressible. An earlier version sent 1200
constant bytes, which code down to almost nothing — so the syscall was moving
about 30 bytes rather than 1200. It also only fitted in a frame *because* it
compressed; the same 1200 bytes of real data are refused, as `max_payload` is
1170.

And it needs a harness that can resolve a microsecond. Timing one send at a
time cannot: the scheduler noise around it is the same order as the thing being
measured, and it will cheerfully report that adding work made the send faster.
These figures time batches of 500 and divide.

### What would settle it

Time `Peer::seal` into a buffer with no socket, which isolates framing and
AEAD; time the `sendto` separately; use a payload of 1023 bytes or an `Opaque`
type so the compression probe is out of the path; equalise or stop the
receivers; and print the paired p05/p95 as the noise floor rather than leaving
a reader to assume there is not one.

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
negotiation to downgrade, and no unencrypted mode to be talked down to — the
two remaining modes use disjoint frame types and both encrypt. The cost is
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

The level is a sender-side choice — `SPEC.md` §6.3 requires a receiver to accept
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
| sensor i16 ×4, slow | 8192 | 7296 | 907 Mbps |
| sensor i16 ×4, fast | 8192 | 7640 | 417 Mbps |
| counter i32 ×2 | 8192 | 4902 | **2.9 Gbps** |
| f32 array | 8192 | 7184 | 938 Mbps |
| JSON log lines | 104 | 61 | 860 Mbps |
| random bytes | 8192 | 8192 | never |

Every real network is below those thresholds, so on this data level 1 is the
faster choice *end to end*, not the slower one — on every dataset that
compresses at all.

**There used to be an exception here, and it was an artefact.** The JSON row
read 34 Mbps and this paragraph singled it out. The times were measured once,
on the counters, and applied to every row — so JSON was charged an encode cost
about fourteen times its own. Timed per dataset it reads 860 Mbps and behaves
like the rest. A column computed from one row's measurement is not a column.

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

## 7b. Bit packing, measured and rejected

Delta coding emits LEB128, which spends a whole byte on any delta below 64 and
two below 8192 — so the ratio steps. Packing each block of deltas at its widest
value's bit width should track the signal instead.

| | transform output | on the wire, after Zstandard |
|---|---|---|
| sensor `i16` ×4, slow | −34.8% | **+9.5%** |
| sensor `i16` ×4, fast | −27.7% | −5.1% |
| counter `i32` ×2 | −35.9% | **+62.5%** |

The transform output gets a third smaller and the frame gets larger. Packing
destroys byte alignment and repetition, which is what the entropy stage lives
on: 2048 identical LEB128 bytes compress to 24, the equivalent bitstream to 39.

Reproduce with `cargo run -p fectp-bench --example bitpack_headroom`. The
no-Zstandard profile does gain the full third, because there the transform
output is the wire — see D45.

## 8. Not compressing what will not compress

Attempting compression costs a few microseconds whether or not it works, and
before this change the send path paid it on **every** message — including on a
stream of encrypted blobs or random telemetry that had never once compressed.

The send path now counts consecutive failures. After four, it stops attempting
and retries once every 32 sends, so a stream whose content changes is picked up
again within a bounded delay.

**The cost that remains is 11%, not the 3% this section used to say.** The
cycle is four attempts followed by thirty-two skips, so four sends in
thirty-six attempt; the older figure divided one by the interval and forgot the
attempts. At 2.9 µs an attempt on 1 KiB of incompressible data that is about
0.3 µs on every send — a quarter of what §5's row calls framing and AEAD, which
is why that row is labelled the way it now is.

| | before | after |
|---|---|---|
| `Connection::send`, unencrypted mode | 9.41 µs | **7.45 µs** (−21%) |
| `Connection::send`, encrypted | 10.83 µs | **9.21 µs** (−15%) |

**Neither row can be reproduced by the command at the top of this file**, and
that is worth saying plainly. Nothing in the harness measures this: "before"
and "after" are different builds, on unstated days, at an unstated compression
level — which matters, because raising the level makes a failed attempt more
expensive. The first row also measures a mode that has since been removed.

So the direction is sound and the mechanism is now stated correctly, but the
two numbers are the one place in this document that rests entirely on absolute
microseconds compared across days, which is exactly what §5 concluded cannot be
done. Settling it needs a section in the harness that alternates batches of an
incompressible stream with the probe interval at its current value and at
zero, in one run.

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
relay. The handshake is exempt: this measures data delivery, not connection
setup.

Each row is the **median of five runs**, with the spread of those runs beside
it. A single run per row will not do: recovery is governed by a retransmission
timer, so whether a drop lands on a datagram that is about to be acknowledged
anyway or on one that stalls the window is worth a factor of ten, and the
generator being seeded does not make a run repeatable — which datagram is the
*n*th to reach the relay depends on timing, so the same seed drops a different
set each time.

The samples are paired across rates: sample *i* draws the same numbers at every
rate, so a higher rate drops a superset of a lower one's until the two diverge.
Seeding by rate instead gave every row an unrelated sequence, and that is what
used to put the 10% row of the second table ahead of the 5% row in every run.

The run reproduced below is one whose control row came out at 1.0x in both
tables. Across ten runs the first table's control read 1.0x to 2.9x, and a run
whose control reads 2.9x has its ratios inflated by the host rather than by
loss — see below for what that is. Choosing among runs by their control, rather
than by their result, is the only such freedom this document takes.

**100 reliable 256-byte messages, sent and acknowledged:**

| loss | time | vs no loss | 5 samples behind it | per datagram actually dropped |
|---|---|---|---|---|
| 0% | 4.27 ms | — | 4.1–4.4 ms | — |
| 1% | 31.89 ms | 7.5x | 6.2–34.0 ms | 5.9 ms |
| 5% | 140.80 ms | 32.9x | 34.0–343.4 ms | 10.5 ms |
| 10% | 435.42 ms | 101.9x | 182.0–856.7 ms | 14.4 ms |
| 0% again (control) | 4.39 ms | 1.0x | 4.2–5.0 ms | — |

**This table orders its rates and can be relied on to.** Over ten runs the
three loss rows read 6.8–8.4x, 30–49x and 102–160x and never came out of order,
and the absolute 1% figure stayed between 31.1 and 32.8 ms throughout. That was
not true while each rate drew its own random sequence.

The last column divides by the drops the relay actually made — counted inside
the relay, both directions, retransmissions included — and each sample is
divided by its own count before the median is taken. It used to divide by a
count derived from the rate and the message total, which counts one direction
and no retransmissions, so it read several times too high: the figures in this
column were 276, 46 and 29 ms.

**A 256 KiB message, fragmented across 226 frames:**

| loss | time | vs no loss | 5 samples behind it | throughput |
|---|---|---|---|---|
| 0% | 5.06 ms | — | 4.7–6.3 ms | 49.5 MiB/s |
| 1% | 108.86 ms | 21.5x | 30.2–154.6 ms | 2.3 MiB/s |
| 5% | 138.87 ms | 27.5x | 91.5–370.8 ms | 1.8 MiB/s |
| 10% | 217.15 ms | 43.0x | 138.6–464.1 ms | 1.2 MiB/s |
| 0% again (control) | 5.01 ms | 1.0x | 4.9–5.1 ms | 49.9 MiB/s |

**This table separates loss from no loss and nothing finer, and the row above
should not be read as though it did.** Over ten runs its rows read 5–22x,
13–28x and 21–63x. Every pair overlaps, and 5% and 10% came out in the wrong
order in two of the ten. Its own baseline is as much to blame as the loss is:
that row ranged from 5.1 to 11.3 ms over the same ten runs, and it is the
denominator of every ratio beside it.

**1% loss costs between eight- and twentyfold**, depending on whether the
message is one frame or fragmented across 226. Nothing is resent until a retransmission
timer fires, and that timer has a 20 ms floor against a loopback round trip of
about 30 µs — so a single loss costs on the order of a thousand round trips. No
protocol tuning changes that; only a faster loss signal would, and there is none
here. The congestion window does narrow on these losses (D24), but narrowing it
does not make a lost fragment arrive sooner.

### What the control row is telling you, and what it is not

The last row of each table repeats the first with nothing changed. Over ten
runs the first table's reads 1.0x to 2.9x, and that spread is **not** drift in
anything this protocol does. The loss rows spend most of their duration waiting
on a 20 ms timer, and on a desktop a measurement taken after the process has
been idle reads two to three times slow:

```
cargo run --release --bin idle
```

is a loopback UDP echo with no FECTP in it at all, a hundred round trips per
sample, five samples a second of sleep apart, and it shows the same step:

```
round 0: median   3.73 ms   range   3.19-  5.63
round 1: median   3.06 ms   range   2.91-  8.71
round 2: median   7.59 ms   range   4.55- 13.01
round 3: median   9.34 ms   range   8.23-  9.86
round 4: median   7.64 ms   range   6.94-  8.21
```

Five identical zero-loss rows a second of sleep apart reproduce it inside the
benchmark too. Neither a busy spin nor an untimed exchange over the same path
recovers it, and a 300 ms spin made it appear a row earlier rather than later.

Which run you get depends on what the machine was doing beforehand, and it is
not under the harness's control — the same build, run back to back, gives 1.0x
once and 2.6x the next time. That is precisely why the control row is there:
it reports which kind of run this was, so the ratios beside it can be believed
or discounted rather than guessed at.

So: read the absolute milliseconds as this host on this day, and the ratios as
good to about a factor of two. The differences this section leans on — 1% loss
against none, timer-bound recovery against path-bound — are far larger than
that. Any conclusion needing better than 2x resolution is not available from
this harness on this machine.

Adding congestion control made the loss-free row about 12% slower, because the
window now ramps from 4 rather than starting at its memory bound. That was one
sample against one sample at the time, and this section's baseline has since
moved for reasons that have nothing to do with it, so the 12% is a record of
that change and not a figure to recompute from the table above. It is the price
of the §10 result, and it is stated rather than hidden.

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
reach, because a split message keeps feeding the window rather than waiting.

### And a second one

With that fixed, every loss still cost about 200 ms rather than the 20 ms the
measured round trip justified. The first transmission's timeout was computed as
`max(INITIAL_RTO_MS, current)` — but `current` already answers `INITIAL_RTO_MS`
while no round trip has been measured, so the maximum only pinned the first
timeout at 200 ms for the life of the session and made the 20 ms floor
unreachable exactly where it mattered.

Removing it was worth this, measured at the time on one sample per row:

| | before | after |
|---|---|---|
| 100 messages, 1% loss | 463 ms | **279 ms** |
| 100 messages, 10% loss | 808 ms | **297 ms** |
| 256 KiB fragmented, 1% loss | 419 ms | **62 ms** |

These are a record of that change and not of the tables above, which have since
been re-measured with paired seeds and a median of five runs. The "after"
column is one sample of a quantity now known to range over a factor of ten, so
read it as the direction it established rather than as a figure to compare
against the current rows.

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

### A bottleneck is where congestion control earns its place

A 256 KiB message through a rate-limited link with a finite queue.

| bottleneck | time | queue overflow | goodput |
|---|---|---|---|
| 10 Mbit/s, 64 KiB queue | 232.72 ms | 0.0% (0/234) | 1.07 MiB/s |
| 10 Mbit/s, 32 KiB queue | 229.10 ms | 2.1% (5/237) | 1.09 MiB/s |
| 10 Mbit/s, 8 KiB queue | 263.79 ms | 13.3% (36/271) | 0.95 MiB/s |
| 1 Mbit/s, 8 KiB queue | 2314.98 ms | 3.9% (10/257) | 0.11 MiB/s |

The overflow column counts drops the sender caused itself: frames offered to a
queue that was already full, each then paid for by a retransmission timer.

**This table is why the protocol has congestion control.** The last row read
**46.5% (218/469)** when the send window was a fixed 32 whatever the path was
doing — nearly half of everything sent was discarded before reaching the far
side, and the link carried it anyway. The window now opens at 4 and widens only
as acknowledgements arrive, so a sender that has learnt nothing about a path
does not put a full burst into it (D24).

Goodput barely moved, because the bottleneck rate is the bottleneck. What
changed is how much of the link is spent on datagrams that will be dropped: the
total offered fell from 469 to 257.

A first draft of this section reasoned that a queue larger than one window —
32 frames, about 38 KiB — could not be made to overflow. The 64 KiB row
disproved it: retransmissions are offered *on top of* the window, so the burst
is not bounded by it. The run-to-run spread on the middle two rows is wide;
only the 1 Mbit/s row is far enough outside it to lean on, and it holds across
runs at 2.4-4.7%.

### A rebinding NAT no longer ends the session

| | after the rebind | expected |
|---|---|---|
| session survives a new source port | yes | yes |

The relay forwards from a second source port part-way through, which is what a
NAT does when its mapping is re-created, **and stops carrying the old mapping
at the same moment**, which is what a NAT also does. Both halves matter: an
earlier version of this measurement kept the old return path alive, so the
session was still being answered on the path it was supposed to have left, and
the row would have read "yes" whether or not anything migrated.

Two controls are printed with the row: the exchange before the rebind must
work, and the relay must actually have switched ports. Without either, the row
reports on nothing — an earlier version rebound after the third datagram, by
which point the test had already finished, and reported the session surviving
something that never happened.

**This row used to read "no", and the reason it did was a keying decision, not
an oversight.** Sessions are keyed on the peer's address *and* its session
identifier, because the identifier alone is chosen by the client and can
collide (D14). What changed is that the identifier is now also indexed on its
own, and consulted only when a frame arrives from an address with no session
on it. A collision there costs one extra AEAD verification; it cannot cause a
wrong delivery, because the tag decides.

The move is not free and is not instant. A peer heard from at a new address is
sent a challenge and nothing else — no acknowledgement, no data — until it
answers, so following a peer costs one extra round trip and the frame that
reveals the move is not the frame that completes it. That delay is the
mechanism, not a shortcoming of it: an authenticated frame proves who sealed
it, never where they are, and a session that moved on the strength of the tag
alone could be pointed at a third party who never asked for it
([D47](DECISIONS.md#d47--a-session-follows-its-peer-but-only-after-being-shown)).

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
