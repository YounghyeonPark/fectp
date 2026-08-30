# Adding a codec for a new data type

FECTP dispatches compression on a declared payload shape. Adding support for a
new kind of data means writing one transform and registering it; the protocol
machinery around it is already there.

## What you write, and what you get for free

You write the transform: a pair of functions that rearrange bytes and put them
back. Everything else is handled:

| | |
|---|---|
| **Negotiation** | Peers exchange a codec bitmap during the handshake. A transform the receiver has not advertised is never used. |
| **Fallback** | If the peer lacks the codec, or coding does not shrink the payload, the original bytes are sent instead. |
| **Framing** | The codec header rides inside the encrypted plaintext. Uncoded frames pay nothing for it. |
| **Composition** | Zstandard runs after your transform automatically, when both peers have it and it helps. |
| **Safety** | A wrong declaration costs compression, never correctness — the size comparison and the round-trip tests see to that. |

## Rules a codec must satisfy

1. **Lossless.** It must reproduce its input byte for byte. This is enforced by
   `every_transform_reproduces_its_input_exactly` in
   `crates/fectp-core/tests/codec.rs`, which runs every transform against
   inputs designed to break a careless one.
2. **Allocation-free, if it is to live in the core.** Transforms in
   `fectp-core` write into caller-provided slices and use no allocator, which
   is what lets a constrained peer reverse them without a Zstandard decoder.
   A codec that needs an allocator belongs in the `fectp` crate and must be
   left out of `CODECS_CORE`.
3. **Refuses ambiguity.** If the input does not match the declared shape — a
   partial frame, a zero channel count — return `Error::BadHeader` rather than
   guessing. The caller falls back to sending plain bytes.
4. **No state between messages.** See D11 in `DECISIONS.md`: cross-message
   state amplifies datagram loss and reopens the compression side channel.

## The three places to touch

### 1. The transform itself

`crates/fectp-core/src/codec/your_codec.rs`:

```rust
pub fn encode(input: &[u8], param: usize, out: &mut [u8]) -> Result<usize>;
pub fn decode(input: &[u8], param: usize, original_len: usize, out: &mut [u8]) -> Result<usize>;
```

`param` is the single byte of shape information the codec header carries —
a channel count, an element size, a row stride.

### 2. Register it

In `crates/fectp-core/src/codec/mod.rs`:

- add a `Transform` variant,
- give it an id in `to_bits`/`from_bits` (4 bits, so ids 0–15),
- add a `CODEC_*` capability bit,
- return that bit from `capability()`,
- dispatch it in `apply()` and `reverse()`,
- add it to `CODECS_CORE` if it is allocation-free.

The capability bit is the important one: it is what stops a sender using a
codec the receiver cannot reverse.

### 3. Expose it

In `crates/fectp/src/compress.rs`, add a `PayloadType` variant and map it in
`PayloadType::transform()`. Callers then reach it through:

```rust
conn.send(&data, PayloadType::YourShape { param })?;
// or, for a stream that is always this shape:
```

## Wire-format budget

The codec header is four bytes: 4-bit transform id, 4-bit entropy id, one
`param` byte, and a `u16` original length. A payload longer than 65535 bytes is
sent uncoded. Anything a codec needs beyond one `param` byte has to go into the
payload itself.

## Choosing what to add

Not every data type needs a codec. The question is whether the data has
structure a byte-oriented compressor cannot see:

- **Already-encoded formats** (JPEG, MP4, ZIP) need no codec. They need a
  *bypass*, which the magic-number check in `compress.rs` already does. Adding
  a codec here would waste CPU re-compressing entropy-coded data.
- **Interleaved or column-shaped numeric data** is where the wins are, because
  interleaving actively hides redundancy from a generic compressor. Measured:
  Zstandard saves nothing on a 4-channel `i16` block, while the typed path
  reaches 1.99x.
- **Raw frames from a fixed camera** are a legitimate candidate: with a static
  background only a small fraction of pixels change, so a spatial transform
  within one frame is worthwhile. Note that temporal differencing *across*
  frames is a different proposition — it is cross-message state, and rule 4
  applies.

When in doubt, measure first. `crates/fectp-core/tests/codec.rs` shows the
shape of a ratio test; a codec that does not beat the generic path on real data
is not worth its wire-format id.
