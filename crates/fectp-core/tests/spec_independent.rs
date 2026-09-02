//! A second implementation, written from `docs/SPEC.md` alone.
//!
//! `interop.rs` cross-validates the handshake against `snow`, and that is the
//! only part of this protocol checked against anything but itself. Everything
//! the specification describes in most detail — the frame header, the
//! acknowledgement block, fragment descriptors, the codec header and the
//! transforms — has been verified only by the implementation that produced it.
//! `spec_conformance.rs` pins the constants the document quotes, which catches
//! a value drifting but not a sentence that never said enough.
//!
//! A specification only its own author can implement is not doing its job. So
//! the `spec` module below is written from the document: each function names
//! the section it follows, and it deliberately shares no code with the crate.
//! Where the two disagree, either the code is wrong or the document is, and
//! both are worth knowing.
//!
//! The honest limit of this: it was written by someone who has read the
//! implementation, so it cannot prove the document is *sufficient* for a
//! stranger. It can prove the two agree on every case below, and it makes an
//! ambiguity visible the moment the document is edited without the code.

use fectp_core::codec::{numeric, transpose, varint, CodecHeader};
use fectp_core::fragment::Fragment;
use fectp_core::frame::{Header, HEADER_LEN};
use fectp_core::reliability::Ack;

/// Everything in here follows `docs/SPEC.md` and nothing else.
mod spec {
    /// §3 — "Every frame begins with a fixed 14-byte header."
    pub const HEADER_LEN: usize = 14;

    /// §3.1 — "`version` MUST be `1` for this specification."
    pub const VERSION: u8 = 1;

    /// §3.1 — the type table. All other values are reserved, 10 to 13
    /// included: they belonged to the plaintext mode, which is gone.
    pub const TYPES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9];

    /// §3.2 — bits 0x01, 0x02, 0x04 and 0x08 are defined; 0x10–0x80 reserved.
    pub const KNOWN_FLAGS: u8 = 0x01 | 0x02 | 0x04 | 0x08;

    /// §3 — the header layout. §2: "All multi-byte integers are little-endian."
    ///
    /// | offset | size | field |
    /// | 0 | 1 | version (high 4) \| type (low 4) |
    /// | 1 | 1 | flags |
    /// | 2 | 4 | session_id, u32 |
    /// | 6 | 8 | sequence, u64 |
    pub fn encode_header(frame_type: u8, flags: u8, session_id: u32, sequence: u64) -> [u8; 14] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = (VERSION << 4) | (frame_type & 0x0f);
        out[1] = flags;
        out[2..6].copy_from_slice(&session_id.to_le_bytes());
        out[6..14].copy_from_slice(&sequence.to_le_bytes());
        out
    }

    /// §3.1 and §3.2 — reject an unknown version, a reserved type, and any
    /// reserved flag bit.
    pub fn decode_header(input: &[u8]) -> Result<(u8, u8, u32, u64), &'static str> {
        if input.len() < HEADER_LEN {
            return Err("shorter than a header");
        }
        if input[0] >> 4 != VERSION {
            return Err("unsupported version");
        }
        let frame_type = input[0] & 0x0f;
        if !TYPES.contains(&frame_type) {
            return Err("reserved frame type");
        }
        let flags = input[1];
        if flags & !KNOWN_FLAGS != 0 {
            return Err("reserved flag bit");
        }
        Ok((
            frame_type,
            flags,
            u32::from_le_bytes(input[2..6].try_into().unwrap()),
            u64::from_le_bytes(input[6..14].try_into().unwrap()),
        ))
    }

    /// §5.7 — "An `Ack` frame's body is a 12-byte block": highest u32, bitmap u64.
    pub fn encode_ack(highest: u32, bitmap: u64) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..4].copy_from_slice(&highest.to_le_bytes());
        out[4..].copy_from_slice(&bitmap.to_le_bytes());
        out
    }

    /// §5.7 — "Bit `i` of `bitmap` set means `highest - 1 - i` was also
    /// received", and an identifier more than 64 below `highest` is
    /// unacknowledged, "since the block cannot report it".
    pub fn ack_covers(highest: u32, bitmap: u64, id: u32) -> bool {
        if id == highest {
            return true;
        }
        let behind = highest.wrapping_sub(id);
        if behind == 0 || behind > 64 {
            return false;
        }
        bitmap & (1u64 << (behind - 1)) != 0
    }

    /// §5.6 — message u32, index u16, count u16, little-endian.
    pub fn encode_fragment(message: u32, index: u16, count: u16) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&message.to_le_bytes());
        out[4..6].copy_from_slice(&index.to_le_bytes());
        out[6..8].copy_from_slice(&count.to_le_bytes());
        out
    }

    /// §5.6 — "MUST reject a descriptor whose `count` is zero, whose `count`
    /// exceeds 4096, or whose `index` is not less than `count`."
    pub fn decode_fragment(input: &[u8]) -> Result<(u32, u16, u16), &'static str> {
        if input.len() < 8 {
            return Err("short descriptor");
        }
        let message = u32::from_le_bytes(input[..4].try_into().unwrap());
        let index = u16::from_le_bytes(input[4..6].try_into().unwrap());
        let count = u16::from_le_bytes(input[6..8].try_into().unwrap());
        if count == 0 || count > 4096 || index >= count {
            return Err("incoherent descriptor");
        }
        Ok((message, index, count))
    }

    /// §6.1 — transform (low 4 bits) | entropy (high 4 bits), param, u16 length.
    pub fn encode_codec_header(transform: u8, entropy: u8, param: u8, original_len: u16) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0] = (transform & 0x0f) | (entropy << 4);
        out[1] = param;
        out[2..].copy_from_slice(&original_len.to_le_bytes());
        out
    }

    /// §6.2.2 — "`zigzag(v) = (v << 1) XOR (v >> 31)`, with `>>` an arithmetic
    /// shift, result interpreted as unsigned."
    pub fn zigzag(value: i32) -> u32 {
        ((value << 1) ^ (value >> 31)) as u32
    }

    pub fn unzigzag(value: u32) -> i32 {
        ((value >> 1) as i32) ^ -((value & 1) as i32)
    }

    /// §6.2.2 — unsigned base-128, least significant group first, high bit a
    /// continuation flag. An encoder MUST emit the shortest encoding.
    pub fn leb128_encode(mut value: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    /// §6.2.2 — reject anything longer than 5 bytes, a final byte whose bits
    /// would overflow a u32, and any encoding that is not the shortest.
    pub fn leb128_decode(input: &[u8]) -> Result<(u32, usize), &'static str> {
        let mut value: u32 = 0;
        for (n, &byte) in input.iter().take(5).enumerate() {
            let shift = 7 * n;
            let payload = u32::from(byte & 0x7f);
            if payload.checked_shl(shift as u32).map(|v| v >> shift) != Some(payload) {
                return Err("overflows a u32");
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                if n > 0 && byte == 0 {
                    return Err("not the shortest encoding");
                }
                return Ok((value, n + 1));
            }
        }
        Err("longer than five bytes")
    }

    /// §6.2.1 — per channel, delta against the previous sample of that channel,
    /// zigzagged and LEB128-encoded. `W` is 2 or 4, `C` is `param`.
    pub fn delta_encode(input: &[u8], channels: usize, width: usize) -> Result<Vec<u8>, &'static str> {
        if channels == 0 {
            return Err("channel count must be at least 1");
        }
        let stride = channels * width;
        if input.len() % stride != 0 {
            return Err("length is not a multiple of C * W");
        }
        let samples = input.len() / stride;
        let mut out = Vec::new();
        for channel in 0..channels {
            let mut prev: i32 = 0;
            for sample in 0..samples {
                let at = (sample * channels + channel) * width;
                let v = read_signed(&input[at..at + width], width);
                let d = v.wrapping_sub(prev);
                prev = v;
                out.extend_from_slice(&leb128_encode(zigzag(d)));
            }
        }
        Ok(out)
    }

    /// §6.2.1 — "Decoding reverses this, wrapping identically. A decoder MUST
    /// reject input with bytes remaining after `C * S` values have been read."
    pub fn delta_decode(
        coded: &[u8],
        channels: usize,
        width: usize,
        original_len: usize,
    ) -> Result<Vec<u8>, &'static str> {
        if channels == 0 {
            return Err("channel count must be at least 1");
        }
        let stride = channels * width;
        if original_len % stride != 0 {
            return Err("length is not a multiple of C * W");
        }
        let samples = original_len / stride;
        let mut out = vec![0u8; original_len];
        let mut read = 0;
        for channel in 0..channels {
            let mut prev: i32 = 0;
            for sample in 0..samples {
                let (encoded, used) = leb128_decode(&coded[read..])?;
                read += used;
                let v = prev.wrapping_add(unzigzag(encoded));
                prev = v;
                let at = (sample * channels + channel) * width;
                write_signed(v, &mut out[at..at + width], width);
            }
        }
        if read != coded.len() {
            return Err("bytes remaining after the last value");
        }
        Ok(out)
    }

    /// §6.2.1 — "signed little-endian W-byte value ... sign-extended to 32 bits".
    fn read_signed(bytes: &[u8], width: usize) -> i32 {
        match width {
            2 => i32::from(i16::from_le_bytes([bytes[0], bytes[1]])),
            _ => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        }
    }

    fn write_signed(value: i32, out: &mut [u8], width: usize) {
        match width {
            2 => out[..2].copy_from_slice(&(value as i16).to_le_bytes()),
            _ => out[..4].copy_from_slice(&value.to_le_bytes()),
        }
    }

    /// §6.2.3 — the pseudocode, transcribed.
    ///
    /// ```text
    /// w = 0
    /// for b in 0 .. E:
    ///     for e in 0 .. n:
    ///         out[w] = in[e*E + b]
    ///         w += 1
    /// out[body .. len] = in[body .. len]
    /// ```
    pub fn transpose_encode(input: &[u8], element: usize) -> Result<Vec<u8>, &'static str> {
        if element == 0 {
            return Err("element size must be at least 1");
        }
        let n = input.len() / element;
        let body = n * element;
        let mut out = vec![0u8; input.len()];
        let mut w = 0;
        for b in 0..element {
            for e in 0..n {
                out[w] = input[e * element + b];
                w += 1;
            }
        }
        out[body..].copy_from_slice(&input[body..]);
        Ok(out)
    }

    /// §6.2.3 — "Output length always equals input length", and the transform
    /// is lossless, so decoding places each byte back where it came from.
    pub fn transpose_decode(input: &[u8], element: usize) -> Result<Vec<u8>, &'static str> {
        if element == 0 {
            return Err("element size must be at least 1");
        }
        let n = input.len() / element;
        let body = n * element;
        let mut out = vec![0u8; input.len()];
        let mut r = 0;
        for b in 0..element {
            for e in 0..n {
                out[e * element + b] = input[r];
                r += 1;
            }
        }
        out[body..].copy_from_slice(&input[body..]);
        Ok(out)
    }
}

// ------------------------------------------------------------- §3 header ---

/// Every header this crate writes is one the document describes, and every
/// header the document describes is one this crate reads.
#[test]
fn frame_headers_agree_in_both_directions() {
    assert_eq!(HEADER_LEN, spec::HEADER_LEN, "SPEC.md §3 says 14 bytes");

    for &frame_type in spec::TYPES {
        for flags in [0u8, 0x01, 0x02, 0x04, 0x08, 0x0f] {
            for (session_id, sequence) in
                [(0u32, 0u64), (1, 1), (0xDEAD_BEEF, 0x0123_4567_89AB_CDEF), (u32::MAX, u64::MAX)]
            {
                let from_spec = spec::encode_header(frame_type, flags, session_id, sequence);

                // Ours reads what the document produces.
                let ours = Header::decode(&from_spec).unwrap_or_else(|e| {
                    panic!("SPEC.md §3 frame type {frame_type} flags {flags:#04x}: {e:?}")
                });
                assert_eq!(ours.flags, flags);
                assert_eq!(ours.session_id, session_id);
                assert_eq!(ours.sequence, sequence);

                // And writes exactly what the document describes.
                let mut round = [0u8; HEADER_LEN];
                ours.encode(&mut round).expect("encode");
                assert_eq!(
                    round, from_spec,
                    "our header bytes differ from SPEC.md §3 for type {frame_type}"
                );
            }
        }
    }
}

/// §3.1 and §3.2 say what MUST be rejected. Both sides must reject the same set.
#[test]
fn both_reject_the_same_headers() {
    // Every version but 1.
    for version in [0u8, 2, 3, 15] {
        let mut frame = spec::encode_header(3, 0, 7, 9);
        frame[0] = (version << 4) | 3;
        assert!(spec::decode_header(&frame).is_err(), "SPEC.md §3.1: version {version}");
        assert!(Header::decode(&frame).is_err(), "we accepted version {version}");
    }

    // Every reserved type. §3.1 lists 1–7 and 10–13; the rest are reserved.
    for frame_type in 0u8..16 {
        if spec::TYPES.contains(&frame_type) {
            continue;
        }
        let frame = spec::encode_header(frame_type, 0, 7, 9);
        assert!(spec::decode_header(&frame).is_err(), "SPEC.md §3.1: type {frame_type}");
        assert!(Header::decode(&frame).is_err(), "we accepted reserved type {frame_type}");
    }

    // Every reserved flag bit.
    for bit in [0x10u8, 0x20, 0x40, 0x80] {
        let frame = spec::encode_header(3, bit, 7, 9);
        assert!(spec::decode_header(&frame).is_err(), "SPEC.md §3.2: flag {bit:#04x}");
        assert!(Header::decode(&frame).is_err(), "we accepted reserved flag {bit:#04x}");
    }
}

// -------------------------------------------------------- §5.7 ack block ---

#[test]
fn acknowledgement_blocks_agree() {
    for (highest, bitmap) in [
        (0u32, 0u64),
        (1, 1),
        (64, u64::MAX),
        (1000, 0x0000_0000_DEAD_BEEF),
        (u32::MAX, 1 << 63),
    ] {
        let from_spec = spec::encode_ack(highest, bitmap);
        let ours = Ack::decode(&from_spec).expect("SPEC.md §5.7 block must decode");
        assert_eq!(ours.highest, highest);
        assert_eq!(ours.bitmap, bitmap);

        let mut round = [0u8; 12];
        ours.encode(&mut round).expect("encode");
        assert_eq!(round, from_spec, "our ack bytes differ from SPEC.md §5.7");
    }
}

/// The rule that decides what stops being retransmitted, checked value by value.
///
/// §5.7: bit `i` set means `highest - 1 - i`, and anything more than 64 below
/// `highest` is unacknowledged "since the block cannot report it".
#[test]
fn what_an_acknowledgement_covers_agrees_with_the_document() {
    for highest in [0u32, 1, 63, 64, 65, 1000, u32::MAX] {
        for bitmap in [0u64, 1, 0b1010_1010, u64::MAX, 1 << 63] {
            let ack = Ack {
                highest,
                bitmap,
            };
            // Every identifier the block could possibly speak about, and a few
            // past the edge in each direction.
            for back in 0u32..70 {
                let id = highest.wrapping_sub(back);
                assert_eq!(
                    ack.covers(id),
                    spec::ack_covers(highest, bitmap, id),
                    "highest={highest} bitmap={bitmap:#x} id={id} ({back} behind)"
                );
            }
        }
    }
}

// ------------------------------------------------------- §5.6 fragments ---

#[test]
fn fragment_descriptors_agree_in_both_directions() {
    for (message, index, count) in [(0u32, 0u16, 1u16), (7, 3, 4), (u32::MAX, 4095, 4096)] {
        let from_spec = spec::encode_fragment(message, index, count);
        let ours = Fragment::decode(&from_spec).expect("SPEC.md §5.6 descriptor must decode");
        assert_eq!((ours.message, ours.index, ours.count), (message, index, count));

        let mut round = [0u8; 8];
        ours.encode(&mut round).expect("encode");
        assert_eq!(round, from_spec, "our descriptor bytes differ from SPEC.md §5.6");
    }
}

/// §5.6 lists exactly what a receiver MUST reject.
#[test]
fn both_reject_the_same_fragment_descriptors() {
    for (message, index, count) in [
        (0u32, 0u16, 0u16),    // count of zero
        (0, 0, 4097),          // count above 4096
        (0, 4096, 4096),       // index not less than count
        (0, 5, 5),
        (0, 9, 4),
    ] {
        let frame = spec::encode_fragment(message, index, count);
        assert!(
            spec::decode_fragment(&frame).is_err(),
            "SPEC.md §5.6 requires rejecting index {index} of {count}"
        );
        assert!(
            Fragment::decode(&frame).is_err(),
            "we accepted index {index} of {count}, which SPEC.md §5.6 forbids"
        );
    }
}

// ----------------------------------------------------- §6.1 codec header ---

#[test]
fn codec_headers_agree() {
    // Transform ids 0–3 (§6.2) against entropy ids 0 and 1 (§6.3).
    for transform in 0u8..4 {
        for entropy in 0u8..2 {
            for (param, original_len) in [(0u8, 0u16), (2, 8192), (u8::MAX, u16::MAX)] {
                let from_spec = spec::encode_codec_header(transform, entropy, param, original_len);
                let ours =
                    CodecHeader::decode(&from_spec).expect("SPEC.md §6.1 header must decode");
                assert_eq!(ours.param, param);
                assert_eq!(ours.original_len, original_len);

                let mut round = [0u8; 4];
                ours.encode(&mut round).expect("encode");
                assert_eq!(round, from_spec, "our codec header differs from SPEC.md §6.1");
            }
        }
    }
}

// ---------------------------------------------------------- §6.2.2 LEB128 ---

#[test]
fn varints_agree_on_every_boundary() {
    for value in [
        0u32, 1, 63, 64, 127, 128, 129, 16_383, 16_384, 2_097_151, 2_097_152,
        268_435_455, 268_435_456, u32::MAX - 1, u32::MAX,
    ] {
        let from_spec = spec::leb128_encode(value);

        let mut ours_bytes = [0u8; 5];
        let n = varint::encode(value, &mut ours_bytes).expect("encode");
        assert_eq!(
            &ours_bytes[..n],
            &from_spec[..],
            "our varint for {value} differs from SPEC.md §6.2.2"
        );

        assert_eq!(
            varint::decode(&from_spec).expect("decode"),
            (value, from_spec.len()),
            "we disagree with the document's encoding of {value}"
        );
        assert_eq!(spec::leb128_decode(&ours_bytes[..n]), Ok((value, n)));
    }
}

/// §6.2.2 states three things a decoder MUST reject. Both must reject all three.
#[test]
fn both_reject_the_same_varints() {
    let bad: &[&[u8]] = &[
        &[0x80, 0x00],                    // not the shortest encoding
        &[0x80, 0x80, 0x00],              // twice over
        &[0xff, 0x00],                    // padded 127
        &[0x80, 0x80, 0x80, 0x80, 0x80],  // longer than five bytes
        &[0xff, 0xff, 0xff, 0xff, 0x7f],  // final byte overflows a u32
        &[],                              // nothing at all
    ];
    for bytes in bad {
        assert!(
            spec::leb128_decode(bytes).is_err(),
            "SPEC.md §6.2.2 requires rejecting {bytes:?}"
        );
        assert!(
            varint::decode(bytes).is_err(),
            "we accepted {bytes:?}, which SPEC.md §6.2.2 forbids"
        );
    }

    // And zigzag, which the same section defines.
    for value in [0i32, 1, -1, 2, -2, i32::MIN, i32::MAX, 12345, -12345] {
        assert_eq!(varint::zigzag(value), spec::zigzag(value), "zigzag({value})");
        let z = spec::zigzag(value);
        assert_eq!(varint::unzigzag(z), spec::unzigzag(z));
        assert_eq!(spec::unzigzag(z), value, "zigzag must round-trip");
    }
}

// -------------------------------------------------------- §6.2 transforms ---

/// Bytes this crate produces must decode with the document's transform, and
/// bytes the document's transform produces must decode with this crate's.
///
/// One direction alone would pass if both sides shared the same misreading.
#[test]
fn delta_transforms_agree_in_both_directions() {
    for (channels, width) in [(1usize, 2usize), (2, 2), (4, 2), (1, 4), (3, 4)] {
        for samples in [0usize, 1, 7, 64] {
            let len = samples * channels * width;
            let input: Vec<u8> = (0..len).map(|i| ((i * 37 + 11) % 251) as u8).collect();

            let from_spec = spec::delta_encode(&input, channels, width).expect("spec encode");

            let mut ours_bytes = vec![0u8; len * 5 + 16];
            let n = if width == 2 {
                numeric::encode_i16(&input, channels, &mut ours_bytes)
            } else {
                numeric::encode_i32(&input, channels, &mut ours_bytes)
            }
            .expect("our encode");
            assert_eq!(
                &ours_bytes[..n],
                &from_spec[..],
                "our {width}-byte delta output differs from SPEC.md §6.2.1 \
                 at {channels} channels, {samples} samples"
            );

            // The document's bytes, through our decoder.
            let mut ours_back = vec![0u8; len];
            let m = if width == 2 {
                numeric::decode_i16(&from_spec, channels, len, &mut ours_back)
            } else {
                numeric::decode_i32(&from_spec, channels, len, &mut ours_back)
            }
            .expect("our decode of the document's bytes");
            assert_eq!(m, len);
            assert_eq!(ours_back, input, "a codec must be lossless");

            // Our bytes, through the document's decoder.
            let spec_back = spec::delta_decode(&ours_bytes[..n], channels, width, len)
                .expect("the document's decode of our bytes");
            assert_eq!(spec_back, input);
        }
    }
}

#[test]
fn byte_transposition_agrees_in_both_directions() {
    for element in 1usize..9 {
        for len in [0usize, 1, 5, 16, 17, 63, 256] {
            let input: Vec<u8> = (0..len).map(|i| ((i * 101 + 7) % 253) as u8).collect();

            let from_spec = spec::transpose_encode(&input, element).expect("spec encode");
            let mut ours_bytes = vec![0u8; len];
            transpose::encode(&input, element, &mut ours_bytes).expect("our encode");
            assert_eq!(
                ours_bytes, from_spec,
                "our transpose differs from SPEC.md §6.2.3 at element size {element}, len {len}"
            );

            // §6.2.3: "Output length always equals input length."
            assert_eq!(from_spec.len(), len);

            let mut ours_back = vec![0u8; len];
            transpose::decode(&from_spec, element, &mut ours_back).expect("our decode");
            assert_eq!(ours_back, input);

            let spec_back = spec::transpose_decode(&ours_bytes, element).expect("spec decode");
            assert_eq!(spec_back, input);
        }
    }
}
