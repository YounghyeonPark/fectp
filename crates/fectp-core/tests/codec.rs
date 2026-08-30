//! Codec correctness, and what the transforms actually buy.

use fectp_core::codec::{
    numeric, transpose, varint, CodecHeader, Entropy, Transform, CODEC_HEADER_LEN,
};
use fectp_core::error::Error;

// ---------------------------------------------------------------- varint ---

#[test]
fn varint_round_trips_across_the_range() {
    for value in [0u32, 1, 127, 128, 16_383, 16_384, u32::MAX / 2, u32::MAX] {
        let mut buf = [0u8; varint::MAX_LEN];
        let n = varint::encode(value, &mut buf).expect("encode");
        let (decoded, used) = varint::decode(&buf[..n]).expect("decode");
        assert_eq!(decoded, value);
        assert_eq!(used, n);
    }
}

#[test]
fn zigzag_keeps_small_magnitudes_small() {
    // This is the property the delta transform depends on: values near zero,
    // positive or negative, must map to small unsigned numbers.
    for value in [-1i32, 0, 1, -2, 2, -63, 63] {
        assert!(varint::zigzag(value) < 128, "{value} should fit in one byte");
        assert_eq!(varint::unzigzag(varint::zigzag(value)), value);
    }
    for value in [i32::MIN, i32::MAX, -100_000, 100_000] {
        assert_eq!(varint::unzigzag(varint::zigzag(value)), value);
    }
}

#[test]
fn malformed_varints_are_rejected() {
    // Continuation bits with no terminator must not loop or read past the end.
    assert_eq!(varint::decode(&[0x80, 0x80, 0x80]), Err(Error::BadHeader));
    assert_eq!(
        varint::decode(&[0x80, 0x80, 0x80, 0x80, 0x80]),
        Err(Error::BadHeader)
    );
    // A fifth byte that would overflow a u32.
    assert_eq!(
        varint::decode(&[0xFF, 0xFF, 0xFF, 0xFF, 0x7F]),
        Err(Error::BadHeader)
    );
    assert_eq!(varint::decode(&[]), Err(Error::BadHeader));
}

// --------------------------------------------------------------- numeric ---

/// A plausible multi-channel sensor block: a sinusoid per channel plus a
/// couple of least-significant bits of noise.
///
/// `rate` is the phase step per sample, which is what decides how large the
/// sample-to-sample differences are and therefore how much the transform can
/// win.
fn sensor_block(samples: usize, channels: usize, rate: f64) -> Vec<u8> {
    let mut out = Vec::with_capacity(samples * channels * 2);
    let mut noise = 0x1234_5678u32;
    for s in 0..samples {
        for c in 0..channels {
            noise = noise.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let phase = (s as f64) * rate + (c as f64) * 0.7;
            let value = (phase.sin() * 8000.0) as i16;
            let jitter = ((noise >> 16) % 5) as i16 - 2;
            out.extend_from_slice(&value.wrapping_add(jitter).to_le_bytes());
        }
    }
    out
}

/// Bytes the `i16` transform produces for a block.
fn coded_len(block: &[u8], channels: usize) -> usize {
    let mut buf = vec![0u8; block.len() * 3];
    numeric::encode_i16(block, channels, &mut buf).expect("encode")
}

#[test]
fn i16_delta_round_trips() {
    for channels in [1usize, 2, 4, 8] {
        let original = sensor_block(200, channels, 0.01);
        let mut coded = vec![0u8; original.len() * 3];
        let n = numeric::encode_i16(&original, channels, &mut coded).expect("encode");

        let mut back = vec![0u8; original.len()];
        let len =
            numeric::decode_i16(&coded[..n], channels, original.len(), &mut back).expect("decode");
        assert_eq!(len, original.len());
        assert_eq!(back, original, "channels = {channels}");
    }
}

#[test]
fn i32_delta_round_trips() {
    let original: Vec<u8> = (0..400i32)
        .flat_map(|i| (i * 3 - 200).to_le_bytes())
        .collect();
    let mut coded = vec![0u8; original.len() * 3];
    let n = numeric::encode_i32(&original, 2, &mut coded).expect("encode");

    let mut back = vec![0u8; original.len()];
    numeric::decode_i32(&coded[..n], 2, original.len(), &mut back).expect("decode");
    assert_eq!(back, original);
}

#[test]
fn delta_coding_shrinks_in_proportion_to_how_slowly_the_signal_moves() {
    // The win is entirely a function of how big the sample-to-sample
    // differences are, and varint granularity makes that a step function: a
    // delta that fits in 7 bits costs one byte, anything larger costs two,
    // which for i16 input is no saving at all. Slow signals win; fast ones
    // barely do.
    //
    // Getting a smooth curve instead of this step would need bit-packing —
    // coding a block of deltas at the minimum width they all fit in — which is
    // what dedicated time-series codecs do. That is the obvious next
    // improvement, not a limit of the approach.
    let mut results = Vec::new();
    for (label, rate) in [("slow", 0.001), ("medium", 0.01), ("fast", 0.1)] {
        let block = sensor_block(512, 4, rate);
        let n = coded_len(&block, 4);
        let ratio = block.len() as f64 / n as f64;
        println!("i16 x4ch 512 samples, {label:>6} signal: {} -> {n} bytes ({ratio:.2}x)", block.len());
        results.push((label, ratio));
    }

    let slow = results[0].1;
    let fast = results[2].1;
    assert!(
        slow > 1.9,
        "a slowly varying signal should roughly halve, got {slow:.2}x"
    );
    assert!(
        slow > fast,
        "the ratio must track how slowly the signal moves: slow {slow:.2}x vs fast {fast:.2}x"
    );
}

#[test]
fn interleaving_is_what_makes_the_difference() {
    // Delta-coding the interleaved buffer as if it were one channel is far
    // worse than splitting it first, because consecutive samples then come
    // from unrelated channels. This is the reason the transform needs to be
    // told the channel count rather than guessing.
    let original = sensor_block(512, 4, 0.001);

    let split = coded_len(&original, 4);
    let flat = coded_len(&original, 1);

    println!("de-interleaved: {split} bytes, treated as one channel: {flat} bytes");
    assert!(
        split < flat,
        "knowing the channel layout must help: {split} vs {flat}"
    );
}

#[test]
fn noise_sets_a_floor_no_transform_can_beat() {
    // Full-scale random samples carry ~16 bits of entropy each. Delta coding
    // cannot invent redundancy that is not there, and honest accounting says
    // so: the transform expands this input, which is why the caller always
    // falls back to sending the original when coding does not pay.
    let mut state = 0x2545_F491u32;
    let noise: Vec<u8> = (0..2048)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 16) as u8
        })
        .collect();

    let mut coded = vec![0u8; noise.len() * 3];
    let n = numeric::encode_i16(&noise, 2, &mut coded).expect("encode");
    println!("pure noise: {} -> {} bytes", noise.len(), n);
    assert!(n >= noise.len(), "random data must not appear to compress");
}

#[test]
fn partial_frames_are_rejected() {
    // A buffer that is not a whole number of frames leaves the channel
    // assignment ambiguous, so it must be refused rather than guessed at.
    let ragged = vec![0u8; 2 * 4 * 3 + 2];
    let mut out = vec![0u8; 256];
    assert_eq!(
        numeric::encode_i16(&ragged, 4, &mut out),
        Err(Error::BadHeader)
    );
    assert_eq!(numeric::encode_i16(&ragged, 0, &mut out), Err(Error::BadHeader));
}

#[test]
fn truncated_coded_data_is_rejected() {
    let original = sensor_block(64, 2, 0.01);
    let mut coded = vec![0u8; original.len() * 3];
    let n = numeric::encode_i16(&original, 2, &mut coded).expect("encode");

    let mut back = vec![0u8; original.len()];
    assert!(
        numeric::decode_i16(&coded[..n - 1], 2, original.len(), &mut back).is_err(),
        "a truncated payload must not decode to a plausible-looking result"
    );
}

// ------------------------------------------------------------- transpose ---

#[test]
fn transpose_round_trips_including_a_ragged_tail() {
    for (len, element) in [(64usize, 4usize), (63, 4), (100, 8), (7, 8), (0, 4)] {
        let original: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let mut coded = vec![0u8; len];
        let n = transpose::encode(&original, element, &mut coded).expect("encode");
        assert_eq!(n, len, "transposition must preserve length");

        let mut back = vec![0u8; len];
        transpose::decode(&coded[..n], element, &mut back).expect("decode");
        assert_eq!(back, original, "len {len}, element {element}");
    }
}

#[test]
fn transpose_groups_equivalent_byte_positions() {
    // Floats sharing a magnitude share their exponent bytes. After
    // transposition those land next to each other, which is what gives an
    // entropy coder something to work with.
    let values: Vec<f32> = (0..64).map(|i| 1.0 + i as f32 * 0.001).collect();
    let raw: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();

    let mut coded = vec![0u8; raw.len()];
    transpose::encode(&raw, 4, &mut coded).expect("encode");

    // The last quarter holds every element's high byte, which is identical
    // across all of these values.
    let high_bytes = &coded[coded.len() - 64..];
    assert!(
        high_bytes.iter().all(|&b| b == high_bytes[0]),
        "high bytes of similar floats should be grouped and identical"
    );
}

// ---------------------------------------------------------------- header ---

#[test]
fn codec_header_round_trips() {
    let header = CodecHeader {
        transform: Transform::I16Delta,
        entropy: Entropy::Zstd,
        param: 4,
        original_len: 4096,
    };
    let mut buf = [0u8; CODEC_HEADER_LEN];
    header.encode(&mut buf).expect("encode");
    assert_eq!(CodecHeader::decode(&buf).expect("decode"), header);
}

#[test]
fn unknown_codec_ids_are_rejected() {
    let mut buf = [0u8; CODEC_HEADER_LEN];
    CodecHeader {
        transform: Transform::None,
        entropy: Entropy::None,
        param: 0,
        original_len: 0,
    }
    .encode(&mut buf)
    .expect("encode");

    buf[0] = 0x0F; // unknown transform
    assert_eq!(CodecHeader::decode(&buf), Err(Error::BadHeader));
    buf[0] = 0xF0; // unknown entropy stage
    assert_eq!(CodecHeader::decode(&buf), Err(Error::BadHeader));
}

#[test]
fn transforms_declare_the_capability_they_need() {
    // A sender must be able to check, from the peer's advertised bitmap alone,
    // whether a transform is safe to use.
    assert_ne!(Transform::I16Delta.capability(), 0);
    assert_ne!(Transform::I32Delta.capability(), 0);
    assert_ne!(Transform::ByteTranspose.capability(), 0);
    assert_eq!(Transform::None.capability(), 0);
}

// -------------------------------------------------------- lossless-only ---
//
// Lossy coding is an explicit non-goal. Every codec must reproduce its input
// byte for byte, and these tests are the guard on that: they fail if a codec
// is ever added — or changed — in a way that discards information.

/// Inputs chosen to break a transform that cuts corners.
fn adversarial_blocks() -> Vec<(&'static str, Vec<u8>)> {
    let mut blocks: Vec<(&'static str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("zeros", vec![0u8; 256]),
        ("ones", vec![0xFFu8; 256]),
    ];

    // Alternating extremes: every delta overflows, so the transform has to
    // wrap consistently in both directions.
    let mut extremes = Vec::new();
    for i in 0..128 {
        let value = if i % 2 == 0 { i16::MIN } else { i16::MAX };
        extremes.extend_from_slice(&value.to_le_bytes());
    }
    blocks.push(("alternating i16 extremes", extremes));

    // Full-scale noise: nothing to compress, and the transform must still be
    // exactly reversible even though it expands the data.
    let mut state = 0x9E37_79B9u32;
    let noise: Vec<u8> = (0..256)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 16) as u8
        })
        .collect();
    blocks.push(("full-scale noise", noise));

    // A monotonic ramp, the friendliest possible case.
    blocks.push((
        "ramp",
        (0..128i16).flat_map(|i| i.wrapping_mul(300).to_le_bytes()).collect(),
    ));

    blocks
}

#[test]
fn every_transform_reproduces_its_input_exactly() {
    let cases: &[(Transform, u8)] = &[
        (Transform::None, 0),
        (Transform::I16Delta, 1),
        (Transform::I16Delta, 2),
        (Transform::I16Delta, 4),
        (Transform::I32Delta, 1),
        (Transform::I32Delta, 2),
        (Transform::ByteTranspose, 1),
        (Transform::ByteTranspose, 4),
        (Transform::ByteTranspose, 8),
    ];

    for (transform, param) in cases {
        for (label, original) in adversarial_blocks() {
            let mut coded = vec![0u8; original.len() * 3 + 64];
            let coded_len = match transform.apply(&original, *param, &mut coded) {
                Ok(len) => len,
                // A shape mismatch is a refusal, not a loss; nothing to check.
                Err(_) => continue,
            };

            let mut back = vec![0u8; original.len()];
            let decoded_len = transform
                .reverse(&coded[..coded_len], *param, original.len(), &mut back)
                .unwrap_or_else(|e| {
                    panic!("{transform:?}/{param} failed to reverse {label}: {e}")
                });

            assert_eq!(decoded_len, original.len(), "{transform:?}/{param} on {label}");
            assert_eq!(
                back, original,
                "{transform:?}/{param} did not reproduce {label} exactly"
            );
        }
    }
}

#[test]
fn transforms_never_silently_drop_low_bits() {
    // The specific failure a lossy codec would show: values that differ only
    // in their least significant bits must stay distinct. Sensor noise lives
    // in exactly those bits, and discarding it is out of scope for the
    // transport — the entropy it carries is a floor we accept, not one we
    // compress our way past.
    let mut original = Vec::new();
    for i in 0..256i16 {
        // Adjacent samples one LSB apart.
        original.extend_from_slice(&(1000 + (i & 1)).to_le_bytes());
    }

    let mut coded = vec![0u8; original.len() * 3];
    let n = numeric::encode_i16(&original, 1, &mut coded).expect("encode");
    let mut back = vec![0u8; original.len()];
    numeric::decode_i16(&coded[..n], 1, original.len(), &mut back).expect("decode");

    assert_eq!(back, original, "one-LSB differences must survive intact");
}
