//! Per-channel delta coding for interleaved integer sample streams.
//!
//! The transform is: de-interleave by channel, difference along time within
//! each channel, zigzag, then varint.
//!
//! De-interleaving matters as much as the differencing. In an interleaved
//! buffer, consecutive bytes come from *different* channels, which have no
//! reason to resemble each other, so a byte-oriented compressor finds little
//! to work with. Split by channel first and each stream becomes a slowly
//! varying signal whose successive differences sit near zero.
//!
//! There is a hard floor here that no transform can beat: noise. A 16-bit
//! sample with three bits of sensor noise carries at least thirteen bits of
//! real entropy, and lossless coding cannot go below it. Crossing that floor
//! would mean discarding low bits, and lossy coding is a non-goal for this
//! protocol — the floor is accepted, not worked around. Samples that differ by
//! one least significant bit stay distinct.

use super::varint;
use crate::error::{Error, Result};

/// Encodes interleaved little-endian `i16` samples.
///
/// `input` must be a whole number of frames: `channels` samples of two bytes
/// each. Returns the encoded length.
pub fn encode_i16(input: &[u8], channels: usize, out: &mut [u8]) -> Result<usize> {
    encode(input, channels, 2, out)
}

/// Decodes what [`encode_i16`] produced back into `out`.
///
/// `original_len` is the byte length of the interleaved buffer that was
/// encoded; it comes from the codec header.
pub fn decode_i16(
    input: &[u8],
    channels: usize,
    original_len: usize,
    out: &mut [u8],
) -> Result<usize> {
    decode(input, channels, 2, original_len, out)
}

/// Encodes interleaved little-endian `i32` samples.
pub fn encode_i32(input: &[u8], channels: usize, out: &mut [u8]) -> Result<usize> {
    encode(input, channels, 4, out)
}

/// Decodes what [`encode_i32`] produced back into `out`.
pub fn decode_i32(
    input: &[u8],
    channels: usize,
    original_len: usize,
    out: &mut [u8],
) -> Result<usize> {
    decode(input, channels, 4, original_len, out)
}

/// Reads one little-endian sample of `width` bytes, sign-extended to `i32`.
fn read_sample(bytes: &[u8], width: usize) -> i32 {
    match width {
        2 => i32::from(i16::from_le_bytes([bytes[0], bytes[1]])),
        _ => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    }
}

/// Writes one little-endian sample of `width` bytes.
fn write_sample(value: i32, width: usize, out: &mut [u8]) {
    match width {
        2 => out[..2].copy_from_slice(&(value as i16).to_le_bytes()),
        _ => out[..4].copy_from_slice(&value.to_le_bytes()),
    }
}

fn frame_layout(len: usize, channels: usize, width: usize) -> Result<usize> {
    if channels == 0 {
        return Err(Error::BadHeader);
    }
    let stride = channels * width;
    if len % stride != 0 {
        // A partial frame would leave the channel assignment ambiguous.
        return Err(Error::BadHeader);
    }
    Ok(len / stride)
}

fn encode(input: &[u8], channels: usize, width: usize, out: &mut [u8]) -> Result<usize> {
    let samples = frame_layout(input.len(), channels, width)?;
    let mut written = 0;

    for channel in 0..channels {
        let mut previous: i32 = 0;
        for sample in 0..samples {
            let offset = (sample * channels + channel) * width;
            let value = read_sample(&input[offset..], width);
            // Wrapping keeps the transform total: any pair of inputs has a
            // representable difference, and the decoder wraps back the same way.
            let delta = value.wrapping_sub(previous);
            previous = value;
            written += varint::encode(varint::zigzag(delta), &mut out[written..])?;
        }
    }
    Ok(written)
}

fn decode(
    input: &[u8],
    channels: usize,
    width: usize,
    original_len: usize,
    out: &mut [u8],
) -> Result<usize> {
    let samples = frame_layout(original_len, channels, width)?;
    if out.len() < original_len {
        return Err(Error::BufferTooSmall);
    }

    let mut read = 0;
    for channel in 0..channels {
        let mut previous: i32 = 0;
        for sample in 0..samples {
            let (encoded, used) = varint::decode(&input[read..])?;
            read += used;
            let value = previous.wrapping_add(varint::unzigzag(encoded));
            previous = value;
            let offset = (sample * channels + channel) * width;
            write_sample(value, width, &mut out[offset..]);
        }
    }
    if read != input.len() {
        // Trailing bytes mean the payload does not match its declared shape.
        return Err(Error::BadHeader);
    }
    Ok(original_len)
}
