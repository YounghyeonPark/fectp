//! LEB128 varints and zigzag mapping.
//!
//! These are what turn a delta transform into an actual size reduction. Delta
//! coding alone does not shrink anything — it only makes the values small.
//! Something has to spend fewer bytes on small values, and a varint is the
//! cheapest such thing: no tables, no entropy model, a few instructions per
//! byte. That matters because this runs on the constrained profile too, where
//! there is no room for a Zstandard encoder.

use crate::error::{Error, Result};

/// Largest number of bytes a `u32` varint can occupy.
pub const MAX_LEN: usize = 5;

/// Maps a signed value to an unsigned one that stays small when the input is
/// near zero, which is what delta coding produces.
pub fn zigzag(value: i32) -> u32 {
    ((value << 1) ^ (value >> 31)) as u32
}

/// Reverses [`zigzag`].
pub fn unzigzag(value: u32) -> i32 {
    ((value >> 1) as i32) ^ -((value & 1) as i32)
}

/// Writes `value` as a LEB128 varint, returning the bytes used.
pub fn encode(mut value: u32, out: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    loop {
        if n >= out.len() {
            return Err(Error::BufferTooSmall);
        }
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out[n] = byte;
            return Ok(n + 1);
        }
        out[n] = byte | 0x80;
        n += 1;
    }
}

/// Reads a LEB128 varint, returning the value and the bytes consumed.
///
/// Rejects encodings longer than [`MAX_LEN`], any final byte that would
/// overflow a `u32`, and any encoding longer than the value needs — so a
/// hostile payload cannot drive an unbounded loop, and every value has exactly
/// one spelling.
///
/// That last rule is why a continuation byte may not be followed by a zero
/// terminator: `[0x80, 0x00]` and `[0x00]` would otherwise both mean zero.
/// [`encode`] never writes the longer form, so refusing it costs nothing here
/// and keeps the transform a bijection — a decoder that accepts input its own
/// encoder cannot produce is a place where two implementations agree on a
/// value while disagreeing about the bytes.
pub fn decode(input: &[u8]) -> Result<(u32, usize)> {
    let mut value: u32 = 0;
    for (n, &byte) in input.iter().take(MAX_LEN).enumerate() {
        let shift = 7 * n;
        let payload = u32::from(byte & 0x7f);
        if shift >= 32 || (payload << shift) >> shift != payload {
            return Err(Error::BadHeader);
        }
        value |= payload << shift;
        if byte & 0x80 == 0 {
            // A terminating byte carrying nothing means the bytes before it
            // were enough: the encoder would have stopped one byte earlier.
            if n > 0 && byte == 0 {
                return Err(Error::BadHeader);
            }
            return Ok((value, n + 1));
        }
    }
    Err(Error::BadHeader)
}
