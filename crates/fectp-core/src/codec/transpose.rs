//! Byte transposition for arrays of fixed-size elements.
//!
//! Groups byte 0 of every element together, then byte 1, and so on. The point
//! is that within an array of `f32`, `f64`, or fixed-layout records, the same
//! byte position across elements is highly correlated — exponent bytes look
//! like other exponent bytes, a record's status field looks like other status
//! fields — while adjacent bytes *within* one element are not.
//!
//! This alone changes nothing about the size; it rearranges bytes so that a
//! following entropy coder has runs to find. It is the standard "shuffle"
//! filter, and it is the practical answer for float data, where delta coding
//! on the raw bit patterns does not work.
//!
//! Any trailing bytes that do not fill a whole element are copied through
//! unchanged, so the transform accepts inputs of any length.

use crate::error::{Error, Result};

/// Transposes `input` into `out`, returning the length written.
///
/// `element_size` must be at least 1. Output length always equals input
/// length.
pub fn encode(input: &[u8], element_size: usize, out: &mut [u8]) -> Result<usize> {
    if element_size == 0 {
        return Err(Error::BadHeader);
    }
    if out.len() < input.len() {
        return Err(Error::BufferTooSmall);
    }
    let elements = input.len() / element_size;
    let body = elements * element_size;

    let mut written = 0;
    for byte in 0..element_size {
        for element in 0..elements {
            out[written] = input[element * element_size + byte];
            written += 1;
        }
    }
    out[written..input.len()].copy_from_slice(&input[body..]);
    Ok(input.len())
}

/// Reverses [`encode`].
pub fn decode(input: &[u8], element_size: usize, out: &mut [u8]) -> Result<usize> {
    if element_size == 0 {
        return Err(Error::BadHeader);
    }
    if out.len() < input.len() {
        return Err(Error::BufferTooSmall);
    }
    let elements = input.len() / element_size;
    let body = elements * element_size;

    let mut read = 0;
    for byte in 0..element_size {
        for element in 0..elements {
            out[element * element_size + byte] = input[read];
            read += 1;
        }
    }
    out[body..input.len()].copy_from_slice(&input[body..]);
    Ok(input.len())
}
