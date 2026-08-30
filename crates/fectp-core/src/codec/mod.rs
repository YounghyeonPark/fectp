//! Payload codecs: a declared data shape selects a transform.
//!
//! A general-purpose compressor sees only bytes. Told that a payload is, say,
//! four interleaved channels of `i16`, a transform can rearrange it into a
//! form where the redundancy is actually visible, and typically beats the
//! generic path by a wide margin on the same data.
//!
//! ## Every codec is lossless
//!
//! This is an invariant, not a default: a codec must reproduce its input byte
//! for byte. Lossy coding is a non-goal for this protocol, so no transform may
//! quantise, truncate, or otherwise discard information, however much it would
//! save. Where that leaves compression bounded by the data's own entropy —
//! sensor noise in the low bits, most obviously — the bound is accepted.
//!
//! `every_transform_reproduces_its_input_exactly` in `tests/codec.rs` enforces
//! this across every transform against inputs designed to break a codec that
//! cuts corners.
//!
//! ## Transform and entropy stage are separate
//!
//! A codec is a *transform* (pure integer rearrangement) optionally followed by
//! an *entropy* stage (Zstandard). They are split for two reasons.
//!
//! The transforms cost a few instructions per byte, need no tables, and live
//! here in the `no_std` core, so the constrained profile gets real compression
//! even though a Zstandard encoder would never fit on it. And on a full
//! profile the two compose: the transform exposes structure, then Zstandard
//! exploits it.
//!
//! ## Everything stays within one message
//!
//! No codec here carries state between messages. That is deliberate, and it is
//! the difference between this and a video-style predictive scheme.
//!
//! Cross-message state would mean a single lost datagram corrupts every
//! message after it, on a transport that drops datagrams by design. It would
//! also undo the protocol's compression side-channel defence: compressing
//! independently per message is exactly what stops an attacker who influences
//! part of a payload from learning about a secret compressed alongside it. A
//! predictive codec that shares a context across messages reintroduces the
//! CRIME condition. If one is ever added it needs periodic keyframes, reliable
//! delivery of reference messages, and strict context separation between
//! logical streams.

pub mod numeric;
pub mod transpose;
pub mod varint;

use crate::error::{Error, Result};

/// Bytes the codec header occupies at the front of a coded plaintext.
pub const CODEC_HEADER_LEN: usize = 4;

/// Largest payload a typed send can carry, bounded by the header's length
/// field.
pub const MAX_ORIGINAL_LEN: usize = u16::MAX as usize;

/// A structural rearrangement applied before any entropy coding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transform {
    /// Bytes are passed through untouched.
    None,
    /// Interleaved little-endian `i16` channels; parameter is the channel count.
    I16Delta,
    /// Interleaved little-endian `i32` channels; parameter is the channel count.
    I32Delta,
    /// Fixed-size elements byte-transposed; parameter is the element size.
    ByteTranspose,
}

impl Transform {
    fn to_bits(self) -> u8 {
        match self {
            Transform::None => 0,
            Transform::I16Delta => 1,
            Transform::I32Delta => 2,
            Transform::ByteTranspose => 3,
        }
    }

    fn from_bits(bits: u8) -> Result<Self> {
        match bits {
            0 => Ok(Transform::None),
            1 => Ok(Transform::I16Delta),
            2 => Ok(Transform::I32Delta),
            3 => Ok(Transform::ByteTranspose),
            _ => Err(Error::BadHeader),
        }
    }

    /// The capability bit a peer must advertise to decode this transform.
    pub fn capability(self) -> u16 {
        match self {
            Transform::None => 0,
            Transform::I16Delta => CODEC_I16_DELTA,
            Transform::I32Delta => CODEC_I32_DELTA,
            Transform::ByteTranspose => CODEC_TRANSPOSE,
        }
    }

    /// Applies the transform, returning the encoded length.
    pub fn apply(self, input: &[u8], param: u8, out: &mut [u8]) -> Result<usize> {
        match self {
            Transform::None => {
                if out.len() < input.len() {
                    return Err(Error::BufferTooSmall);
                }
                out[..input.len()].copy_from_slice(input);
                Ok(input.len())
            }
            Transform::I16Delta => numeric::encode_i16(input, usize::from(param), out),
            Transform::I32Delta => numeric::encode_i32(input, usize::from(param), out),
            Transform::ByteTranspose => transpose::encode(input, usize::from(param), out),
        }
    }

    /// Reverses the transform, returning the decoded length.
    pub fn reverse(
        self,
        input: &[u8],
        param: u8,
        original_len: usize,
        out: &mut [u8],
    ) -> Result<usize> {
        match self {
            Transform::None => {
                if input.len() != original_len {
                    return Err(Error::BadHeader);
                }
                if out.len() < input.len() {
                    return Err(Error::BufferTooSmall);
                }
                out[..input.len()].copy_from_slice(input);
                Ok(input.len())
            }
            Transform::I16Delta => {
                numeric::decode_i16(input, usize::from(param), original_len, out)
            }
            Transform::I32Delta => {
                numeric::decode_i32(input, usize::from(param), original_len, out)
            }
            Transform::ByteTranspose => {
                if input.len() != original_len {
                    return Err(Error::BadHeader);
                }
                transpose::decode(input, usize::from(param), out)
            }
        }
    }
}

/// The entropy coder applied after the transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entropy {
    /// No entropy stage; the transform's output goes on the wire as is.
    None,
    /// Zstandard, at the negative level the specification selected.
    Zstd,
}

impl Entropy {
    fn to_bits(self) -> u8 {
        match self {
            Entropy::None => 0,
            Entropy::Zstd => 1,
        }
    }

    fn from_bits(bits: u8) -> Result<Self> {
        match bits {
            0 => Ok(Entropy::None),
            1 => Ok(Entropy::Zstd),
            _ => Err(Error::BadHeader),
        }
    }

    /// The capability bit a peer must advertise to decode this stage.
    pub fn capability(self) -> u16 {
        match self {
            Entropy::None => 0,
            Entropy::Zstd => CODEC_ZSTD,
        }
    }
}

/// Capability bit: peer can decode Zstandard.
pub const CODEC_ZSTD: u16 = 1 << 0;
/// Capability bit: peer can decode the `i16` delta transform.
pub const CODEC_I16_DELTA: u16 = 1 << 1;
/// Capability bit: peer can decode the `i32` delta transform.
pub const CODEC_I32_DELTA: u16 = 1 << 2;
/// Capability bit: peer can decode the byte-transpose transform.
pub const CODEC_TRANSPOSE: u16 = 1 << 3;

/// Every transform implemented by the `no_std` core.
///
/// These need no allocator and no tables, so any profile can decode them.
pub const CODECS_CORE: u16 = CODEC_I16_DELTA | CODEC_I32_DELTA | CODEC_TRANSPOSE;

/// Describes how a coded payload was produced.
///
/// Carried at the front of the *encrypted* plaintext rather than in the frame
/// header, so it costs nothing on uncoded frames and cannot be rewritten by an
/// attacker to force a different decode path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecHeader {
    /// Structural transform applied first.
    pub transform: Transform,
    /// Entropy stage applied to the transform's output.
    pub entropy: Entropy,
    /// Transform parameter: channel count, or element size.
    pub param: u8,
    /// Byte length of the payload before any coding.
    pub original_len: u16,
}

impl CodecHeader {
    /// Serialises into the first [`CODEC_HEADER_LEN`] bytes of `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < CODEC_HEADER_LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.transform.to_bits() | (self.entropy.to_bits() << 4);
        out[1] = self.param;
        out[2..4].copy_from_slice(&self.original_len.to_le_bytes());
        Ok(())
    }

    /// Parses a codec header.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < CODEC_HEADER_LEN {
            return Err(Error::MessageTooShort);
        }
        let mut len = [0u8; 2];
        len.copy_from_slice(&input[2..4]);
        Ok(Self {
            transform: Transform::from_bits(input[0] & 0x0f)?,
            entropy: Entropy::from_bits(input[0] >> 4)?,
            param: input[1],
            original_len: u16::from_le_bytes(len),
        })
    }
}
