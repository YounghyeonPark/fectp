//! Content- and size-aware compression policy.
//!
//! The original specification selected compression by payload type alone.
//! That is not sufficient. Zstandard loses to the alternatives below roughly
//! 64 KiB, and on the small messages an API like this actually carries, the
//! ratio is poor enough that compression is a net loss once the frame's own
//! overhead is counted. A 200-byte JSON message is not worth compressing at
//! any level.
//!
//! So the bypass decision here is made on three grounds, in order:
//!
//! 1. Can the peer decompress at all? A microcontroller has no room for a
//!    Zstandard decoder, and compressing towards it would produce a frame it
//!    could never decode.
//! 2. Is the payload large enough to be worth it?
//! 3. Does the payload already look compressed? Recompressing JPEG, MP4, or
//!    ZIP wastes CPU and usually *increases* the frame size.
//!
//! A final check compares the compressed and original lengths and keeps
//! whichever is smaller, so a bad guess costs CPU but never bytes.

use fectp_core::codec::{CodecHeader, Entropy, Transform, CODEC_HEADER_LEN, MAX_ORIGINAL_LEN};
use fectp_core::session::Capabilities;

/// Payloads below this size are never compressed.
///
/// Below roughly a kilobyte, Zstandard has too little context to find
/// redundancy, and any saving is swamped by the frame's fixed overhead.
pub const MIN_COMPRESS_SIZE: usize = 1024;

/// Compression level used for payloads that qualify.
///
/// The design note specified `-4` (Zstandard's `--fast=4`) on the reasoning
/// that a latency-sensitive transport cannot afford a slow compressor.
/// Measured, that reasoning does not survive: at `-4` Zstandard finds nothing
/// in structured binary data and emits *more* bytes than it was given, so the
/// payload goes out raw. Level 1 costs single-digit microseconds more and is
/// worth it well past any link speed this will run on — sending takes encode
/// time plus bytes over the wire, and the bytes it saves outweigh the time it
/// spends on anything slower than about 2 Gbit/s. On declared payload types,
/// where the transform runs first, it is the difference between 2.00x and
/// 3.46x on sensor data.
///
/// Nothing on the wire depends on this: a receiver decodes any level, so a
/// sender may pick another without coordination. See `docs/BENCHMARKS.md` §7.
pub const LEVEL: i32 = 1;

/// Whether `payload` should be compressed before being sent to a peer with
/// `peer_caps`.
pub fn should_compress(payload: &[u8], peer_caps: Capabilities) -> bool {
    peer_caps.accepts_compression()
        && payload.len() >= MIN_COMPRESS_SIZE
        && !looks_precompressed(payload)
}

/// Recognises container formats that are already entropy-coded.
///
/// This is a cheap magic-number check, not a full sniffer: a false negative
/// only costs the wasted attempt, which the size comparison then discards.
pub fn looks_precompressed(payload: &[u8]) -> bool {
    const MAGICS: &[&[u8]] = &[
        &[0xFF, 0xD8, 0xFF],                    // JPEG
        &[0x89, 0x50, 0x4E, 0x47],              // PNG
        &[0x47, 0x49, 0x46, 0x38],              // GIF
        &[0x50, 0x4B, 0x03, 0x04],              // ZIP, and the formats built on it
        &[0x1F, 0x8B],                          // gzip
        &[0x28, 0xB5, 0x2F, 0xFD],              // Zstandard
        &[0x04, 0x22, 0x4D, 0x18],              // LZ4 frame
        &[0x42, 0x5A, 0x68],                    // bzip2
        &[0xFD, 0x37, 0x7A, 0x58, 0x5A],        // xz
        &[0x4F, 0x67, 0x67, 0x53],              // Ogg
        &[0x66, 0x4C, 0x61, 0x43],              // FLAC
        &[0x49, 0x44, 0x33],                    // MP3 with an ID3 tag
    ];
    if MAGICS.iter().any(|m| payload.starts_with(m)) {
        return true;
    }
    // ISO base media (MP4, MOV, M4A) carries its brand at offset 4.
    if payload.len() >= 12 && &payload[4..8] == b"ftyp" {
        return true;
    }
    // WebP and other RIFF containers.
    if payload.len() >= 12 && payload.starts_with(b"RIFF") && &payload[8..12] == b"WEBP" {
        return true;
    }
    false
}

#[cfg(feature = "compress")]
mod codec {
    use super::LEVEL;
    use crate::{Error, Result};

    /// Compresses `input` into `out`, returning the compressed length.
    ///
    /// Returns `None` when the result would not be smaller than the input, so
    /// the caller can send the original instead. A compression attempt must
    /// never make a frame bigger.
    pub fn compress(input: &[u8], out: &mut [u8]) -> Result<Option<usize>> {
        match zstd::bulk::compress_to_buffer(input, out, LEVEL) {
            Ok(n) if n < input.len() => Ok(Some(n)),
            // Either it did not shrink, or it did not fit; both mean "send it
            // uncompressed", which is always a valid choice.
            Ok(_) | Err(_) => Ok(None),
        }
    }

    /// Decompresses `input` into `out`, returning the plaintext length.
    pub fn decompress(input: &[u8], out: &mut [u8]) -> Result<usize> {
        zstd::bulk::decompress_to_buffer(input, out).map_err(|_| Error::Decompress)
    }
}

#[cfg(feature = "compress")]
pub use codec::{compress, decompress};

/// Payloads below this size are not worth a typed transform either.
///
/// Lower than [`MIN_COMPRESS_SIZE`] because the transforms are far cheaper
/// than Zstandard and pay off on much smaller blocks: delta-coding a hundred
/// samples already halves them.
pub const MIN_TRANSFORM_SIZE: usize = 32;

/// What the caller knows about the shape of a payload.
///
/// Declaring this lets the transport pick a transform that suits the data
/// instead of treating it as opaque bytes. It changes nothing about
/// correctness — a mis-declared type still round-trips, it just compresses
/// badly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PayloadType {
    /// Unknown structure. Generic compression heuristics apply.
    #[default]
    Opaque,
    /// Interleaved little-endian `i16` samples across `channels` channels.
    ///
    /// The usual shape of an ADC or multi-channel sensor stream.
    I16 {
        /// Number of interleaved channels.
        channels: u8,
    },
    /// Interleaved little-endian `i32` samples across `channels` channels.
    I32 {
        /// Number of interleaved channels.
        channels: u8,
    },
    /// An array of fixed-size elements, byte-transposed before coding.
    ///
    /// The right choice for `f32`/`f64` arrays (size 4 or 8) and for arrays of
    /// fixed-layout records, where delta coding on raw bit patterns does not
    /// work but grouping equivalent byte positions does.
    Elements {
        /// Size of one element in bytes.
        size: u8,
    },
}

impl PayloadType {
    /// The transform and its parameter for this shape.
    pub fn transform(self) -> (Transform, u8) {
        match self {
            PayloadType::Opaque => (Transform::None, 0),
            PayloadType::I16 { channels } => (Transform::I16Delta, channels),
            PayloadType::I32 { channels } => (Transform::I32Delta, channels),
            PayloadType::Elements { size } => (Transform::ByteTranspose, size),
        }
    }
}

/// Grows `buf` to at least `len` bytes.
fn ensure(buf: &mut Vec<u8>, len: usize) {
    if buf.len() < len {
        buf.resize(len, 0);
    }
}

/// Codes `data` according to `payload_type`, leaving the result in `primary`.
///
/// Returns the codec header and the coded length, or `None` if coding was
/// skipped or did not pay off — in which case the caller sends the payload
/// uncoded. `secondary` is working space.
///
/// The peer's advertised codecs are respected at every step: a transform or
/// entropy stage the receiver cannot reverse is never used, whatever it would
/// have saved.
pub fn encode_payload(
    data: &[u8],
    payload_type: PayloadType,
    peer_caps: Capabilities,
    primary: &mut Vec<u8>,
    secondary: &mut Vec<u8>,
) -> Option<(CodecHeader, usize)> {
    if data.len() > MAX_ORIGINAL_LEN {
        return None;
    }
    let zstd_available = cfg!(feature = "compress") && peer_caps.accepts_compression();

    let (transform, param) = payload_type.transform();
    let transform_usable = transform != Transform::None
        && data.len() >= MIN_TRANSFORM_SIZE
        && peer_caps.supports_codecs(transform.capability());

    // Byte transposition does not change the size on its own; it only
    // rearranges bytes so an entropy coder has something to find. Without one
    // there is nothing to gain.
    let transform_usable =
        transform_usable && !(transform == Transform::ByteTranspose && !zstd_available);

    let (transform, param, transformed_len) = if transform_usable {
        // Delta plus varint can expand in the worst case, so give the buffer
        // room and fall back if it still does not fit.
        ensure(primary, data.len() * 2 + 16);
        match transform.apply(data, param, primary) {
            Ok(len) => (transform, param, len),
            Err(_) => return None,
        }
    } else {
        if !zstd_available || data.len() < MIN_COMPRESS_SIZE || looks_precompressed(data) {
            return None;
        }
        ensure(primary, data.len());
        primary[..data.len()].copy_from_slice(data);
        (Transform::None, 0, data.len())
    };

    let (entropy, coded_len) = if zstd_available {
        ensure(secondary, transformed_len + 64);
        #[cfg(feature = "compress")]
        {
            match codec::compress(&primary[..transformed_len], secondary) {
                Ok(Some(len)) => {
                    primary[..len].copy_from_slice(&secondary[..len]);
                    (Entropy::Zstd, len)
                }
                _ => (Entropy::None, transformed_len),
            }
        }
        #[cfg(not(feature = "compress"))]
        {
            (Entropy::None, transformed_len)
        }
    } else {
        (Entropy::None, transformed_len)
    };

    // The codec header is part of the plaintext, so it counts against any
    // saving. If the coded form is not actually smaller, send the original.
    if CODEC_HEADER_LEN + coded_len >= data.len() {
        return None;
    }

    Some((
        CodecHeader {
            transform,
            entropy,
            param,
            original_len: data.len() as u16,
        },
        coded_len,
    ))
}

/// Reverses [`encode_payload`], writing the original payload into `out`.
///
/// `plaintext` is the decrypted frame body, codec header included. `scratch`
/// is working space.
pub fn decode_payload(
    plaintext: &[u8],
    scratch: &mut Vec<u8>,
    out: &mut [u8],
) -> crate::Result<usize> {
    let header = CodecHeader::decode(plaintext)?;
    let coded = &plaintext[CODEC_HEADER_LEN..];
    let original_len = usize::from(header.original_len);

    if out.len() < original_len {
        return Err(crate::Error::PayloadTooLarge {
            len: original_len,
            limit: out.len(),
        });
    }

    let transformed: &[u8] = match header.entropy {
        Entropy::None => coded,
        Entropy::Zstd => {
            #[cfg(feature = "compress")]
            {
                // The transform's output is bounded by what the sender could
                // have produced from `original_len` bytes.
                ensure(scratch, original_len * 2 + 16);
                let len = codec::decompress(coded, scratch)?;
                &scratch[..len]
            }
            #[cfg(not(feature = "compress"))]
            {
                let _ = scratch;
                return Err(crate::Error::Decompress);
            }
        }
    };

    header
        .transform
        .reverse(transformed, header.param, original_len, out)
        .map_err(crate::Error::Protocol)
}
