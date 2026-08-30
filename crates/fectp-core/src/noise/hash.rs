//! BLAKE2s hashing, HMAC, and the Noise HKDF construction.

use blake2::{Blake2s256, Digest};
use zeroize::Zeroize;

/// Output length of the hash function, in bytes.
pub const HASHLEN: usize = 32;

/// Internal block size of BLAKE2s, in bytes. Required by the HMAC padding.
const BLOCKLEN: usize = 64;

/// A BLAKE2s-256 digest.
pub type Hash = [u8; HASHLEN];

/// BLAKE2s-256 over the concatenation of `parts`.
pub fn hash(parts: &[&[u8]]) -> Hash {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-BLAKE2s (RFC 2104) over the concatenation of `parts`.
///
/// The Noise specification mandates the HMAC construction here rather than
/// BLAKE2's native keyed mode, so that HKDF is identical across cipher suites.
///
/// This is written out rather than taken from the `hmac` crate because BLAKE2
/// uses a lazy block buffer, which `hmac::Hmac` cannot wrap. Correctness is
/// covered by the cross-implementation handshake tests, which fail if any step
/// of the key schedule diverges.
fn hmac(key: &[u8], parts: &[&[u8]]) -> Hash {
    let mut padded = [0u8; BLOCKLEN];
    if key.len() > BLOCKLEN {
        padded[..HASHLEN].copy_from_slice(&hash(&[key]));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCKLEN];
    let mut opad = [0u8; BLOCKLEN];
    for i in 0..BLOCKLEN {
        ipad[i] = padded[i] ^ 0x36;
        opad[i] = padded[i] ^ 0x5c;
    }
    padded.zeroize();

    let mut inner = Blake2s256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let mut inner_digest: Hash = inner.finalize().into();

    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let out: Hash = outer.finalize().into();

    ipad.zeroize();
    opad.zeroize();
    inner_digest.zeroize();
    out
}

/// The three-output Noise HKDF.
///
/// Required by `MixKeyAndHash`, which the pre-shared-key patterns use.
pub fn hkdf3(chaining_key: &Hash, input_key_material: &[u8]) -> (Hash, Hash, Hash) {
    let mut temp = hmac(chaining_key, &[input_key_material]);
    let out1 = hmac(&temp, &[&[0x01]]);
    let out2 = hmac(&temp, &[&out1, &[0x02]]);
    let out3 = hmac(&temp, &[&out2, &[0x03]]);
    temp.zeroize();
    (out1, out2, out3)
}

/// The two-output Noise HKDF.
///
/// Returns `(output1, output2)` as defined by the Noise specification's
/// `HKDF(chaining_key, input_key_material, 2)`.
pub fn hkdf2(chaining_key: &Hash, input_key_material: &[u8]) -> (Hash, Hash) {
    let mut temp = hmac(chaining_key, &[input_key_material]);
    let out1 = hmac(&temp, &[&[0x01]]);
    let out2 = hmac(&temp, &[&out1, &[0x02]]);
    temp.zeroize();
    (out1, out2)
}
