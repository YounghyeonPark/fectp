//! The Noise `SymmetricState`: chaining key, transcript hash, and cipher.

use super::cipher::{CipherState, KEYLEN};
use super::hash::{hash, hkdf2, hkdf3, Hash, HASHLEN};
use crate::error::Result;

/// Tracks the handshake transcript and derives keys from it.
pub struct SymmetricState {
    chaining_key: Hash,
    transcript: Hash,
    cipher: CipherState,
}

impl SymmetricState {
    /// `InitializeSymmetric(protocol_name)`.
    ///
    /// A protocol name of at most `HASHLEN` bytes is zero-padded; a longer one
    /// is hashed. FECTP's name is 33 bytes, so it takes the hashing branch.
    pub fn new(protocol_name: &[u8]) -> Self {
        let transcript = if protocol_name.len() <= HASHLEN {
            let mut h = [0u8; HASHLEN];
            h[..protocol_name.len()].copy_from_slice(protocol_name);
            h
        } else {
            hash(&[protocol_name])
        };
        Self {
            chaining_key: transcript,
            transcript,
            cipher: CipherState::new(),
        }
    }

    /// `MixHash(data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.transcript = hash(&[&self.transcript, data]);
    }

    /// `MixKey(input_key_material)`.
    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let (ck, temp_k) = hkdf2(&self.chaining_key, input_key_material);
        self.chaining_key = ck;
        self.cipher.initialize_key(temp_k);
    }

    /// `MixKeyAndHash(input)`, used by the pre-shared-key patterns.
    ///
    /// Unlike `MixKey`, this also folds the input into the transcript, so the
    /// two peers disagree on the hash — and every later decryption fails — if
    /// they hold different pre-shared keys.
    pub fn mix_key_and_hash(&mut self, input: &[u8]) {
        let (ck, temp_h, temp_k) = hkdf3(&self.chaining_key, input);
        self.chaining_key = ck;
        self.mix_hash(&temp_h);
        self.cipher.initialize_key(temp_k);
    }

    /// Processes an `e` token in a pre-shared-key handshake.
    ///
    /// The Noise specification requires that, when a PSK is in play, an
    /// ephemeral public key is mixed into the chaining key as well as the
    /// transcript. Omitting the `MixKey` would silently produce a different
    /// key schedule from every conforming implementation.
    pub fn mix_ephemeral_with_psk(&mut self, public_key: &[u8]) {
        self.mix_hash(public_key);
        self.mix_key(public_key);
    }

    /// `EncryptAndHash(plaintext)`, in place.
    ///
    /// `buf[..plaintext_len]` holds the plaintext and `buf` must have `TAGLEN`
    /// bytes of headroom beyond it. Returns the ciphertext length.
    pub fn encrypt_and_hash(&mut self, buf: &mut [u8], plaintext_len: usize) -> Result<usize> {
        let h = self.transcript;
        let ct_len = self.cipher.encrypt_with_ad(&h, buf, plaintext_len)?;
        self.mix_hash(&buf[..ct_len]);
        Ok(ct_len)
    }

    /// `DecryptAndHash(ciphertext)`, in place.
    ///
    /// The transcript must absorb the ciphertext, which in-place decryption
    /// destroys, so the next transcript value is computed first.
    pub fn decrypt_and_hash(&mut self, buf: &mut [u8]) -> Result<usize> {
        let h = self.transcript;
        let next = hash(&[&h, buf]);
        let pt_len = self.cipher.decrypt_with_ad(&h, buf)?;
        self.transcript = next;
        Ok(pt_len)
    }

    /// `Split()`, returning the two transport ciphers in `(c1, c2)` order.
    ///
    /// Per the Noise specification the initiator sends on `c1` and receives on
    /// `c2`; the responder does the reverse.
    pub fn split(&self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.chaining_key, &[]);
        let mut c1 = CipherState::new();
        let mut c2 = CipherState::new();
        c1.initialize_key(truncate_key(k1));
        c2.initialize_key(truncate_key(k2));
        (c1, c2)
    }

    /// Derives the key a later resumption will use as its pre-shared key.
    ///
    /// Domain-separated from `Split`, which feeds HKDF an empty input, so the
    /// resumption key is independent of the transport keys: learning one tells
    /// an attacker nothing about the other.
    pub fn resumption_key(&self) -> [u8; KEYLEN] {
        let (key, _) = hkdf2(&self.chaining_key, RESUMPTION_LABEL);
        truncate_key(key)
    }

    /// The current transcript hash, suitable for channel binding.
    pub fn handshake_hash(&self) -> Hash {
        self.transcript
    }
}

/// Domain separator for the resumption key derivation.
pub const RESUMPTION_LABEL: &[u8] = b"fectp/1 resumption";

/// `HASHLEN` and `KEYLEN` are both 32 for this suite; this makes that explicit
/// so the code breaks loudly if a future suite changes one of them.
fn truncate_key(h: Hash) -> [u8; KEYLEN] {
    const _: () = assert!(HASHLEN == KEYLEN);
    h
}
