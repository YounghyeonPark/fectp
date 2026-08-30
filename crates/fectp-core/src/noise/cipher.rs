//! The Noise `CipherState`: ChaCha20-Poly1305 with a 64-bit counter nonce.

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Length of a ChaCha20-Poly1305 key, in bytes.
pub const KEYLEN: usize = 32;

/// Length of a Poly1305 authentication tag, in bytes.
pub const TAGLEN: usize = 16;

/// Nonce value reserved by the Noise specification to signal exhaustion.
const MAX_NONCE: u64 = u64::MAX;

/// A keyed cipher with a monotonically increasing nonce counter.
///
/// Encryption is always in place: the caller supplies one buffer holding the
/// plaintext with `TAGLEN` bytes of headroom. This keeps the core allocation
/// free, which is what makes it usable on a microcontroller.
pub struct CipherState {
    key: Option<[u8; KEYLEN]>,
    nonce: u64,
}

impl CipherState {
    /// Creates an unkeyed `CipherState`. Encryption is a no-op until keyed.
    pub fn new() -> Self {
        Self { key: None, nonce: 0 }
    }

    /// Installs `key` and resets the nonce counter, per Noise `InitializeKey`.
    pub fn initialize_key(&mut self, key: [u8; KEYLEN]) {
        if let Some(mut old) = self.key.take() {
            old.zeroize();
        }
        self.key = Some(key);
        self.nonce = 0;
    }

    /// Returns whether a key has been installed.
    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Returns the nonce that the next counter-based operation will use.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Overrides the nonce counter.
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }

    /// Builds the 96-bit ChaCha20-Poly1305 nonce for `counter`.
    ///
    /// Noise specifies 32 zero bits followed by the 64-bit counter in
    /// little-endian order.
    fn build_nonce(counter: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&counter.to_le_bytes());
        *Nonce::from_slice(&n)
    }

    /// Encrypts `buf[..plaintext_len]` in place and appends the tag.
    ///
    /// `buf` must be at least `plaintext_len + TAGLEN` bytes long. Returns the
    /// total ciphertext length, `plaintext_len + TAGLEN`.
    ///
    /// With no key installed this leaves the buffer untouched and returns
    /// `plaintext_len`, matching Noise's unkeyed pass-through behaviour.
    pub fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        buf: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize> {
        if self.key.is_none() {
            return Ok(plaintext_len);
        }
        if self.nonce == MAX_NONCE {
            return Err(Error::NonceExhausted);
        }
        let n = self.nonce;
        let written = self.encrypt_at(ad, n, buf, plaintext_len)?;
        self.nonce += 1;
        Ok(written)
    }

    /// Decrypts `buf` in place, where `buf` is ciphertext followed by its tag.
    ///
    /// Returns the plaintext length; the plaintext occupies `buf[..len]`.
    pub fn decrypt_with_ad(&mut self, ad: &[u8], buf: &mut [u8]) -> Result<usize> {
        if self.key.is_none() {
            return Ok(buf.len());
        }
        if self.nonce == MAX_NONCE {
            return Err(Error::NonceExhausted);
        }
        let n = self.nonce;
        let len = self.decrypt_at(ad, n, buf)?;
        self.nonce += 1;
        Ok(len)
    }

    /// Encrypts at an explicit nonce without touching the counter.
    ///
    /// The transport layer uses this because the sequence number travels in
    /// the frame header rather than being implicit.
    pub fn encrypt_at(
        &self,
        ad: &[u8],
        counter: u64,
        buf: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize> {
        let key = self.key.as_ref().ok_or(Error::NotReady)?;
        let end = plaintext_len
            .checked_add(TAGLEN)
            .ok_or(Error::PayloadTooLarge)?;
        if buf.len() < end {
            return Err(Error::BufferTooSmall);
        }
        let aead = ChaCha20Poly1305::new(Key::from_slice(key));
        let tag = aead
            .encrypt_in_place_detached(&Self::build_nonce(counter), ad, &mut buf[..plaintext_len])
            .map_err(|_| Error::Decrypt)?;
        buf[plaintext_len..end].copy_from_slice(&tag);
        Ok(end)
    }

    /// Decrypts at an explicit nonce without touching the counter.
    ///
    /// Datagrams may arrive out of order, so the transport layer tracks which
    /// sequence numbers are acceptable with a replay window instead of
    /// relying on a strictly increasing counter.
    pub fn decrypt_at(&self, ad: &[u8], counter: u64, buf: &mut [u8]) -> Result<usize> {
        let key = self.key.as_ref().ok_or(Error::NotReady)?;
        if buf.len() < TAGLEN {
            return Err(Error::MessageTooShort);
        }
        let plaintext_len = buf.len() - TAGLEN;
        let (body, tag) = buf.split_at_mut(plaintext_len);
        let tag = Tag::clone_from_slice(tag);
        let aead = ChaCha20Poly1305::new(Key::from_slice(key));
        aead.decrypt_in_place_detached(&Self::build_nonce(counter), ad, body, &tag)
            .map_err(|_| Error::Decrypt)?;
        Ok(plaintext_len)
    }
}

impl Default for CipherState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CipherState {
    fn drop(&mut self) {
        if let Some(k) = self.key.as_mut() {
            k.zeroize();
        }
    }
}
