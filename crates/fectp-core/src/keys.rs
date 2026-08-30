//! X25519 key material.

use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};
use zeroize::Zeroize;

/// Length of an X25519 public key, secret key, and DH output, in bytes.
pub const DHLEN: usize = 32;

/// An X25519 public key.
pub type PublicKey = [u8; DHLEN];

/// An X25519 keypair.
///
/// Used for both static and ephemeral keys. Ephemeral keys are held rather
/// than consumed because the Noise IK handshake needs the same ephemeral for
/// two separate DH operations.
pub struct Keypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl Keypair {
    /// Generates a fresh keypair from `rng`.
    ///
    /// `rng` must be a cryptographically secure generator. On MCU targets this
    /// is typically a hardware TRNG peripheral.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; DHLEN];
        rng.fill_bytes(&mut bytes);
        let kp = Self::from_secret(bytes);
        bytes.zeroize();
        kp
    }

    /// Reconstructs a keypair from stored secret key bytes.
    ///
    /// X25519 clamps the scalar internally, so any 32 bytes are accepted.
    pub fn from_secret(bytes: [u8; DHLEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = DalekPublic::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// Returns this keypair's public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Performs X25519 with `peer` and returns the raw shared secret.
    ///
    /// The result is fed straight into `MixKey`; it is never used as a key
    /// directly.
    pub fn dh(&self, peer: &PublicKey) -> [u8; DHLEN] {
        self.secret
            .diffie_hellman(&DalekPublic::from(*peer))
            .to_bytes()
    }
}

impl core::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
