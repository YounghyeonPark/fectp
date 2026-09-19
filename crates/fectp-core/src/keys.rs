//! X25519 key material.

use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};
use zeroize::Zeroize;

/// Length of an X25519 public key, secret key, and DH output, in bytes.
pub const DHLEN: usize = 32;

/// An X25519 public key.
pub type PublicKey = [u8; DHLEN];

/// A public key stand-in for peers that present no identity.
///
/// A pre-shared-key session authenticates by the secret rather than by a static
/// key, so there is no public key to report for its peer. This is what
/// `remote_static` answers, so callers do not have to special-case the mode.
pub const ANONYMOUS: PublicKey = [0u8; DHLEN];

/// A long-term private key, which the caller may not be able to read.
///
/// Everything this protocol does with a static private key is two operations:
/// name its public half, and Diffie-Hellman against a peer. [`Keypair`] is the
/// in-memory implementation and is what almost every caller wants. A secure
/// element or an HSM implements this instead and never hands the key over —
/// which is the whole reason for having one, and was impossible before this
/// trait existed.
///
/// **Static keys only.** Ephemeral keys are generated per handshake and stay
/// [`Keypair`]s. That is deliberate rather than unfinished: an ephemeral lives
/// for one handshake and is discarded, so putting it in hardware protects one
/// session's forward secrecy, where the static key is the long-term identity
/// and losing it is permanent impersonation. The narrower interface is also
/// the one an element is likeliest to offer.
pub trait StaticKey {
    /// The public half, which peers need in order to reach this key.
    ///
    /// By value because an element may compute it rather than store it.
    fn public(&self) -> PublicKey;

    /// Diffie-Hellman against `peer`, using the private half.
    ///
    /// Fallible, which [`Keypair`] never is. That asymmetry is the point: a
    /// device can be busy, locked, or absent, and a handshake written against
    /// an operation that cannot fail has nowhere to put that.
    ///
    /// The result is fed straight into `MixKey` and is never used as a key
    /// directly.
    fn dh(&self, peer: &PublicKey) -> crate::Result<[u8; DHLEN]>;
}

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

/// Lending a key to a handshake rather than giving it away.
///
/// A handshake owns its static key for its duration, which is right for a
/// `Keypair` and wrong for a device: an element is owned by the application,
/// outlives any one handshake, and is likely to be asked other things — a
/// health check, an unlock, a call count. This lets `&Element` be the key, so
/// the application keeps the device and the handshake borrows it.
impl<T: StaticKey> StaticKey for &T {
    fn public(&self) -> PublicKey {
        (*self).public()
    }

    fn dh(&self, peer: &PublicKey) -> crate::Result<[u8; DHLEN]> {
        (*self).dh(peer)
    }
}

impl StaticKey for Keypair {
    fn public(&self) -> PublicKey {
        self.public
    }

    /// Never fails. Spelled out rather than inherited so that the one
    /// implementation which cannot fail says so.
    fn dh(&self, peer: &PublicKey) -> crate::Result<[u8; DHLEN]> {
        Ok(Keypair::dh(self, peer))
    }
}

impl core::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
