//! The IK handshake pattern.
//!
//! ```text
//! IK:
//!   <- s
//!   ...
//!   -> e, es, s, ss
//!   <- e, ee, se
//! ```
//!
//! The responder's static public key is known to the initiator in advance,
//! which is what lets the first message already carry encrypted application
//! data.

use rand_core::{CryptoRng, RngCore};

use super::cipher::{CipherState, TAGLEN};
use super::symmetric::SymmetricState;
use super::PROTOCOL_NAME;
use crate::error::{Error, Result};
use crate::keys::{Keypair, PublicKey, DHLEN};

/// Bytes that message 1 adds on top of its payload.
///
/// `e` (32) + encrypted `s` (32 + 16) + payload tag (16).
pub const MSG1_OVERHEAD: usize = DHLEN + (DHLEN + TAGLEN) + TAGLEN;

/// Bytes that message 2 adds on top of its payload.
///
/// `e` (32) + payload tag (16).
pub const MSG2_OVERHEAD: usize = DHLEN + TAGLEN;

/// Offset of the payload within message 1.
///
/// Callers that assemble a payload directly in the output buffer, to avoid a
/// staging copy, write it at this offset.
pub const MSG1_PAYLOAD_OFFSET: usize = DHLEN + DHLEN + TAGLEN;

/// Offset of the payload within message 2.
pub const MSG2_PAYLOAD_OFFSET: usize = DHLEN;

/// Which side of the handshake this peer is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sends message 1, receives message 2.
    Initiator,
    /// Receives message 1, sends message 2.
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    AwaitingMessage1,
    AwaitingMessage2,
    Done,
}

/// An in-progress IK handshake.
pub struct HandshakeState {
    sym: SymmetricState,
    role: Role,
    s: Keypair,
    e: Option<Keypair>,
    rs: Option<PublicKey>,
    re: Option<PublicKey>,
    step: Step,
}

impl HandshakeState {
    fn init(role: Role, s: Keypair, rs: Option<PublicKey>, prologue: &[u8]) -> Self {
        let mut sym = SymmetricState::new(PROTOCOL_NAME);
        sym.mix_hash(prologue);
        // Pre-message `<- s`: both sides absorb the responder's static key.
        match role {
            Role::Initiator => sym.mix_hash(rs.as_ref().expect("initiator knows rs")),
            Role::Responder => sym.mix_hash(s.public()),
        }
        Self {
            sym,
            role,
            s,
            e: None,
            rs,
            re: None,
            step: match role {
                Role::Initiator => Step::AwaitingMessage2,
                Role::Responder => Step::AwaitingMessage1,
            },
        }
    }

    /// Starts a handshake as the initiator.
    ///
    /// `remote_static` is the responder's public key, which must already be
    /// known; obtaining it is out of scope for the protocol.
    pub fn initiator(s: Keypair, remote_static: PublicKey, prologue: &[u8]) -> Self {
        Self::init(Role::Initiator, s, Some(remote_static), prologue)
    }

    /// Starts a handshake as the responder.
    pub fn responder(s: Keypair, prologue: &[u8]) -> Self {
        Self::init(Role::Responder, s, None, prologue)
    }

    /// This peer's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The peer's static public key, once it is known.
    ///
    /// The responder learns this while reading message 1, which is how it
    /// authenticates who connected.
    pub fn remote_static(&self) -> Option<&PublicKey> {
        self.rs.as_ref()
    }

    /// Whether the handshake has completed.
    pub fn is_done(&self) -> bool {
        self.step == Step::Done
    }

    /// Writes message 1 into `out`, carrying `payload` as 0-RTT data.
    ///
    /// `out` must be at least `MSG1_OVERHEAD + payload.len()` bytes. Returns
    /// the number of bytes written.
    ///
    /// The payload is encrypted but, unlike post-handshake data, has weaker
    /// forward secrecy and no replay protection: it is protected only by the
    /// responder's static key. Callers should treat it as suitable for a
    /// request that is safe to replay.
    pub fn write_message_1<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let end = MSG1_PAYLOAD_OFFSET
            .checked_add(payload.len())
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < end + TAGLEN {
            return Err(Error::BufferTooSmall);
        }
        out[MSG1_PAYLOAD_OFFSET..end].copy_from_slice(payload);
        self.write_message_1_in_place(rng, payload.len(), out)
    }

    /// Writes message 1 with the payload already staged in `out`.
    ///
    /// The caller must have placed `payload_len` bytes at
    /// `out[MSG1_PAYLOAD_OFFSET..][..payload_len]`. This avoids the staging
    /// copy that [`write_message_1`](Self::write_message_1) performs, which
    /// matters when the payload is assembled from several pieces and no
    /// allocator is available.
    pub fn write_message_1_in_place<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        payload_len: usize,
        out: &mut [u8],
    ) -> Result<usize> {
        if self.role != Role::Initiator || self.step != Step::AwaitingMessage2 || self.e.is_some() {
            return Err(Error::HandshakeState);
        }
        let total = MSG1_OVERHEAD
            .checked_add(payload_len)
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        let rs = *self.rs.as_ref().ok_or(Error::HandshakeState)?;

        // -> e
        let e = Keypair::generate(rng);
        out[..DHLEN].copy_from_slice(e.public());
        self.sym.mix_hash(&out[..DHLEN]);

        // -> es
        self.sym.mix_key(&e.dh(&rs));

        // -> s
        out[DHLEN..DHLEN + DHLEN].copy_from_slice(self.s.public());
        let enc_s_len = self
            .sym
            .encrypt_and_hash(&mut out[DHLEN..MSG1_PAYLOAD_OFFSET], DHLEN)?;
        debug_assert_eq!(enc_s_len, DHLEN + TAGLEN);

        // -> ss
        self.sym.mix_key(&self.s.dh(&rs));

        // -> payload
        self.sym
            .encrypt_and_hash(&mut out[MSG1_PAYLOAD_OFFSET..total], payload_len)?;

        self.e = Some(e);
        Ok(total)
    }

    /// Reads message 1, writing the decrypted payload into `out`.
    ///
    /// Returns the payload length. `out` must be at least
    /// `msg.len() - MSG1_OVERHEAD + TAGLEN` bytes.
    pub fn read_message_1(&mut self, msg: &[u8], out: &mut [u8]) -> Result<usize> {
        if self.role != Role::Responder || self.step != Step::AwaitingMessage1 {
            return Err(Error::HandshakeState);
        }
        if msg.len() < MSG1_OVERHEAD {
            return Err(Error::MessageTooShort);
        }

        // <- e
        let mut re = [0u8; DHLEN];
        re.copy_from_slice(&msg[..DHLEN]);
        self.sym.mix_hash(&re);

        // <- es
        self.sym.mix_key(&self.s.dh(&re));

        // <- s
        let mut enc_s = [0u8; DHLEN + TAGLEN];
        enc_s.copy_from_slice(&msg[DHLEN..MSG1_PAYLOAD_OFFSET]);
        let rs_len = self.sym.decrypt_and_hash(&mut enc_s)?;
        if rs_len != DHLEN {
            return Err(Error::BadHeader);
        }
        let mut rs = [0u8; DHLEN];
        rs.copy_from_slice(&enc_s[..DHLEN]);

        // <- ss
        self.sym.mix_key(&self.s.dh(&rs));

        // <- payload
        let ct = &msg[MSG1_PAYLOAD_OFFSET..];
        if out.len() < ct.len() {
            return Err(Error::BufferTooSmall);
        }
        out[..ct.len()].copy_from_slice(ct);
        let pt_len = self.sym.decrypt_and_hash(&mut out[..ct.len()])?;

        self.re = Some(re);
        self.rs = Some(rs);
        self.step = Step::AwaitingMessage2;
        Ok(pt_len)
    }

    /// Writes message 2 into `out`, carrying `payload`.
    ///
    /// `out` must be at least `MSG2_OVERHEAD + payload.len()` bytes.
    pub fn write_message_2<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let end = MSG2_PAYLOAD_OFFSET
            .checked_add(payload.len())
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < end + TAGLEN {
            return Err(Error::BufferTooSmall);
        }
        out[MSG2_PAYLOAD_OFFSET..end].copy_from_slice(payload);
        self.write_message_2_in_place(rng, payload.len(), out)
    }

    /// Writes message 2 with the payload already staged in `out`.
    ///
    /// The caller must have placed `payload_len` bytes at
    /// `out[MSG2_PAYLOAD_OFFSET..][..payload_len]`.
    pub fn write_message_2_in_place<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        payload_len: usize,
        out: &mut [u8],
    ) -> Result<usize> {
        if self.role != Role::Responder || self.step != Step::AwaitingMessage2 {
            return Err(Error::HandshakeState);
        }
        let total = MSG2_OVERHEAD
            .checked_add(payload_len)
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        let re = *self.re.as_ref().ok_or(Error::HandshakeState)?;
        let rs = *self.rs.as_ref().ok_or(Error::HandshakeState)?;

        // -> e
        let e = Keypair::generate(rng);
        out[..DHLEN].copy_from_slice(e.public());
        self.sym.mix_hash(&out[..DHLEN]);

        // -> ee
        self.sym.mix_key(&e.dh(&re));

        // -> se: responder mixes its ephemeral with the initiator's static.
        self.sym.mix_key(&e.dh(&rs));

        // -> payload
        self.sym
            .encrypt_and_hash(&mut out[MSG2_PAYLOAD_OFFSET..total], payload_len)?;

        self.e = Some(e);
        self.step = Step::Done;
        Ok(total)
    }

    /// Reads message 2, writing the decrypted payload into `out`.
    ///
    /// Returns the payload length.
    pub fn read_message_2(&mut self, msg: &[u8], out: &mut [u8]) -> Result<usize> {
        if self.role != Role::Initiator || self.step != Step::AwaitingMessage2 {
            return Err(Error::HandshakeState);
        }
        if msg.len() < MSG2_OVERHEAD {
            return Err(Error::MessageTooShort);
        }
        let e = self.e.as_ref().ok_or(Error::HandshakeState)?;

        // <- e
        let mut re = [0u8; DHLEN];
        re.copy_from_slice(&msg[..DHLEN]);
        self.sym.mix_hash(&re);

        // <- ee
        let ee = e.dh(&re);
        self.sym.mix_key(&ee);

        // <- se: initiator mixes its static with the responder's ephemeral.
        let se = self.s.dh(&re);
        self.sym.mix_key(&se);

        // <- payload
        let ct = &msg[DHLEN..];
        if out.len() < ct.len() {
            return Err(Error::BufferTooSmall);
        }
        out[..ct.len()].copy_from_slice(ct);
        let pt_len = self.sym.decrypt_and_hash(&mut out[..ct.len()])?;

        self.re = Some(re);
        self.step = Step::Done;
        Ok(pt_len)
    }

    /// Finishes the handshake, returning `(send, receive)` transport ciphers.
    ///
    /// Fails with [`Error::HandshakeState`] if the handshake is incomplete.
    pub fn split(self) -> Result<(CipherState, CipherState)> {
        if self.step != Step::Done {
            return Err(Error::HandshakeState);
        }
        let (c1, c2) = self.sym.split();
        Ok(match self.role {
            Role::Initiator => (c1, c2),
            Role::Responder => (c2, c1),
        })
    }

    /// Derives the key a later resumption will use as its pre-shared key.
    ///
    /// Valid only once the handshake is complete. Both peers derive the same
    /// value, so it can be stored on each side and used to skip three of the
    /// four Diffie-Hellman operations next time.
    pub fn resumption_key(&self) -> [u8; 32] {
        self.sym.resumption_key()
    }

    /// The final transcript hash, usable as a channel binding value.
    pub fn handshake_hash(&self) -> super::Hash {
        self.sym.handshake_hash()
    }
}
