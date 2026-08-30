//! The `NNpsk0` handshake, used for session resumption.
//!
//! ```text
//! NNpsk0:
//!   -> psk, e
//!   <- e, ee
//! ```
//!
//! ## Why this pattern
//!
//! The full `IK` handshake costs each peer four Diffie-Hellman operations. On
//! a Cortex-M4 that is on the order of a hundred milliseconds, and a device
//! that reboots pays it again every time. That is the single largest latency
//! cost the protocol has on constrained hardware.
//!
//! `NNpsk0` costs **one** Diffie-Hellman. Authentication comes from a
//! pre-shared key that a previous `IK` handshake established, so the identities
//! are still bound — transitively, the same way TLS 1.3 resumption works.
//!
//! ## Forward secrecy is retained
//!
//! Both peers contribute a fresh ephemeral and the `ee` operation mixes them,
//! so an attacker who later steals the stored resumption key still cannot
//! decrypt a recorded resumed session: they would also need an ephemeral
//! private key, and those are discarded.
//!
//! ## The `e` token behaves differently here
//!
//! In a pre-shared-key pattern the Noise specification requires that an
//! ephemeral public key be mixed into the chaining key as well as the
//! transcript. It is an easy thing to miss, and missing it produces a key
//! schedule that no conforming implementation agrees with, so the cross
//! implementation tests cover this pattern too.

use rand_core::{CryptoRng, RngCore};

use super::cipher::{CipherState, TAGLEN};
use super::symmetric::SymmetricState;
use super::RESUME_PROTOCOL_NAME;
use crate::error::{Error, Result};
use crate::keys::{Keypair, PublicKey, DHLEN};

/// Bytes either resumption message adds on top of its payload.
///
/// `e` (32) plus the payload tag (16). Both messages have the same shape.
pub const RESUME_MSG_OVERHEAD: usize = DHLEN + TAGLEN;

/// Offset of the payload within a resumption message.
pub const RESUME_PAYLOAD_OFFSET: usize = DHLEN;

/// Length of the pre-shared key.
pub const PSK_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    AwaitingMessage1,
    AwaitingMessage2,
    Done,
}

/// An in-progress `NNpsk0` handshake.
pub struct ResumeHandshake {
    sym: SymmetricState,
    initiator: bool,
    e: Option<Keypair>,
    re: Option<PublicKey>,
    step: Step,
}

impl ResumeHandshake {
    fn init(initiator: bool, psk: &[u8; PSK_LEN], prologue: &[u8]) -> Self {
        let mut sym = SymmetricState::new(RESUME_PROTOCOL_NAME);
        sym.mix_hash(prologue);
        // `psk0`: the key is consumed before any other token.
        sym.mix_key_and_hash(psk);
        Self {
            sym,
            initiator,
            e: None,
            re: None,
            step: if initiator {
                Step::AwaitingMessage2
            } else {
                Step::AwaitingMessage1
            },
        }
    }

    /// Starts a resumption as the initiator.
    pub fn initiator(psk: &[u8; PSK_LEN], prologue: &[u8]) -> Self {
        Self::init(true, psk, prologue)
    }

    /// Starts a resumption as the responder.
    pub fn responder(psk: &[u8; PSK_LEN], prologue: &[u8]) -> Self {
        Self::init(false, psk, prologue)
    }

    /// Whether the handshake has completed.
    pub fn is_done(&self) -> bool {
        self.step == Step::Done
    }

    /// Writes message 1, carrying `payload` as 0-RTT data.
    ///
    /// The payload is encrypted under a key derived from the resumption key
    /// alone, so it has the same caveats as 0-RTT data in a full handshake: no
    /// forward secrecy, and replayable by anyone who captures the frame.
    pub fn write_message_1<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        payload_len: usize,
        out: &mut [u8],
    ) -> Result<usize> {
        if !self.initiator || self.step != Step::AwaitingMessage2 || self.e.is_some() {
            return Err(Error::HandshakeState);
        }
        let total = RESUME_MSG_OVERHEAD
            .checked_add(payload_len)
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        // -> e
        let e = Keypair::generate(rng);
        out[..DHLEN].copy_from_slice(e.public());
        self.sym.mix_ephemeral_with_psk(&out[..DHLEN]);

        // -> payload
        self.sym
            .encrypt_and_hash(&mut out[RESUME_PAYLOAD_OFFSET..total], payload_len)?;

        self.e = Some(e);
        Ok(total)
    }

    /// Reads message 1, writing the decrypted payload into `out`.
    pub fn read_message_1(&mut self, msg: &[u8], out: &mut [u8]) -> Result<usize> {
        if self.initiator || self.step != Step::AwaitingMessage1 {
            return Err(Error::HandshakeState);
        }
        if msg.len() < RESUME_MSG_OVERHEAD {
            return Err(Error::MessageTooShort);
        }

        // <- e
        let mut re = [0u8; DHLEN];
        re.copy_from_slice(&msg[..DHLEN]);
        self.sym.mix_ephemeral_with_psk(&re);

        // <- payload
        let ct = &msg[RESUME_PAYLOAD_OFFSET..];
        if out.len() < ct.len() {
            return Err(Error::BufferTooSmall);
        }
        out[..ct.len()].copy_from_slice(ct);
        let pt_len = self.sym.decrypt_and_hash(&mut out[..ct.len()])?;

        self.re = Some(re);
        self.step = Step::AwaitingMessage2;
        Ok(pt_len)
    }

    /// Writes message 2, carrying `payload`.
    pub fn write_message_2<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        payload_len: usize,
        out: &mut [u8],
    ) -> Result<usize> {
        if self.initiator || self.step != Step::AwaitingMessage2 {
            return Err(Error::HandshakeState);
        }
        let total = RESUME_MSG_OVERHEAD
            .checked_add(payload_len)
            .ok_or(Error::PayloadTooLarge)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        let re = *self.re.as_ref().ok_or(Error::HandshakeState)?;

        // -> e
        let e = Keypair::generate(rng);
        out[..DHLEN].copy_from_slice(e.public());
        self.sym.mix_ephemeral_with_psk(&out[..DHLEN]);

        // -> ee: the one and only Diffie-Hellman in this handshake.
        self.sym.mix_key(&e.dh(&re));

        // -> payload
        self.sym
            .encrypt_and_hash(&mut out[RESUME_PAYLOAD_OFFSET..total], payload_len)?;

        self.e = Some(e);
        self.step = Step::Done;
        Ok(total)
    }

    /// Reads message 2, writing the decrypted payload into `out`.
    pub fn read_message_2(&mut self, msg: &[u8], out: &mut [u8]) -> Result<usize> {
        if !self.initiator || self.step != Step::AwaitingMessage2 {
            return Err(Error::HandshakeState);
        }
        if msg.len() < RESUME_MSG_OVERHEAD {
            return Err(Error::MessageTooShort);
        }
        let e = self.e.as_ref().ok_or(Error::HandshakeState)?;

        // <- e
        let mut re = [0u8; DHLEN];
        re.copy_from_slice(&msg[..DHLEN]);
        self.sym.mix_ephemeral_with_psk(&re);

        // <- ee
        let ee = e.dh(&re);
        self.sym.mix_key(&ee);

        // <- payload
        let ct = &msg[RESUME_PAYLOAD_OFFSET..];
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
    pub fn split(self) -> Result<(CipherState, CipherState)> {
        if self.step != Step::Done {
            return Err(Error::HandshakeState);
        }
        let (c1, c2) = self.sym.split();
        Ok(if self.initiator { (c1, c2) } else { (c2, c1) })
    }

    /// The transcript hash, from which the next resumption key is derived.
    pub fn handshake_hash(&self) -> super::Hash {
        self.sym.handshake_hash()
    }

    /// Derives the key for the next resumption from the finished handshake.
    pub fn next_resumption_key(&self) -> [u8; PSK_LEN] {
        self.sym.resumption_key()
    }
}
