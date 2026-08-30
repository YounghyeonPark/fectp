//! The datagram transport abstraction.
//!
//! FECTP's core is defined over datagrams, not streams. That is not a
//! stylistic choice: QUIC cannot run on the smallest supported targets, so a
//! plain UDP socket is the only transport every profile shares. Richer
//! transports (QUIC, in particular) plug in here as optional backends on
//! platforms that can afford them.
//!
//! Implementations are connection-scoped: an instance is already bound to one
//! peer, so neither `send` nor `recv` carries an address.

/// A bidirectional, unreliable, unordered datagram channel to one peer.
///
/// Implementations must preserve datagram boundaries. They may drop,
/// duplicate, or reorder datagrams; the session layer tolerates all three.
pub trait Transport {
    /// Transport-specific failure type.
    type Error;

    /// Sends one datagram.
    ///
    /// This must hand the bytes to the underlying device without buffering or
    /// coalescing them with later datagrams. Nagle-style batching would add
    /// milliseconds of delay and defeat the protocol's purpose.
    fn send(&mut self, datagram: &[u8]) -> Result<(), Self::Error>;

    /// Receives one datagram into `buf`, returning its length.
    ///
    /// A datagram longer than `buf` is an error, not a truncation.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Largest datagram this transport can carry, in bytes.
    ///
    /// This bounds the frame size and therefore the buffers the caller must
    /// provide. On constrained targets it is set by available RAM rather than
    /// by the path MTU.
    fn max_datagram_size(&self) -> usize;
}
