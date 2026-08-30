//! Splitting a message across several frames, and putting it back together.
//!
//! A frame is bounded by the path MTU — 1200 bytes by default — because a
//! datagram larger than that is fragmented by IP, and IP fragmentation
//! multiplies the loss probability of the whole datagram by the number of
//! pieces it was cut into. FECTP therefore never emits an oversized datagram.
//!
//! That left a hard ceiling: a payload above `max_payload` could not be sent at
//! all. This module lifts it by cutting the message at the *protocol* layer
//! instead, where a lost piece can be retransmitted on its own rather than
//! costing the whole message.
//!
//! The descriptor below travels inside the encrypted plaintext, gated by
//! [`FLAG_FRAGMENT`](crate::frame::FLAG_FRAGMENT), so an unfragmented message
//! carries none of it. That placement is not incidental: the frame header is
//! deliberately fixed-size with no length arithmetic before authentication, and
//! reassembly state is exactly the kind of attacker-influenced arithmetic that
//! must stay behind the AEAD.

use crate::error::{Error, Result};

/// Bytes a fragment descriptor adds to the plaintext.
pub const FRAGMENT_LEN: usize = 8;

/// Largest message that may be reassembled, in bytes.
///
/// A receiver commits this much memory the moment it believes a peer's claim
/// about how many fragments are coming, so the claim has to be bounded. One
/// mebibyte is far above any single sensor block and far below anything that
/// would embarrass a constrained host.
pub const MAX_MESSAGE_LEN: usize = 1 << 20;

/// Largest number of fragments one message may be cut into.
pub const MAX_FRAGMENTS: u16 = 4096;

/// Where one frame sits within a larger message.
///
/// `message` identifies the logical message and is unrelated to the per-frame
/// [`MessageId`](crate::reliability::MessageId) the reliability layer assigns:
/// every fragment is its own reliable message, acknowledged and retransmitted
/// independently, and this is what says which larger thing they belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    /// Identifies the message these fragments make up.
    pub message: u32,
    /// Position of this fragment, counting from zero.
    pub index: u16,
    /// How many fragments the message was cut into.
    pub count: u16,
}

impl Fragment {
    /// Serialises into the first [`FRAGMENT_LEN`] bytes of `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < FRAGMENT_LEN {
            return Err(Error::BufferTooSmall);
        }
        out[..4].copy_from_slice(&self.message.to_le_bytes());
        out[4..6].copy_from_slice(&self.index.to_le_bytes());
        out[6..8].copy_from_slice(&self.count.to_le_bytes());
        Ok(())
    }

    /// Parses a fragment descriptor, rejecting one that cannot be coherent.
    ///
    /// A descriptor is checked here rather than at the point of use so that a
    /// receiver never reaches its reassembly table holding an index past the
    /// end of the message it claims to belong to.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < FRAGMENT_LEN {
            return Err(Error::MessageTooShort);
        }
        let mut message = [0u8; 4];
        message.copy_from_slice(&input[..4]);
        let mut index = [0u8; 2];
        index.copy_from_slice(&input[4..6]);
        let mut count = [0u8; 2];
        count.copy_from_slice(&input[6..8]);

        let fragment = Self {
            message: u32::from_le_bytes(message),
            index: u16::from_le_bytes(index),
            count: u16::from_le_bytes(count),
        };
        if fragment.count == 0
            || fragment.count > MAX_FRAGMENTS
            || fragment.index >= fragment.count
        {
            return Err(Error::BadHeader);
        }
        Ok(fragment)
    }

    /// Whether this is the last fragment of its message.
    pub fn is_last(&self) -> bool {
        self.index + 1 == self.count
    }
}

/// How many fragments `len` bytes need at `per_fragment` bytes each.
///
/// Returns `None` if the message would need more fragments than the protocol
/// allows, which is the same answer as "too large to send".
pub fn fragments_needed(len: usize, per_fragment: usize) -> Option<u16> {
    if per_fragment == 0 || len > MAX_MESSAGE_LEN {
        return None;
    }
    // An empty message is still one fragment: zero would mean "no message".
    let count = len.div_ceil(per_fragment).max(1);
    let count = u16::try_from(count).ok()?;
    (count <= MAX_FRAGMENTS).then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let fragment = Fragment {
            message: 0xDEAD_BEEF,
            index: 7,
            count: 9,
        };
        let mut buf = [0u8; FRAGMENT_LEN];
        fragment.encode(&mut buf).expect("encode");
        assert_eq!(Fragment::decode(&buf).expect("decode"), fragment);
    }

    #[test]
    fn an_index_past_the_end_is_refused() {
        // Reassembly indexes an array with this, so it is checked at the parse
        // rather than trusted and bounds-checked later.
        let fragment = Fragment {
            message: 1,
            index: 9,
            count: 9,
        };
        let mut buf = [0u8; FRAGMENT_LEN];
        fragment.encode(&mut buf).expect("encode");
        assert!(Fragment::decode(&buf).is_err());
    }

    #[test]
    fn a_count_of_zero_is_refused() {
        let mut buf = [0u8; FRAGMENT_LEN];
        buf[..4].copy_from_slice(&1u32.to_le_bytes());
        assert!(Fragment::decode(&buf).is_err());
    }

    #[test]
    fn an_absurd_fragment_count_is_refused() {
        // The receiver sizes a buffer from this, so an unbounded count is an
        // unbounded allocation.
        let mut buf = [0u8; FRAGMENT_LEN];
        buf[4..6].copy_from_slice(&0u16.to_le_bytes());
        buf[6..8].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(Fragment::decode(&buf).is_err());
    }

    #[test]
    fn counts_fragments() {
        assert_eq!(fragments_needed(0, 100), Some(1));
        assert_eq!(fragments_needed(100, 100), Some(1));
        assert_eq!(fragments_needed(101, 100), Some(2));
        assert_eq!(fragments_needed(MAX_MESSAGE_LEN + 1, 100), None);
    }

    #[test]
    fn refuses_a_message_needing_too_many_fragments() {
        // Small fragments and a large message: the limit that bites is the
        // fragment count, not the byte ceiling.
        assert_eq!(fragments_needed(MAX_MESSAGE_LEN, 16), None);
    }
}
