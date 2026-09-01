//! Every combination of the optional plaintext prefixes.
//!
//! A data frame's plaintext may carry three things before the payload, each
//! present only when its flag is set (SPEC §5.3, §5.4, §5.6):
//!
//! ```text
//! [ length : u16 ]?      PADDED    — 2 bytes, then the payload, then zero fill
//! [ message_id : u32 ]?  RELIABLE  — 4 bytes
//! [ fragment : 8 ]?      FRAGMENT  — 8 bytes
//! payload
//! ```
//!
//! `open` peels them in that order with hand-written arithmetic — an offset
//! that advances, a length that shrinks, and a final `copy_within` that moves
//! the payload down to where callers expect it. Eight combinations, and the
//! tests covered padding alone and reliability alone. Nothing sealed a
//! fragment at all: `seal_fragment` appeared in no test in the repository.
//!
//! Off-by-one errors live in exactly this shape, and an off-by-one here is a
//! payload delivered with somebody else's bytes on the front of it.

use fectp_core::fragment::Fragment;
use fectp_core::frame::{FLAG_FRAGMENT, FLAG_PADDED, FLAG_RELIABLE, HEADER_LEN};
use fectp_core::keys::Keypair;
use fectp_core::session::{Capabilities, Initiator, Responder, PAD_BLOCK};
use proptest::prelude::*;
use rand_core::OsRng;

const SERVER_SECRET: [u8; 32] = [0xA1; 32];
const CLIENT_SECRET: [u8; 32] = [0xB2; 32];

/// Two established sessions.
fn connect() -> (fectp_core::Session, fectp_core::Session) {
    let server_kp = Keypair::from_secret(SERVER_SECRET);
    let server_public = *server_kp.public();
    let caps = Capabilities::minimal(4096);

    let mut initiator = Initiator::new(
        Keypair::from_secret(CLIENT_SECRET),
        server_public,
        0xFECD_0001,
        caps,
    )
    .expect("initiator");
    let mut responder = Responder::new(server_kp, caps);

    let mut wire = [0u8; 4096];
    let mut scratch = [0u8; 4096];
    let n = initiator.write_init(&mut OsRng, b"", &mut wire).expect("init");
    responder.read_init(&wire[..n], &mut scratch).expect("read init");
    let (server, n) = responder
        .write_response(&mut OsRng, b"", &mut wire)
        .expect("response");
    let (client, _) = initiator
        .read_response(&wire[..n], &mut scratch)
        .expect("read response");
    (client, server)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Whatever prefixes a frame carries, the payload comes back exactly.
    ///
    /// The generated part is the payload and the identifiers; the combinations
    /// are enumerated rather than sampled, because there are only eight and
    /// leaving one to chance is how a gap like this one survives.
    #[test]
    fn a_payload_survives_every_combination_of_prefixes(
        len in 0usize..600,
        message_id in any::<u32>(),
        message in any::<u32>(),
        index in 0u16..64,
        extra in 0u16..64,
        seed in any::<u64>(),
    ) {
        let mut state = seed | 1;
        let payload: Vec<u8> = (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();

        // A coherent descriptor: SPEC §5.6 requires index < count <= 4096.
        let count = index.saturating_add(extra).saturating_add(1).min(4096);
        let fragment = Fragment {
            message,
            index: index.min(count - 1),
            count,
        };

        for padded in [false, true] {
            for reliable in [false, true] {
                for fragmented in [false, true] {
                    // A descriptor without an identifier is not a shape the
                    // protocol has: every fragment is a reliable message.
                    if fragmented && !reliable {
                        continue;
                    }

                    let (mut client, mut server) = connect();
                    client.set_padding(padded);

                    let mut frame = vec![0u8; 4096];
                    let n = if fragmented {
                        client.seal_fragment(&payload, message_id, fragment, 0, &mut frame)
                    } else if reliable {
                        client.seal_reliable(&payload, message_id, 0, &mut frame)
                    } else {
                        client.seal(&payload, 0, &mut frame)
                    }
                    .expect("seal");

                    let opened = server.open(&mut frame[..n]).expect("open");

                    prop_assert_eq!(
                        opened.header.flags & FLAG_PADDED != 0, padded,
                        "the padded flag must survive"
                    );
                    prop_assert_eq!(
                        opened.header.flags & FLAG_RELIABLE != 0, reliable,
                        "the reliable flag must survive"
                    );
                    prop_assert_eq!(
                        opened.header.flags & FLAG_FRAGMENT != 0, fragmented,
                        "the fragment flag must survive"
                    );

                    prop_assert_eq!(
                        opened.len, len,
                        "padded={} reliable={} fragmented={}: length came back wrong",
                        padded, reliable, fragmented
                    );
                    prop_assert_eq!(
                        &frame[HEADER_LEN..HEADER_LEN + opened.len],
                        &payload[..],
                        "padded={} reliable={} fragmented={}: the payload is not where it should be",
                        padded, reliable, fragmented
                    );

                    prop_assert_eq!(
                        opened.message_id,
                        reliable.then_some(message_id),
                        "the identifier must come back as it went"
                    );
                    prop_assert_eq!(
                        opened.fragment,
                        fragmented.then_some(fragment),
                        "the descriptor must come back as it went"
                    );
                }
            }
        }
    }

    /// Padding hides the length whatever else the frame carries.
    ///
    /// The existing test covers a plain payload. With a message identifier and
    /// a descriptor in front of it, the block boundary is computed over the
    /// whole plaintext — so the property has to hold there too, or the frame
    /// size leaks through the prefixes.
    #[test]
    fn padding_reaches_a_block_boundary_with_any_prefix(
        len in 0usize..400,
        message_id in any::<u32>(),
    ) {
        let fragment = Fragment { message: 7, index: 0, count: 3 };

        for (reliable, fragmented) in [(false, false), (true, false), (true, true)] {
            let (mut client, _server) = connect();
            client.set_padding(true);

            let mut frame = vec![0u8; 4096];
            let n = if fragmented {
                client.seal_fragment(&vec![0u8; len], message_id, fragment, 0, &mut frame)
            } else if reliable {
                client.seal_reliable(&vec![0u8; len], message_id, 0, &mut frame)
            } else {
                client.seal(&vec![0u8; len], 0, &mut frame)
            }
            .expect("seal");

            let plaintext = n - HEADER_LEN - 16; // the AEAD tag
            prop_assert_eq!(
                plaintext % PAD_BLOCK, 0,
                "reliable={} fragmented={}: {} bytes of plaintext is not a multiple of {}",
                reliable, fragmented, plaintext, PAD_BLOCK
            );
        }
    }
}

/// Two payloads in the same block are the same size on the wire, prefixes and
/// all.
///
/// This is what padding is *for*, and the existing test checks it for a bare
/// payload. A prefix that pushed one of them into the next block would leak the
/// difference the padding exists to hide.
#[test]
fn same_block_payloads_are_indistinguishable_with_prefixes() {
    let fragment = Fragment {
        message: 1,
        index: 2,
        count: 5,
    };

    // 2 length + 4 identifier + 8 descriptor is 14, so a payload of 1 and one
    // of 49 both land in the first 64-byte block and must come to one size.
    let mut sizes = Vec::new();
    for len in [1usize, 20, 49] {
        let (mut client, mut server) = connect();
        client.set_padding(true);
        let mut frame = vec![0u8; 4096];
        let n = client
            .seal_fragment(&vec![0xC3; len], 77, fragment, 0, &mut frame)
            .expect("seal");
        sizes.push(n);

        let opened = server.open(&mut frame[..n]).expect("open");
        assert_eq!(opened.len, len, "the real length must survive");
        assert_eq!(opened.fragment, Some(fragment));
    }
    assert!(
        sizes.windows(2).all(|w| w[0] == w[1]),
        "payloads of 1 and 49 bytes must look the same on the wire even behind \
         a message identifier and a fragment descriptor, got {sizes:?}"
    );
}

/// A fragment descriptor that could not be coherent is refused on the way in.
///
/// `open` decodes it rather than trusting it, so the reassembly layer never
/// receives an index past the end of the message it claims to belong to.
#[test]
fn an_incoherent_descriptor_is_refused_when_the_frame_is_opened() {
    for bad in [
        Fragment { message: 1, index: 0, count: 0 },
        Fragment { message: 1, index: 4, count: 4 },
        Fragment { message: 1, index: 0, count: 4097 },
    ] {
        let (mut client, mut server) = connect();
        let mut frame = vec![0u8; 4096];
        let n = client
            .seal_fragment(b"payload", 1, bad, 0, &mut frame)
            .expect("sealing does not judge the descriptor");
        assert!(
            server.open(&mut frame[..n]).is_err(),
            "opening must refuse index {} of {}",
            bad.index,
            bad.count
        );
    }
}
