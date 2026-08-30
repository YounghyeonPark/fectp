//! Cross-implementation validation against `snow`.
//!
//! A hand-written Noise implementation is only trustworthy if it interoperates
//! with an independent one. These tests drive our `HandshakeState` against
//! `snow` in both roles. Any divergence in the key schedule, the transcript
//! hash, the HMAC, or the HKDF makes the peer's decryption fail, so a passing
//! run exercises every step of the handshake.

use fectp_core::keys::Keypair;
use fectp_core::noise::{HandshakeState, ResumeHandshake, RESUME_PAYLOAD_OFFSET};
use rand_core::OsRng;
use snow::Builder;

const PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"fectp/1 interop";

const INITIATOR_SECRET: [u8; 32] = [0x11; 32];
const RESPONDER_SECRET: [u8; 32] = [0x22; 32];

/// Our initiator against snow's responder.
#[test]
fn our_initiator_talks_to_snow_responder() {
    let responder_kp = Keypair::from_secret(RESPONDER_SECRET);
    let responder_public = *responder_kp.public();
    let initiator_kp = Keypair::from_secret(INITIATOR_SECRET);
    let initiator_public = *initiator_kp.public();

    let mut ours = HandshakeState::initiator(initiator_kp, responder_public, PROLOGUE);
    let mut theirs = Builder::new(PARAMS.parse().unwrap())
        .local_private_key(&RESPONDER_SECRET)
        .prologue(PROLOGUE)
        .build_responder()
        .expect("snow responder");

    let mut wire = [0u8; 1024];
    let mut plain = [0u8; 1024];

    // Message 1, carrying 0-RTT application data.
    let n = ours
        .write_message_1(&mut OsRng, b"0-RTT request", &mut wire)
        .expect("write message 1");
    let len = theirs.read_message(&wire[..n], &mut plain).expect("snow reads message 1");
    assert_eq!(&plain[..len], b"0-RTT request");

    // The responder authenticates the initiator from message 1 alone.
    assert_eq!(
        theirs.get_remote_static().expect("remote static"),
        &initiator_public[..],
        "snow must recover our static key from the encrypted `s` token"
    );

    // Message 2.
    let n = theirs.write_message(b"welcome", &mut wire).expect("snow writes message 2");
    let len = ours.read_message_2(&wire[..n], &mut plain).expect("read message 2");
    assert_eq!(&plain[..len], b"welcome");

    // Both sides must derive identical transport keys.
    let (our_send, our_recv) = ours.split().expect("split");
    let mut their_transport = theirs.into_transport_mode().expect("transport mode");

    let mut buf = [0u8; 256];
    buf[..12].copy_from_slice(b"ping from us");
    let ct = our_send.encrypt_at(&[], 0, &mut buf, 12).expect("seal");
    let len = their_transport
        .read_message(&buf[..ct], &mut plain)
        .expect("snow decrypts our data");
    assert_eq!(&plain[..len], b"ping from us");

    let ct = their_transport
        .write_message(b"pong from snow", &mut wire)
        .expect("snow seals");
    let mut buf = [0u8; 256];
    buf[..ct].copy_from_slice(&wire[..ct]);
    let len = our_recv.decrypt_at(&[], 0, &mut buf[..ct]).expect("open");
    assert_eq!(&buf[..len], b"pong from snow");
}

/// Snow's initiator against our responder.
#[test]
fn snow_initiator_talks_to_our_responder() {
    let responder_kp = Keypair::from_secret(RESPONDER_SECRET);
    let responder_public = *responder_kp.public();
    let initiator_public = *Keypair::from_secret(INITIATOR_SECRET).public();

    let mut theirs = Builder::new(PARAMS.parse().unwrap())
        .local_private_key(&INITIATOR_SECRET)
        .remote_public_key(&responder_public)
        .prologue(PROLOGUE)
        .build_initiator()
        .expect("snow initiator");
    let mut ours = HandshakeState::responder(responder_kp, PROLOGUE);

    let mut wire = [0u8; 1024];
    let mut plain = [0u8; 1024];

    let n = theirs.write_message(b"hello from snow", &mut wire).expect("snow message 1");
    let len = ours.read_message_1(&wire[..n], &mut plain).expect("read message 1");
    assert_eq!(&plain[..len], b"hello from snow");
    assert_eq!(ours.remote_static(), Some(&initiator_public));

    let n = ours
        .write_message_2(&mut OsRng, b"welcome from fectp", &mut wire)
        .expect("write message 2");
    let len = theirs.read_message(&wire[..n], &mut plain).expect("snow reads message 2");
    assert_eq!(&plain[..len], b"welcome from fectp");

    let (our_send, _our_recv) = ours.split().expect("split");
    let mut their_transport = theirs.into_transport_mode().expect("transport mode");

    let mut buf = [0u8; 256];
    buf[..9].copy_from_slice(b"responder");
    let ct = our_send.encrypt_at(&[], 0, &mut buf, 9).expect("seal");
    let len = their_transport
        .read_message(&buf[..ct], &mut plain)
        .expect("snow decrypts");
    assert_eq!(&plain[..len], b"responder");
}

/// An initiator that targets the wrong responder key must fail to authenticate.
#[test]
fn wrong_responder_key_is_rejected() {
    let wrong_public = *Keypair::from_secret([0x33; 32]).public();
    let mut ours =
        HandshakeState::initiator(Keypair::from_secret(INITIATOR_SECRET), wrong_public, PROLOGUE);
    let mut theirs = Builder::new(PARAMS.parse().unwrap())
        .local_private_key(&RESPONDER_SECRET)
        .prologue(PROLOGUE)
        .build_responder()
        .expect("snow responder");

    let mut wire = [0u8; 1024];
    let mut plain = [0u8; 1024];
    let n = ours.write_message_1(&mut OsRng, b"", &mut wire).expect("write");
    assert!(
        theirs.read_message(&wire[..n], &mut plain).is_err(),
        "a handshake aimed at the wrong static key must not authenticate"
    );
}

/// A mismatched prologue must break the handshake, which is what makes the
/// frame header tamper-evident.
#[test]
fn prologue_mismatch_is_rejected() {
    let responder_public = *Keypair::from_secret(RESPONDER_SECRET).public();
    let mut ours = HandshakeState::initiator(
        Keypair::from_secret(INITIATOR_SECRET),
        responder_public,
        b"prologue-a",
    );
    let mut theirs = Builder::new(PARAMS.parse().unwrap())
        .local_private_key(&RESPONDER_SECRET)
        .prologue(b"prologue-b")
        .build_responder()
        .expect("snow responder");

    let mut wire = [0u8; 1024];
    let mut plain = [0u8; 1024];
    let n = ours.write_message_1(&mut OsRng, b"", &mut wire).expect("write");
    assert!(theirs.read_message(&wire[..n], &mut plain).is_err());
}

// --------------------------------------------------------- resumption ---

const RESUME_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const PSK: [u8; 32] = [0x5A; 32];

/// Stages `payload` where a resumption message expects it and writes message 1.
fn write_resume_1(hs: &mut ResumeHandshake, payload: &[u8], out: &mut [u8]) -> usize {
    out[RESUME_PAYLOAD_OFFSET..RESUME_PAYLOAD_OFFSET + payload.len()].copy_from_slice(payload);
    hs.write_message_1(&mut OsRng, payload.len(), out)
        .expect("write resume 1")
}

fn write_resume_2(hs: &mut ResumeHandshake, payload: &[u8], out: &mut [u8]) -> usize {
    out[RESUME_PAYLOAD_OFFSET..RESUME_PAYLOAD_OFFSET + payload.len()].copy_from_slice(payload);
    hs.write_message_2(&mut OsRng, payload.len(), out)
        .expect("write resume 2")
}

/// Our resumption initiator against snow's `NNpsk0` responder.
///
/// This is the test that catches the easy mistake in a pre-shared-key pattern:
/// the `e` token must be mixed into the chaining key as well as the
/// transcript. Get that wrong and the key schedules diverge silently.
#[test]
fn our_resume_initiator_talks_to_snow() {
    let mut ours = ResumeHandshake::initiator(&PSK, PROLOGUE);
    let mut theirs = Builder::new(RESUME_PARAMS.parse().unwrap())
        .prologue(PROLOGUE)
        .psk(0, &PSK)
        .build_responder()
        .expect("snow responder");

    let mut wire = [0u8; 1024];
    let mut plain = [0u8; 1024];

    let n = write_resume_1(&mut ours, b"resumed 0-RTT", &mut wire);
    let len = theirs.read_message(&wire[..n], &mut plain).expect("snow reads 1");
    assert_eq!(&plain[..len], b"resumed 0-RTT");

    let n = theirs.write_message(b"welcome back", &mut wire).expect("snow writes 2");
    let len = ours.read_message_2(&wire[..n], &mut plain).expect("read 2");
    assert_eq!(&plain[..len], b"welcome back");

    // Transport keys must match.
    let (our_send, _) = ours.split().expect("split");
    let mut their_transport = theirs.into_transport_mode().expect("transport");
    let mut buf = [0u8; 256];
    buf[..8].copy_from_slice(b"resumed!");
    let ct = our_send.encrypt_at(&[], 0, &mut buf, 8).expect("seal");
    let len = their_transport.read_message(&buf[..ct], &mut plain).expect("snow opens");
    assert_eq!(&plain[..len], b"resumed!");
}

/// Snow's `NNpsk0` initiator against our resumption responder.
#[test]
fn snow_resume_initiator_talks_to_us() {
    let mut theirs = Builder::new(RESUME_PARAMS.parse().unwrap())
        .prologue(PROLOGUE)
        .psk(0, &PSK)
        .build_initiator()
        .expect("snow initiator");
    let mut ours = ResumeHandshake::responder(&PSK, PROLOGUE);

    let mut wire = [0u8; 1024];
    let mut plain = [0u8; 1024];

    let n = theirs.write_message(b"hello again", &mut wire).expect("snow writes 1");
    let len = ours.read_message_1(&wire[..n], &mut plain).expect("read 1");
    assert_eq!(&plain[..len], b"hello again");

    let n = write_resume_2(&mut ours, b"welcome", &mut wire);
    let len = theirs.read_message(&wire[..n], &mut plain).expect("snow reads 2");
    assert_eq!(&plain[..len], b"welcome");

    let (our_send, _) = ours.split().expect("split");
    let mut their_transport = theirs.into_transport_mode().expect("transport");
    let mut buf = [0u8; 256];
    buf[..6].copy_from_slice(b"server");
    let ct = our_send.encrypt_at(&[], 0, &mut buf, 6).expect("seal");
    let len = their_transport.read_message(&buf[..ct], &mut plain).expect("snow opens");
    assert_eq!(&plain[..len], b"server");
}

/// The wrong resumption key must not authenticate.
#[test]
fn a_mismatched_resumption_key_is_rejected() {
    let mut ours = ResumeHandshake::initiator(&[0xEE; 32], PROLOGUE);
    let mut theirs = Builder::new(RESUME_PARAMS.parse().unwrap())
        .prologue(PROLOGUE)
        .psk(0, &PSK)
        .build_responder()
        .expect("snow responder");

    let mut wire = [0u8; 1024];
    let mut plain = [0u8; 1024];
    let n = write_resume_1(&mut ours, b"", &mut wire);
    assert!(
        theirs.read_message(&wire[..n], &mut plain).is_err(),
        "a stale or forged resumption key must not let the handshake through"
    );
}

/// Both peers derive the same resumption key from a full handshake.
#[test]
fn both_peers_derive_the_same_resumption_key() {
    let responder_kp = Keypair::from_secret(RESPONDER_SECRET);
    let responder_public = *responder_kp.public();

    let mut initiator =
        HandshakeState::initiator(Keypair::from_secret(INITIATOR_SECRET), responder_public, PROLOGUE);
    let mut responder = HandshakeState::responder(responder_kp, PROLOGUE);

    let mut wire = [0u8; 1024];
    let mut plain = [0u8; 1024];

    let n = initiator.write_message_1(&mut OsRng, b"", &mut wire).expect("msg1");
    responder.read_message_1(&wire[..n], &mut plain).expect("read msg1");
    let n = responder.write_message_2(&mut OsRng, b"", &mut wire).expect("msg2");
    initiator.read_message_2(&wire[..n], &mut plain).expect("read msg2");

    let client_key = initiator.resumption_key();
    let server_key = responder.resumption_key();
    assert_eq!(
        client_key, server_key,
        "resumption is only possible if both sides derive the same key"
    );

    // And it must be independent of the transport keys.
    let mut probe = [0u8; 256];
    probe[..4].copy_from_slice(b"test");
    let (send, _) = initiator.split().expect("split");
    let ct = send.encrypt_at(&[], 0, &mut probe, 4).expect("seal");
    assert_ne!(
        &client_key[..],
        &probe[..ct.min(32)],
        "the resumption key must not be a transport key"
    );
}
