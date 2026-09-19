//! Test vectors: fixed inputs, and the exact bytes this implementation makes.
//!
//! [SPEC.md](../../../docs/SPEC.md) §9 tells an independent implementer to
//! validate the handshake against an existing Noise library and to implement
//! §3 through §6 themselves. Those are the parts no library gives them, and
//! until now the only way to check them was to run this code. That is the gap
//! these close: `docs/test-vectors.txt` is fixed inputs and expected bytes, in
//! a format that needs no parser library, so somebody working in C or Go can
//! compare their output without a Rust toolchain.
//!
//! **What a vector proves, and what it does not.** These are generated from
//! this implementation, so they cannot show it matches the specification —
//! only a reader can do that. What they do is pin the wire image: against
//! *this* implementation drifting silently, and for *another* implementation
//! to check itself against. The two tests below are the two directions, and
//! both are needed: `the_file_is_what_this_implementation_produces` catches
//! drift, and `the_file_decodes_back` catches an encoder and a decoder that
//! are wrong in the same direction and agree with each other.
//!
//! There is a class of fault vectors cannot reach at all, and it is not
//! hypothetical here. §5.5 notes that a conforming receiver cannot observe
//! whether a sender gave up on a reliable message — so the abandonment
//! reporting this project got wrong twice (D63) produces byte-identical
//! traffic either way. No vector catches it. Said here because the ordering in
//! OTHER-LANGUAGES.md puts vectors before bindings as though they subsume this.
//!
//! Regenerate with `FECTP_WRITE_VECTORS=1 cargo test -p fectp-core --test
//! vectors`. That is a deliberate act and shows up as a diff; a change to the
//! wire format that nobody intended shows up as a failing test.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use fectp_core::codec::{varint, CodecHeader, Entropy, Transform, CODEC_HEADER_LEN};
use fectp_core::frame::{
    FrameType, Header, FLAG_COMPRESSED, FLAG_FRAGMENT, FLAG_PADDED, FLAG_RELIABLE, HEADER_LEN,
};
use fectp_core::keys::Keypair;
use fectp_core::session::{Capabilities, Initiator, Responder, CAPS_LEN, REKEY_INTERVAL, INITIATOR_OVERHEAD, RESPONDER_OVERHEAD};
use rand_core::{CryptoRng, Error as RngError, RngCore};

/// Where the committed file lives.
fn vectors_path() -> PathBuf {
    docs_dir().join("test-vectors.txt")
}

/// The repository's documentation directory, two levels up from this crate.
fn docs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
}

/// Whether this is the repository rather than a crate unpacked from the index.
///
/// The vectors live in `docs/`, which is outside the package, so a consumer
/// running `cargo test` on the published crate has no file to check against.
/// Excluding the test from the package would do the same job and make
/// `cargo publish` warn every time — a warning during the one operation that
/// cannot be undone is worth avoiding.
///
/// The whole directory is the discriminator, not the file. A missing
/// `test-vectors.txt` beside a `docs/` that exists is a deleted artefact and
/// must still fail.
fn in_the_repository() -> bool {
    docs_dir().is_dir()
}

// ---------------------------------------------------------------- the format

/// One vector: a name and its ordered fields.
struct Vector {
    name: String,
    fields: Vec<(String, String)>,
}

/// Builds the file, one section at a time.
#[derive(Default)]
struct Builder {
    out: Vec<(String, Vec<Vector>)>,
}

impl Builder {
    fn section(&mut self, title: &str) -> &mut Vec<Vector> {
        self.out.push((title.to_string(), Vec::new()));
        &mut self.out.last_mut().expect("just pushed").1
    }
}

/// A vector under construction.
struct Fields(Vec<(String, String)>);

impl Fields {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn num(mut self, key: &str, value: u64) -> Self {
        self.0.push((key.to_string(), value.to_string()));
        self
    }

    fn word(mut self, key: &str, value: &str) -> Self {
        self.0.push((key.to_string(), value.to_string()));
        self
    }

    fn hex(mut self, key: &str, value: &[u8]) -> Self {
        self.0.push((key.to_string(), hex(value)));
        self
    }

    fn done(self, name: &str) -> Vector {
        Vector {
            name: name.to_string(),
            fields: self.0,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string has an odd length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// A parsed file: vector name to its fields, plus the order they appeared in.
struct Parsed {
    order: Vec<String>,
    by_name: BTreeMap<String, BTreeMap<String, String>>,
}

impl Parsed {
    /// Reads the format described at the top of the file itself.
    ///
    /// Deliberately small: comments, `[name]`, and `key = value`. An
    /// implementer in another language writes this in a dozen lines, which is
    /// the reason the file is not JSON.
    fn read(text: &str) -> Self {
        let mut order = Vec::new();
        let mut by_name: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut current: Option<String> = None;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                assert!(
                    by_name.insert(name.to_string(), BTreeMap::new()).is_none(),
                    "two vectors are named {name}"
                );
                order.push(name.to_string());
                current = Some(name.to_string());
                continue;
            }
            let (key, value) = line.split_once('=').unwrap_or_else(|| {
                panic!("a line is neither a comment, a name, nor a key: {line}")
            });
            let name = current.as_ref().expect("a field before any vector name");
            by_name
                .get_mut(name)
                .expect("named above")
                .insert(key.trim().to_string(), value.trim().to_string());
        }

        Self { order, by_name }
    }

    fn get(&self, vector: &str) -> &BTreeMap<String, String> {
        self.by_name
            .get(vector)
            .unwrap_or_else(|| panic!("the file has no vector named {vector}"))
    }
}

/// The fields of one vector, with the accessors the checks want.
trait Field {
    fn text(&self, key: &str) -> &str;
    fn bytes(&self, key: &str) -> Vec<u8>;
    fn number(&self, key: &str) -> u64;
}

impl Field for BTreeMap<String, String> {
    fn text(&self, key: &str) -> &str {
        self.get(key)
            .unwrap_or_else(|| panic!("a vector is missing the field {key}"))
    }

    fn bytes(&self, key: &str) -> Vec<u8> {
        unhex(self.text(key))
    }

    fn number(&self, key: &str) -> u64 {
        self.text(key).parse().expect("a decimal number")
    }
}

// ------------------------------------------------------------- the fixed RNG

/// Hands out a recorded byte string in place of randomness.
///
/// Every ephemeral below comes from here, which is what makes a handshake
/// frame reproducible: an implementer supplies the same bytes and must get the
/// same wire image. It panics rather than wrapping when it runs out, so a
/// change in how much randomness the handshake draws is loud.
struct Fixed {
    bytes: Vec<u8>,
    at: usize,
}

impl Fixed {
    fn new(seed: u8) -> Self {
        // A fixed, obviously-not-random pattern. Stated in the file as the
        // ephemeral secret, before X25519 clamps it.
        Self::from_bytes(
            (0..32u16)
                .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
                .collect(),
        )
    }

    /// From the bytes the file states, which is what an outside implementer
    /// has. The replay uses this so that nothing it checks comes from a
    /// compiled-in constant.
    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes, at: 0 }
    }
}

impl RngCore for Fixed {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(
            self.at + dest.len() <= self.bytes.len(),
            "the handshake drew {} bytes of randomness; this vector supplies {}. \
             If that is intended, widen Fixed and regenerate.",
            self.at + dest.len(),
            self.bytes.len()
        );
        dest.copy_from_slice(&self.bytes[self.at..self.at + dest.len()]);
        self.at += dest.len();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Fixed {}

// ------------------------------------------------------- the fixed key material

/// The initiator's long-term secret, before clamping.
const INITIATOR_SECRET: [u8; 32] = [0x11; 32];
/// The responder's long-term secret, before clamping.
const RESPONDER_SECRET: [u8; 32] = [0x22; 32];
/// Ephemeral seeds, so each side's ephemeral differs.
const INITIATOR_EPHEMERAL_SEED: u8 = 0x40;
const RESPONDER_EPHEMERAL_SEED: u8 = 0x80;
/// The session identifier these vectors use.
const SESSION_ID: u32 = 0x5eed_face;

fn caps() -> Capabilities {
    Capabilities {
        flags: fectp_core::session::CAP_RELIABLE,
        max_frame_size: 1200,
        codecs: fectp_core::codec::CODECS_CORE,
    }
}

// ------------------------------------------------------------- the generator

fn build() -> String {
    let mut b = Builder::default();
    frame_headers(&mut b);
    varints(&mut b);
    codec_headers(&mut b);
    transforms(&mut b);
    handshake(&mut b);
    render(&b)
}

fn frame_headers(b: &mut Builder) {
    let every_type = [
        ("handshake-init", FrameType::HandshakeInit),
        ("handshake-response", FrameType::HandshakeResponse),
        ("data", FrameType::Data),
        ("close", FrameType::Close),
        ("ack", FrameType::Ack),
        ("resume-init", FrameType::ResumeInit),
        ("resume-response", FrameType::ResumeResponse),
        ("path-challenge", FrameType::PathChallenge),
        ("path-response", FrameType::PathResponse),
    ];

    let section = b.section(
        "SPEC 3. Frame header, 14 bytes.\n\
         One vector per frame type with everything else at zero, so the type \
         bits stand alone,\n\
         then the flag and field edges. `encoded` is the whole header.",
    );

    for (name, frame_type) in every_type {
        let header = Header::new(frame_type, 0);
        section.push(encoded_header(&format!("header/type/{name}"), header));
    }

    for (name, flags) in [
        ("compressed", FLAG_COMPRESSED),
        ("reliable", FLAG_RELIABLE),
        ("padded", FLAG_PADDED),
        ("fragment", FLAG_FRAGMENT),
        (
            "all",
            FLAG_COMPRESSED | FLAG_RELIABLE | FLAG_PADDED | FLAG_FRAGMENT,
        ),
    ] {
        let mut header = Header::new(FrameType::Data, 0);
        header.flags = flags;
        section.push(encoded_header(&format!("header/flags/{name}"), header));
    }

    let mut edge = Header::new(FrameType::Data, u32::MAX);
    edge.sequence = u64::MAX;
    edge.flags = 0;
    section.push(encoded_header("header/edge/max-fields", edge));

    let mut typical = Header::new(FrameType::Data, SESSION_ID);
    typical.sequence = 0x0102_0304_0506_0708;
    typical.flags = FLAG_RELIABLE;
    section.push(encoded_header("header/edge/mixed-endianness", typical));
}

fn encoded_header(name: &str, header: Header) -> Vector {
    let mut out = [0u8; HEADER_LEN];
    header.encode(&mut out).expect("a header fits HEADER_LEN");
    Fields::new()
        .word("kind", "frame-header")
        .word("frame_type", frame_type_name(header.frame_type))
        .num("flags", u64::from(header.flags))
        .num("session_id", u64::from(header.session_id))
        .num("sequence", header.sequence)
        .hex("encoded", &out)
        .done(name)
}

fn frame_type_name(frame_type: FrameType) -> &'static str {
    match frame_type {
        FrameType::HandshakeInit => "handshake-init",
        FrameType::HandshakeResponse => "handshake-response",
        FrameType::Data => "data",
        FrameType::Close => "close",
        FrameType::Ack => "ack",
        FrameType::ResumeInit => "resume-init",
        FrameType::ResumeResponse => "resume-response",
        FrameType::PathChallenge => "path-challenge",
        FrameType::PathResponse => "path-response",
    }
}

fn frame_type_from_name(name: &str) -> FrameType {
    match name {
        "handshake-init" => FrameType::HandshakeInit,
        "handshake-response" => FrameType::HandshakeResponse,
        "data" => FrameType::Data,
        "close" => FrameType::Close,
        "ack" => FrameType::Ack,
        "resume-init" => FrameType::ResumeInit,
        "resume-response" => FrameType::ResumeResponse,
        "path-challenge" => FrameType::PathChallenge,
        "path-response" => FrameType::PathResponse,
        other => panic!("the file names a frame type this build does not have: {other}"),
    }
}

fn varints(b: &mut Builder) {
    let section = b.section(
        "SPEC 6. Varint, base-128 little-endian, and zigzag.\n\
         Every length boundary, because an overlong encoding was a real bug \
         here: the decoder\n\
         accepted one, so a value had two spellings.",
    );

    for value in [
        0u32,
        1,
        127,
        128,
        255,
        16_383,
        16_384,
        2_097_151,
        2_097_152,
        268_435_455,
        268_435_456,
        u32::MAX,
    ] {
        let mut out = [0u8; 5];
        let n = varint::encode(value, &mut out).expect("five bytes hold any u32");
        section.push(
            Fields::new()
                .word("kind", "varint")
                .num("value", u64::from(value))
                .num("length", n as u64)
                .hex("encoded", &out[..n])
                .done(&format!("varint/{value}")),
        );
    }

    for value in [0i32, -1, 1, -2, 2, i32::MAX, i32::MIN] {
        let zigzag = varint::zigzag(value);
        let mut out = [0u8; 5];
        let n = varint::encode(zigzag, &mut out).expect("five bytes hold any u32");
        section.push(
            Fields::new()
                .word("kind", "zigzag")
                .word("value", &value.to_string())
                .num("zigzag", u64::from(zigzag))
                .hex("encoded", &out[..n])
                .done(&format!("zigzag/{value}")),
        );
    }
}

fn codec_headers(b: &mut Builder) {
    let section = b.section(
        "SPEC 6. Codec header, 4 bytes, at the front of the *plaintext*.\n\
         The transform and entropy stages share a byte, low nibble first, \
         which is the part\n\
         an implementer is most likely to get backwards.",
    );

    let cases = [
        ("none", Transform::None, Entropy::None, 0u8, 0u16),
        ("i16-delta", Transform::I16Delta, Entropy::None, 2, 512),
        ("i32-delta", Transform::I32Delta, Entropy::None, 1, 1024),
        ("transpose", Transform::ByteTranspose, Entropy::None, 4, 256),
        ("zstd-alone", Transform::None, Entropy::Zstd, 0, 4096),
        ("transpose-zstd", Transform::ByteTranspose, Entropy::Zstd, 8, 65535),
    ];

    for (name, transform, entropy, param, original_len) in cases {
        let header = CodecHeader {
            transform,
            entropy,
            param,
            original_len,
        };
        let mut out = [0u8; CODEC_HEADER_LEN];
        header.encode(&mut out).expect("four bytes");
        section.push(
            Fields::new()
                .word("kind", "codec-header")
                .word("transform", transform_name(transform))
                .word("entropy", entropy_name(entropy))
                .num("param", u64::from(param))
                .num("original_len", u64::from(original_len))
                .hex("encoded", &out)
                .done(&format!("codec-header/{name}")),
        );
    }
}

fn transform_name(transform: Transform) -> &'static str {
    match transform {
        Transform::None => "none",
        Transform::I16Delta => "i16-delta",
        Transform::I32Delta => "i32-delta",
        Transform::ByteTranspose => "byte-transpose",
    }
}

fn transform_from_name(name: &str) -> Transform {
    match name {
        "none" => Transform::None,
        "i16-delta" => Transform::I16Delta,
        "i32-delta" => Transform::I32Delta,
        "byte-transpose" => Transform::ByteTranspose,
        other => panic!("the file names a transform this build does not have: {other}"),
    }
}

fn entropy_name(entropy: Entropy) -> &'static str {
    match entropy {
        Entropy::None => "none",
        Entropy::Zstd => "zstd",
    }
}

fn entropy_from_name(name: &str) -> Entropy {
    match name {
        "none" => Entropy::None,
        "zstd" => Entropy::Zstd,
        other => panic!("the file names an entropy stage this build does not have: {other}"),
    }
}

/// Four `i16` pairs and four `i32` values, chosen to cross zero and wrap.
const SAMPLES_I16: [u8; 16] = [
    0x00, 0x00, 0xff, 0x7f, 0x01, 0x00, 0x00, 0x80, 0x10, 0x27, 0xf0, 0xd8, 0xff, 0xff, 0x00, 0x00,
];
const SAMPLES_I32: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x80, 0x2a, 0x00, 0x00, 0x00,
];

fn transforms(b: &mut Builder) {
    let section = b.section(
        "SPEC 6. Structural transforms, applied before any entropy stage.\n\
         Entropy stages are not here: Zstandard's output depends on its \
         encoder's version and\n\
         level, so pinning those bytes would pin a dependency rather than \
         this protocol.",
    );

    let cases = [
        ("i16-delta/2ch", Transform::I16Delta, 2u8, &SAMPLES_I16[..]),
        ("i32-delta/1ch", Transform::I32Delta, 1, &SAMPLES_I32[..]),
        ("transpose/4", Transform::ByteTranspose, 4, &SAMPLES_I32[..]),
        ("transpose/2", Transform::ByteTranspose, 2, &SAMPLES_I16[..]),
    ];

    for (name, transform, param, input) in cases {
        let mut out = vec![0u8; input.len() + 64];
        let n = transform
            .apply(input, param, &mut out)
            .expect("the transform accepts its own sample");
        section.push(
            Fields::new()
                .word("kind", "transform")
                .word("transform", transform_name(transform))
                .num("param", u64::from(param))
                .hex("input", input)
                .hex("output", &out[..n])
                .done(&format!("transform/{name}")),
        );
    }
}

/// 0-RTT payload carried with message 1.
const ZERO_RTT: &[u8] = b"fectp/1 zero-rtt";
/// Payload carried with message 2.
const REPLY_PAYLOAD: &[u8] = b"fectp/1 reply";
/// Payload sealed into the data-frame vectors.
const DATA_PAYLOAD: &[u8] = b"fectp/1 data frame payload";

fn handshake(b: &mut Builder) {
    let initiator_key = Keypair::from_secret(INITIATOR_SECRET);
    let responder_key = Keypair::from_secret(RESPONDER_SECRET);
    let initiator_public = *initiator_key.public();
    let responder_public = *responder_key.public();

    let mut caps_encoded = [0u8; CAPS_LEN];
    caps()
        .encode_into(&mut caps_encoded)
        .expect("capabilities fit CAPS_LEN");

    let mut initiator =
        Initiator::new(initiator_key, responder_public, SESSION_ID, caps()).expect("initiator");
    let mut msg1 = vec![0u8; INITIATOR_OVERHEAD + ZERO_RTT.len()];
    let msg1_len = initiator
        .write_init(&mut Fixed::new(INITIATOR_EPHEMERAL_SEED), ZERO_RTT, &mut msg1)
        .expect("message 1");
    msg1.truncate(msg1_len);

    let mut responder = Responder::new(responder_key, caps());
    let mut zero_rtt_out = vec![0u8; msg1.len()];
    let zero_rtt_len = responder
        .read_init(&msg1, &mut zero_rtt_out)
        .expect("read message 1");
    assert_eq!(&zero_rtt_out[..zero_rtt_len], ZERO_RTT);

    let mut msg2 = vec![0u8; RESPONDER_OVERHEAD + REPLY_PAYLOAD.len()];
    let (mut server, msg2_len) = responder
        .write_response(
            &mut Fixed::new(RESPONDER_EPHEMERAL_SEED),
            REPLY_PAYLOAD,
            &mut msg2,
        )
        .expect("message 2");
    msg2.truncate(msg2_len);

    let mut reply_out = vec![0u8; msg2.len()];
    let (mut client, reply_len) = initiator
        .read_response(&msg2, &mut reply_out)
        .expect("read message 2");
    assert_eq!(&reply_out[..reply_len], REPLY_PAYLOAD);

    let section = b.section(
        "SPEC 4. Handshake, Noise_IK_25519_ChaChaPoly_BLAKE2s.\n\
         Every secret here is fixed and every ephemeral comes from a \
         recorded byte string, so\n\
         the frames are reproducible. The secrets are given before X25519 \
         clamps them, which is\n\
         what a library takes; each ephemeral public key is the first 32 \
         bytes of the Noise\n\
         message, so it can be read out of `frame` rather than restated. \
         X25519 clamps a scalar,\n\
         so the low three bits of the first byte and the top two of the \
         last do not reach the\n\
         frame: changing them here changes nothing, and an implementation \
         that clamps is right.\n\
         The message-1 header is the Noise prologue: version, frame type and \
         session id are\n\
         bound into the transcript, and tampering with them makes the \
         handshake fail to\n\
         authenticate. The message-2 header is not. An initiator compares \
         its frame type and\n\
         session id against what it is expecting and rejects a mismatch, \
         which is a check and\n\
         not a proof. The sequence and flag bytes of a handshake header are \
         zero and unused.",
    );

    section.push(
        Fields::new()
            .word("kind", "capabilities")
            .num("flags", u64::from(caps().flags))
            .num("max_frame_size", u64::from(caps().max_frame_size))
            .num("codecs", u64::from(caps().codecs))
            .hex("encoded", &caps_encoded)
            .done("handshake/capabilities"),
    );

    section.push(
        Fields::new()
            .word("kind", "static-keys")
            .hex("initiator_secret", &INITIATOR_SECRET)
            .hex("initiator_public", &initiator_public)
            .hex("responder_secret", &RESPONDER_SECRET)
            .hex("responder_public", &responder_public)
            .done("handshake/static-keys"),
    );

    section.push(
        Fields::new()
            .word("kind", "handshake-message")
            .num("session_id", u64::from(SESSION_ID))
            .hex("ephemeral_secret", &Fixed::new(INITIATOR_EPHEMERAL_SEED).bytes)
            .hex("payload", ZERO_RTT)
            .hex("frame", &msg1)
            .done("handshake/message-1"),
    );

    section.push(
        Fields::new()
            .word("kind", "handshake-message")
            .num("session_id", u64::from(SESSION_ID))
            .hex("ephemeral_secret", &Fixed::new(RESPONDER_EPHEMERAL_SEED).bytes)
            .hex("payload", REPLY_PAYLOAD)
            .hex("frame", &msg2)
            .done("handshake/message-2"),
    );

    // The identifier only. The ticket's key is secret material, and the
    // identifier is a hash of it — so an implementation that matches this got
    // the key right, and nothing has to print a key to show it.
    let initiator_ticket = client.resumption_ticket();
    let responder_ticket = server.resumption_ticket();
    assert_eq!(
        initiator_ticket.key(),
        responder_ticket.key(),
        "both sides derive the same resumption key"
    );
    section.push(
        Fields::new()
            .word("kind", "resumption-ticket")
            .hex("id", initiator_ticket.id())
            .done("handshake/resumption-ticket"),
    );

    // ----------------------------------------------------------- data frames

    let data = b.section(
        "SPEC 5. Data frames sealed by the session the handshake above \
         produced.\n\
         The whole 14-byte header is the AEAD's associated data and the \
         sequence number is the\n\
         nonce, so these pin the nonce schedule as well as the key \
         derivation. `sequence` counts\n\
         from zero per direction and never repeats.",
    );

    for (name, flags) in [
        ("client-to-server/first", 0u8),
        ("client-to-server/second", 0),
        ("client-to-server/compressed-flag", FLAG_COMPRESSED),
    ] {
        let mut out = vec![0u8; DATA_PAYLOAD.len() + 64];
        let n = client.seal(DATA_PAYLOAD, flags, &mut out).expect("seal");
        out.truncate(n);
        let header = Header::decode(&out).expect("its own header");
        data.push(
            Fields::new()
                .word("kind", "data-frame")
                .word("sender", "initiator")
                .num("sequence", header.sequence)
                .num("flags", u64::from(flags))
                .hex("plaintext", DATA_PAYLOAD)
                .hex("frame", &out)
                .done(&format!("data/{name}")),
        );
    }

    let mut out = vec![0u8; DATA_PAYLOAD.len() + 64];
    let n = server.seal(DATA_PAYLOAD, 0, &mut out).expect("seal");
    out.truncate(n);
    let header = Header::decode(&out).expect("its own header");
    data.push(
        Fields::new()
            .word("kind", "data-frame")
            .word("sender", "responder")
            .num("sequence", header.sequence)
            .num("flags", 0)
            .hex("plaintext", DATA_PAYLOAD)
            .hex("frame", &out)
            .done("data/server-to-client/first"),
    );

    // The frame at the rekey boundary. An implementation that never rekeys
    // agrees with every vector above and diverges here, which is the point of
    // paying for the loop.
    let rekey = b.section(&format!(
        "SPEC 5. The first frame after a rekey, at sequence {REKEY_INTERVAL}.\n\
         Reached by sealing that many frames and keeping the last, because \
         the chaining is what\n\
         is being pinned. An implementation that never rekeys matches every \
         vector above this\n\
         line and fails this one."
    ));

    // Three frames are already sealed above, so this skips to the boundary and
    // records the frame that lands exactly on it.
    let mut frame = vec![0u8; DATA_PAYLOAD.len() + 64];
    for _ in 3..REKEY_INTERVAL {
        client.seal(DATA_PAYLOAD, 0, &mut frame).expect("seal");
    }
    let n = client.seal(DATA_PAYLOAD, 0, &mut frame).expect("seal");
    frame.truncate(n);
    let sequence = Header::decode(&frame).expect("its own header").sequence;
    assert_eq!(sequence, REKEY_INTERVAL, "the vector is meant to sit on the boundary");
    rekey.push(
        Fields::new()
            .word("kind", "data-frame")
            .word("sender", "initiator")
            .num("sequence", sequence)
            .num("flags", 0)
            .hex("plaintext", DATA_PAYLOAD)
            .hex("frame", &frame)
            .done("data/client-to-server/after-rekey"),
    );
}

/// The file's own preamble, which is the only documentation a reader outside
/// this repository gets.
const PREAMBLE: &str = "\
# FECTP/1 test vectors
#
# Generated by crates/fectp-core/tests/vectors.rs. Do not edit by hand: the
# test regenerates this and compares, so a hand edit shows up as a failure.
#
# These are for checking an independent implementation of docs/SPEC.md. Sections
# 3 through 6 are the parts a Noise library does not give you, and they are most
# of what is here; the handshake vectors are included because FECTP's prologue
# and framing sit around the Noise message and a library does not know about
# them.
#
# FORMAT. Comments start with #. A vector begins with its name in square
# brackets and is followed by `key = value` lines. Values are decimal integers,
# lowercase hex with no prefix or separators, or a bare word from a fixed set.
# There is nothing else to parse.
#
# WHAT THESE DO NOT COVER. They are generated from the reference implementation,
# so they show what it produces and not that it is right -- only a reader of
# SPEC.md can say that. And some faults leave no trace on the wire at all:
# SPEC 5.5 notes that a conforming receiver cannot observe whether a sender gave
# up on a reliable message, so a sender that reports delivery wrongly produces
# byte-identical traffic. No vector here or anywhere can catch that.
";

fn render(b: &Builder) -> String {
    let mut s = String::from(PREAMBLE);
    for (title, vectors) in &b.out {
        s.push_str("\n\n");
        for line in title.lines() {
            let _ = writeln!(s, "# {line}");
        }
        for vector in vectors {
            let _ = writeln!(s, "\n[{}]", vector.name);
            for (key, value) in &vector.fields {
                let _ = writeln!(s, "{key} = {value}");
            }
        }
    }
    s
}

// ------------------------------------------------------------------ the tests

#[test]
fn the_file_is_what_this_implementation_produces() {
    if !in_the_repository() {
        eprintln!("skipped: docs/ is not beside this crate, so there is no file to check");
        return;
    }
    let path = vectors_path();
    let generated = build();

    if std::env::var_os("FECTP_WRITE_VECTORS").is_some() {
        fs::write(&path, &generated).expect("write the vectors");
        eprintln!("wrote {}", path.display());
        return;
    }

    let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}. Generate it with \
             FECTP_WRITE_VECTORS=1 cargo test -p fectp-core --test vectors",
            path.display()
        )
    });

    if committed.replace("\r\n", "\n") == generated.replace("\r\n", "\n") {
        return;
    }

    // Report the first differing vector rather than the first differing line:
    // a byte that moves shifts everything after it, and the name is what says
    // which part of the wire format changed.
    let theirs = Parsed::read(&committed);
    let ours = Parsed::read(&generated);
    for name in &ours.order {
        match theirs.by_name.get(name) {
            None => panic!("{name} is a new vector; regenerate the file"),
            Some(fields) if fields != ours.get(name) => panic!(
                "{name} differs.\n  committed: {:?}\n  produced:  {:?}\n\
                 The wire format changed. If that was intended, regenerate \
                 with FECTP_WRITE_VECTORS=1.",
                fields,
                ours.get(name)
            ),
            Some(_) => {}
        }
    }
    for name in &theirs.order {
        assert!(
            ours.by_name.contains_key(name),
            "{name} is in the file and is no longer produced; regenerate it"
        );
    }
    panic!("the file differs from what was generated, but no vector does — a comment moved");
}

#[test]
fn the_file_decodes_back() {
    if !in_the_repository() {
        eprintln!("skipped: docs/ is not beside this crate, so there is no file to check");
        return;
    }
    // The other direction. Without this, an encoder and a decoder that are
    // wrong in the same way agree with each other and with the file.
    let text = fs::read_to_string(vectors_path()).expect("read the vectors");
    let parsed = Parsed::read(&text);
    let mut seen = 0;

    for name in &parsed.order {
        let v = parsed.get(name);
        match v.text("kind") {
            "frame-header" => {
                let header = Header::decode(&v.bytes("encoded")).expect("decode a header");
                assert_eq!(header.frame_type, frame_type_from_name(v.text("frame_type")), "{name}");
                assert_eq!(u64::from(header.flags), v.number("flags"), "{name}");
                assert_eq!(u64::from(header.session_id), v.number("session_id"), "{name}");
                assert_eq!(header.sequence, v.number("sequence"), "{name}");
            }
            "varint" => {
                let (value, len) = varint::decode(&v.bytes("encoded")).expect("decode a varint");
                assert_eq!(u64::from(value), v.number("value"), "{name}");
                assert_eq!(len as u64, v.number("length"), "{name}");
            }
            "zigzag" => {
                let (value, _) = varint::decode(&v.bytes("encoded")).expect("decode a varint");
                assert_eq!(u64::from(value), v.number("zigzag"), "{name}");
                let signed: i32 = v.text("value").parse().expect("a signed decimal");
                assert_eq!(varint::unzigzag(value), signed, "{name}");
            }
            "codec-header" => {
                let header = CodecHeader::decode(&v.bytes("encoded")).expect("decode");
                assert_eq!(header.transform, transform_from_name(v.text("transform")), "{name}");
                assert_eq!(header.entropy, entropy_from_name(v.text("entropy")), "{name}");
                assert_eq!(u64::from(header.param), v.number("param"), "{name}");
                assert_eq!(u64::from(header.original_len), v.number("original_len"), "{name}");
            }
            "transform" => {
                let transform = transform_from_name(v.text("transform"));
                let input = v.bytes("input");
                let output = v.bytes("output");
                let mut back = vec![0u8; input.len() + 64];
                let n = transform
                    .reverse(&output, v.number("param") as u8, input.len(), &mut back)
                    .expect("reverse the transform");
                assert_eq!(&back[..n], &input[..], "{name}");
            }
            "capabilities" => {
                let decoded = Capabilities::decode_from(&v.bytes("encoded")).expect("decode caps");
                assert_eq!(u64::from(decoded.flags), v.number("flags"), "{name}");
                assert_eq!(
                    u64::from(decoded.max_frame_size),
                    v.number("max_frame_size"),
                    "{name}"
                );
                assert_eq!(u64::from(decoded.codecs), v.number("codecs"), "{name}");
            }
            // The handshake and data frames are checked together below, because
            // opening a data frame needs the session the handshake produced.
            "static-keys" | "handshake-message" | "resumption-ticket" | "data-frame" => {}
            other => panic!("{name} has an unrecognised kind: {other}"),
        }
        seen += 1;
    }

    assert!(seen > 30, "only {seen} vectors were read; the file looks truncated");
    replay_the_handshake(&parsed);
}

/// Drives the handshake from the file's bytes rather than from fresh output.
///
/// This is the check that matters most: the frames in the file go into a
/// responder and an initiator that have never seen them, and every data frame
/// is opened by the session that comes out. A decoder that agrees with a
/// matching encoder fails here.
fn replay_the_handshake(parsed: &Parsed) {
    let keys = parsed.get("handshake/static-keys");
    let responder_key = Keypair::from_secret(
        keys.bytes("responder_secret")
            .try_into()
            .expect("32 secret bytes"),
    );
    let initiator_key = Keypair::from_secret(
        keys.bytes("initiator_secret")
            .try_into()
            .expect("32 secret bytes"),
    );
    assert_eq!(
        initiator_key.public()[..],
        keys.bytes("initiator_public")[..],
        "the file's initiator public key is not what this secret derives"
    );
    assert_eq!(
        responder_key.public()[..],
        keys.bytes("responder_public")[..],
        "the file's responder public key is not what this secret derives"
    );

    let msg1 = parsed.get("handshake/message-1");
    let msg2 = parsed.get("handshake/message-2");
    let responder_public = *responder_key.public();

    // From the file, not from caps(): an implementer working off this file has
    // no access to the constant, and a capability block that no longer matches
    // its own vector would change every handshake frame below it.
    let stated_caps =
        Capabilities::decode_from(&parsed.get("handshake/capabilities").bytes("encoded"))
            .expect("the file's capability block");

    let mut responder = Responder::new(responder_key, stated_caps);
    let frame1 = msg1.bytes("frame");
    let mut out = vec![0u8; frame1.len()];
    let n = responder
        .read_init(&frame1, &mut out)
        .expect("the file's message 1 is readable");
    assert_eq!(out[..n], msg1.bytes("payload")[..], "the 0-RTT payload");

    // Message 2 is produced again from the file's ephemeral, so the responder
    // reaches the same session the vectors were sealed with.
    let mut initiator = Initiator::new(
        initiator_key,
        responder_public,
        msg1.number("session_id") as u32,
        stated_caps,
    )
    .expect("initiator");
    let mut regenerated = vec![0u8; INITIATOR_OVERHEAD + ZERO_RTT.len()];
    let n1 = initiator
        .write_init(
            &mut Fixed::from_bytes(msg1.bytes("ephemeral_secret")),
            &msg1.bytes("payload"),
            &mut regenerated,
        )
        .expect("message 1");
    assert_eq!(
        regenerated[..n1],
        frame1[..],
        "message 1 from the file's ephemeral is not the file's frame"
    );

    let frame2 = msg2.bytes("frame");
    let mut reply = vec![0u8; frame2.len()];
    let (mut client, reply_len) = initiator
        .read_response(&frame2, &mut reply)
        .expect("the file's message 2 is readable");
    assert_eq!(reply[..reply_len], msg2.bytes("payload")[..], "the reply payload");

    // Now every data frame in the file, opened by the session that handshake
    // produced. The client opens what the responder sent; the client's own
    // frames are checked by sealing them again, because a session cannot open
    // what it sealed.
    let mut sealed_again = 0;
    let mut opened = 0;
    let mut next_seq = 0u64;
    for name in &parsed.order {
        let v = parsed.get(name);
        if v.text("kind") != "data-frame" {
            continue;
        }
        let frame = v.bytes("frame");
        if v.text("sender") == "responder" {
            let mut buf = frame.clone();
            let got = client.open(&mut buf).expect("open the file's frame");
            assert_eq!(
                buf[HEADER_LEN..HEADER_LEN + got.len],
                v.bytes("plaintext")[..],
                "{name}"
            );
            opened += 1;
            continue;
        }

        // The rekey vector sits far along the sequence, so catch up to it. The
        // key chain advances with the sequence number and not with what is
        // sealed, so the skipped frames can carry anything.
        let want = v.number("sequence");
        let mut skip = vec![0u8; frame.len() + 64];
        while next_seq < want {
            client.seal(DATA_PAYLOAD, 0, &mut skip).expect("seal");
            next_seq += 1;
        }

        let mut buf = vec![0u8; frame.len() + 64];
        let n = client
            .seal(&v.bytes("plaintext"), v.number("flags") as u8, &mut buf)
            .expect("seal");
        next_seq += 1;
        assert_eq!(buf[..n], frame[..], "{name} is not what this session seals");
        sealed_again += 1;
    }

    assert!(opened >= 1, "no frame from the responder was opened");
    assert!(sealed_again >= 3, "only {sealed_again} initiator frames were re-sealed");
}
