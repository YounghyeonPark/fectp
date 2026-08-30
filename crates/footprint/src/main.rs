//! A bare-metal image that links FECTP, so its cost on a microcontroller can be
//! measured rather than estimated.
//!
//! `DECISIONS.md` carried only a pre-link upper bound: the core's own code at
//! about 21 KiB, plus roughly 95 KiB of crypto dependencies *before* dead-code
//! elimination. That is not a number anyone can plan with, because most of
//! `curve25519-dalek` is never reached and the linker discards it.
//!
//! This links a real image for `thumbv7em-none-eabihf` with fat LTO,
//! `opt-level = "z"` and `--gc-sections`, and drives the whole protocol so
//! nothing that matters is discarded: a full public-key handshake in both
//! roles, a sealed and opened data frame, and the codec path. What is left in
//! `.text` and `.rodata` is what a firmware image actually pays.
//!
//! ```bash
//! cargo build -p fectp-footprint --release
//! ```
//!
//! The memory layout in `link.x` is a plausible Cortex-M4F, not any particular
//! part. Where the regions sit does not change how much code survives.

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::panic::PanicInfo;

use fectp_core::codec::{CodecHeader, Entropy, Transform};
use fectp_core::session::{Capabilities, Initiator, Responder};
use fectp_core::Keypair;

/// Somewhere to put results so the optimiser cannot decide the work was
/// pointless and delete the code being measured.
const SINK: *mut u32 = 0x2001_FF00 as *mut u32;

/// A deterministic stand-in for an entropy source.
///
/// **Not usable for anything real.** A microcontroller supplies randomness from
/// its own hardware, and what that costs is the board's business, not the
/// protocol's. Linking a real one in would measure the vendor HAL rather than
/// FECTP, so this is the smallest thing that satisfies the bound.
struct Counter(u64);

impl rand_core::RngCore for Counter {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for Counter {}

/// The same image with the protocol left out.
///
/// Subtracting this from the full build is what isolates FECTP from the cost of
/// a bare-metal Rust image at all — the vector table, the panic handler, and
/// whatever `core` brings with them.
#[cfg(feature = "baseline")]
fn exercise() -> u32 {
    0
}

/// Runs a whole session so the linker keeps every part of the protocol.
#[cfg(not(feature = "baseline"))]
fn exercise() -> u32 {
    let mut rng = Counter(0x2545_F491_4F6C_DD1D);
    let mut total: u32 = 0;

    let server_key = Keypair::generate(&mut rng);
    let server_public = *server_key.public();
    let client_key = Keypair::generate(&mut rng);
    let caps = Capabilities::minimal(1200);

    let mut msg1 = [0u8; 512];
    let mut msg2 = [0u8; 512];
    let mut plain = [0u8; 512];

    // Message 1, with 0-RTT data.
    let Ok(mut initiator) = Initiator::new(client_key, server_public, 0x1234_5678, caps) else {
        return 0;
    };
    let Ok(n1) = initiator.write_init(&mut rng, b"hello", &mut msg1) else {
        return 0;
    };
    total = total.wrapping_add(n1 as u32);

    // Message 2.
    let mut responder = Responder::new(server_key, caps);
    let Ok(zero_rtt) = responder.read_init(&msg1[..n1], &mut plain) else {
        return 0;
    };
    total = total.wrapping_add(zero_rtt as u32);
    let Ok((mut server, n2)) = responder.write_response(&mut rng, b"hi", &mut msg2) else {
        return 0;
    };
    total = total.wrapping_add(n2 as u32);

    let Ok((mut client, replied)) = initiator.read_response(&msg2[..n2], &mut plain) else {
        return 0;
    };
    total = total.wrapping_add(replied as u32);

    // A data frame, sealed one way and opened the other.
    let mut frame = [0u8; 512];
    let Ok(sealed) = client.seal(b"steady state", 0, &mut frame) else {
        return total;
    };
    let Ok(opened) = server.open(&mut frame[..sealed]) else {
        return total;
    };
    total = total.wrapping_add(opened.len as u32);

    // The codec header, which is the part of the coding path a constrained
    // peer still has to parse even when it advertises no transforms.
    let header = CodecHeader {
        transform: Transform::I16Delta,
        entropy: Entropy::None,
        param: 4,
        original_len: 256,
    };
    let mut coded = [0u8; 8];
    if header.encode(&mut coded).is_ok() {
        if let Ok(back) = CodecHeader::decode(&coded) {
            total = total.wrapping_add(u32::from(back.original_len));
        }
    }

    total
}

/// The reset handler. Never returns, as a firmware entry point does not.
///
/// # Safety
/// Called by the hardware with no Rust invariants established yet.
#[no_mangle]
pub unsafe extern "C" fn reset() -> ! {
    let result = exercise();
    core::ptr::write_volatile(SINK, result);
    loop {
        core::hint::spin_loop();
    }
}

/// The minimum vector table: initial stack pointer and reset vector.
#[link_section = ".vector_table"]
#[no_mangle]
pub static VECTORS: [unsafe extern "C" fn() -> !; 2] = [stack_top, reset];

/// Stands in for the initial stack pointer, which is an address rather than a
/// function. Only its position in the table matters here.
///
/// # Safety
/// Never called; it exists to occupy the first vector slot.
#[no_mangle]
pub unsafe extern "C" fn stack_top() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panicked(_: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
