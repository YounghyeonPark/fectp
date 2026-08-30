//! Reports the RAM a peer has to find for one session.
//!
//! ```bash
//! cargo run -p fectp-core --example sizes
//! ```
//!
//! The core allocates nothing, so every byte it needs is either in one of these
//! structures or in a buffer the caller supplies. That makes the figure below
//! the whole answer to "will this fit", which on a microcontroller is the
//! question that decides whether the protocol is usable at all.
//!
//! The sizes are host figures, but these are plain arrays and integers with no
//! pointers in them except `Keypair`'s, so a 32-bit target differs only
//! trivially. `crates/footprint` measures the other half — how much *flash* the
//! code occupies once linked.

use core::mem::size_of;

use fectp_core::reliability::{DedupWindow, RetransmitQueue};
use fectp_core::session::{Capabilities, Session};
use fectp_core::Keypair;

fn main() {
    let session = size_of::<Session>();
    let queue = size_of::<RetransmitQueue>();
    let dedup = size_of::<DedupWindow>();
    let caps = size_of::<Capabilities>();
    let keypair = size_of::<Keypair>();

    println!("Per-session state, in bytes:\n");
    println!("  {:<18}{session:>6}   two cipher states and the sequencing", "Session");
    println!("  {:<18}{keypair:>6}   this peer's static key", "Keypair");
    println!("  {:<18}{dedup:>6}   receiver side of the reliability layer", "DedupWindow");
    println!("  {:<18}{caps:>6}   what the peer said it can do", "Capabilities");
    println!(
        "  {:<18}{queue:>6}   sender side; only if sending reliably",
        "RetransmitQueue"
    );

    let minimum = session + keypair + dedup + caps;
    let full = minimum + queue;
    println!();
    println!("  {:<18}{minimum:>6}   unreliable only", "subtotal");
    println!("  {:<18}{full:>6}   with reliable delivery", "subtotal");
    println!();
    println!("Buffers are the caller's, and dominate: a peer that sends and");
    println!("receives at the frame limit needs two of them. At the default");
    println!("1200-byte datagram that is 2400 bytes, so a full-duplex reliable");
    println!("session costs roughly {} bytes of RAM in total.", full + 2400);
}
