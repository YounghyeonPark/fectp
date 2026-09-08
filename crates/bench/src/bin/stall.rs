//! Chases the stall the jitter table shows.
//!
//! Two hundred reliable messages through a relay that delays each datagram by
//! a random amount, with nothing dropped anywhere, occasionally take tens of
//! seconds instead of a hundred milliseconds. This runs that scenario in a
//! loop and reports where the time went, so the stall can be looked at rather
//! than averaged away.
//!
//! ```text
//! cargo run --release --bin stall -- [spread_ms] [rounds]
//! ```

use std::time::{Duration, Instant};

use fectp::{Connection, Identity, PayloadType};

// The crate has no lib target, so the relays are included rather than
// imported. Restructuring it for a diagnostic would be the tail wagging.
// Only a couple of the transports are used here; the rest belong to the
// benchmark that shares this file.
#[allow(dead_code)]
#[path = "../transports.rs"]
mod transports;
use transports::{FectpEcho, JitterRelay};

const MESSAGES: usize = 200;

fn main() {
    let mut args = std::env::args().skip(1);
    let spread_ms: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(10);
    let rounds: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(20);
    let spread = Duration::from_millis(spread_ms);

    println!("{MESSAGES} reliable messages, 0-{spread_ms} ms jitter, {rounds} rounds.");
    println!("Each round prints its total and its slowest single message.\n");

    let mut worst_round = 0.0f64;
    for round in 0..rounds {
        let echo = FectpEcho::public_key();
        let public = echo.public.expect("identity");
        let relay = JitterRelay::spawn(echo.addr, spread, 0x5EED_1234 + round as u64);

        let conn =
            Connection::connect(relay.addr, &public, &Identity::generate()).expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(60)))
            .expect("timeout");

        let payload = vec![0x5Au8; 256];
        let start = Instant::now();
        // Where each message's time went, so a stall can be placed rather than
        // just totalled: a single message holding the window for seconds looks
        // nothing like every message being slightly slow.
        let mut per_message: Vec<(usize, f64)> = Vec::with_capacity(MESSAGES);
        let mut flushes = 0usize;
        for i in 0..MESSAGES {
            let at = Instant::now();
            loop {
                match conn.send_reliable(&payload, PayloadType::Opaque) {
                    Ok(_) => break,
                    Err(_) => {
                        flushes += 1;
                        if let Err(e) = conn.flush(Duration::from_secs(60)) {
                            eprintln!("  [flush-err] at message {i}: {e:?}");
                        }
                    }
                }
            }
            per_message.push((i, at.elapsed().as_secs_f64() * 1000.0));
        }
        let before_final = start.elapsed().as_secs_f64() * 1000.0;
        if let Err(e) = conn.flush(Duration::from_secs(60)) {
            eprintln!("  [flush-err] final: {e:?}");
        }
        let total = start.elapsed().as_secs_f64() * 1000.0;
        let forwarded = relay.forwarded.load(std::sync::atomic::Ordering::Relaxed);
        drop(conn);
        drop(relay);
        drop(echo);

        per_message.sort_by(|a, b| b.1.total_cmp(&a.1));
        let (slowest_index, slowest) = per_message[0];
        worst_round = worst_round.max(total);
        println!(
            "round {round:2}: total {total:9.1} ms  (sending {before_final:9.1}, \
             final flush {:8.1})  slowest msg #{slowest_index} {slowest:8.1} ms  \
             blocked {flushes:3}x  relay forwarded {forwarded}",
            total - before_final
        );
        if slowest > 1000.0 {
            println!(
                "          next slowest: {:?}",
                &per_message[1..4.min(per_message.len())]
            );
        }
    }
    println!("\nworst round {worst_round:.1} ms");
}
