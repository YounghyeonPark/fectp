//! Whether this machine measures slower after it has been idle.
//!
//! Section 8 of the benchmark repeats its no-loss row at the end as a control,
//! and on a desktop that control commonly reads two to three times the first
//! row. That looks like the protocol degrading over the block. It is not.
//!
//! This is the same shape of measurement with no FECTP in it at all: a
//! loopback UDP echo, a hundred round trips per sample, five samples a second
//! of sleep apart. On the host these figures were taken on it reads
//!
//! ```text
//! round 0: median   3.73 ms   range   3.19-  5.63
//! round 1: median   3.06 ms   range   2.91-  8.71
//! round 2: median   7.59 ms   range   4.55- 13.01
//! round 3: median   9.34 ms   range   8.23-  9.86
//! round 4: median   7.64 ms   range   6.94-  8.21
//! ```
//!
//! — the same step, from the same cause, measuring nothing but `sendto` and
//! `recvfrom`. Section 8's loss rows wait on a 20 ms retransmission timer for
//! most of their duration, so the row that follows them is measured in exactly
//! this state.
//!
//! Neither a busy spin beforehand nor an untimed exchange over the same path
//! recovers it; a 300 ms spin made it appear a row earlier. Run this before
//! concluding that a benchmark change made something slower.

use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

/// Round trips per sample.
const TRIPS: usize = 100;
/// Samples per round, of which the median is reported.
const SAMPLES: usize = 5;
/// Rounds, each after a second of sleep.
const ROUNDS: usize = 5;

fn main() {
    let echo = UdpSocket::bind("127.0.0.1:0").expect("bind echo");
    let echo_addr = echo.local_addr().expect("addr");
    // Left running: the process exits when main returns and there is nothing
    // for this thread to clean up.
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, from)) = echo.recv_from(&mut buf) else {
                continue;
            };
            let _ = echo.send_to(&buf[..n], from);
        }
    });

    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client.connect(echo_addr).expect("connect");
    let payload = [7u8; 256];
    let mut buf = [0u8; 2048];

    println!("Loopback UDP round trips, {TRIPS} per sample, a second of idle between rounds.");
    for round in 0..ROUNDS {
        if round > 0 {
            thread::sleep(Duration::from_secs(1));
        }
        let mut times = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let start = Instant::now();
            for _ in 0..TRIPS {
                client.send(&payload).expect("send");
                client.recv(&mut buf).expect("recv");
            }
            times.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        times.sort_unstable_by(f64::total_cmp);
        println!(
            "round {round}: median {:6.2} ms   range {:6.2}-{:6.2}",
            times[SAMPLES / 2],
            times[0],
            times[SAMPLES - 1]
        );
    }
}
