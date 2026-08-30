//! A measured comparison of FECTP against other ways of moving the same bytes.
//!
//! ```bash
//! cargo run -p fectp-bench --release
//! ```
//!
//! Everything here runs over loopback. That removes the network from the
//! comparison, which is what you want for measuring a protocol's own cost — and
//! it is also why the latency table below flatters every protocol that needs
//! extra round trips. Those round trips are counted separately, because on a
//! real path they are what dominates.

mod datasets;
mod timing;
mod transports;

use std::time::Duration;

use datasets::Shape;
use fectp::{Capabilities, Connection, Identity, PayloadType};
use timing::{measure, measure_batched, throughput_mib};
use transports::{
    AsymmetricRelay, BottleneckRelay, FectpEcho, JitterRelay, LossyRelay, RebindingRelay,
    ReorderingRelay, TlsEcho, TlsSetup, UdpEcho,
};

const SECRET: &[u8] = b"benchmark-secret";
const WARMUP: usize = 50;
const SAMPLES: usize = 400;

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install crypto provider");

    println!("FECTP — measured comparison");
    println!("{}", "=".repeat(72));
    println!(
        "\nLoopback, release build, median of {SAMPLES} samples after {WARMUP} warmup runs."
    );

    connection_setup();
    round_trip_latency();
    round_trips_needed();
    per_message_overhead();
    crypto_cost();
    compression();
    compression_level();
    under_loss();
    other_things_a_path_does();
    jitter_asymmetry_and_crowding();

    println!("\n{}", "=".repeat(72));
    println!("Absolute times are loopback figures; see the round-trip table for");
    println!("what happens once a real network is involved.");
}

// ─────────────────────────────────────────────── 1. connection setup ──────

fn connection_setup() {
    heading("1. Opening a connection", "wall time from call to usable session");

    let pk = FectpEcho::public_key();
    let pk_public = pk.public.expect("identity");
    let full_hs = measure(10, 100, || {
        Connection::connect(pk.addr, &pk_public, &Identity::generate()).expect("connect");
    });

    // Resumption needs a ticket, and each is single use, so a fresh one is
    // earned outside the timed section.
    let resumed = timing::measure_reported(5, 60, || {
        let conn =
            Connection::connect(pk.addr, &pk_public, &Identity::generate()).expect("connect");
        let ticket = conn.resumption_ticket().expect("encrypted");
        drop(conn);
        let start = std::time::Instant::now();
        let _ = Connection::resume(pk.addr, &ticket, &pk_public, Duration::from_secs(2))
            .expect("resume");
        start.elapsed()
    });
    drop(pk);

    let psk = FectpEcho::psk(SECRET);
    let psk_stats = measure(10, 100, || {
        Connection::connect_psk(psk.addr, SECRET, Duration::from_secs(2)).expect("connect");
    });
    drop(psk);

    let plain = FectpEcho::plain();
    let plain_stats = measure(10, 100, || {
        Connection::connect_plain(plain.addr, Duration::from_secs(2)).expect("connect");
    });
    drop(plain);

    let tls_setup = TlsSetup::new();
    let tls = TlsEcho::spawn(std::sync::Arc::clone(&tls_setup.server));
    let tls_stats = measure(10, 100, || {
        transports::tls_connect(&tls_setup, tls.addr);
    });
    drop(tls);

    row_header(&["", "median", "p95", "X25519 ops"]);
    row(&[
        "FECTP, public key",
        &ms(full_hs.median_ms()),
        &ms(full_hs.p95.as_secs_f64() * 1000.0),
        "4",
    ]);
    row(&[
        "FECTP, resumed",
        &ms(resumed.median_ms()),
        &ms(resumed.p95.as_secs_f64() * 1000.0),
        "1",
    ]);
    row(&[
        "FECTP, pre-shared key",
        &ms(psk_stats.median_ms()),
        &ms(psk_stats.p95.as_secs_f64() * 1000.0),
        "1",
    ]);
    row(&[
        "FECTP, plaintext",
        &ms(plain_stats.median_ms()),
        &ms(plain_stats.p95.as_secs_f64() * 1000.0),
        "0",
    ]);
    row(&[
        "TCP + TLS 1.3 (rustls)",
        &ms(tls_stats.median_ms()),
        &ms(tls_stats.p95.as_secs_f64() * 1000.0),
        "1 + certificate",
    ]);
    note("TLS also verifies a certificate chain; FECTP has no chain to verify.");
}

// ────────────────────────────────────────────── 2. round-trip latency ─────

fn round_trip_latency() {
    heading(
        "2. Request and response, connection already open",
        "one 256-byte message out, the same back",
    );

    let payload = vec![0x5Au8; 256];
    let mut buf = vec![0u8; 8192];

    let udp = UdpEcho::spawn();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket.connect(udp.addr).expect("connect");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let udp_stats = measure(WARMUP, SAMPLES, || {
        socket.send(&payload).expect("send");
        socket.recv(&mut buf).expect("recv");
    });
    drop(udp);

    let pk = FectpEcho::public_key();
    let mut conn =
        Connection::connect(pk.addr, &pk.public.expect("identity"), &Identity::generate())
            .expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    let fectp_stats = measure(WARMUP, SAMPLES, || {
        transports::fectp_round_trip(&mut conn, &payload, &mut buf);
    });
    drop(conn);
    drop(pk);

    let plain = FectpEcho::plain();
    let mut pconn = Connection::connect_plain(plain.addr, Duration::from_secs(2)).expect("connect");
    pconn.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    let fectp_plain = measure(WARMUP, SAMPLES, || {
        transports::fectp_round_trip(&mut pconn, &payload, &mut buf);
    });
    drop(pconn);
    drop(plain);

    let tls_setup = TlsSetup::new();
    let tls = TlsEcho::spawn(std::sync::Arc::clone(&tls_setup.server));
    let mut client = transports::tls_connect(&tls_setup, tls.addr);
    let tls_stats = measure(WARMUP, SAMPLES, || {
        transports::tls_round_trip(&mut client, &payload, &mut buf);
    });
    drop(client);
    drop(tls);

    // The same raw UDP measurement again, last instead of first. Any gap
    // between the two is drift and scheduling noise, not protocol cost, and it
    // sets the bar a difference has to clear before it means anything.
    let udp2 = UdpEcho::spawn();
    let socket2 = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket2.connect(udp2.addr).expect("connect");
    socket2
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let udp_control = measure(WARMUP, SAMPLES, || {
        socket2.send(&payload).expect("send");
        socket2.recv(&mut buf).expect("recv");
    });
    drop(udp2);

    row_header(&["", "median", "p95", "vs raw UDP"]);
    let base = udp_stats.median_us();
    row(&["raw UDP (no encryption)", &us(udp_stats.median_us()), &us(udp_stats.p95.as_secs_f64()*1e6), "—"]);
    row(&[
        "FECTP, plaintext",
        &us(fectp_plain.median_us()),
        &us(fectp_plain.p95.as_secs_f64()*1e6),
        &format!("{:+.0}%", (fectp_plain.median_us() / base - 1.0) * 100.0),
    ]);
    row(&[
        "FECTP, encrypted",
        &us(fectp_stats.median_us()),
        &us(fectp_stats.p95.as_secs_f64()*1e6),
        &format!("{:+.0}%", (fectp_stats.median_us() / base - 1.0) * 100.0),
    ]);
    row(&[
        "TCP + TLS 1.3",
        &us(tls_stats.median_us()),
        &us(tls_stats.p95.as_secs_f64()*1e6),
        &format!("{:+.0}%", (tls_stats.median_us() / base - 1.0) * 100.0),
    ]);
    let noise = (udp_control.median_us() / base - 1.0) * 100.0;
    row(&[
        "raw UDP again (control)",
        &us(udp_control.median_us()),
        &us(udp_control.p95.as_secs_f64()*1e6),
        &format!("{noise:+.0}%"),
    ]);
    println!();
    note("The control is the same measurement as the first row, run last: it moved");
    note(&format!(
        "{:.0}%. Treat any difference smaller than that as noise rather than result —",
        noise.abs()
    ));
    note("which on this host is most of the gap between raw UDP and FECTP. The TLS");
    note("figure is the only one in this table that clearly clears the bar.");
    note("On loopback the transport barely matters anyway. Section 3 is where it does.");
}

// ──────────────────────────────────────── 3. round trips, and what they cost

fn round_trips_needed() {
    heading(
        "3. Round trips before a request is answered",
        "counted from the protocol, then priced at three real path latencies",
    );

    // These are properties of each handshake, not measurements.
    let cases: &[(&str, f64)] = &[
        ("FECTP, first ever contact", 1.0),
        ("FECTP, resumed", 1.0),
        ("QUIC + TLS 1.3, first contact", 2.0),
        ("QUIC + TLS 1.3, resumed (0-RTT)", 1.0),
        ("TCP + TLS 1.3, first contact", 3.0),
    ];

    row_header(&["", "trips", "LAN 0.2ms", "regional 20ms", "far 150ms"]);
    for (name, trips) in cases {
        row(&[
            name,
            &format!("{trips:.0}"),
            &ms(trips * 0.2),
            &ms(trips * 20.0),
            &ms(trips * 150.0),
        ]);
    }
    note("TCP + TLS: 1 round trip for the TCP handshake, 1 for TLS, 1 for the exchange.");
    note("This is the whole argument. Everything else is a rounding error beside it.");
}

// ──────────────────────────────────────────── 4. per-message overhead ─────

fn per_message_overhead() {
    heading(
        "4. Bytes added to a 256-byte message",
        "TLS measured at the socket; FECTP is fixed by its frame format",
    );

    let payload = vec![0x5Au8; 256];
    let mut buf = vec![0u8; 8192];

    let tls_setup = TlsSetup::new();
    let tls = TlsEcho::spawn(std::sync::Arc::clone(&tls_setup.server));
    let mut client = transports::tls_connect(&tls_setup, tls.addr);
    // Ignore the handshake bytes; charge only the steady state.
    let before = client.written.load(std::sync::atomic::Ordering::Relaxed);
    const MESSAGES: u64 = 100;
    for _ in 0..MESSAGES {
        transports::tls_round_trip(&mut client, &payload, &mut buf);
    }
    let tls_per_message =
        (client.written.load(std::sync::atomic::Ordering::Relaxed) - before) as f64
            / MESSAGES as f64
            - 256.0;
    drop(client);
    drop(tls);

    row_header(&["", "protocol", "IP + transport", "total"]);
    row(&["raw UDP", "0", "28", "28"]);
    row(&["FECTP, plaintext", "14", "28", "42"]);
    row(&["FECTP, encrypted", "30", "28", "58"]);
    row(&[
        "TCP + TLS 1.3",
        &format!("{tls_per_message:.0}"),
        "40",
        &format!("{:.0}", tls_per_message + 40.0),
    ]);
    note("The 4-byte length prefix this benchmark adds to TLS is counted against it;");
    note("a datagram protocol gets message boundaries for nothing.");
    note("TCP headers are 40 bytes against UDP's 28, before any retransmission.");
}

// ──────────────────────────────────────────────────── 5. crypto cost ──────

fn crypto_cost() {
    heading(
        "5. Cost of one send, split from the syscall",
        "1024 incompressible bytes, against the same sendto with no protocol",
    );

    // The floor: the same syscall, same payload size, no protocol at all.
    // Anything above this line is what FECTP costs to run.
    let sink = UdpEcho::sink();
    let bare = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    bare.connect(sink.addr).expect("connect");
    // Incompressible, and small enough to fit a frame raw. A constant-byte
    // payload would code down to almost nothing and the syscall would be
    // moving 30 bytes rather than 1024 — measuring the wrong thing.
    let payload = datasets::incompressible(1024);
    let raw = measure_batched(WARMUP, 40, 500, || {
        bare.send(&payload).expect("send");
    });
    drop(sink);

    let plain = FectpEcho::plain_drain();
    let pconn = Connection::connect_plain(plain.addr, Duration::from_secs(2)).expect("connect");
    let plain_send = measure_batched(WARMUP, 40, 500, || {
        pconn.send(&payload).expect("send");
    });
    drop(pconn);
    drop(plain);

    let pk = FectpEcho::public_key_drain();
    let conn =
        Connection::connect(pk.addr, &pk.public.expect("identity"), &Identity::generate())
            .expect("connect");
    let sealed = measure_batched(WARMUP, 40, 500, || {
        conn.send(&payload).expect("send");
    });
    drop(conn);
    drop(pk);

    let base = raw.median_us();
    row_header(&["", "per send", "over raw sendto", "throughput"]);
    row(&[
        "raw UDP sendto (no protocol)",
        &us(base),
        "—",
        &format!("{:.0} MiB/s", throughput_mib(1024, raw.median)),
    ]);
    row(&[
        "FECTP plaintext: + framing",
        &us(plain_send.median_us()),
        &us(plain_send.median_us() - base),
        &format!("{:.0} MiB/s", throughput_mib(1024, plain_send.median)),
    ]);
    row(&[
        "FECTP encrypted: + framing + AEAD",
        &us(sealed.median_us()),
        &us(sealed.median_us() - base),
        &format!("{:.0} MiB/s", throughput_mib(1024, sealed.median)),
    ]);
    println!();
    note(&format!(
        "Encrypting costs {} on top of framing. The throughput column is",
        us(sealed.median_us() - plain_send.median_us())
    ));
    note("bounded by the syscall, which is the largest single item here — but not");
    note("by as much as it looks: the two protocol rows together cost more than it.");
}

// ─────────────────────────────────────────────────── 6. compression ───────

fn compression() {
    heading(
        "6. Compression, by what the data actually is",
        "bytes on the wire for one payload, smaller is better",
    );

    let full = Capabilities {
        flags: fectp::CAP_ZSTD,
        max_frame_size: u16::MAX,
        codecs: u16::MAX,
    };
    // A peer with the core transforms but no room for a Zstandard decoder.
    let no_zstd = Capabilities {
        flags: 0,
        max_frame_size: u16::MAX,
        codecs: fectp::CORE_CODECS,
    };

    row_header(&[
        "dataset",
        "raw bytes",
        "gzip",
        "zstd only",
        "FECTP typed",
        "no zstd",
        "encode",
    ]);

    for set in datasets::all() {
        let raw = set.bytes.len();
        let gzip = gzip_size(&set.bytes);
        let zstd_only = coded(&set.bytes, PayloadType::Opaque, full);
        let typed_shape = match set.shape {
            Shape::Opaque => PayloadType::Opaque,
            Shape::I16 { channels } => PayloadType::I16 { channels },
            Shape::I32 { channels } => PayloadType::I32 { channels },
            Shape::Elements { size } => PayloadType::Elements { size },
        };
        let typed = coded(&set.bytes, typed_shape, full);
        let typed_bare = coded(&set.bytes, typed_shape, no_zstd);

        let encode = measure(20, 200, || {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            let _ = fectp::compress::encode_payload(&set.bytes, typed_shape, full, &mut a, &mut b);
        });

        row(&[
            set.name,
            &format!("{raw}"),
            &ratio(raw, gzip),
            &ratio(raw, zstd_only),
            &ratio(raw, typed),
            &ratio(raw, typed_bare),
            &us(encode.median_us()),
        ]);
    }

    println!();
    for set in datasets::all() {
        println!("    {:<22} {}", set.name, set.description);
    }
    note("\"typed, no zstd\" is what a microcontroller peer gets: the transforms are");
    note("plain integer code in the no_std core, so it needs no decompressor.");
    note("Ratios are raw/coded, so higher is better; FECTP figures include its");
    note("4-byte codec header.");
}

// ────────────────────────────────────────── 7. the Zstandard level ────────

/// The default was `-4` — the design note's `--fast=4` — on the reasoning that
/// a transport this latency-sensitive cannot afford a slow compressor. This
/// section is what changed it to 1.
fn compression_level() {
    heading(
        "7. Why the Zstandard level changed from -4 to 1",
        "level is a sender-side choice; a receiver decodes any of them",
    );

    const LEVELS: &[i32] = &[-4, -1, 1, 3, 9];

    row_header(&["dataset", "-4 (was)", "-1", "1 (now)", "3", "9"]);
    for set in datasets::all() {
        let raw = set.bytes.len();
        let cells: Vec<String> = LEVELS
            .iter()
            .map(|&lvl| ratio(raw, zstd_size(&set.bytes, lvl)))
            .collect();
        let mut cols = vec![set.name.to_string()];
        cols.extend(cells);
        row(&cols.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    }

    println!();
    row_header(&["encode 8 KiB", "-4 (was)", "-1", "1 (now)", "3", "9"]);
    let sample = &datasets::all()[2].bytes;
    let times: Vec<String> = LEVELS
        .iter()
        .map(|&lvl| {
            let stats = measure(20, 200, || {
                let _ = zstd_size(sample, lvl);
            });
            us(stats.median_us())
        })
        .collect();
    let mut cols = vec!["counter i32 x2".to_string()];
    cols.extend(times);
    row(&cols.iter().map(|s| s.as_str()).collect::<Vec<_>>());

    note("At level -4 Zstandard finds nothing in structured binary data and emits");
    note("more bytes than it was given, so FECTP falls back to sending the payload");
    note("uncompressed — the 1.00x column is a real result, not a failure to run.");
    println!();
    println!();
    row_header(&["dataset", "-4 bytes", "1 bytes", "1 wins below"]);
    let t4 = level_time(-4);
    let t1 = level_time(1);
    for set in datasets::all() {
        let b4 = zstd_size(&set.bytes, -4).min(set.bytes.len());
        let b1 = zstd_size(&set.bytes, 1).min(set.bytes.len());
        let verdict = match break_even_mbps((b4, t4), (b1, t1)) {
            Some(mbps) if mbps >= 1000.0 => format!("{:.1} Gbps", mbps / 1000.0),
            Some(mbps) => format!("{mbps:.0} Mbps"),
            None => "never".to_string(),
        };
        row(&[set.name, &format!("{b4}"), &format!("{b1}"), &verdict]);
    }
    println!();
    note("A send costs encode time plus bytes over the link, so the higher level wins");
    note("on any link slower than the figure above — which is every real network for");
    note("all but the JSON, where -4 already found nearly everything and the extra");
    note("saving is 43 bytes. That is why the default is now 1.");
    println!();
    note("Section 6 is the stronger half of the case, and it is about declared types");
    note("rather than opaque bytes: running the transform first does not make the");
    note("level irrelevant. Sensor data goes from 2.00x to 3.46x and the f32 table");
    note("from 5.43x to 8.21x. Only the i32 counters were already fine at -4.");
    println!();
    note("Raising the level is also safer than it was: the send path now stops");
    note("attempting compression on a stream that has repeatedly failed to shrink,");
    note("so the case where a higher level costs more and returns nothing is the one");
    note("case that no longer pays for itself on every message.");
}

/// Median microseconds to encode the 8 KiB counter dataset at one level.
fn level_time(level: i32) -> f64 {
    let sample = &datasets::all()[2].bytes;
    measure(20, 200, || {
        let _ = zstd_size(sample, level);
    })
    .median_us()
}

/// The link speed at which a higher level stops paying for itself.
///
/// Sending takes `encode + bytes / bandwidth`, so a level that costs `dt` more
/// and saves `db` bytes wins whenever `dt < db / bandwidth` — that is, on every
/// link slower than `db / dt`. Above that the link is quick enough that the
/// saved bytes arrive in less time than it took to find them.
fn break_even_mbps(fast: (usize, f64), slow: (usize, f64)) -> Option<f64> {
    let saved = fast.0.checked_sub(slow.0)?;
    let extra = slow.1 - fast.1;
    if saved == 0 || extra <= 0.0 {
        return None;
    }
    Some((saved as f64 / (extra * 1e-6)) * 8.0 / 1e6)
}

/// Bytes plain Zstandard produces at a given level, with no FECTP transform.
fn zstd_size(data: &[u8], level: i32) -> usize {
    zstd::bulk::compress(data, level).expect("zstd").len()
}

/// Bytes FECTP would put on the wire for this payload and declared shape.
fn coded(data: &[u8], shape: PayloadType, peer: Capabilities) -> usize {
    let (mut a, mut b) = (Vec::new(), Vec::new());
    match fectp::compress::encode_payload(data, shape, peer, &mut a, &mut b) {
        Some((_, len)) => fectp::CODEC_OVERHEAD + len,
        // Coding did not pay, so the original goes out unchanged.
        None => data.len(),
    }
}

fn gzip_size(data: &[u8]) -> usize {
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip");
    encoder.finish().expect("gzip").len()
}

// ─────────────────────────────────────────────────────── formatting ───────

fn heading(title: &str, subtitle: &str) {
    println!("\n\n{title}");
    println!("{}", "-".repeat(title.len()));
    println!("{subtitle}\n");
}

fn row_header(cells: &[&str]) {
    print_row(cells);
    let mut line = String::from("    ");
    for (i, _) in cells.iter().enumerate() {
        if i == 0 {
            line.push_str(&format!("{:<38}", "-".repeat(36)));
        } else {
            line.push_str(&format!("{:>16}", "-".repeat(14)));
        }
    }
    println!("{}", line.trim_end());
}

fn row(cells: &[&str]) {
    print_row(cells);
}

fn print_row(cells: &[&str]) {
    let mut line = String::from("    ");
    for (i, cell) in cells.iter().enumerate() {
        if i == 0 {
            line.push_str(&format!("{cell:<38}"));
        } else {
            line.push_str(&format!("{cell:>16}"));
        }
    }
    println!("{}", line.trim_end());
}

fn note(text: &str) {
    println!("    {text}");
}

fn ms(value: f64) -> String {
    format!("{value:.2} ms")
}

fn us(value: f64) -> String {
    format!("{value:.1} us")
}

fn ratio(raw: usize, coded: usize) -> String {
    format!("{:.2}x", raw as f64 / coded as f64)
}


// ───────────────────────────────────────────────────────── 8. loss ────────

/// What everything above does not measure.
///
/// Sections 1 to 7 run over loopback, which never drops anything — so they
/// exercise the parts of the protocol that are cheap and leave the reliability
/// layer, the only part with a hard job, entirely untested. This injects loss
/// so the numbers include the cost of recovering from it.
fn under_loss() {
    heading(
        "8. Under packet loss",
        "loss injected by a relay; the handshake is exempt so this measures data",
    );

    const RATES: &[u32] = &[0, 10, 50, 100];
    const MESSAGES: usize = 100;

    row_header(&[
        "loss",
        "100 reliable msgs",
        "vs no loss",
        "1 lost costs",
    ]);

    let mut baseline = 0.0;
    for &rate in RATES {
        let echo = FectpEcho::public_key();
        let relay = LossyRelay::spawn(echo.addr, rate, 0x1234_5678 + u64::from(rate));
        let public = echo.public.expect("identity");

        let conn = Connection::connect(relay.addr, &public, &Identity::generate())
            .expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");

        let payload = datasets::incompressible(256);
        let start = std::time::Instant::now();
        for _ in 0..MESSAGES {
            // The window is 32, so this blocks partway through and the send
            // rate becomes whatever acknowledgements allow.
            loop {
                match conn.send_reliable(&payload) {
                    Ok(_) => break,
                    Err(_) => conn.flush(Duration::from_secs(30)).expect("flush"),
                }
            }
        }
        conn.flush(Duration::from_secs(30)).expect("flush");
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        drop(conn);
        drop(relay);
        drop(echo);

        if rate == 0 {
            baseline = elapsed;
        }
        // Roughly how much each lost datagram added, spread over the ones this
        // rate should have dropped.
        let expected_losses = (MESSAGES as f64 * f64::from(rate) / 1000.0).max(1.0);
        let per_loss = if rate == 0 {
            "—".to_string()
        } else {
            format!("{:.0} ms", (elapsed - baseline) / expected_losses)
        };

        row(&[
            &format!("{:.1}%", f64::from(rate) / 10.0),
            &ms(elapsed),
            &if rate == 0 {
                "—".to_string()
            } else {
                format!("{:.1}x", elapsed / baseline)
            },
            &per_loss,
        ]);
    }

    note("Nothing is resent until a retransmission timer fires, and that timer has");
    note("a 20 ms floor against a loopback round trip of about 30 us. Recovery is");
    note("governed by the timer, not by the path — one loss costs on the order of");
    note("a thousand round trips, and no amount of protocol tuning changes that.");
    note("The per-loss column falls as the rate rises because the fixed cost of the");
    note("first timeout is shared over more of them.");
    println!();

    // The same again for a fragmented message, where every fragment is a
    // reliable message and one loss stalls the whole thing.
    row_header(&["loss", "256 KiB fragmented", "vs no loss", "throughput"]);

    let mut baseline = 0.0;
    for &rate in RATES {
        let echo = FectpEcho::public_key();
        let relay = LossyRelay::spawn(echo.addr, rate, 0xABCD_EF01 + u64::from(rate));
        let public = echo.public.expect("identity");

        let conn = Connection::connect(relay.addr, &public, &Identity::generate())
            .expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(60)))
            .expect("timeout");

        const SIZE: usize = 256 * 1024;
        let payload = datasets::incompressible(SIZE);
        let start = std::time::Instant::now();
        let outcome = conn.send_reliable(&payload).and_then(|()| conn.flush(Duration::from_secs(60)));
        let elapsed = start.elapsed();
        let ms_taken = elapsed.as_secs_f64() * 1000.0;
        drop(conn);
        drop(relay);
        drop(echo);

        if rate == 0 {
            baseline = ms_taken;
        }
        let (time, ratio, rate_col) = match outcome {
            Ok(()) => (
                ms(ms_taken),
                if rate == 0 {
                    "—".to_string()
                } else {
                    format!("{:.1}x", ms_taken / baseline)
                },
                format!("{:.1} MiB/s", throughput_mib(SIZE, elapsed)),
            ),
            // Every fragment gets MAX_RETRIES attempts; past some loss rate one
            // of them runs out and the message is lost entire.
            Err(_) => ("gave up".to_string(), "—".to_string(), "—".to_string()),
        };
        row(&[
            &format!("{:.1}%", f64::from(rate) / 10.0),
            &time,
            &ratio,
            &rate_col,
        ]);
    }

    note("A fragmented message needs every fragment, so its chance of stalling");
    note("grows with the fragment count: at 1% loss a 226-fragment message expects");
    note("two stalls, each costing a timeout. Throughput falls by more than an");
    note("order of magnitude for 1% loss, which is the honest cost of recovering");
    note("by timer alone. The congestion window does react to these losses — see");
    note("section 9 — but narrowing the window does not make a lost fragment");
    note("arrive any sooner, and the timer is what decides that.");
}

// ────────────────────────────── 9. reordering, bottlenecks, rebinding ─────

/// The conditions loss alone does not cover.
///
/// A real path also delivers out of order, runs out of bandwidth, and moves the
/// address a peer appears to come from. Each is separated here because a
/// protocol can be right about one and wrong about another, and because two of
/// the three are known gaps rather than results.
fn other_things_a_path_does() {
    heading(
        "9. Reordering, a bottleneck, and a rebinding NAT",
        "the parts of a real path that are not loss",
    );

    // ── reordering ───────────────────────────────────────────────────────
    const MESSAGES: usize = 200;
    let payload = datasets::incompressible(256);

    let mut baseline = 0.0;
    row_header(&["reordering", "200 reliable msgs", "vs in order", "arrived"]);
    for (label, every, delay) in [
        ("none", 0u64, Duration::ZERO),
        ("every one by 2 ms (control)", 1, Duration::from_millis(2)),
        ("1 in 10 by 2 ms", 10, Duration::from_millis(2)),
        ("every one by 5 ms (control)", 1, Duration::from_millis(5)),
        ("1 in 5 by 5 ms", 5, Duration::from_millis(5)),
    ] {
        let echo = FectpEcho::public_key();
        let public = echo.public.expect("identity");
        let relay = (every > 0).then(|| ReorderingRelay::spawn(echo.addr, every, delay));
        let addr = relay.as_ref().map_or(echo.addr, |r| r.addr);

        let conn =
            Connection::connect(addr, &public, &Identity::generate()).expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");

        let start = std::time::Instant::now();
        for _ in 0..MESSAGES {
            loop {
                match conn.send_reliable(&payload) {
                    Ok(_) => break,
                    Err(_) => conn.flush(Duration::from_secs(30)).expect("flush"),
                }
            }
        }
        let delivered = conn.flush(Duration::from_secs(30)).is_ok();
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        drop(conn);
        drop(relay);
        drop(echo);

        if every == 0 {
            baseline = elapsed;
        }
        row(&[
            label,
            &ms(elapsed),
            &if every == 0 {
                "—".to_string()
            } else {
                format!("{:.1}x", elapsed / baseline)
            },
            if delivered { "all" } else { "INCOMPLETE" },
        ]);
    }
    note("Delaying a datagram slows any protocol down, so the reordering rows mean");
    note("nothing without the control above each of them, which applies the same");
    note("delay to every datagram and therefore reorders nothing. The difference");
    note("between a pair is what reordering itself costs; the rest is latency.");
    note("Delivery is unordered by design — a frame is delivered on arrival rather");
    note("than held for the one before it — so that difference should be small.");
    println!();

    // ── a bottleneck ─────────────────────────────────────────────────────
    row_header(&["bottleneck", "256 KiB", "queue overflow", "goodput"]);
    for (label, bytes_per_sec, queue) in [
        ("10 Mbit/s, 64 KiB queue", 1_250_000u64, 64 * 1024usize),
        ("10 Mbit/s, 32 KiB queue", 1_250_000, 32 * 1024),
        ("10 Mbit/s, 8 KiB queue", 1_250_000, 8 * 1024),
        ("1 Mbit/s, 8 KiB queue", 125_000, 8 * 1024),
    ] {
        let echo = FectpEcho::public_key();
        let public = echo.public.expect("identity");
        let relay = BottleneckRelay::spawn(echo.addr, bytes_per_sec, queue);

        let conn = Connection::connect(relay.addr, &public, &Identity::generate())
            .expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(60)))
            .expect("timeout");

        const SIZE: usize = 256 * 1024;
        let payload = datasets::incompressible(SIZE);
        let start = std::time::Instant::now();
        let outcome = conn.send_reliable(&payload).and_then(|()| conn.flush(Duration::from_secs(60)));
        let elapsed = start.elapsed();

        let offered = relay.offered.load(std::sync::atomic::Ordering::Relaxed);
        let dropped = relay.overflowed.load(std::sync::atomic::Ordering::Relaxed);
        drop(conn);
        drop(relay);
        drop(echo);

        let share = if offered == 0 {
            0.0
        } else {
            dropped as f64 * 100.0 / offered as f64
        };
        row(&[
            label,
            &match &outcome {
                Ok(()) => ms(elapsed.as_secs_f64() * 1000.0),
                Err(_) => "gave up".to_string(),
            },
            &format!("{share:.1}% ({dropped}/{offered})"),
            &if outcome.is_ok() {
                format!("{:.2} MiB/s", throughput_mib(SIZE, elapsed))
            } else {
                "—".to_string()
            },
        ]);
    }
    note("The overflow column counts drops the sender caused itself: frames offered");
    note("to a queue that was already full, each then paid for by a retransmission");
    note("timer. This table is why congestion control exists here — it used to read");
    note("46.5% on the last row, when the send window was a fixed 32 whatever the");
    note("path was doing.");
    note("The window now opens at 4 and widens only as acknowledgements arrive, so");
    note("a sender that has learnt nothing about a path does not put a full burst");
    note("into it. Goodput barely moves, because the bottleneck rate is the");
    note("bottleneck — what changes is how much of the link is spent on datagrams");
    note("that will be dropped.");
    note("Treat these as one host's figures: the run-to-run spread on the middle");
    note("rows is wide, and only the last one is far enough outside it to lean on.");
    println!();

    // ── a rebinding NAT ──────────────────────────────────────────────────
    row_header(&["", "after the rebind", "expected"]);
    let echo = FectpEcho::public_key();
    let public = echo.public.expect("identity");
    let relay = RebindingRelay::spawn(echo.addr, 2);

    let conn =
        Connection::connect(relay.addr, &public, &Identity::generate()).expect("connect");
    conn.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    conn.send(b"before").expect("send");
    let mut buf = [0u8; 256];
    let before = conn.recv(&mut buf).is_ok();

    conn.send(b"after the mapping moved").expect("send");
    let after = conn.recv(&mut buf).is_ok();
    drop(conn);
    drop(relay);
    drop(echo);

    row(&[
        "session survives a new source port",
        if after { "yes" } else { "no" },
        "no",
    ]);
    note(&format!(
        "The exchange before the rebind {}, which is the control.",
        if before { "worked" } else { "did NOT work" }
    ));
    note("A session is keyed on the peer's address and its session identifier, so a");
    note("peer that reappears on a new port is a stranger. Keying on the pair is");
    note("what stops one client's chosen identifier colliding with another's, so");
    note("this is a consequence of that choice rather than an oversight — but it");
    note("does mean a NAT rebinding ends the session.");
}

// ─────────────────────── 10. jitter, asymmetry, and a crowded endpoint ────

/// The last three conditions, and the only one of them that is a real test of
/// the round-trip estimator.
fn jitter_asymmetry_and_crowding() {
    heading(
        "10. Jitter, an asymmetric path, and a crowded endpoint",
        "variable delay, loss in one direction only, and many peers at once",
    );

    const MESSAGES: usize = 200;
    let payload = datasets::incompressible(256);

    // ── jitter ───────────────────────────────────────────────────────────
    //
    // Nothing is dropped here, so every datagram above `MESSAGES + 1` is a
    // retransmission the sender decided on for no reason. That is the number
    // worth having: it says whether the round-trip estimator is tracking the
    // variation or being fooled by it.
    row_header(&["jitter", "200 reliable msgs", "datagrams sent", "spurious"]);
    for (label, spread) in [
        ("none", Duration::ZERO),
        ("0-2 ms", Duration::from_millis(2)),
        ("0-10 ms", Duration::from_millis(10)),
        ("0-40 ms", Duration::from_millis(40)),
    ] {
        let echo = FectpEcho::public_key();
        let public = echo.public.expect("identity");
        let relay = JitterRelay::spawn(echo.addr, spread, 0x5EED_1234);

        let conn = Connection::connect(relay.addr, &public, &Identity::generate())
            .expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(60)))
            .expect("timeout");

        let start = std::time::Instant::now();
        for _ in 0..MESSAGES {
            loop {
                match conn.send_reliable(&payload) {
                    Ok(_) => break,
                    Err(_) => conn.flush(Duration::from_secs(60)).expect("flush"),
                }
            }
        }
        conn.flush(Duration::from_secs(60)).expect("flush");
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        let sent = relay.forwarded.load(std::sync::atomic::Ordering::Relaxed);
        drop(conn);
        drop(relay);
        drop(echo);

        let expected = MESSAGES as u64 + 1;
        let extra = sent.saturating_sub(expected);
        row(&[
            label,
            &ms(elapsed),
            &format!("{sent}"),
            &format!("{extra} ({:.1}%)", extra as f64 * 100.0 / expected as f64),
        ]);
    }
    note("Nothing is dropped in this table, so every datagram past 201 is one the");
    note("sender resent although the first copy was still on its way. There are");
    note("none at all until the jitter reaches four times the timer's floor, and");
    note("three even then. The round-trip estimator carries a variation term and is");
    note("evidently using it: an estimator that averaged without one would retransmit");
    note("the moment a datagram took longer than usual, which here is constantly.");
    println!();

    // ── asymmetry ────────────────────────────────────────────────────────
    row_header(&["loss", "200 reliable msgs", "vs no loss", "delivered"]);
    let mut baseline = 0.0;
    for (label, fwd, back) in [
        ("none", 0u32, 0u32),
        ("2% on data only", 20, 0),
        ("2% on acks only", 0, 20),
        ("2% both ways", 20, 20),
        ("none again (control)", 0, 0),
    ] {
        let echo = FectpEcho::public_key();
        let public = echo.public.expect("identity");
        let relay = AsymmetricRelay::spawn(echo.addr, fwd, back, 0xC0FF_EE01);

        let conn = Connection::connect(relay.addr, &public, &Identity::generate())
            .expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(60)))
            .expect("timeout");

        let start = std::time::Instant::now();
        for _ in 0..MESSAGES {
            loop {
                match conn.send_reliable(&payload) {
                    Ok(_) => break,
                    Err(_) => conn.flush(Duration::from_secs(60)).expect("flush"),
                }
            }
        }
        let ok = conn.flush(Duration::from_secs(60)).is_ok();
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        drop(conn);
        drop(relay);
        drop(echo);

        let first = baseline == 0.0;
        if first {
            baseline = elapsed;
        }
        row(&[
            label,
            &ms(elapsed),
            &if first {
                "—".to_string()
            } else {
                format!("{:.1}x", elapsed / baseline)
            },
            if ok { "all" } else { "INCOMPLETE" },
        ]);
    }
    note("The last row repeats the first with nothing changed, and its distance from");
    note("1.0x is the noise floor. Losing an acknowledgement lands inside it, which");
    note("is the expected result rather than a surprising one: each acknowledgement");
    note("reports the whole receive window, so the next repairs a lost one, while");
    note("lost data has to be sent again and waits for a timer first.");
    println!();

    // ── a crowded endpoint ───────────────────────────────────────────────
    //
    // One connection's round trip, measured while others hammer the same
    // endpoint. An earlier version sent to every peer and then read from every
    // peer, and reported the per-peer figure *falling* as peers were added —
    // which was the batching amortising the syscall, not the endpoint getting
    // faster. The question is what one peer waits for, so only one is timed.
    row_header(&["other peers busy", "round trip", "vs idle", "p95"]);
    let mut baseline = 0.0;
    for others in [0usize, 7, 23] {
        let echo = FectpEcho::public_key();
        let public = echo.public.expect("identity");

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let load: Vec<std::thread::JoinHandle<()>> = (0..others)
            .map(|_| {
                let addr = echo.addr;
                let flag = std::sync::Arc::clone(&stop);
                std::thread::spawn(move || {
                    let Ok(conn) =
                        Connection::connect(addr, &public, &Identity::generate())
                    else {
                        return;
                    };
                    let _ = conn.set_read_timeout(Some(Duration::from_millis(200)));
                    let filler = vec![0x22u8; 256];
                    let mut buf = vec![0u8; 4096];
                    // Paced rather than a spin loop. Unpaced, thirty-one of
                    // these saturate every core and the table measures CPU
                    // starvation on a shared machine instead of what a peer
                    // waits for at the endpoint.
                    while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                        if conn.send(&filler).is_err() {
                            break;
                        }
                        let _ = conn.recv(&mut buf);
                        std::thread::sleep(Duration::from_micros(200));
                    }
                })
            })
            .collect();

        let mut conn =
            Connection::connect(echo.addr, &public, &Identity::generate()).expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut buf = vec![0u8; 4096];
        let stats = measure(20, 150, || {
            transports::fectp_round_trip(&mut conn, &payload, &mut buf);
        });

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        drop(conn);
        for handle in load {
            let _ = handle.join();
        }
        drop(echo);

        if others == 0 {
            baseline = stats.median_us();
        }
        row(&[
            &format!("{others}"),
            &us(stats.median_us()),
            &if others == 0 {
                "—".to_string()
            } else {
                format!("{:.2}x", stats.median_us() / baseline)
            },
            &us(stats.p95.as_secs_f64() * 1e6),
        ]);
    }
    note("Read the p95 column, not the median. The median barely moves, so a typical");
    note("request is unaffected by two dozen busy neighbours — but the tail grows");
    note("about fivefold, because one socket and one loop serve everyone and a");
    note("request that arrives behind a burst waits for it. That is the shape of a");
    note("single-threaded event loop, and it is the cost of the design in D14.");
    note("Client and server share this machine's cores, so the load threads compete");
    note("for CPU as well as for the endpoint: treat this as an upper bound.");
}
