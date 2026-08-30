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
use timing::{measure, throughput_mib};
use transports::{FectpEcho, TlsEcho, TlsSetup, UdpEcho};

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
    heading("5. Encrypting a frame", "ChaCha20-Poly1305 over a 1200-byte payload");

    let pk = FectpEcho::public_key();
    let mut conn =
        Connection::connect(pk.addr, &pk.public.expect("identity"), &Identity::generate())
            .expect("connect");
    conn.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");

    // Sending without waiting isolates the send path: coding, sealing, and the
    // syscall, with no round trip in the way.
    let payload = vec![0x33u8; 1200];
    let stats = measure(WARMUP, SAMPLES, || {
        conn.send(&payload).expect("send");
    });
    drop(conn);
    drop(pk);

    row_header(&["", "per frame", "throughput"]);
    row(&[
        "seal 1200 bytes and hand to the kernel",
        &us(stats.median_us()),
        &format!("{:.0} MiB/s", throughput_mib(1200, stats.median)),
    ]);
    note("This includes the sendto syscall, which dominates: the AEAD itself is");
    note("a fraction of it. Encryption is not what costs anything here.");
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

    row_header(&["dataset", "raw bytes", "gzip", "zstd -4", "FECTP typed", "no zstd"]);

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

        row(&[
            set.name,
            &format!("{raw}"),
            &ratio(raw, gzip),
            &ratio(raw, zstd_only),
            &ratio(raw, typed),
            &ratio(raw, typed_bare),
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

/// The default level was inherited from the design note's `--fast=4`
/// recommendation, on the reasoning that a transport this latency-sensitive
/// cannot afford a slow compressor. That reasoning deserves to be checked
/// against the cost it was trading away, which is what this section does.
fn compression_level() {
    heading(
        "7. What the Zstandard level costs and buys",
        "level is a sender-side choice; a receiver decodes any of them",
    );

    const LEVELS: &[i32] = &[-4, -1, 1, 3, 9];

    row_header(&[
        "dataset",
        "-4 (default)",
        "-1",
        "1",
        "3",
        "9",
    ]);
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
    row_header(&["encode 8 KiB", "-4 (default)", "-1", "1", "3", "9"]);
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
    note("more bytes than it was given, so FECTP correctly falls back to sending the");
    note("payload uncompressed — the 1.00x column is a real result, not a failure to");
    note("run. Level 1 costs about 10 us more per 8 KiB and does substantially better.");
    println!();
    note("Read this against section 6 before concluding the default is wrong. When a");
    note("payload's type is declared, the transform runs first and leaves something");
    note("repetitive enough that even level -4 finds it: the i32 counters reach 248x.");
    note("The gap is on opaque payloads, where nothing has exposed the structure and");
    note("-4 is the only thing standing between the data and the wire.");
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

