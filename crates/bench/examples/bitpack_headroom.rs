//! What block-wise bit packing would buy over LEB128, measured before building.
//!
//! D11 records that delta coding only pays when the deltas fit in seven bits: a
//! varint costs one byte below 64, two below 8192, so the ratio steps rather
//! than tracking the signal. Bit packing writes a block of deltas at whatever
//! width the widest of them needs, which should track.
//!
//! Whether that is worth a new transform id, a specification section and a
//! second decoder every implementation has to write depends on how large the
//! gap actually is. This measures it on the same data `datasets.rs` generates,
//! reproduced here because the bench crate is a binary and has no library to
//! import.
//!
//! **The answer is no, where Zstandard is available.** Packing produces a
//! third less transform output and a *larger* frame on two of three datasets
//! once the entropy stage has run: bit packing destroys byte alignment and
//! repetition, which is what an entropy coder lives on. On the counters it is
//! 62% worse. Only the no-Zstandard profile gains, and there it gains a lot —
//! kept here because both halves of that are worth being able to reproduce.
//!
//! ```bash
//! cargo run -p fectp-bench --example bitpack_headroom
//! ```

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// `datasets::sensor_i16`, verbatim.
fn sensor_i16(samples: usize, channels: usize, rate: f64) -> Vec<u8> {
    let mut out = Vec::with_capacity(samples * channels * 2);
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for s in 0..samples {
        for c in 0..channels {
            let phase = (s as f64) * rate + (c as f64) * 0.7;
            let value = (phase.sin() * 8000.0) as i16;
            let jitter = (rng.next() % 5) as i16 - 2;
            out.extend_from_slice(&value.wrapping_add(jitter).to_le_bytes());
        }
    }
    out
}

fn zigzag(v: i32) -> u32 {
    ((v << 1) ^ (v >> 31)) as u32
}

fn varint_len(v: u32) -> usize {
    match v {
        0..=0x7f => 1,
        0x80..=0x3fff => 2,
        0x4000..=0x1f_ffff => 3,
        0x0020_0000..=0x0fff_ffff => 4,
        _ => 5,
    }
}

/// The zigzagged deltas, per channel, exactly as the transform emits them.
fn deltas(bytes: &[u8], channels: usize, width: usize) -> Vec<u32> {
    let stride = channels * width;
    let samples = bytes.len() / stride;
    let mut out = Vec::with_capacity(samples * channels);
    for c in 0..channels {
        let mut prev = 0i32;
        for s in 0..samples {
            let at = (s * channels + c) * width;
            let v = if width == 2 {
                i32::from(i16::from_le_bytes([bytes[at], bytes[at + 1]]))
            } else {
                i32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
            };
            out.push(zigzag(v.wrapping_sub(prev)));
            prev = v;
        }
    }
    out
}

/// A block-packed encoding: one width byte per block, then every value in the
/// block at the widest one's bit length.
fn pack(values: &[u32], block: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in values.chunks(block) {
        let bits = chunk
            .iter()
            .map(|v| 32 - v.leading_zeros() as usize)
            .max()
            .unwrap_or(1)
            .max(1);
        out.push(bits as u8);
        let mut acc: u64 = 0;
        let mut held = 0usize;
        for v in chunk {
            acc |= u64::from(*v) << held;
            held += bits;
            while held >= 8 {
                out.push(acc as u8);
                acc >>= 8;
                held -= 8;
            }
        }
        if held > 0 {
            out.push(acc as u8);
        }
    }
    out
}

/// The LEB128 encoding, for the same values, so both go to zstd as bytes.
fn leb128(values: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in values {
        let mut v = *v;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }
    out
}

fn main() {
    let sets: Vec<(&str, Vec<u8>, usize, usize)> = vec![
        ("sensor i16 x4, slow", sensor_i16(1024, 4, 0.001), 4, 2),
        ("sensor i16 x4, fast", sensor_i16(1024, 4, 0.1), 4, 2),
        (
            "counter i32 x2",
            (0..2048i32).flat_map(|i| (i * 7).to_le_bytes()).collect(),
            2,
            4,
        ),
    ];

    println!("Transform output only. The entropy stage runs after either, and");
    println!("this is what it would be given.\n");
    println!(
        "{:<22} {:>8} {:>8} {:>8} {:>9}",
        "dataset", "raw", "LEB128", "packed", "change"
    );
    println!("{}", "-".repeat(60));

    for (name, bytes, channels, width) in &sets {
        let values = deltas(bytes, *channels, *width);
        let leb = leb128(&values);
        let packed = pack(&values, 64);
        let change = 100.0 * (packed.len() as f64 - leb.len() as f64) / leb.len() as f64;
        println!(
            "{:<22} {:>8} {:>8} {:>8} {:>8.1}%",
            name,
            bytes.len(),
            leb.len(),
            packed.len(),
            change
        );
    }

    // The number that actually decides it. Zstandard runs after the transform,
    // and a denser stream is not automatically a smaller one once it has: the
    // packing destroys byte alignment, and repetition is what an entropy coder
    // lives on.
    println!();
    println!("After the entropy stage, which is what goes on the wire:");
    println!();
    println!(
        "{:<22} {:>10} {:>10} {:>9} {:>10}",
        "dataset", "LEB+zstd", "packed+zstd", "change", "ratio now"
    );
    println!("{}", "-".repeat(66));
    for (name, bytes, channels, width) in &sets {
        let values = deltas(bytes, *channels, *width);
        let leb = zstd::bulk::compress(&leb128(&values), 1).expect("zstd");
        let packed = zstd::bulk::compress(&pack(&values, 64), 1).expect("zstd");
        let change = 100.0 * (packed.len() as f64 - leb.len() as f64) / leb.len() as f64;
        println!(
            "{:<22} {:>10} {:>10} {:>8.1}% {:>9.2}x",
            name,
            leb.len(),
            packed.len(),
            change,
            bytes.len() as f64 / leb.len() as f64
        );
    }

    // Where the varint boundary actually falls, since that is what decides it.
    println!("\nHow many deltas land in each varint width:");
    for (name, bytes, channels, width) in &sets {
        let values = deltas(bytes, *channels, *width);
        let mut buckets = [0usize; 6];
        for v in &values {
            buckets[varint_len(*v)] += 1;
        }
        let widest = values
            .iter()
            .map(|v| 32 - v.leading_zeros() as usize)
            .max()
            .unwrap_or(0);
        println!(
            "  {:<22} 1 byte {:>5}   2 bytes {:>5}   3+ {:>4}   widest {} bits",
            name,
            buckets[1],
            buckets[2],
            buckets[3] + buckets[4] + buckets[5],
            widest
        );
    }
}
