//! Payloads that stand in for what a transport like this actually carries.
//!
//! Compression numbers mean nothing without saying what was compressed, so each
//! of these is described alongside its result.

/// A deterministic pseudo-random source, so every run compresses the same
/// bytes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

pub struct Dataset {
    pub name: &'static str,
    pub description: &'static str,
    pub bytes: Vec<u8>,
    /// The shape to declare to FECTP, as `(channels, element size)`.
    pub shape: Shape,
}

#[derive(Clone, Copy)]
pub enum Shape {
    Opaque,
    I16 { channels: u8 },
    I32 { channels: u8 },
    Elements { size: u8 },
}

/// Multi-channel ADC samples: a sinusoid per channel plus a few bits of noise.
///
/// `rate` is the phase step per sample, which decides how far apart successive
/// samples are and therefore how much a delta transform can win.
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

pub fn all() -> Vec<Dataset> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);

    vec![
        Dataset {
            name: "sensor i16 x4, slow",
            description: "4 channels of 16-bit ADC, slowly varying — instrument telemetry",
            bytes: sensor_i16(1024, 4, 0.001),
            shape: Shape::I16 { channels: 4 },
        },
        Dataset {
            name: "sensor i16 x4, fast",
            description: "the same, changing quickly between samples",
            bytes: sensor_i16(1024, 4, 0.1),
            shape: Shape::I16 { channels: 4 },
        },
        Dataset {
            name: "counter i32 x2",
            description: "2 channels of monotonic 32-bit counters",
            bytes: (0..2048i32)
                .flat_map(|i| (i * 7).to_le_bytes())
                .collect(),
            shape: Shape::I32 { channels: 2 },
        },
        Dataset {
            name: "f32 array",
            description: "floats of similar magnitude — a calibration table",
            bytes: (0..2048)
                .flat_map(|i| (1.0f32 + i as f32 * 0.001).to_le_bytes())
                .collect(),
            shape: Shape::Elements { size: 4 },
        },
        Dataset {
            name: "JSON log lines",
            description: "repetitive structured text",
            bytes: b"{\"sensor\":\"temp\",\"value\":21.5,\"unit\":\"C\"}\n"
                .iter()
                .cycle()
                .take(8192)
                .copied()
                .collect(),
            shape: Shape::Opaque,
        },
        Dataset {
            name: "random bytes",
            description: "incompressible — the floor nothing can beat",
            bytes: (0..8192).map(|_| (rng.next() >> 24) as u8).collect(),
            shape: Shape::Opaque,
        },
    ]
}
