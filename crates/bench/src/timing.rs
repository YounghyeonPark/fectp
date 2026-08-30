//! Measurement helpers.
//!
//! Reports the median rather than the mean. On a desktop the tail is dominated
//! by scheduling noise that has nothing to do with the code being measured, and
//! a single 20 ms hiccup moves a mean far more than it moves reality.

use std::time::{Duration, Instant};

/// A distribution of timings.
#[derive(Clone, Copy)]
pub struct Stats {
    pub median: Duration,
    pub p95: Duration,
}

impl Stats {
    fn from(mut values: Vec<Duration>) -> Self {
        values.sort_unstable();
        let pick = |q: f64| values[((values.len() - 1) as f64 * q) as usize];
        Self {
            median: pick(0.50),
            p95: pick(0.95),
        }
    }

    /// Median as milliseconds, for tables where microseconds are noise.
    pub fn median_ms(&self) -> f64 {
        self.median.as_secs_f64() * 1000.0
    }

    /// Median as microseconds.
    pub fn median_us(&self) -> f64 {
        self.median.as_secs_f64() * 1_000_000.0
    }
}

/// Times `f` `samples` times after `warmup` untimed runs.
pub fn measure<F: FnMut()>(warmup: usize, samples: usize, mut f: F) -> Stats {
    for _ in 0..warmup {
        f();
    }
    let mut values = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        f();
        values.push(start.elapsed());
    }
    Stats::from(values)
}

/// Times `f` in batches, reporting the per-operation cost of each batch.
///
/// A single operation of a few microseconds is the same order as the scheduler
/// noise around it, so timing one at a time cannot resolve a difference of a
/// microsecond — it will happily report that adding work made something
/// faster. Timing a batch and dividing amortises that noise away.
pub fn measure_batched<F: FnMut()>(warmup: usize, batches: usize, per_batch: usize, mut f: F) -> Stats {
    for _ in 0..warmup {
        f();
    }
    let mut values = Vec::with_capacity(batches);
    for _ in 0..batches {
        let start = Instant::now();
        for _ in 0..per_batch {
            f();
        }
        values.push(start.elapsed() / per_batch as u32);
    }
    Stats::from(values)
}

/// Times an operation that reports its own duration, for cases where setup
/// must not be counted.
pub fn measure_reported<F: FnMut() -> Duration>(
    warmup: usize,
    samples: usize,
    mut f: F,
) -> Stats {
    for _ in 0..warmup {
        f();
    }
    Stats::from((0..samples).map(|_| f()).collect())
}

/// Throughput in mebibytes per second.
pub fn throughput_mib(bytes: usize, elapsed: Duration) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64()
}
