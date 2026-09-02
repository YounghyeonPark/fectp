# What FECTP costs on a microcontroller

The project was scoped around running on a 32-bit MCU, and that premise went
unchecked for a long time. What the design notes carried was a pre-link upper
bound — the core's own code at ~21 KiB plus ~95 KiB of crypto dependencies —
which reads as about 116 KiB and would rule the protocol out on many parts.

It is not a number anyone can plan with. Most of `curve25519-dalek` is never
reached, and the linker discards it.

This crate links a real image and measures what survives.

```bash
cargo build --release && python size.py
cargo build --release --features baseline && python size.py   # the same image, protocol removed
```

| | flash |
|---|---|
| full protocol | 22,614 bytes |
| baseline | 36 bytes |
| **FECTP** | **22,578 bytes (22.0 KiB)** |

The estimate was five times too pessimistic.

## How it is measured

`main.rs` drives a full public-key handshake in both roles, seals and opens a
data frame, and exercises the codec header, writing the result to a volatile
address — otherwise the optimiser would notice the work is unobserved and
delete the code being measured.

The profile is `opt-level = "z"`, fat LTO, `panic = "abort"` and
`--gc-sections`. Those are not incidental: without them the figure is the
pre-link bound again.

`link.x` describes a plausible Cortex-M4F, not any particular part. Where the
regions sit does not change how much code survives.

The random number generator is a deterministic stand-in and is **not usable for
anything real**. A microcontroller takes entropy from its own hardware, and
linking a vendor HAL in would measure the board rather than the protocol.

## Why it is outside the workspace

It only links for a bare-metal target, so `cargo build --workspace` on a host
would try to link it and fail. Its profile also has to differ from the
workspace's, which is the whole point.

## RAM

Flash is half the question. For the other half:

```bash
cargo run -p fectp-core --example sizes
```

294 bytes of session state, 1,334 with the reliable-delivery queue, plus the
buffers the caller supplies. The core allocates nothing, so that is the whole
answer.
