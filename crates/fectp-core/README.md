# fectp-core

The `no_std` half of [FECTP](https://github.com/YounghyeonPark/fectp): the
Noise_IK_25519_ChaChaPoly_BLAKE2s session layer, the wire format, and the
reliability and congestion state — with no sockets, no threads and no
allocator.

**Not audited.** This carries `#![forbid(unsafe_code)]` and is cross-validated
frame by frame against an independent Noise implementation, and neither of
those is a security review. Do not put it in front of an adversary yet.

## What it is for

Two things, and it is worth knowing which one you want.

**A microcontroller.** Linked for `thumbv7em-none-eabihf` the whole protocol
costs about 23 KiB of flash and 358 bytes of session state, or 1,414 with the
reliable-delivery queue, plus whatever buffers the caller supplies. There is no
allocator anywhere in it.

**A binding from another language.** This layer is defined over buffers:
`Session::seal` and `Session::open` take bytes and return bytes, and never
touch a socket. A binding shaped the same way has no blocking calls to release
a GIL around, no threads of its own, and no owned memory crossing the boundary.
That is the half to bind — see
[OTHER-LANGUAGES.md](https://github.com/YounghyeonPark/fectp/blob/main/docs/OTHER-LANGUAGES.md),
which also explains why a browser cannot speak this protocol at all.

What it leaves to you: retransmission, congestion control and fragmentation are
driven by the [`fectp`](https://crates.io/crates/fectp) crate. Used directly,
this layer gives you the pieces and you drive them.

## Features

`std` enables the error trait and a few `Vec`-based conveniences. Off by
default; everything else works without it.

## The specification

The wire format is specified independently of this implementation, in
[SPEC.md](https://github.com/YounghyeonPark/fectp/blob/main/docs/SPEC.md), and a
conformance suite pins every normative constant against it.

## Licence

BSD 3-Clause.
