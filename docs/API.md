# API reference

Every public method, grouped by what you are trying to do.
[USAGE.md](USAGE.md) explains *when* to reach for each; this is the list.

Two types do the work:

| | |
|---|---|
| [`Connection`](#connection) | one peer. Methods take `&self`, so two threads can use it at once. |
| [`Endpoint`](#endpoint) | many peers on one socket, driven by an event loop. |

---

## Connection

### Opening one

Four modes, each with a variant that carries a payload in the first packet.
None takes a timeout: they all use `HANDSHAKE_TIMEOUT`.

| | |
|---|---|
| `connect(addr, peer_public, identity)` | Public-key mode. You must already know the peer's key. |
| `connect_with_zero_rtt(addr, peer_public, identity, zero_rtt)` | The same, carrying a payload; returns the reply too. |
| `resume(addr, ticket, peer_public)` | Redeems a ticket, sparing three of the four key agreements. |
| `resume_with_zero_rtt(addr, ticket, peer_public, zero_rtt)` | The same, carrying a payload. |
| `connect_psk(addr, secret)` | Pre-shared-key mode. No public keys involved. |
| `connect_psk_with_zero_rtt(addr, secret, zero_rtt)` | The same, carrying a payload. |
| `connect_plain(addr)` | **No encryption.** Loopback and trusted links only. |
| `connect_plain_with_data(addr, data)` | The same, carrying a payload. |

> 0-RTT data is encrypted but **replayable** and has no forward secrecy. Put
> idempotent requests there, or nothing. See `SPEC.md` §4.4.1.

### Sending

| | size | if it is lost |
|---|---|---|
| `send(data)` | one frame | gone |
| `send_reliable(data)` | **any** | resent until acknowledged |

Each has a `_typed` twin taking a `PayloadType`, for a message whose shape
differs from the connection's default: `send_typed`, `send_reliable_typed`.

**There is no size for you to check.** `send_reliable` splits a payload larger
than a frame across several, each retransmitted on its own. That matters
because the frame limit depends on what the *peer* advertised at handshake, so
the caller cannot know it in advance.

Neither call waits. A split message will not fit in the congestion window, so
the rest is queued and fed out by `recv`, `flush` and later sends — `flush` is
how you wait for delivery.

`send` is one frame only, and refuses anything larger. Splitting a payload that
cannot be retransmitted would fail whenever any one piece went missing: for a
message of 200 fragments at 1% loss, that is nine times out of ten. It is a
trap rather than a feature.

`send_reliable` fails with `Error::Protocol(WindowFull)` when too many messages
are already queued, and refuses anything above `MAX_MESSAGE_LEN`.

### Receiving

| | |
|---|---|
| `recv(out)` | Blocks for the next message, writes it to `out`, returns its length. |

There is one receive method. Fragmented messages arrive whole, coded payloads
arrive decoded, acknowledgements and retransmissions are handled on the way.

### Waiting

| | |
|---|---|
| `flush(timeout)` | Returns once every reliable message has been acknowledged. |

Fails with `Error::Unacknowledged { count }` if a message was abandoned after
its retries, or if the timeout expires.

### Asking

| | |
|---|---|
| `peer_public_key()` | The peer's authenticated static key. |
| `peer_addr()` | Where it is. |
| `is_encrypted()` | False in plaintext mode. |
| `resumption_ticket()` | A single-use ticket for resuming later, if encrypted. |
| `max_payload()` | Largest `send`. |
| `max_reliable_payload()` | Largest `send_reliable` — smaller, by the message identifier. |
| `max_fragment_payload()` | What one frame of a split message carries. |
| `unacknowledged()` | Reliable messages still in flight. |
| `reassembling()` | Split messages half-arrived. |
| `queued()` | Split messages not yet fully sent. |
| `rto_ms()` | The current retransmission timeout estimate. |
| `default_payload_type()` | What `send` assumes. |

### Setting

| | |
|---|---|
| `set_default_payload_type(t)` | The shape `send` assumes from now on. |
| `set_read_timeout(t)` | How long `recv` waits before reporting a timeout. |
| `set_padding(on)` | Pads frames to 64 bytes to mask payload lengths. Off by default. |

---

## Endpoint

Many peers, one socket, one event loop. Peers are named by `PeerId`.

### Opening one

| | |
|---|---|
| `bind(addr, identity)` | Public-key mode. |
| `bind_psk(addr, secret)` | Pre-shared-key mode. |
| `bind_plain(addr)` | **No encryption.** |

### The loop

| | |
|---|---|
| `poll(timeout)` | Returns the next `Event`. Everything else happens inside it. |

```rust
match endpoint.poll(Some(Duration::from_millis(50)))? {
    Event::Connected { peer, zero_rtt, resumed, initiated } => {}
    Event::Message { peer, data } => {}
    Event::Sent { peer, delivered } => {}      // a split message finished
    Event::ConnectFailed { peer } => {}
    Event::Idle => {}                          // nothing arrived
}
```

Retransmissions, acknowledgements and queued large messages all advance here.
An endpoint that is not polled does nothing.

### Dialling out

| | |
|---|---|
| `connect(addr, peer_public)` | Starts a handshake; the result arrives as `Event::Connected`. |
| `connect_with_zero_rtt(addr, peer_public, zero_rtt)` | The same, carrying a payload. |
| `connecting()` | Handshakes started here and still unanswered. |
| `disconnect(peer)` | Drops one peer. |

An endpoint dials *and* listens on the same socket, which is what makes NAT
hole punching possible at all.

### Sending

The same two kinds as `Connection`, each taking a `PeerId` first, each with a
`_typed` twin:

| | size | |
|---|---|---|
| `send(peer, data)` | one frame | Fire and forget. |
| `send_reliable(peer, data)` | **any** | Resent until acknowledged. |

A message that had to be split reports its outcome as `Event::Sent`, since
there is nothing here to block on. Progress happens inside `poll`.

### Asking

| | |
|---|---|
| `local_addr()` | Where this endpoint is bound. |
| `public_key()` | This endpoint's static key, in public-key mode. |
| `is_encrypted()` | False in plaintext mode. |
| `peers()` / `peer_count()` | Who is connected. |
| `peer_public_key(peer)` / `peer_addr(peer)` | About one of them. |
| `unacknowledged(peer)` | Reliable messages still in flight to one peer. |
| `outstanding_tickets()` | Resumption tickets issued and not yet redeemed. |

### Setting

| | |
|---|---|
| `set_default_payload_type(peer, t)` | Per peer, unlike the connection-wide one. |

---

## Constants worth knowing

| | | |
|---|---|---|
| `MAX_UNACKED` | 32 | Reliable messages outstanding — the memory bound. |
| `INITIAL_CWND` | 4 | Where the congestion window opens. |
| `MIN_CWND` | 2 | Where it collapses to on loss. |
| `MAX_RETRIES` | 5 | Attempts before a message is abandoned. |
| `MAX_MESSAGE_LEN` | 1 MiB | Largest `send_reliable`. |
| `MAX_FRAGMENTS` | 4096 | Pieces one message may be cut into. |
| `MAX_QUEUED` | 4 | Split messages queued per peer. |
| `CODEC_OVERHEAD` | 4 | Bytes a coded payload adds. |
| `HANDSHAKE_TIMEOUT` | 5 s | How long any way of connecting waits for a reply. |

---

## Where this list is untidy

Recorded rather than smoothed over, because it is visible above.

**`_typed` doubles every send.** Two kinds of send become four on each type,
eight across both, and the twin differs by one argument. Rust has no default
arguments, so the alternatives are a builder — which adds a concept — or making
the type argument mandatory everywhere, which taxes the common case to tidy the
list.

Neither is a correctness problem, and neither is fixed here. There used to be
three kinds rather than two: `send_large` was a separate call, and the caller
had to compare their payload against `max_reliable_payload()` to know which to
use. That comparison is gone.
