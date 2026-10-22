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

Three ways in, each with a variant that sends data in the very first packet,
saving the round trip the handshake would otherwise cost. None takes a timeout:
they all use `HANDSHAKE_TIMEOUT`, and all return `Result<Self>`.

| | |
|---|---|
| `connect(addr, peer_public, identity)` | Public-key mode. You must already know the peer's key. |
| `connect_and_send(addr, peer_public, identity, first)` | The same, sending `first` with the handshake. |
| `resume(addr, ticket, peer_public)` | Redeems a ticket, sparing three of the four key agreements. |
| `resume_and_send(addr, ticket, peer_public, first)` | The same, sending `first` with the handshake. |
| `connect_psk(addr, secret)` | Pre-shared-key mode. No public keys involved. |
| `connect_psk_and_send(addr, secret, first)` | The same, sending `first` with the handshake. |

There is no way to connect without encryption. Every constructor above
encrypts; they differ in who gets authenticated.

`first` shares the opening datagram with the handshake, and that datagram is
held to 1200 bytes whatever the ceiling, since nothing is known about the path
yet: **at most 1082 bytes** with a public key, 1122 resuming or with a
pre-shared key. More is refused with `Error::PayloadTooLarge`, whose `limit`
says how much fits. An `Endpoint`'s `connect_and_send` is held to the same.

> Data sent with the handshake is encrypted but **replayable** — an attacker
> who captures the packet can send it again — and has no forward secrecy. Send
> only what is safe to repeat. A sensor reading is; "open the valve" is not.
> See `SPEC.md` §4.4.1.
>
> It saves one round trip *once per connection*, so it is worth reaching for
> when connections are short and worth ignoring when they stay open.

### Sending

| | size | if it is lost |
|---|---|---|
| `send(data, shape)` | one frame | gone |
| `send_reliable(data, shape)` | **any** | resent until acknowledged |

Two calls, not four. `shape` is a [`PayloadType`](#payloadtype) naming what the
bytes are, so a transform suited to them can run before the generic compressor.
`PayloadType::Opaque` means "just bytes" and is always correct.

**The shape is named at every call rather than set once.** A setting would mean
a line's behaviour depended on a call somewhere else, and forgetting it would
cost compression silently — no error, no warning. Repeating it is cheap:
`PayloadType` is two bytes and `Copy`, so bind it to a local and pass it.

```rust
let shape = PayloadType::I16 { channels: 4 };
conn.send(&samples, shape)?;
conn.send(&more, shape)?;
conn.send(b"a status line", PayloadType::Opaque)?;
```

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
| `resumption_ticket()` | A single-use ticket for resuming later. `None` once closed. |
| `max_payload()` | Largest `send`. |
| `max_reliable_payload()` | Largest `send_reliable` — smaller, by the message identifier. |
| `max_fragment_payload()` | What one frame of a split message carries. |
| `unacknowledged()` | Reliable messages still in flight. |
| `reassembling()` | Split messages half-arrived. |
| `queued()` | Split messages not yet fully sent. |
| `rto_ms()` | The current retransmission timeout estimate. |

### Setting

| | |
|---|---|
| `set_read_timeout(t)` | How long `recv` waits before reporting a timeout. |
| `set_padding(on)` | Pads frames to 64 bytes to mask payload lengths. Off by default. |
| `set_keepalive(every)` | Send a 38-byte frame whenever nothing has been sent for `every`, so a NAT mapping does not lapse in a quiet period. Off by default, and only runs while a call is inside `recv` or `flush`. |
| `set_max_retries(n)` | How many times a reliable message is resent before it is given up on, replacing `MAX_RETRIES`. A count, not a duration: five attempts are about 1.3 seconds once the round-trip estimate settles near the 20 ms floor, and about eleven from a cold start. A long `flush` timeout does not buy more attempts. |

---

## Endpoint

Many peers, one socket, one event loop. Peers are named by `PeerId`.

### Opening one

| | |
|---|---|
| `bind(addr, identity)` | Public-key mode. |
| `bind_psk(addr, secret)` | Pre-shared-key mode. |
| `bind_socket(socket, identity)` | Public-key mode over any `DatagramSocket`: a socket with options of your own, a transport of your own, a simulated network. |

### Setting

| | |
|---|---|
| `set_keepalive(every)` | See the constants table below. |
| `set_peer_timeout(within)` | |
| `set_max_peers(limit)` | |
| `set_max_retries(n)` | As on `Connection`, applied to every peer — those already open as well as those still to arrive. |
| `set_handshake_attempts(n)` | Opening frames sent before a connect is given up on. A floor rather than a ceiling: the endpoint gives up once it has spent both this many attempts *and* the wall clock the cold schedule would have taken — measured, 788 ms for two, 2.55 s for four and 9.09 s for eight. On an address it has already measured, the intervals come from that measurement, so the same wall clock buys more attempts (D71). `Connection` has no equivalent — its handshake ends before there is an object to set anything on, so `HANDSHAKE_TIMEOUT` bounds it instead. |
| `set_max_handshakes_per_second(rate)` | |
| `set_max_migration_attempts_per_peer(rate)` | |
| `set_ticket_lifetime(how_long)` | |
| `set_handshake_reply(payload)` | A payload carried in the response to every handshake. |

### The loop

| | |
|---|---|
| `poll(timeout)` | Returns the next `Event`. Everything else happens inside it. |
| `set_handshake_reply(payload)` | A payload carried in the response to every handshake, so a peer that sent data with its opening frame is answered in the same round trip. Same bytes for every peer. |

```rust
match endpoint.poll(Some(Duration::from_millis(50)))? {
    Event::Connected { peer, zero_rtt, resumed, initiated } => {}
    Event::Message { peer, data } => {}
    Event::Sent { peer, delivered } => {}      // a reliable message settled
    Event::ConnectFailed { peer } => {}
    Event::PeerMoved { peer, from, to } => {}  // the peer changed address
    Event::PeerLost { peer } => {}             // gave up on the peer
    Event::IntroductionFailed { peer_public, reason } => {} // see below
    Event::Idle => {}                          // nothing arrived
}
```

`PeerMoved` reports a move that has already happened and been proved: the
handle is unchanged, because it is the same session. A peer heard from at a new
address is challenged first and followed only if it answers, so nothing is sent
to the new address until then — a frame that authenticates says who sealed it,
not where they are. Nothing needs handling for this to work; the event is there
for logging and for applications that key anything on a peer's address.

Retransmissions, acknowledgements and queued large messages all advance here.
An endpoint that is not polled does nothing.

### Dialling out

| | |
|---|---|
| `connect(addr, peer_public)` | Starts a handshake; the result arrives as `Event::Connected`. |
| `connect_and_send(addr, peer_public, zero_rtt)` | The same, carrying a payload. |
| `connecting()` | Handshakes started here and still unanswered. |
| `disconnect(peer)` | Drops one peer. |

An endpoint dials *and* listens on the same socket, which is what makes NAT
hole punching possible at all.

### Through a rendezvous

| | |
|---|---|
| `connect_rendezvous(addr, rendezvous_public)` | Registers with a `Rendezvous`. Its messages are not raised as `Event::Message`. |
| `introduce(their_public)` | Asks to be introduced. Nothing happens until they ask for this endpoint too. |
| `observed_addr()` | Where the rendezvous sees this endpoint: outside its NAT. |
| `is_relayed(peer)` | Whether a session runs through the relay rather than directly. |

Success is an ordinary `Event::Connected` for a peer whose `peer_public_key`
is the one asked for; failure is `Event::IntroductionFailed { peer_public,
reason }` — on both sides when the rendezvous refuses to relay for a pair it
introduced, except for a request over its rate bound, which only the asker
hears. A relay drops a
session that carries nothing for a minute, so a relayed one that may fall
quiet wants `set_keepalive` below that. A relayed session follows this
endpoint when its NAT moves it: it proves its new address to the relay on its
next resend, and every `RELAY_REFRESH` (20 s) regardless. At most `MAX_INTRODUCTIONS` (16)
outstanding at once, each given up on after `INTRODUCTION_DEADLINE` (90 s).
Public-key mode only: a rendezvous knows its clients by their keys.

### Sending

The same two calls as `Connection`, with a `PeerId` first:

| | size | |
|---|---|---|
| `send(peer, data, shape)` | one frame | Fire and forget. |
| `send_reliable(peer, data, shape)` | **any** | Resent until acknowledged. |

The outcome arrives as `Event::Sent`, since there is nothing here to block on.
A split message reports either way, once for the whole message; a message that
fitted in one frame reports only failure, with `delivered` false. Success for a
small message is silent — one event per reliable send would grow this queue
without limit. Progress happens inside `poll`.

### Asking

| | |
|---|---|
| `local_addr()` | Where this endpoint is bound. |
| `public_key()` | This endpoint's static key, in public-key mode. |
| `peers()` / `peer_count()` | Who is connected. |
| `peer_public_key(peer)` / `peer_addr(peer)` | About one of them. |
| `max_payload(peer)` | Largest `send` to one peer now. Moves with path MTU discovery. |
| `unacknowledged(peer)` | Reliable messages still in flight to one peer. |
| `outstanding_tickets()` | Resumption tickets issued and not yet redeemed. |

---

## Rendezvous

The third party two NATed peers both reach (SPEC Appendix A). An endpoint
underneath, driven the same way.

| | |
|---|---|
| `bind(addr, identity)` | Serves `identity`; clients must know its public key. |
| `set_relay_address(ip)` | Where clients reach this host, for relay ports to be advertised at. Bound to `0.0.0.0`, it refuses to relay until told. Behind a NAT of its own, set it too: it cannot tell, and would advertise its private address. |
| `poll(timeout)` | Does whatever is due, returning within a second whatever `timeout` says. Call it in a loop. A client cannot make it fail. |
| `set_policy(allow)` | Which pairs may be introduced, and so relayed. Every pair that asked, by default. |
| `set_introduction_window(d)` | How long one side's request waits for the other's. 30 s by default. |
| `clients()` / `relays()` | Registered now; relay allocations held now. |

It turns on keep-alives every 15 s and a 60 s peer timeout for itself, so a
departed client's address is not handed out. Relay allocations are capped at
64 in total and 4 per client IP address, forward at most 1 MiB/s each, and go
after 60 s of forwarding nothing.

---

## PayloadType

What the bytes are, so the right transform runs before the compressor.

| | |
|---|---|
| `Opaque` | Just bytes. Always correct; the compressor is on its own. |
| `I16 { channels }` | Interleaved 16-bit samples — an ADC or sensor stream. |
| `I32 { channels }` | Interleaved 32-bit samples or counters. |
| `Elements { size }` | Fixed-size elements, byte-transposed. `4` for `f32`, `8` for `f64`. |

Measured on 8 KiB (BENCHMARKS.md §7), declaring the shape is worth a lot on
structured binary and nothing on text or random bytes:

| | as `Opaque` | declared |
|---|---|---|
| sensor i16 ×4, slow | 1.12x | **3.46x** |
| counter i32 ×2 | 1.67x | **292.57x** |
| f32 array | 1.14x | **8.21x** |
| JSON text | 126.03x | 126.03x |

A wrong declaration is safe: the payload still round-trips, it just compresses
badly.

---

## Types you will need to name

Most of the API takes these rather than returning them, so they are easy to
miss until you want to store one.

| | |
|---|---|
| `Identity` | An X25519 keypair. `generate()`, `from_secret([u8; 32])`, `public()`, `secret()`. |
| `PeerKey` | A peer's 32-byte public key — a plain `[u8; 32]`. **This is the name to import**; method signatures spell the underlying type `PublicKey`. |
| `PeerId` | Handle for one peer of an `Endpoint`. Returned by `connect` and carried by every `Event`. |
| `Ticket` | A resumption ticket. `from_key([u8; 32])`, `key()`. Key material — store it like a secret. |
| `PayloadType` | What the bytes are; see [above](#payloadtype). |

A worked example of the first two — generating an identity, storing the secret,
printing the public half as hex, parsing it back, and deciding which keys are
allowed — is `cargo run -p fectp --example keys`, which runs as two separate
processes so the key genuinely has to be copied between them.

---

## Frame size

| | |
|---|---|
| `max_datagram()` | The largest datagram this process will send or advertise. |
| `set_max_datagram(n)` | Raises or lowers it. Clamped to `MIN_MAX_DATAGRAM..=65535`. |
| `path_mtu_discovery()` | Whether sessions search for a size above 1200. |
| `set_path_mtu_discovery(on)` | Turns that on or off, for sessions established afterwards. On by default. |

`DEFAULT_MAX_DATAGRAM` is 1200, which any internet path carries without
fragmenting. On ethernet that leaves 272 bytes of every frame unused — 1472 is
what 1500 carries after IP and UDP — and until there was a way to raise it, a
peer's advertised limit could only ever lower it.

**Process-wide, and set before anything connects.** The path MTU belongs to the
network this process sits on rather than to a connection, and the value travels
to the peer inside the handshake: one already told 1200 keeps sending 1200.

**Raised, it is searched for, not assumed.** Each session starts at 1200 and
probes upward (SPEC §5.8.7) and uses the largest size answered. It falls back
to 1200 when a large reliable frame has to be resent and a check of the size in
use goes unanswered; otherwise the ten-minute re-check is what notices, so large
*unreliable* frames lost in between are lost silently. Read
`max_payload` when sizing a message, not once at connect. Handshakes stay at
1200. A peer that does not answer probes — any before this — is sent at the
ceiling from the start, as is everyone with discovery off.

**An answer proves arrival, not wholeness.** fectp does not control the
don't-fragment bit, so a size split on the way — by a router, or by the sending
host, on IPv4 or IPv6 — can still be answered, and settled on
([D85](DECISIONS.md#d85--path-mtu-discovery-without-the-dont-fragment-bit)).
Where that matters, set the ceiling to what the path carries whole.

---

## Constants worth knowing

| | | |
|---|---|---|
| `MAX_UNACKED` | 32 | Reliable messages outstanding — the memory bound. |
| `INITIAL_CWND` | 4 | Where the congestion window opens. |
| `MIN_CWND` | 2 | Where it collapses to on loss. |
| `MAX_RETRIES` | 5 | Attempts before a message is abandoned. `set_max_retries` replaces it. |
| `MAX_MESSAGE_LEN` | 1 MiB | Largest `send_reliable`. |
| `MAX_FRAGMENTS` | 4096 | Pieces one message may be cut into. |
| `MAX_QUEUED` | 4 | Split messages queued per peer. |
| `CODEC_OVERHEAD` | 4 | Bytes a coded payload adds. |
| `DEFAULT_MAX_DATAGRAM` | 1200 | The frame ceiling, before `set_max_datagram`. |
| `MIN_MAX_DATAGRAM` | 128 | Below this a handshake does not fit. |
| `HANDSHAKE_TIMEOUT` | 10 s | How long a `Connection` constructor waits for a reply, resending meanwhile. |
| `HANDSHAKE_ATTEMPTS` | 4 | Opening frames an `Endpoint` sends before it may give up, cold at 250, 500, 750 and 1000 ms. `set_handshake_attempts` replaces it. |
| `MAX_PEERS` | 1024 | Sessions one `Endpoint` holds, before the longest-silent is dropped. `set_max_peers` overrides it. |
| `TICKET_LIFETIME` | 1 hour | How long a resumption ticket stays redeemable. `set_ticket_lifetime` overrides it. |
| `MAX_HANDSHAKES_PER_SECOND` | 512 | New sessions answered per second. Established peers are not affected. `set_max_handshakes_per_second` overrides it. |
| `MIN_KEEPALIVE` | 100 ms | Floor under `set_keepalive`. A zero interval taken literally sends one datagram per loop pass — measured at 1,123 in 200 ms. |
| `MIN_PEER_TIMEOUT` | 1 s | Floor under `set_peer_timeout`. Below a second nothing distinguishes a peer that has gone from one that is slow. |
| `MAX_MIGRATION_ATTEMPTS_PER_PEER` | 8 | Attempts a second, **per session**, to open a frame from an address that session is not filed under — what following a moved peer costs. Per session so that one peer flooding the lookup cannot stop every other peer migrating. `set_max_migration_attempts_per_peer` overrides it; zero refuses to follow peers at all. |

---

## Where this list is untidy

Nothing, now. Both of the entries that were here have been dealt with:
`send_large` was folded into `send_reliable` so there is no size to compare
against, and the timeout argument that appeared on some constructors and not
others turned out to be covering a hang.

The `_typed` twins are gone too. They existed because Rust has no default
arguments, so `send(data)` and `send_typed(data, shape)` had to be separate
methods; the shape is now an argument on `send` itself, and the setter that
made `send(data)` mean different things at different times is gone with it.
