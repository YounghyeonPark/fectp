# Using FECTP

Every snippet here is compiled as part of `crates/fectp/examples/tour.rs`, so
none of it can go stale.

## Adding the dependency

```toml
[dependencies]
fectp = { path = "crates/fectp" }
```

Zstandard compression is opt-in, because it needs a C toolchain to build:

```toml
fectp = { path = "crates/fectp", features = ["compress"] }
```

Without it everything still works — payloads simply go uncompressed, and the
built-in integer transforms (see [Typed payloads](#typed-payloads)) still apply.

## Choosing a mode

A connection runs in one of two modes. Both encrypt — that is not something a
caller can decline — and what they differ in is who gets authenticated.
Everything after the constructor — `send`, `recv`, `send_reliable`, codecs,
`poll` — is identical in both, so this is a one-line decision, not a different
way of working.

| | pre-shared | authenticates | handshake | use it for |
|---|---|---|---|---|
| Public key | server's public key | each peer separately | 4 DH | the internet, several organisations |
| Pre-shared key | one secret | membership of the group | **1 DH** | one closed system, a lab network |

```rust
// Public key
let conn = Connection::connect(addr, &server_public, &Identity::generate())?;
let server = Endpoint::bind("0.0.0.0:4433", Identity::generate())?;

// Pre-shared key
let conn = Connection::connect_psk(addr, b"lab-instrument-7")?;
let server = Endpoint::bind_psk("0.0.0.0:4433", b"lab-instrument-7")?;
```

**Encryption is not what costs you anything.** Encrypting a frame takes about a
microsecond; distributing keys is what takes effort. So if public-key mode
feels heavy, the answer is usually a pre-shared key — one secret both sides
configure, no public keys to ship — rather than turning encryption off.

**A pre-shared key is symmetric.** Everyone holding it can impersonate everyone
else holding it. Right for one closed system, wrong across organisations.

**There is no unencrypted mode.** There was one, for physically trusted links
and for readable packet captures during development. It was removed: a protocol
named for encryption should not ship a way to turn it off, and the only real
argument for it — avoiding key distribution — is what pre-shared-key mode is
for, at one X25519 operation.

**Modes never mix.** A peer in one mode cannot talk to a peer in another — the
frame types are disjoint, so there is nothing to negotiate and nothing to
downgrade. Mismatched peers simply fail to connect.

## Identities and keys

A peer is identified by an X25519 keypair.

```rust
use fectp::Identity;

let identity = Identity::generate();
let public = *identity.public();     // [u8; 32] — hand this to peers
let secret = *identity.secret();     // [u8; 32] — persist this, keep it secret
let restored = Identity::from_secret(secret);
```

**A client must know the server's public key before connecting.** FECTP has no
certificate authority and does no key discovery: distributing that key is your
problem, the same way an SSH host key is. Ship it with the firmware, put it in a
config file, print it on a label — but it has to arrive out of band.

### Using them, start to finish

An `Identity` is an X25519 keypair: a 32-byte secret you keep, and a 32-byte
public key you hand out. Four steps, once per deployment.

**1. Generate an identity and keep the secret.** Generating a fresh one on every
start would change your public key every restart, and every peer would stop
trusting you — so store it, exactly as an SSH host key is stored.

```rust
// First run only.
let identity = Identity::generate();
save_to_flash(identity.secret());              // 32 bytes, keep private

// Every run after.
let identity = Identity::from_secret(load_from_flash());
```

**2. Print the public half so a person can copy it.** A `PeerKey` is a bare
`[u8; 32]`, which is not something you paste into a config file:

```rust
let public_key = *identity.public();
let shareable: String = public_key.iter().map(|b| format!("{b:02x}")).collect();
println!("public key: {shareable}");          // 64 hex characters
```

**3. The dialling side puts that string in its configuration** and connects with
it. That one string is the only thing that has to travel between the machines
beforehand — the secret never moves.

```rust
let mut server = Endpoint::bind("0.0.0.0:4433", identity)?;                  // listening
let conn = Connection::connect(addr, &server_public, &Identity::generate())?; // dialling
```

**4. Decide who is allowed.** The handshake proves *which* key the peer holds.
It does not decide whether that key may do anything — that is yours:

```rust
// `their_public` came from `endpoint.peer_public_key(peer)`.
if !allow_list.contains(&their_public) {
    server.disconnect(peer);
}
```

> **All four as two real processes**, runnable:
> [`examples/keys.rs`](../crates/fectp/examples/keys.rs).
>
> ```bash
> cargo run -p fectp --example keys -- serve            # prints its public key
> cargo run -p fectp --example keys -- connect <key>    # another terminal
> ```
>
> Two processes rather than two threads on purpose. A public key has to
> *travel*, and faking that with a shared variable skips the step you actually
> have to get right — so there it reaches the client through `argv`, as text you
> copied. The first `connect` is **refused**: the server has no reason to trust
> it yet, and prints the line to add to its allow-list.

### Where to keep the secret

Two requirements, and nothing else: the same 32 bytes must be there after a
restart, and nothing else may read them. Miss the first and your public key
changes on every boot, so every peer stops trusting you. Miss the second and
anyone who can read the file can *be* you.

| | |
|---|---|
| Linux, BSD service | `/etc/<service>/identity.key`, owned by the service account, mode `600` |
| Linux, BSD per-user | `$XDG_CONFIG_HOME/<app>`, else `~/.config/<app>` |
| macOS | `~/Library/Application Support/<app>` |
| Windows | `%APPDATA%\<app>` — files there inherit an ACL granting only the owner and administrators |
| Microcontroller | A flash region the application does not rewrite. Better, one the bootloader write-protects after provisioning. |
| Cloud | KMS, Vault, or the platform's secrets manager, read at start into memory |

**Do not** hardcode the secret in source, commit it, pass it in an environment
variable that shows up in `ps`, or leave it in a temporary directory — a cleaner
will eventually delete it, and the identity with it. And do not call
`Identity::generate()` on every start unless a fresh identity every boot is what
you actually want.

Two habits worth copying from `ssh`, both in
[`examples/keys.rs`](../crates/fectp/examples/keys.rs):

- **Refuse a key file others can read.** Check the mode on load and fail loudly.
  Permissions drift, and the moment you find out should not be an incident.
- **Write atomically** — a temporary name, restricted, then renamed over the
  target. Writing in place risks a truncated file, and a truncated key file is
  an identity that no longer exists.

```rust
let secret = *identity.secret();
// ...store it by whichever route above...
let identity = Identity::from_secret(secret);
```

**The secret must be in your process's memory.** `Identity::from_secret` takes
the raw 32 bytes and the handshake performs its own Diffie-Hellman, so a secure
element or HSM that never releases the key — the whole point of one — cannot be
used without a change to `fectp-core`. If key isolation is a requirement, that
is a gap to know about before building on this.

## The shortest working pair

Endpoint:

```rust
use fectp::{Event, Identity, Endpoint};

let identity = Identity::generate();
println!("public key: {:?}", identity.public());
let mut server = Endpoint::bind("0.0.0.0:4433", identity)?;

loop {
    match server.poll(Some(Duration::from_millis(100)))? {
        Event::Message { peer, data } =>
            server.send(peer, &data, PayloadType::Opaque)?,   // echo
        _ => {}
    }
}
```

Client:

```rust
use fectp::{Connection, Identity};

let mut conn = Connection::connect("server:4433", &server_public, &Identity::generate())?;
conn.send(b"hello", PayloadType::Opaque)?;

let mut buf = vec![0u8; 2048];
let n = conn.recv(&mut buf)?;
```

> One `Endpoint` handles one peer or a thousand, and dials as well as
> listens — see [Peers, not clients and servers](#peers-not-clients-and-servers).

## Timeouts

There are two, and only one of them is yours to set.

**Opening a connection** needs no attention: every way of doing it gives up
after `fectp::HANDSHAKE_TIMEOUT` (5 seconds). That is not a convenience. A peer
that cannot authenticate a frame drops it silently — there is no reply and no
error on the wire — so a handshake aimed at an unreachable address or the wrong
key has nothing at all to wait for, and without a deadline would wait for ever.

The opening frame is resent while that timeout runs — linear backoff from 250 ms — so a lost handshake datagram costs a retry rather than the whole connection. Five seconds is the budget for the attempt, not for one packet.

**`recv` blocks** until something arrives, unless you say otherwise:

```rust
use std::time::Duration;

conn.set_read_timeout(Some(Duration::from_secs(5)))?;
match conn.recv(&mut buf) {
    Ok(n) => { /* ... */ }
    Err(fectp::Error::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => { /* ... */ }
    Err(e) => return Err(e),
}
```

`flush` takes its own timeout as an argument, since waiting is the whole point
of it.

## Sending data

```rust
conn.send(b"fire and forget", PayloadType::Opaque)?;   // no acknowledgement
```

`send` returns once the datagram is handed to the kernel. It does not wait for
anything, and it never batches payloads.

Payloads are bounded by one datagram:

```rust
let limit = conn.max_payload();      // typically 1170 bytes
```

A larger payload is refused with `Error::PayloadTooLarge` — *unless* it
compresses under the limit, in which case it goes through. What has to fit is
the frame on the wire.

A reliable send carries a message identifier as well, so its ceiling is a few
bytes lower:

```rust
let limit = conn.max_reliable_payload();   // typically 1166 bytes
```

For anything above either limit, see [Large messages](#large-messages).

## Sending with the handshake

Opening a connection normally costs a round trip before any data moves. If you
have data ready, it can ride along in the very first packet:

```rust
let conn = Connection::connect_and_send(
    addr, &server_public, &identity, &reading,
)?;
```

The peer receives it as `Event::Connected { zero_rtt, .. }`, or as the second
element of `accept()`. Anything it sends back arrives through `recv` like any
other message.

**When this is worth using.** It saves exactly one round trip, once, per
connection. On a connection that stays open and carries thousands of messages
that is nothing. It matters when connections are short:

- a battery-powered sensor that wakes, reports one reading, and sleeps
- reconnecting after a peer has been unreachable long enough to give up on
- anywhere the very first answer's latency is what somebody notices

If your program connects once and streams, use plain `connect` and ignore this.

**What it costs.** That first payload is encrypted, but:

- **replayable** — an attacker who captures the packet can send it again, and
  the peer cannot tell
- **no forward secrecy** — it is protected only by the peer's static key, so a
  later key compromise exposes it

Send only what is safe to repeat. A sensor reading is; "open the valve" is not.
`SPEC.md` §4.4.1 states this normatively.

## Reliable delivery

```rust
conn.send_reliable(b"this must arrive", PayloadType::Opaque)?;
conn.flush(Duration::from_secs(2))?;     // wait for acknowledgement
```

Three things to know:

**Retransmission needs to be driven.** `send_reliable` returns immediately;
progress happens inside `recv` and `flush`. A program that sends reliably and
then does neither will never retransmit.

**Delivery is unordered.** A message that arrives is delivered at once, even if
an earlier one is still in flight. Holding it back would be head-of-line
blocking. If you need order, put a sequence number in your own payload.

**The window is bounded, and it moves.** Two limits apply: `fectp::MAX_UNACKED`
(32) bounds memory and never changes, and a congestion window bounds what the
path has shown it can carry. The second is the tighter one — it opens at
`fectp::INITIAL_CWND` (4) on a new connection, widens as acknowledgements
arrive, and collapses when a message times out.

So `send_reliable` fails with `Error::Protocol(WindowFull)` sooner than the
memory bound suggests, and how soon depends on the path. Handle it:

```rust
while conn.send_reliable(&payload, PayloadType::Opaque).is_err() {
    conn.flush(Duration::from_secs(2))?;   // wait for room
}
```

A sender that must sometimes wait is what congestion control is. Without it,
against a 1 Mbit/s link, 46% of what this protocol sent was dropped by a full
queue before it reached the far side.

```rust
println!("{} still in flight", conn.unacknowledged());
println!("retransmit timeout now {} ms", conn.rto_ms());
```

`flush` fails with `Error::Unacknowledged { count }` if messages were abandoned
after exhausting their retries, or if the timeout expires first.

## Large messages

There is no separate call and no size to check:

```rust
conn.send_reliable(&recording, PayloadType::Opaque)?;   // any size
conn.flush(Duration::from_secs(10))?; // wait for it to arrive
```

A payload larger than one frame is split across several, each acknowledged and
retransmitted on its own, and it arrives as **one** message:

```rust
let n = conn.recv(&mut buf)?;    // the whole thing, reassembled
```

Why there is no size to check: the frame limit depends on what the peer
advertised at handshake, so it differs per connection and a microcontroller
peer will advertise less. Asking the caller to compare against a number they
cannot know in advance was the wrong shape.

Three things to know:

**`send_reliable` does not wait.** A split message will not fit in the
congestion window, so the rest is queued and fed out by `recv`, `flush` and
later sends. `flush` is how you wait for it, and it fails with
`Error::Unacknowledged` if any fragment was abandoned — a message missing one
piece is not partly delivered, it is not delivered.

**`send` is still one frame only.** Splitting a payload that cannot be
retransmitted would fail whenever any one piece went missing: for 200 fragments
at 1% loss, nine times out of ten. It is refused rather than offered.

**There is a ceiling.** `fectp::MAX_MESSAGE_LEN` (1 MiB) and
`fectp::MAX_FRAGMENTS` (4096) bound what a receiver will reassemble, because a
receiver commits memory on the strength of the sender's own fragment count.
Above that, `send_reliable` fails with `Error::PayloadTooLarge`.

Compression is per fragment, so each frame is self-describing. That costs ratio
— the compressor sees one fragment of context rather than the whole message —
so data that compresses well is better compressed by your own code first.

On an `Endpoint` it is the same call. There is nothing to block on there, so a
message that had to be split reports its outcome as `Event::Sent { delivered }`.

## Typed payloads

A generic compressor sees only bytes. Telling it the shape lets a transform run
first — interleaved sensor samples are split by channel and delta-coded, which
a byte-oriented compressor cannot do for itself.

Every send names the shape:

```rust
let shape = PayloadType::I16 { channels: 4 };   // 4 channels of 16-bit ADC
conn.send(&samples, shape)?;
conn.send(&more, shape)?;

conn.send(b"a status line", PayloadType::Opaque)?;   // just bytes
```

| | |
|---|---|
| `Opaque` | Just bytes. Always correct; the compressor is on its own. |
| `I16 { channels }` | Interleaved 16-bit samples. |
| `I32 { channels }` | Interleaved 32-bit samples or counters. |
| `Elements { size }` | Fixed-size elements, byte-transposed. `4` for `f32`, `8` for `f64`. |

What it is worth, measured on 8 KiB:

| | as `Opaque` | declared |
|---|---|---|
| sensor i16 ×4, slow | 1.12x | **3.46x** |
| counter i32 ×2 | 1.67x | **292.57x** |
| f32 array | 1.14x | **8.21x** |
| JSON text | 126.03x | 126.03x |
| random bytes | 1.00x | 1.00x |

Structured binary gains a lot; text and random bytes gain nothing.

**A wrong declaration is safe.** The payload still round-trips — it just
compresses badly, and the peer reverses whatever was applied.

**Why it is named every time and not set once.** A setting would mean this
line's behaviour depended on a call made somewhere else, and forgetting it
would cost compression with no error and no warning. Repeating a shape costs
nothing: `PayloadType` is two bytes and `Copy`, so bind it to a local and pass
it. Changing the channel count then means changing one line.

**Below 32 bytes no transform runs at all**, and a stream that repeatedly fails
to compress stops being asked — so a wrong shape on incompressible data costs a
few microseconds at the start and almost nothing after that.

### Two stages, and the second is optional

The transform is plain integer code in the `no_std` core. Zstandard is a
separate stage behind a feature flag, and needs a C toolchain. A peer with no
room for a decoder still gets the transform:

| | sensor `i16` ×4 | counter `i32` ×2 | `f32` table |
|---|---|---|---|
| transform only, `no_std` | 2.00x | 3.99x | 1.00x |
| transform + Zstandard | **3.46x** | **292.57x** | **8.21x** |

The `f32` row shows what the transform alone is and is not. Byte transposition
changes no sizes — it groups the bytes so that an entropy coder can see the
pattern. Delta coding on the integer rows shrinks the data by itself.

Codecs are a registry, not a fixed set. Supporting a new data type means
writing one transform: [ADDING-A-CODEC.md](ADDING-A-CODEC.md).

### When compression does not run

Attempting it costs a few microseconds whether or not it works, so it is
skipped whenever it would not pay:

| Skipped when | Threshold |
|---|---|
| the payload is tiny | under **32 bytes**, no transform |
| it is small | under **1 KiB**, no Zstandard |
| it already looks compressed | detected, not guessed |
| the peer cannot decompress | settled during the handshake |
| coding has stopped working on this connection | it backs off, then retries periodically |

And if compression runs and fails to shrink the payload, the original is sent.
**A bad guess costs CPU, never bytes.**

## Resumption

A full handshake costs each peer four X25519 operations — on a microcontroller
roughly a hundred milliseconds, paid again after every reset. Resumption costs
one.

```rust
// After any connection, take the ticket and persist the 32-byte key.
let key: [u8; 32] = *conn.resumption_ticket().expect("encrypted").key();
save_to_flash(&key);

// Later, instead of connect():
use fectp::Ticket;
let conn = Connection::resume(
    addr, &Ticket::from_key(load_from_flash()), &server_public,
)?;
```

**Tickets are single use.** Each handshake issues the next one, so store the
new ticket after every connection, resumed ones included. Redeeming a spent
ticket fails — that is what stops a captured resumption request being replayed.

**Always keep the full-handshake path.** A server that restarted, or evicted
the ticket, cannot answer; the resume times out. Fall back:

```rust
let conn = match Connection::resume(addr, &ticket, &server_public) {
    Ok(conn) => conn,
    Err(_) => Connection::connect(addr, &server_public, &identity)?,
};
```

Resumption keeps forward secrecy — fresh ephemerals are still exchanged — but
the ticket is key material. Store it as carefully as the identity secret.

## Peers, not clients and servers

`Endpoint` binds one socket and uses it **both** to accept connections and to
start them. "Initiator" and "responder" are roles a connection has, not
properties a node has; once a handshake finishes the session is symmetric and
neither side is privileged.

```rust
let mut node = Endpoint::bind_psk("0.0.0.0:4433", b"mesh-secret")?;

// Dial another node — from this same socket.
let peer = node.connect("other-node:4433", None)?;

loop {
    match node.poll(Some(Duration::from_millis(100)))? {
        Event::Connected { peer, initiated, .. } => {
            println!("{peer:?} ({})", if initiated { "we dialled" } else { "they dialled" });
        }
        Event::Message { peer, data } =>
            node.send(peer, &data, PayloadType::Opaque)?,
        Event::ConnectFailed { peer } => println!("{peer:?} never answered"),
        _ => {}
    }
}
```

Sharing the socket is not tidiness. A NAT maps a *local port*, so a node that
dials out from one port and listens on another cannot be reached through the
mapping its own traffic created. One socket is what makes hole punching
possible at all.

`connect` does **not** block. It sends the opening frame and hands back a
`PeerId`; the handshake finishes when the reply arrives, surfacing as
`Event::Connected { initiated: true }`. Nothing may be sent to that handle
before then. A peer that never answers becomes `Event::ConnectFailed` after a
few retries — silence is reported, not waited on forever.

In public-key mode `connect` needs the peer's key; in the other two it does not:

```rust
node.connect(addr, Some(&their_public))?;   // public-key mode
node.connect(addr, None)?;                  // pre-shared key: no peer key needed
```

`Connection` remains the simpler blocking client for code that only ever dials
and never listens.

## Serving many peers

`Endpoint` owns the socket and routes each datagram by session identifier. One
thread, no locks, no socket per peer.

```rust
use fectp::{Event, Identity, Endpoint};

let mut server = Endpoint::bind("0.0.0.0:4433", Identity::generate())?;
loop {
    match server.poll(Some(Duration::from_millis(100)))? {
        Event::Connected { peer, zero_rtt, resumed, .. } => {
            println!("{peer:?} connected (resumed: {resumed}), 0-RTT: {zero_rtt:?}");
        }
        Event::Message { peer, data } => {
            server.send(peer, &data, PayloadType::Opaque)?;   // echo
        }
        Event::PeerMoved { peer, from, to } => {
            println!("{peer:?} moved from {from} to {to}");    // same session
        }
        Event::Idle => {}
        _ => {}                                     // `Event` is non-exhaustive
    }
}
```

`poll` also drives retransmission for every peer, so call it regularly even
when idle.

Per-peer operations take the `PeerId`:

```rust
server.send(peer, &samples, PayloadType::I16 { channels: 4 })?;
server.send_reliable(peer, b"command", PayloadType::Opaque)?;

let who = server.peer_public_key(peer);      // Option<&[u8; 32]>
let outstanding = server.unacknowledged(peer);
server.disconnect(peer);
```

`PeerId` handles are never reused, so one belonging to a departed peer stops
resolving rather than addressing whoever took its place.

**Sessions are bound to the peer's address.** A peer that changes address (a
phone moving between networks) loses its session and must reconnect — or
resume, which is cheap.

## When a peer changes address

A NAT whose mapping expires re-creates it on a new port. A phone moving from
Wi-Fi to a cellular network changes address outright. The peer is the same peer
and holds the same keys, and an `Endpoint` follows it — the `PeerId` does not
change, because the session does not change.

```rust
match server.poll(Some(Duration::from_millis(100)))? {
    Event::PeerMoved { peer, from, to } => {
        println!("{peer:?} moved from {from} to {to}");
    }
    _ => {}
}
```

**Nothing needs handling for this to work.** The event is there for logging,
and for an application that keys anything on a peer's address — a rate limit, a
log line, an access rule. If yours does, this is where to update it, and it is
worth asking whether the address was ever the right key: it can change now.

Two things are worth knowing about the timing.

**A move costs a round trip.** A peer heard from at a new address is sent a
challenge and nothing else — not even the acknowledgement its frame provoked —
until it answers. So the frame that reveals a move is never the frame that
completes it, and a reliable message sent across the change will be
retransmitted once. That delay is deliberate: a frame that authenticates proves
who sealed it, never where they are, and a session that moved without asking
could be pointed at a third party who never wanted it.

**A `Connection` does not follow a server that moves.** Its socket is connected
to one address, so a frame from anywhere else never reaches it. The case that
happens in practice is a client changing address, and that is the one an
`Endpoint` handles.

## Staying reachable through a quiet period

A NAT maps an inside address to an outside one when something is sent out, and
forgets the mapping when nothing has been for a while. RFC 4787 asks for at
least two minutes; plenty of equipment does thirty seconds. Once the mapping is
gone, **inbound datagrams have nowhere to go** — and nothing reports this. Both
ends still hold a perfectly good session; one of them has simply become
unreachable.

A peer with traffic of its own never notices, because its own traffic refreshes
the mapping. The case that breaks is a peer that connects and then mostly
listens: a device waiting for commands.

```rust
conn.set_keepalive(Some(Duration::from_secs(15)))?;
```

or, on an endpoint:

```rust
node.set_keepalive(Some(Duration::from_secs(15)));
```

Nothing is sent while the connection is busy — the interval is measured from
the last thing sent, whatever it was, so an active session sends no keep-alives
at all. Nor to a peer nothing has ever been heard from: completing a handshake
takes one datagram and its source address is whatever the sender wrote, so a
session can point somewhere that never asked for it. When it does fire, it is a 38-byte path challenge, which the peer
answers, so one exchange refreshes the mapping in **both** directions.

**It is off by default, and that is deliberate.** A battery-powered sensor that
wakes, reports a reading and sleeps must not be woken every fifteen seconds by
its own transport. Turn it on where a session stays open through quiet periods
and the cost is worth paying, and leave it off otherwise.

**Pick the interval from the equipment, not from taste.** It has to be shorter
than the shortest mapping timeout on the path, which you generally cannot see;
15–25 seconds is the usual guess and is what ICE uses. Shorter costs more
traffic and, on a battery, more wake-ups.

**Only outbound traffic refreshes a mapping**, so this helps the side *behind*
the NAT — the side that dialled. A server that only accepts gains liveness from
it, not reachability.

On a `Connection` it only runs while a call is inside `recv` or `flush`,
because a `Connection` has no thread of its own — a program that leaves one
idle without reading from it sends nothing, and wants an `Endpoint`.

### Giving up on a peer

```rust
node.set_peer_timeout(Some(Duration::from_secs(30)));
```

A peer nothing authenticated has been heard from for that long is released and
reported as `Event::PeerLost { peer }`. The handle stops resolving; the peer
must connect again.

**This is only meaningful with keep-alives on.** Silence is not evidence of
death — a peer that is alive and has nothing to say looks exactly like one that
has gone. With keep-alives the peer is asked at intervals, so silence means it
did not answer. Without them this is a plain idle timeout, and it will drop
peers that are merely quiet. That is occasionally what you want; it should be
what you chose.

Only frames that *authenticate* count as being heard, so a stranger cannot hold
a departed peer's session open by addressing the socket.

Off by default. Memory is bounded without it: `MAX_PEERS` and the eviction
order already drop the longest-silent session when room is needed, so a timeout
buys prompt notice rather than safety.

## Length masking

Frame sizes reveal payload lengths. If the lengths themselves are sensitive:

```rust
conn.set_padding(true);      // pad to a 64-byte boundary
```

Off by default, because a 10-byte message becomes a 64-byte one — a steep price
for the small messages this protocol targets. It is per-frame and per-direction;
the peer follows the flag.

This narrows length leakage; it does not defeat CRIME-style attacks. The
defence against those is that FECTP compresses every message independently.

## Errors

<!-- doc-check: skip -->
```rust
pub enum Error {
    Closed,                      // the connection is over
    Io(std::io::Error),          // socket failure, or a read timeout
    Protocol(fectp_core::Error), // protocol-level failure
    Decompress,                  // a compressed payload could not be decoded
    PayloadTooLarge { len, limit },
    Handshake,                   // the peer never answered, or answered wrongly
    Unacknowledged { count },    // reliable messages were abandoned
    ReliabilityUnsupported,      // the peer does not implement it
    UnknownTicket,               // stale or already-redeemed resumption ticket
    UnknownPeer,                 // no such connected peer (endpoint only)
    MissingPeerKey,              // public-key mode needs the peer's key
}
```

Note what is **not** an error: a forged, replayed, or misdirected frame. Those
are silently discarded and the call keeps waiting. Anyone can send bytes to a
UDP port; surfacing that as an error would hand an off-path attacker a denial
of service.

## On a microcontroller

`fectp-core` is `no_std` and allocation-free. It has no socket, no clock, and
no threads — you supply all three.

```toml
[dependencies]
fectp-core = { path = "crates/fectp-core", default-features = false }
```

Implement `Transport` over whatever link you have, then drive `Initiator` /
`Responder` and `Session` directly. Every operation writes into a buffer you
provide, and the reliability layer takes `now_ms` as a parameter rather than
reading a clock.

Advertise honest capabilities — a device with no Zstandard decoder must not
claim one:

```rust
use fectp_core::Capabilities;
let caps = Capabilities::minimal(256);   // small frames, core transforms only
```

Build check:

```bash
cargo build -p fectp-core --target thumbv7em-none-eabihf --release
```

### What it costs

Measured on a linked image rather than estimated — `crates/footprint` builds
one for `thumbv7em-none-eabihf` with LTO and `--gc-sections`:

| | |
|---|---|
| flash | **23.1 KiB**, handshake, session and codec included |
| RAM, session state | 358 bytes, or 1,406 with reliable delivery |
| RAM, buffers | the caller's — 2,400 bytes for send and receive at the default frame size |

```bash
cd crates/footprint && cargo build --release && python size.py
cargo run -p fectp-core --example sizes
```

The core allocates nothing, so those numbers are the whole answer. On a
Cortex-M4 with 256 KiB of flash that is 9% of it.

## Common mistakes

| | |
|---|---|
| Reliable messages never arrive | Nothing is calling `recv` or `flush` to drive retransmission. |
| `recv` hangs forever | No read timeout set. |
| Resumption always fails | The ticket was already used — store the new one after every connection. |
| `connect` fails with no obvious reason | Wrong peer public key. The peer cannot authenticate the frame so it drops it silently — there is no reply and no error on the wire, only `HANDSHAKE_TIMEOUT` expiring. |
| Compression saves nothing | The payload is small, already compressed, or the peer never advertised `CAP_ZSTD`. Name a `PayloadType` other than `Opaque` if the data is structured. |
| `match` on `Event` will not compile | `Event` is `#[non_exhaustive]`; add a `_` arm. |
| Client and server never connect | They are in different modes. Modes do not interoperate, by design. |
| `send` after `connect` fails | An `Endpoint` dial is not finished until `Event::Connected` arrives; poll first. |
| `send_reliable` fails early on a new connection | The congestion window opens at 4, not at the 32-message memory bound. Call `flush` and retry. |
| A large `send_reliable` never finishes | Nothing is calling `recv` or `flush`, so the queued fragments are never fed out. |
| `resumption_ticket()` is `None` | The connection is already closed. |

## The whole list

[API.md](API.md) has every public method grouped by task, the constants with
their values, and an honest note about the two places the list is untidy. This
document explains *when* to reach for each; that one is the index.

## Further reading

| | |
|---|---|
| [`SPEC.md`](SPEC.md) | The normative wire format. |
| [`DECISIONS.md`](DECISIONS.md) | Why the protocol is shaped this way. |
| [`ADDING-A-CODEC.md`](ADDING-A-CODEC.md) | Supporting a new data shape. |
