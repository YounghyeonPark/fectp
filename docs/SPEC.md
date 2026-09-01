# FECTP wire specification, version 1

Normative specification of the Fast Encrypted Compressed Transport Protocol.
This document defines what goes on the wire. It is written so that an
independent implementation, in any language, interoperates with any other
conforming implementation.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as in RFC 2119.

## 1. Scope and conventions

FECTP runs over an unreliable, unordered datagram transport that preserves
datagram boundaries. UDP is the expected substrate.

FECTP provides optional per-message retransmission (§5.5). It does not
provide ordering, congestion control, or path MTU discovery.

- All multi-byte integers are **little-endian**.
- Byte offsets are zero-based and inclusive of the start, exclusive of the end.
- "Frame" means one datagram payload.
- `||` denotes concatenation.

### 1.1 Versioning

The version number appears in every frame header. A receiver MUST reject a
frame whose version it does not implement.

Version 1 defines two handshakes: the full `IK` handshake of §4.4–§4.5 and
the resumption handshake of §4.7–§4.8. Both are fixed per version.

The cipher suite is fixed per version, not negotiated. A future suite — a
post-quantum one, in particular — is a new protocol version, not a negotiated
option within version 1. This removes downgrade negotiation from the protocol
entirely.

### 1.2 Security modes

A session runs in exactly one of three modes. **The mode is fixed when the
session is built and never appears on the wire as something to agree on.**

| mode | pre-shared | encrypted | handshake |
|---|---|---|---|
| Public key | the responder's public key | yes | `IK`, four DH each (§4.4) |
| Pre-shared key | one secret, both sides | yes | `NNpsk0`, one DH each (§4.7) |
| Plaintext | nothing | **no** | capability exchange only (§1.2.2) |

A peer MUST implement exactly one mode per session and MUST NOT offer a choice
between them. A protocol that negotiates its own security level is a protocol
an attacker can talk down to the weakest option; there is deliberately no field
here to rewrite.

The modes are kept apart by their frame types, which are disjoint: an encrypted
peer receiving `PlainInit` sees a type it does not accept, and a plaintext peer
receiving `HandshakeInit` likewise. Neither has to *decide* anything.

#### 1.2.1 Pre-shared-key mode

Identical on the wire to resumption (§4.7, §4.8), because it is the same
handshake — `NNpsk0` with a key both sides already hold. Only the provenance of
the key differs, and one consequence follows from it:

```
psk = BLAKE2s-256("fectp/1 psk" || secret)
```

`secret` may be any length. The `ticket_id` is derived from `psk` exactly as in
§4.6, so a responder finds it the same way.

**A configured pre-shared key MUST NOT be consumed on redemption**, unlike a
resumption ticket, which MUST be. It is long-lived by definition; a responder
that spent it would refuse the peer's next connection.

A pre-shared key is symmetric: every holder can impersonate every other holder.
It is appropriate within one administrative domain and inappropriate across
several, where public-key mode gives each peer a distinct identity.

#### 1.2.2 Plaintext mode

No encryption, no authentication, no identities. Anyone on the path can read,
forge, or alter every byte. It exists for links that are physically trusted and
for development, where a readable packet capture is worth more than
confidentiality.

It is **not** the remedy for awkward key distribution. Encrypting a frame costs
on the order of a microsecond; distribution is what costs anything, and
pre-shared-key mode removes that without giving up encryption.

The exchange:

```
-> PlainInit     : header(14) || capability_block(8) || payload
<- PlainResponse : header(14) || capability_block(8) || payload
```

There are no keys to agree; the exchange exists so that capabilities (§4.3) are
still negotiated and everything above the session layer — codecs, reliability,
sequencing — behaves exactly as it does when encrypted.

Data frames:

```
PlainData : header(14) || [message_id(4)]? || payload
PlainAck  : header(14) || acknowledgement_block(12)
```

Per-frame overhead is 14 bytes rather than 30: there is no authentication tag,
because there is nothing to authenticate. `FLAG_RELIABLE` applies as in §5.4.
`FLAG_PADDED` MUST NOT be set — padding hides a length from someone who can see
the ciphertext but not the plaintext, and here there is no ciphertext.

A receiver MAY apply the replay window of §5.1 so that reordering and duplicate
behaviour matches the encrypted path. It is not a security mechanism in this
mode: nothing is authenticated, so an attacker can forge any sequence number.

## 2. Cryptographic suite

Version 1 uses the Noise Protocol Framework with two patterns over one set
of primitives:

```
Noise_IK_25519_ChaChaPoly_BLAKE2s        (full handshake)
Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s   (resumption)
```

- **DH**: X25519. `DHLEN` = 32.
- **AEAD**: ChaCha20-Poly1305 (RFC 8439). `TAGLEN` = 16, `KEYLEN` = 32.
- **Hash**: BLAKE2s-256. `HASHLEN` = 32, block length 64.

BLAKE2s rather than BLAKE2b is required, not preferred: BLAKE2b's 64-bit words
cost a large constant factor on 32-bit microcontrollers, and both peers must
agree on the hash for their transcripts to match.

### 2.1 Protocol name

The protocol name is the 33 ASCII bytes:

```
4E 6F 69 73 65 5F 49 4B 5F 32 35 35 31 39 5F 43 68 61 43 68 61 50 6F 6C 79 5F 42 4C 41 4B 45 32 73
"Noise_IK_25519_ChaChaPoly_BLAKE2s"
```

It is 33 bytes, which exceeds `HASHLEN`, so per the Noise specification the
initial transcript hash is `h = BLAKE2s-256(protocol_name)`. Implementations
MUST NOT zero-pad it.

The resumption name is the 37 ASCII bytes of
`"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"`, likewise hashed.

### 2.2 HKDF

`HKDF(chaining_key, ikm, 2)` is as defined by the Noise specification, using
HMAC-BLAKE2s (RFC 2104, block length 64):

```
temp_key = HMAC(chaining_key, ikm)
output1  = HMAC(temp_key, 0x01)
output2  = HMAC(temp_key, output1 || 0x02)
```

The HMAC construction is required. BLAKE2's native keyed mode MUST NOT be
substituted.

### 2.3 Nonce construction

The 96-bit AEAD nonce is four zero bytes followed by the 64-bit counter in
little-endian order:

```
nonce = 00 00 00 00 || counter[8, little-endian]
```

A counter value of 2^64 − 1 is reserved and MUST NOT be used. A sender that
reaches it MUST terminate the session rather than reuse a nonce.

## 3. Frame header

Every frame begins with a fixed 14-byte header.

| offset | size | field |
|---|---|---|
| 0 | 1 | `version` (high 4 bits) \| `type` (low 4 bits) |
| 1 | 1 | `flags` |
| 2 | 4 | `session_id`, u32 |
| 6 | 8 | `sequence`, u64 |

The header is fixed-size and contains no length fields. Parsing an
attacker-supplied frame therefore involves no length arithmetic before
authentication. Implementations SHOULD preserve this property.

### 3.1 Version and type

`version` MUST be `1` for this specification. A receiver MUST reject any other
value.

| `type` | meaning |
|---|---|
| 1 | `HandshakeInit` — Noise message 1 |
| 2 | `HandshakeResponse` — Noise message 2 |
| 3 | `Data` — post-handshake application data |
| 4 | `Close` — orderly shutdown |
| 5 | `Ack` — acknowledges received reliable messages (§5.7) |
| 6 | `ResumeInit` — resumption message 1 (§4.7) |
| 7 | `ResumeResponse` — resumption message 2 (§4.8) |
| 10 | `PlainInit` — plaintext session opening (§1.2) |
| 11 | `PlainResponse` — plaintext session response (§1.2) |
| 12 | `PlainData` — plaintext application data (§1.2) |
| 13 | `PlainAck` — plaintext acknowledgement (§1.2) |

All other values are reserved. A receiver MUST reject them.

### 3.2 Flags

| bit | name | meaning |
|---|---|---|
| 0x01 | `COMPRESSED` | The plaintext begins with a codec header (§6). |
| 0x02 | `RELIABLE` | The plaintext carries a message identifier (§5.4). |
| 0x04 | `PADDED` | The plaintext is length-prefixed and padded (§5.3). |
| 0x08 | `FRAGMENT` | The plaintext carries a fragment descriptor (§5.5). |
| 0x10–0x80 | — | Reserved. |

A receiver MUST reject a frame with any reserved flag bit set. Flags describe
what the sender already did to this frame, so a receiver that ignored an
unrecognised one would decode the payload incorrectly.

### 3.3 Session identifier

`session_id` demultiplexes concurrent sessions arriving on one socket. The
initiator chooses it, SHOULD choose it at random, and both peers use the same
value in both directions for the life of the session.

A receiver MUST reject a `Data`, `Close`, or `Ack` frame whose `session_id`
does not match the session's.

A server serving many peers on one socket SHOULD key its session table on
the **pair** `(source address, session_id)`. The identifier alone is chosen
by the initiator and two initiators may pick the same value; the pair cannot
collide. A consequence is that a peer changing address loses its session —
address migration is not supported in version 1.

`session_id` is not a security mechanism; it is a routing hint. Authentication
comes from the AEAD, so a misrouted frame fails to decrypt rather than
reaching the wrong session.

### 3.4 Sequence

For `Data`, `Close`, and `Ack` frames, `sequence` is the AEAD nonce counter
(§2.3) and MUST start at 0 and increase by one per frame sent, independently
in each direction.

A retransmission is a new frame and MUST therefore carry a new `sequence`.
Reusing the original would reuse the nonce. This is exactly why reliable
messages need their own identifier (§5.4): the receiver cannot recognise a
retransmission from the header.

For handshake frames `sequence` MUST be 0 on send. A receiver MUST ignore its
value on handshake frames.

The counter is explicit rather than implicit because datagrams are lost and
reordered; an implicit counter would desynchronise.

## 4. Handshake

The IK pattern:

```
IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

The initiator MUST know the responder's static public key before connecting.
Obtaining it is out of scope; FECTP has no certificate authority and performs
no key discovery.

### 4.1 Prologue

Both peers MUST use, as the Noise prologue, the **exact 14 header bytes of the
`HandshakeInit` frame** as they appear on the wire.

The initiator uses the header it is about to send. The responder uses the
header it received. This binds the version, frame type, and session id into
both transcripts: an attacker who rewrites those bytes causes the handshake to
fail authentication rather than succeed under altered parameters.

### 4.2 Handshake payload

The payload of both handshake messages MUST be:

```
capability_block (8 bytes)  ||  application_data (0 or more bytes)
```

A receiver MUST reject a handshake message whose decrypted payload is shorter
than 8 bytes.

### 4.3 Capability block

| offset | size | field |
|---|---|---|
| 0 | 1 | `cap_flags` |
| 1 | 1 | reserved |
| 2 | 2 | `max_frame_size`, u16 |
| 4 | 2 | `codecs`, u16 |
| 6 | 2 | reserved |

| `cap_flags` bit | meaning |
|---|---|
| 0x01 | `ZSTD` — this peer can decompress Zstandard. |
| 0x02 | `RELIABLE` — this peer implements the reliability layer. |

`max_frame_size` is the largest frame, header included, that this peer is
willing to receive. A sender MUST NOT emit a frame larger than the peer's
advertised value. On constrained devices this is set by available memory, not
by the path MTU.

`codecs` is a bitmap of decodable codecs (§6.2, §6.3).

Senders MUST set reserved fields to zero. Receivers MUST ignore them, so that a
later version may define them without breaking version-1 peers.

This differs deliberately from the header flags of §3.2, which MUST be
rejected when unrecognised. The distinction is that header flags describe
processing already applied to the frame in hand, where a misunderstanding
corrupts data, whereas capability fields advertise what a peer *can* do, where
ignoring an unknown field is safe.

The capability block travels inside the **encrypted** handshake payload. It
MUST NOT be moved into the header. Encrypted, an attacker who tampers with it
can only cause a decryption failure, never force a weaker configuration.

### 4.4 Message 1 — `HandshakeInit`

```
frame = header(14) || e(32) || EncryptAndHash(s)(48) || EncryptAndHash(payload)(N+16)
```

| offset (within the Noise message) | size | content |
|---|---|---|
| 0 | 32 | initiator ephemeral public key, cleartext |
| 32 | 48 | initiator static public key, encrypted (32 + 16 tag) |
| 80 | N+16 | payload, encrypted |

Noise token processing, in order:

1. `e` — generate ephemeral keypair; write public key; `MixHash(e.public)`
2. `es` — `MixKey(DH(e, rs))`
3. `s` — `EncryptAndHash(s.public)`
4. `ss` — `MixKey(DH(s, rs))`
5. payload — `EncryptAndHash(payload)`

Total frame size is `118 + len(application_data)`: 14 header + 96 Noise
overhead + 8 mandatory capability block. A receiver MUST reject a frame shorter
than 118 bytes. (Noise parsing itself fails below 110; the further 8 bytes are
the capability block of §4.3, which is mandatory.)

The responder learns and authenticates the initiator's static public key from
step 3; no separate client authentication step exists.

#### 4.4.1 0-RTT data

`application_data` in message 1 reaches the responder in one flight, before the
handshake completes. This is the protocol's main latency advantage over
TLS 1.3, which requires a prior session for 0-RTT.

It carries weaker guarantees than post-handshake data and implementations MUST
document this:

- **No forward secrecy.** It is protected only by the responder's static key.
  Compromise of that key later exposes it.
- **Replayable.** There is no replay protection on message 1. An attacker who
  captures the frame can resend it.

Applications MUST NOT put non-idempotent requests in 0-RTT data. A responder
that cannot tolerate replay MUST ignore 0-RTT data.

### 4.5 Message 2 — `HandshakeResponse`

```
frame = header(14) || e(32) || EncryptAndHash(payload)(N+16)
```

Token processing, in order:

1. `e` — generate ephemeral keypair; write public key; `MixHash(e.public)`
2. `ee` — `MixKey(DH(e, re))`
3. `se` — responder computes `MixKey(DH(e, rs))`; initiator computes
   `MixKey(DH(s, re))`
4. payload — `EncryptAndHash(payload)`

Total frame size is `70 + len(application_data)`: 14 header + 48 Noise
overhead + 8 mandatory capability block. A receiver MUST reject a frame shorter
than 70 bytes. (Noise parsing itself fails below 62.)

The `HandshakeResponse` header MUST carry the same `session_id` as message 1.
A receiver MUST reject one that does not.

### 4.6 Split

After message 2, both peers call `Split()`:

```
(k1, k2) = HKDF(chaining_key, empty, 2)
```

- The **initiator** sends with `k1` and receives with `k2`.
- The **responder** sends with `k2` and receives with `k1`.

Both directions start their nonce counters at 0.

### 4.6 Resumption keys and tickets

At the end of **any** completed handshake — full or resumed — both peers derive
the same resumption key from the final chaining key:

```
resumption_key = HKDF(chaining_key, "fectp/1 resumption", 2).output1
```

The label domain-separates this from `Split`, which feeds HKDF an empty input,
so the resumption key and the transport keys are independent: recovering one
reveals nothing about the other.

The **ticket identifier** is derived from the key, not assigned:

```
ticket_id = BLAKE2s-256("fectp/1 ticket-id" || resumption_key)[0..8]
```

Deriving rather than assigning means the two cannot drift apart and no separate
index is needed. The identifier travels in the clear, because a responder must
know which key to try before it can decrypt anything; it is a one-way function
of the key, so it discloses nothing, and §4.7 binds it into the transcript.

**Tickets are single use.** A responder MUST remove a ticket when it is
redeemed, and MUST refuse a second redemption. Allowing reuse would let an
attacker replay a captured resumption request.

A responder MAY forget tickets at any time — it MUST bound how many it holds,
or a peer could grow its memory without limit. A resumption naming an unknown
ticket cannot be authenticated, so the responder MUST simply discard the frame.
The initiator will time out and SHOULD fall back to a full handshake.

### 4.7 Resumption message 1 — `ResumeInit`

```
frame = header(14) || ticket_id(8) || e(32) || EncryptAndHash(payload)(N+16)
```

The pattern is `NNpsk0`, with `resumption_key` as the pre-shared key:

```
NNpsk0:
  -> psk, e
  <- e, ee
```

The prologue MUST be the **22 bytes of the header and ticket identifier** as
they appear on the wire, so both are bound into the transcript.

Token processing, in order:

1. `psk` — `MixKeyAndHash(resumption_key)`
2. `e` — generate ephemeral; write public key; `MixHash(e.public)`; then
   **`MixKey(e.public)`**
3. payload — `EncryptAndHash(payload)`

Step 2's `MixKey` is required by the Noise specification for any pattern using
a pre-shared key, and is easy to omit. An implementation that omits it produces
a key schedule no conforming peer agrees with, while appearing self-consistent.

Total frame size is `78 + len(application_data)`: 14 header + 8 identifier + 48
Noise overhead + 8 capability block. A receiver MUST reject a shorter frame.

Payload layout and the capability block are as in §4.2 and §4.3.

0-RTT data carries the caveats of §4.4.1, for the same reasons.

### 4.8 Resumption message 2 — `ResumeResponse`

```
frame = header(14) || e(32) || EncryptAndHash(payload)(N+16)
```

Token processing:

1. `e` — generate ephemeral; write public key; `MixHash(e.public)`;
   `MixKey(e.public)`
2. `ee` — `MixKey(DH(e, re))`
3. payload — `EncryptAndHash(payload)`

Total frame size is `70 + len(application_data)`. The header MUST carry the
same `session_id` as message 1.

`Split()` is as in §4.6 of the full handshake: the initiator sends with `k1`.

### 4.9 Why resumption is worth a second handshake

The full `IK` handshake performs four Diffie-Hellman operations per peer.
On a 32-bit microcontroller that is on the order of a hundred milliseconds, and
it is paid again after every reset — the single largest latency cost the
protocol has on constrained hardware.

`NNpsk0` performs **one**. Authentication comes from the ticket, which a
previous authenticated handshake established, so identities remain bound
transitively.

Forward secrecy is retained: both peers contribute fresh ephemerals and `ee`
mixes them, so an attacker who later obtains a stored resumption key still
cannot decrypt a recorded session without an ephemeral private key.

What resumption does **not** provide is protection against a compromised
ticket being used to impersonate, before it is redeemed. A ticket is key
material and MUST be stored as such.

## 5. Data frames

```
frame = header(14) || AEAD_encrypt(key, nonce, aad, plaintext) || tag(16)
```

- `aad` is the **complete 14-byte header**, exactly as transmitted.
- `nonce` is derived from `header.sequence` per §2.3.

Because the whole header is authenticated data, modifying any header byte
causes authentication to fail. Implementations MUST NOT reduce the AAD to a
subset of the header.

### 5.1 Replay protection

A receiver MUST maintain a replay window of at least 64 sequence numbers below
the highest accepted value, and MUST reject:

- a sequence number already accepted, and
- a sequence number more than the window size below the highest accepted.

A receiver MUST NOT update the window until the frame has authenticated.
Checking the window before decryption is permitted as a cheap filter, but
updating it before authentication would let a forged frame advance the window
and lock out legitimate traffic.

Out-of-order frames within the window MUST be accepted; the transport reorders
by nature.

### 5.2 Handling of rejected frames

A receiver MUST silently discard, and continue receiving, any frame that fails
to parse, fails authentication, replays, or belongs to another session.

Such frames MUST NOT be surfaced to the application as errors. Anyone can send
arbitrary bytes to an open port; treating a forged frame as a session error
would hand an off-path attacker a denial of service.

### 5.3 Padding

When `PADDED` is set, the plaintext (before encryption, and before the codec
header if any) is:

```
length(2, u16) || payload || zero_padding
```

padded with zero bytes to a multiple of **64** bytes. `length` is the byte
length of `payload` alone.

A receiver MUST reject a padded frame whose plaintext is shorter than 2 bytes,
or whose `length` field exceeds the available plaintext. A receiver SHOULD NOT
verify that the padding bytes are zero.

Padding is per-frame and per-direction. A sender MAY enable or disable it at
any time; the receiver follows the flag.

Padding narrows length leakage from one byte to 64 bytes. It does **not**
defeat CRIME- or BREACH-style attacks, which rely on the attacker influencing
plaintext compressed alongside a secret and observing the change in compressed
size. The defence against those is §6.5.

### 5.4 Plaintext layout

The decrypted plaintext of a `Data`, `Close`, or `Ack` frame is:

```
[ pad_len : u16 ]?          present when PADDED
[ message_id : u32 ]?       present when RELIABLE
[ fragment : 8 bytes ]?     present when FRAGMENT
[ codec_header : 4 bytes ]? present when COMPRESSED
body
[ zero padding ]?           present when PADDED
```

Every part is present only when its header flag is set, and they appear in
exactly this order. A receiver MUST peel them in the same order.

`pad_len` counts the bytes between itself and the padding — the message
identifier, fragment descriptor and codec header included, since padding is
outermost and hides the total.

An implementation that sets no flags therefore transmits the application
payload with no per-frame overhead beyond the header and tag.

### 5.5 Reliable messages

When `RELIABLE` is set, the plaintext carries a `message_id`: a `u32` assigned
by the sender, starting at 0 and increasing by one per reliable message, per
direction.

**Identifiers wrap**, and every comparison between two of them is modulo 2^32:
the one a shorter distance ahead is the later one. A session therefore does not
end at the 2^32nd reliable message. An implementation that compares them as
plain integers agrees with this everywhere except at the wrap, where it decides
that every new identifier is four billion old — and refuses all of them, for the
rest of the session. Version 1 of this document did not say so, and the
implementation that wrote it had the bug.

Reliability is **per message and optional**. A sender MAY mix reliable and
unreliable frames freely on one session.

A sender MUST NOT send reliably to a peer that did not advertise `CAP_RELIABLE`
(§4.3); such a peer will never acknowledge, so every message would be
retransmitted until abandoned.

**Delivery is unordered.** A receiver MUST deliver each message as it arrives
and MUST NOT hold one back waiting for a lower identifier. Ordering would mean
head-of-line blocking, which this protocol exists to avoid. An application
needing order must sequence its own payloads.

A receiver MUST:

1. Acknowledge every reliable message it authenticates, **including duplicates**
   — a duplicate arrives precisely because the sender has not heard back.
2. Deduplicate on `message_id`, over a window of at least 64 identifiers below
   the highest seen, and deliver each message to the application exactly once.
3. Treat an identifier older than that window as already delivered. Handing the
   application a duplicate is the worse failure.

A sender MUST:

4. Not issue a `message_id` more than `ACK_WINDOW` ahead of its oldest
   unacknowledged one.

Rule 4 is what makes rules 2 and 3 safe, and it is easy to get wrong. An
acknowledgement can only name identifiers within `ACK_WINDOW` of the highest
seen (§5.7), and by rule 3 a receiver discards anything older. A sender that
runs further ahead than the window has therefore put its own outstanding
message beyond rescue: no acknowledgement can mention it, and its
retransmissions are discarded as stale rather than delivered. It is lost
however many retries remain.

Bounding how many messages are unacknowledged *at once* does not achieve this,
which is the trap. One stuck message occupies one slot while the others keep
cycling, so a sender with a 32-message limit will still run hundreds of
identifiers past it. The bound has to be on the distance between identifiers,
not on how many are outstanding.

A sender SHOULD:

5. Retransmit an unacknowledged message after a timeout, with exponential
   backoff, and abandon it after a bounded number of attempts.
6. Derive that timeout from measured round trips (RFC 6298 is suitable) and
   ignore samples from retransmitted messages, whose acknowledgement is
   ambiguous (Karn's algorithm).
7. Bound how many messages may be unacknowledged at once. This caps memory.
8. Bound it again by what the path has shown it can carry, opening small and
   widening only as acknowledgements arrive. The memory bound is a property of
   the sender's host and says nothing about the path; treating it as flow
   control means offering a full window to a link that may not take it, and
   whatever the bottleneck cannot buffer is dropped. Measured, that was 46% of
   everything sent on a 1 Mbit/s link.

Points 5 to 8 are sender-side quality of implementation: they are not
observable by a conforming receiver, and this specification does not fix an
algorithm for point 8. Point 4 is not — a receiver conforming to
rules 2 and 3 will silently fail to deliver what a sender violating it sends.

### 5.6 Fragmented messages

A message larger than the frame limit MAY be split across several frames. The
descriptor present when `FRAGMENT` is set is:

| offset | size | field |
|---|---|---|
| 0 | 4 | `message`, u32 |
| 4 | 2 | `index`, u16 |
| 6 | 2 | `count`, u16 |

All fields are little-endian. `message` identifies the logical message; it is
unrelated to `message_id`, which identifies this individual frame to the
reliability layer. `index` is the fragment's position, counting from zero, and
`count` is how many fragments the message was cut into.

A sender:

1. MUST set `RELIABLE` on every fragment. A message missing one fragment is
   entirely undeliverable, so fragments that could be lost without recovery
   would make fragmentation useless.
2. MUST use the same `message` and `count` on every fragment of one message,
   and MUST NOT reuse a `message` value while any fragment of the previous
   message bearing it may still be in flight.
3. MUST make every fragment except the last the same length, so that a receiver
   can place a fragment from its index alone.
4. MUST NOT emit a `count` of zero, or greater than 4096.

A receiver:

1. MUST reject a descriptor whose `count` is zero, whose `count` exceeds 4096,
   or whose `index` is not less than `count`.
2. MUST bound both the number of messages it is reassembling at once and the
   total bytes it holds for them, and MUST NOT let a peer's `count` decide an
   allocation without applying that bound. A conforming implementation refuses
   to reassemble a message above an implementation-defined ceiling; this
   specification requires the ceiling to exist, not its value.
3. MUST discard a fragment whose `count` disagrees with one already recorded
   for that `message`.
4. MUST deliver the reassembled message only once every fragment has arrived,
   and MUST deliver it as a single message.
5. MAY discard a partial reassembly at any time — for instance on a timeout or
   under memory pressure. Doing so loses the message, which the reliability
   layer will not repair, since each fragment was acknowledged on arrival.

Point 5 is the cost of this design and is stated rather than hidden: fragments
are acknowledged individually, so a sender learns that every piece arrived, not
that the receiver still holds them all.

### 5.7 Acknowledgements

An `Ack` frame's body is a 12-byte block:

| offset | size | field |
|---|---|---|
| 0 | 4 | `highest`, u32 — highest `message_id` received |
| 4 | 8 | `bitmap`, u64 |

Bit `i` of `bitmap` set means `highest - 1 - i` was also received, with the
subtraction wrapping as §5.5 requires. An acknowledgement therefore reports
`highest` plus the 64 identifiers below it.

The report is **selective, not cumulative**: one gap does not withhold
acknowledgement of everything behind it, so only genuinely missing messages are
resent.

A sender MUST treat an identifier more than 64 below `highest` as
unacknowledged rather than as delivered, since the block cannot report it.

`Ack` frames MUST NOT be acknowledged, and MUST NOT set `RELIABLE`. Each one
restates the whole receive window, so a lost acknowledgement is repaired by the
next one.

A receiver SHOULD acknowledge promptly. Delaying acknowledgements to batch them
saves bandwidth at the cost of retransmission latency; version 1 does not
specify a delay algorithm.

## 6. Payload coding

When `COMPRESSED` is set, a 4-byte codec header precedes the body at the
position given in §5.4. When it is clear, there is no codec header and coding
costs nothing.

### 6.1 Codec header

| offset | size | field |
|---|---|---|
| 0 | 1 | `transform` (low 4 bits) \| `entropy` (high 4 bits) |
| 1 | 1 | `param` |
| 2 | 2 | `original_len`, u16 |

`original_len` is the length of the application payload before any coding. A
payload longer than 65535 bytes MUST NOT be coded; send it uncoded.

Encoding order is transform first, then entropy stage. Decoding reverses that.

A receiver MUST reject an unknown `transform` or `entropy` id, and MUST verify
that reversing the coding yields exactly `original_len` bytes.

### 6.2 Transforms

| id | name | `codecs` bit | `param` |
|---|---|---|---|
| 0 | none | — | 0 |
| 1 | i16 delta | 0x02 | channel count |
| 2 | i32 delta | 0x04 | channel count |
| 3 | byte transpose | 0x08 | element size |

**Transforms MUST be lossless.** Every transform reproduces its input byte for
byte. Lossy coding is outside this protocol.

#### 6.2.1 Delta transforms (ids 1, 2)

Let `W` be 2 for id 1 and 4 for id 2, and `C` = `param`.

`C` MUST be at least 1, and the input length MUST be a multiple of `C * W`. A
transform MUST refuse other inputs rather than guess at the layout. Let
`S = len / (C * W)`.

Encoding, for each channel `c` from 0 to `C-1`, in order:

```
prev = 0
for s in 0 .. S:
    v    = signed little-endian W-byte value at offset (s*C + c) * W,
           sign-extended to 32 bits
    d    = v - prev            (wrapping, 32-bit)
    prev = v
    emit LEB128(zigzag(d))
```

where `zigzag(v) = (v << 1) XOR (v >> 31)`, with `>>` an arithmetic shift,
result interpreted as unsigned.

Decoding reverses this, wrapping identically. A decoder MUST reject input with
bytes remaining after `C * S` values have been read.

Wrapping arithmetic is required, not incidental: it makes the transform total,
so that inputs such as alternating `i16::MIN`/`i16::MAX` round-trip exactly.

#### 6.2.2 LEB128

Unsigned base-128, least significant group first; the high bit of each byte is
a continuation flag. A `u32` occupies at most 5 bytes.

An encoder MUST emit the shortest encoding of a value.

A decoder MUST reject an encoding longer than 5 bytes, any final byte whose
bits would overflow a `u32`, and any encoding that is not the shortest for the
value it carries — that is, a final byte of `0x00` preceded by at least one
continuation byte. Without that last rule `[0x80, 0x00]` and `[0x00]` both mean
zero, so a value has two spellings and two implementations can agree on the
value while disagreeing about the bytes.

#### 6.2.3 Byte transpose (id 3)

`param` is the element size `E`, which MUST be at least 1. Let
`n = len / E` and `body = n * E`.

```
w = 0
for b in 0 .. E:
    for e in 0 .. n:
        out[w] = in[e*E + b]
        w += 1
out[body .. len] = in[body .. len]        # trailing partial element, verbatim
```

Output length always equals input length. This transform changes no sizes; it
groups equivalent byte positions so that a following entropy stage has runs to
find. It is therefore useless without an entropy stage, and a sender SHOULD NOT
select it when the peer has not advertised one.

### 6.3 Entropy stages

| id | name | `codecs` bit |
|---|---|---|
| 0 | none | — |
| 1 | Zstandard | 0x01 |

Zstandard payloads MUST be complete, standard Zstandard frames. The compression
level is a sender-side choice: a receiver MUST accept any valid frame. The
reference implementation uses level 1; it previously used −4 (`--fast=4`),
which measured worse end to end on every payload shape tested.

### 6.4 Sender obligations

A sender:

- MUST NOT use a transform or entropy stage whose `codecs` bit the peer has not
  advertised. The receiver would have no way to reverse it.
- MUST NOT emit a coded payload that is not smaller than the uncoded one; the
  4-byte codec header counts toward this comparison.
- SHOULD skip coding entirely for payloads already in an entropy-coded
  container format. Recognising JPEG, PNG, GIF, ZIP, gzip, Zstandard, LZ4,
  bzip2, xz, Ogg, FLAC, ID3, ISO base media (`ftyp` at offset 4), and RIFF/WEBP
  by magic number is sufficient in practice.
- SHOULD skip generic compression for payloads below about 1 KiB, where the
  saving does not repay the overhead.

None of these are observable by the receiver; they are quality-of-implementation
rules that a conforming receiver need not verify.

### 6.5 Compression and confidentiality

Every payload MUST be coded independently. Implementations MUST NOT share a
compression context, dictionary, or prediction state between messages.

This is a security requirement, not a simplification. A shared context makes
the compressed size of one message depend on the content of another, which is
precisely the condition CRIME and BREACH exploit: an attacker who influences
part of a payload learns about a secret compressed alongside it. Independent
coding is the actual defence; the padding of §5.3 only coarsens the signal.

It is also what keeps the protocol usable over a lossy datagram transport,
where cross-message state would mean one dropped datagram corrupts every
message after it.

## 7. Security requirements

A conforming implementation MUST:

1. Reject unknown protocol versions, frame types, and reserved header flag
   bits.
2. Use the complete frame header as AEAD associated data on data frames.
3. Never reuse a nonce. Terminate the session on counter exhaustion.
4. Never advance the replay window before a frame authenticates.
5. Silently discard frames that fail any check (§5.2).
6. Compare authentication tags in constant time. The AEAD implementation is
   normally responsible for this.
7. Code each payload independently (§6.5).
8. Treat 0-RTT data as replayable and lacking forward secrecy (§4.4.1).
9. Give every retransmission a fresh `sequence`, never reusing a nonce
   (§3.4).
10. Deduplicate reliable messages on `message_id` so that a retransmission
    never reaches the application twice (§5.5).
11. Redeem each resumption ticket at most once, and bound how many are
    held (§4.6). A *configured* pre-shared key is exempt: it is long-lived
    and MUST NOT be consumed (§1.2.1).
12. Run exactly one security mode per session, and never offer a choice
    between them on the wire (§1.2).
13. Apply `MixKey` as well as `MixHash` to ephemeral public keys in the
    resumption pattern (§4.7).

A conforming implementation SHOULD:

14. Use a constant-time X25519 implementation.
15. Zeroise key material when it goes out of scope — resumption keys and
    configured pre-shared keys included.
16. Avoid variable-length parsing of unauthenticated input.

## 8. Constants

| name | value |
|---|---|
| `VERSION` | 1 |
| `HEADER_LEN` | 14 |
| `DHLEN`, `KEYLEN`, `HASHLEN` | 32 |
| `TAGLEN` | 16 |
| BLAKE2s block length | 64 |
| `CAPS_LEN` | 8 |
| `CODEC_HEADER_LEN` | 4 |
| `PAD_BLOCK` | 64 |
| `REPLAY_WINDOW` | 64 (minimum) |
| Message 1 Noise overhead | 96 |
| Message 2 Noise overhead | 48 |
| Minimum valid `HandshakeInit` frame | 118 |
| Minimum valid `HandshakeResponse` frame | 70 |
| Maximum coded payload | 65535 |
| `ACK_BLOCK_LEN` | 12 |
| `MESSAGE_ID_LEN` | 4 |
| Acknowledgement / dedup window | 64 (minimum) |
| `TICKET_ID_LEN` | 8 |
| Resumption key length | 32 |
| Resumption Noise overhead (each message) | 48 |
| Minimum valid `ResumeInit` frame | 78 |
| Minimum valid `ResumeResponse` frame | 70 |
| Plaintext data-frame overhead | 14 |
| Minimum valid `PlainInit` / `PlainResponse` frame | 22 |

## 9. Interoperability

The handshake is standard Noise. An implementation in another language SHOULD
use an existing Noise library — `noise-c`, `noiseprotocol` (Python),
`flynn/noise` (Go), `snow` (Rust), and others implement
`Noise_IK_25519_ChaChaPoly_BLAKE2s` — and implement only §3 through §6 itself.
That is three fixed-size binary layouts and the transforms.

The reference implementation validates its handshake against `snow` in both
roles; see `crates/fectp-core/tests/interop.rs`. A new implementation SHOULD do
the same before testing against FECTP itself, so that a handshake bug is not
mistaken for a framing bug.

### 9.1 Conformance checklist

An implementation is conforming if it:

- completes a handshake in both roles against the reference implementation,
- exchanges data frames in both directions,
- rejects every single-bit mutation of a data frame header,
- rejects a replayed data frame,
- accepts data frames delivered out of order within the replay window,
- round-trips every transform it advertises, byte for byte, including
  alternating extreme values,
- resumes from a ticket, and refuses that ticket a second time,
- refuses to complete a handshake with a peer in a different mode (§1.2),
- falls back to uncoded payloads towards a peer advertising `codecs = 0`,
- acknowledges reliable messages, duplicates included, and delivers each to
  the application exactly once,
- delivers a reliable message that arrives after a later one, rather than
  holding it back.

The reference test suite covers each of these; see `crates/fectp-core/tests/`
and `crates/fectp/tests/`.

## 10. Not specified in version 1

These are absent by omission and remain to be defined:

- **Ordering.** Deliberately absent, not merely unspecified; see §5.5.
- **Congestion control.** A sender may saturate a path. The in-flight bound
  of §5.5 limits the damage but is not a congestion controller.
- **Address migration.** A session is bound to its peer's address (§3.3); a
  peer that moves must handshake again, or resume.
- **Delayed acknowledgement.** Acknowledgements are sent per message; no
  batching algorithm is defined.
- **Ticket expiry.** Tickets are bounded in number but carry no lifetime;
  a responder decides for itself when to forget one.
- **Rekeying.** A session ends at counter exhaustion rather than rekeying.
- **Path MTU discovery.** Frame size comes from `max_frame_size` alone.
- **Key distribution.** Obtaining the responder's static public key is out of
  scope. So is distributing the first ticket, which falls out of the full
  handshake.
- **Close semantics.** The `Close` frame type is assigned; its payload and
  state machine are not defined.

## Licence

BSD 3-Clause. This specification may be implemented freely, without royalty or
patent licence.
