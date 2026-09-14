/**
 * The TypeScript binding, exercised as a caller would use it.
 *
 * The second test in this repository that crosses the boundary from outside
 * Rust, and the first from a runtime with a moving garbage collector — which
 * is the difference that matters here. Python's objects stay where they are
 * put; a JavaScript runtime relocates them, so a pointer handed across has to
 * survive a collection that may run between two calls.
 *
 *     cargo build -p fectp-ffi --release
 *     cd bindings/typescript && npm install && npm test
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  BufferTooSmall,
  FectpError,
  Identity,
  Initiator,
  KEY_LEN,
  ProtocolError,
  Responder,
  Session,
} from "./fectp.ts";

/** A full handshake, returning both sessions and what each side received. */
function establish(fromClient = new Uint8Array(), fromServer = new Uint8Array()) {
  const serverId = Identity.generate();
  const clientId = Identity.generate();

  const initiator = new Initiator(clientId, serverId.publicKey, 0x5eed);
  const responder = new Responder(serverId);

  const clientSaid = responder.readInit(initiator.writeInit(fromClient));
  const { session: server, frame: reply } = responder.writeResponse(fromServer);
  const { session: client, payload: serverSaid } = initiator.readResponse(reply);

  return { client, server, clientSaid, serverSaid };
}

const bytes = (s: string) => new TextEncoder().encode(s);
const text = (b: Uint8Array) => new TextDecoder().decode(b);

test("a handshake completes and both sides agree", () => {
  const { client, server, clientSaid, serverSaid } = establish(
    bytes("data with the opening frame"),
    bytes("and with the reply"),
  );
  assert.equal(text(clientSaid), "data with the opening frame");
  assert.equal(text(serverSaid), "and with the reply");

  // Both directions, so this shows the keys match rather than one side
  // decrypting its own traffic.
  assert.equal(text(server.open(client.seal(bytes("up")))), "up");
  assert.equal(text(client.open(server.seal(bytes("down")))), "down");
});

test("an empty payload is allowed on both flights", () => {
  const { clientSaid, serverSaid } = establish();
  assert.equal(clientSaid.length, 0);
  assert.equal(serverSaid.length, 0);
});

test("a tampered frame is refused", () => {
  const { client, server } = establish();
  const frame = client.seal(bytes("genuine"));
  frame[frame.length - 1] ^= 0x01;
  assert.throws(() => server.open(frame), ProtocolError);
});

test("a frame from a stranger is refused", () => {
  // A third party with its own identity cannot produce a frame this session
  // accepts, which is what the handshake is for.
  const { server } = establish();
  const other = establish();
  assert.throws(() => server.open(other.client.seal(bytes("not from the peer"))), ProtocolError);
});

test("there is no way to read a private key", () => {
  // The property the binding is shaped around. Bytes handed to a JavaScript
  // runtime cannot be wiped: a Buffer may be relocated by the collector and
  // the old copy is not cleared. An absence is what a future convenience
  // method would quietly end, so the absence is what is asserted.
  const identity = Identity.generate();
  const names: string[] = [];
  for (let o = identity; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) {
    names.push(...Object.getOwnPropertyNames(o));
  }
  const offenders = names.filter((n) => /secret/i.test(n) && n !== "fromSecret");
  assert.deepEqual(offenders, [], `these look like ways to read the key back out: ${offenders}`);
});

test("a restored identity is the same one, and usable", () => {
  const secret = new Uint8Array(KEY_LEN);
  for (let i = 0; i < KEY_LEN; i++) secret[i] = (i * 7 + 3) & 0xff;

  const first = Identity.fromSecret(secret);
  const second = Identity.fromSecret(secret);
  assert.deepEqual(first.publicKey, second.publicKey);

  // Constructible is not the same as usable.
  const responder = new Responder(first);
  const initiator = new Initiator(Identity.generate(), first.publicKey, 1);
  assert.equal(text(responder.readInit(initiator.writeInit(bytes("x")))), "x");
});

test("a wrong-length key is refused before it reaches C", () => {
  assert.throws(() => Identity.fromSecret(new Uint8Array(8)), RangeError);
  assert.throws(() => new Initiator(Identity.generate(), new Uint8Array(8), 1), RangeError);
});

test("a consumed handle cannot be used again", () => {
  // The double free every hand-written binding eventually has.
  const serverId = Identity.generate();
  const clientId = Identity.generate();
  const initiator = new Initiator(clientId, serverId.publicKey, 2);
  const responder = new Responder(serverId);
  responder.readInit(initiator.writeInit());
  const { frame } = responder.writeResponse();

  assert.throws(() => responder.writeResponse(), FectpError);
  initiator.readResponse(frame);
  assert.throws(() => initiator.readResponse(frame), FectpError);
});

test("a failed handshake still consumes the initiator", () => {
  // Failure consumes it too: the handshake cannot be retried from a half-read
  // state, and a handle that still looks alive invites a second call.
  const serverId = Identity.generate();
  const initiator = new Initiator(Identity.generate(), serverId.publicKey, 3);
  initiator.writeInit();
  assert.throws(() => initiator.readResponse(new Uint8Array(64)), ProtocolError);
  assert.throws(() => initiator.readResponse(new Uint8Array(64)), FectpError);
});

test("closing twice is harmless and using a closed handle throws", () => {
  const identity = Identity.generate();
  identity.close();
  identity.close();
  assert.throws(() => identity.publicKey, FectpError);
});

test("a session survives a garbage collection between calls", () => {
  // The reason this file exists as well as the Python one. A moving collector
  // may relocate objects between two calls, and a handle that held a pointer
  // into anything the runtime owns would break here rather than at the call
  // that created it.
  const { client, server } = establish();
  const sealed = client.seal(bytes("before the collection"));

  // Make the collector work, whether or not --expose-gc was given.
  for (let i = 0; i < 200_000; i++) {
    // eslint-disable-next-line no-new
    new Uint8Array(64);
  }
  if (typeof globalThis.gc === "function") globalThis.gc();

  assert.equal(text(server.open(sealed)), "before the collection");
  assert.equal(text(client.open(server.seal(bytes("after")))), "after");
});

test("many sessions can be open at once", () => {
  // Handles must not share state; a wrapper that kept one global scratch
  // buffer would pass every test above and fail here.
  const pairs = Array.from({ length: 16 }, () => establish());
  pairs.forEach(({ client, server }, i) => {
    const message = bytes(`session ${i}`);
    assert.equal(text(server.open(client.seal(message))), `session ${i}`);
  });
  for (const { client, server } of pairs) {
    client.close();
    server.close();
  }
});
