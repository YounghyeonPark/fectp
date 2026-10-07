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

import { createPrivateKey, createPublicKey, diffieHellman, type KeyObject } from "node:crypto";

import {
  _heldKeyCount,
  BufferTooSmall,
  FectpError,
  Identity,
  Initiator,
  KEY_LEN,
  KeyUnavailable,
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

// ------------------------------------------------------- a key held elsewhere

/**
 * A device: Node's own X25519 standing in for a secure element. It does the
 * Diffie-Hellman, counts its calls, and can be locked. An implementation that
 * shares no code with FECTP's, so the first test checks they agree.
 */
class SoftElement {
  readonly publicKey: Uint8Array;
  calls = 0;
  locked = false;
  readonly #key: KeyObject;

  constructor(fill: number) {
    const raw = Buffer.alloc(KEY_LEN, fill);
    // PKCS#8 and SPKI headers for X25519: how Node takes a raw key.
    this.#key = createPrivateKey({
      key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), raw]),
      format: "der",
      type: "pkcs8",
    });
    const spki = createPublicKey(this.#key).export({ format: "der", type: "spki" });
    this.publicKey = new Uint8Array(spki.subarray(spki.length - KEY_LEN));
  }

  dh = (peerPublic: Uint8Array): Uint8Array => {
    this.calls += 1;
    if (this.locked) throw new Error("the device is locked");
    const peer = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.from(peerPublic)]),
      format: "der",
      type: "spki",
    });
    return new Uint8Array(diffieHellman({ privateKey: this.#key, publicKey: peer }));
  };
}

/** A whole handshake between two identities, then one message each way. */
function handshakeBetween(client: Identity, server: Identity): void {
  const initiator = new Initiator(client, server.publicKey, 0xe1e);
  const responder = new Responder(server);
  responder.readInit(initiator.writeInit());
  const { session: serverSession, frame } = responder.writeResponse();
  const { session: clientSession } = initiator.readResponse(frame);
  assert.equal(text(serverSession.open(clientSession.seal(bytes("up")))), "up");
  assert.equal(text(clientSession.open(serverSession.seal(bytes("down")))), "down");
  clientSession.close();
  serverSession.close();
}

test("the stand-in agrees with FECTP about X25519", () => {
  // Otherwise every test below would be testing the stand-in.
  const element = new SoftElement(0x41);
  const same = Identity.fromSecret(new Uint8Array(KEY_LEN).fill(0x41));
  assert.deepEqual(same.publicKey, element.publicKey);
  same.close();
});

test("a key held elsewhere works on either side", () => {
  const element = new SoftElement(0x42);
  const held = Identity.fromKey(element.publicKey, element.dh);
  const ordinary = Identity.generate();
  assert.deepEqual(held.publicKey, element.publicKey);
  handshakeBetween(held, ordinary);
  assert.equal(element.calls, 2, "an initiator uses its key twice");
  handshakeBetween(ordinary, held);
  assert.equal(element.calls, 4, "and a responder twice");
  held.close();
  ordinary.close();
});

test("a failing key throws with what it threw as the cause", () => {
  const element = new SoftElement(0x43);
  const held = Identity.fromKey(element.publicKey, element.dh);
  const ordinary = Identity.generate();
  element.locked = true;
  const initiator = new Initiator(held, ordinary.publicKey, 1);
  assert.throws(
    () => initiator.writeInit(),
    (error: unknown) =>
      error instanceof KeyUnavailable &&
      error.cause instanceof Error &&
      error.cause.message.includes("locked"),
  );
  initiator.close();

  // A refusal ends the handshake, not the identity.
  element.locked = false;
  handshakeBetween(held, ordinary);
  held.close();
  ordinary.close();
});

test("a wrong length is a key failure", () => {
  const held = Identity.fromKey(new SoftElement(0x44).publicKey, () => new Uint8Array(31));
  const ordinary = Identity.generate();
  const initiator = new Initiator(held, ordinary.publicKey, 2);
  assert.throws(
    () => initiator.writeInit(),
    (error: unknown) => error instanceof KeyUnavailable && error.cause instanceof RangeError,
  );
  initiator.close();
  held.close();
  ordinary.close();
});

test("the key function is held until FECTP lets it go", () => {
  // A handshake can outlive the identity it began from, and its key goes with
  // it; the function has to stay reachable until FECTP says so.
  const element = new SoftElement(0x45);
  const before = _heldKeyCount();
  const held = Identity.fromKey(element.publicKey, element.dh);
  assert.equal(_heldKeyCount(), before + 1);

  const ordinary = Identity.generate();
  const initiator = new Initiator(held, ordinary.publicKey, 3);
  held.close();
  assert.equal(_heldKeyCount(), before + 1, "still referenced by the handshake");
  initiator.writeInit();
  assert.equal(element.calls, 1);
  initiator.close();
  assert.equal(_heldKeyCount(), before, "released once nothing can call it");
  ordinary.close();
});
