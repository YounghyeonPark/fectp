/**
 * FECTP from TypeScript, over the C ABI in `crates/ffi`.
 *
 * The sans-IO session layer: payloads in, frames out, and back again. It does
 * no I/O, so **you** own the socket — `node:dgram`, `Deno.listenDatagram`,
 * `Bun.udpSocket` — the thread and the event loop. Nothing here blocks, owns a
 * thread, or hands you memory to free. That is the trade `docs/OTHER-LANGUAGES.md`
 * argues for, and it is why none of this is `async`.
 *
 * **Not audited.** Nothing in this project has been reviewed by someone who
 * breaks protocols for a living.
 *
 * ## Runtimes
 *
 * TypeScript is not what decides where this runs; the runtime under it is. The
 * types are compiled away, and what matters is whether the host can load a
 * shared library and open a UDP socket. A browser can do neither, which is why
 * `OTHER-LANGUAGES.md` rules it out — the missing piece is the socket, not the
 * code, so WebAssembly does not change it.
 *
 * Only the loading differs between server runtimes, and it is the one function
 * below marked as such. Node has no FFI of its own and uses `koffi`; Deno has
 * `Deno.dlopen` and Bun has `bun:ffi`, both built in, and either would replace
 * `load()` without touching anything else. Node is what is written and tested
 * here because Node is what this repository has.
 *
 * ## The secret key
 *
 * There is no way to read a private key out of an {@link Identity}, and the C
 * ABI exports no such call for this to wrap. Bytes handed to a JavaScript
 * runtime cannot be wiped: a `Buffer` may be copied by the garbage collector,
 * the old copy is not cleared, and it may reach swap. Keep the handle, not the
 * bytes.
 */

import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Length of a public or secret key, in bytes. */
export const KEY_LEN = 32;

const OK = 0;
const ERR_NULL = -1;
const ERR_BUFFER = -2;
const ERR_PROTOCOL = -3;
const ERR_PANIC = -4;
const ERR_TOO_LARGE = -5;

/** Room for a frame and a handshake's overhead; the wrapper's scratch size. */
const SCRATCH = 65535;

/** Something the library refused. */
export class FectpError extends Error {}

/**
 * A frame was malformed, failed to authenticate, or arrived out of turn.
 *
 * Ordinary rather than exceptional: anyone can send bytes to a socket, so this
 * is a datagram to discard and not a fault in the program.
 */
export class ProtocolError extends FectpError {}

/** An output buffer was too small. Nothing was written to it. */
export class BufferTooSmall extends FectpError {}

/**
 * A panic was caught inside FECTP, which is a bug in FECTP.
 *
 * Thrown separately so it cannot be mistaken for a protocol error and retried;
 * the handle it happened on is unusable.
 */
export class InternalPanic extends FectpError {}

/** Where the shared library is, by environment or by convention. */
function libraryPath(): string {
  const named = process.env.FECTP_LIBRARY;
  if (named) return named;

  const name = process.platform === "win32"
    ? "fectp.dll"
    : process.platform === "darwin"
    ? "libfectp.dylib"
    : "libfectp.so";

  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
  for (const profile of ["release", "debug"]) {
    const candidate = join(root, "target", profile, name);
    if (existsSync(candidate)) return candidate;
  }
  throw new FectpError(
    `${name} was not found under ${join(root, "target")}. Build it with ` +
      "`cargo build -p fectp-ffi --release`, or set FECTP_LIBRARY to its path.",
  );
}

/**
 * Binds the C ABI.
 *
 * **The one runtime-specific function.** Node has no FFI of its own, so this
 * uses `koffi`. On Deno this would be `Deno.dlopen` and on Bun `bun:ffi`, both
 * built in and needing no dependency; everything below this line is the same
 * either way.
 *
 * Every signature is declared rather than inferred. A guessed one is wrong
 * silently, and only on some platforms.
 */
function load() {
  const require = createRequire(import.meta.url);
  const koffi = require("koffi");
  const lib = koffi.load(libraryPath());

  const ptr = "void *";
  const u8 = "uint8_t *";
  // A `void **` is marshalled to a temporary unless its direction is declared,
  // so what the library writes back never reaches the caller. `inout` for the
  // handle slot, which is read and then nulled; `out` for the session, which
  // is only written.
  const slot = koffi.inout(koffi.pointer(ptr));
  const outPtr = koffi.out(koffi.pointer(ptr));
  return {
    identityGenerate: lib.func("fectp_identity_generate", ptr, []),
    identityFromSecret: lib.func("fectp_identity_from_secret", ptr, [u8]),
    identityPublic: lib.func("fectp_identity_public", "intptr_t", [ptr, u8]),
    identityFree: lib.func("fectp_identity_free", "void", [ptr]),

    initiatorNew: lib.func("fectp_initiator_new", ptr, [ptr, u8, "uint32_t", "uint16_t"]),
    initiatorWriteInit: lib.func(
      "fectp_initiator_write_init",
      "intptr_t",
      [ptr, u8, "size_t", u8, "size_t"],
    ),
    initiatorReadResponse: lib.func(
      "fectp_initiator_read_response",
      "intptr_t",
      [slot, u8, "size_t", u8, "size_t", outPtr],
    ),
    initiatorFree: lib.func("fectp_initiator_free", "void", [ptr]),

    responderNew: lib.func("fectp_responder_new", ptr, [ptr, "uint16_t"]),
    responderReadInit: lib.func(
      "fectp_responder_read_init",
      "intptr_t",
      [ptr, u8, "size_t", u8, "size_t"],
    ),
    responderWriteResponse: lib.func(
      "fectp_responder_write_response",
      "intptr_t",
      [slot, u8, "size_t", u8, "size_t", outPtr],
    ),
    responderFree: lib.func("fectp_responder_free", "void", [ptr]),

    sessionSeal: lib.func("fectp_session_seal", "intptr_t", [ptr, u8, "size_t", u8, "size_t"]),
    sessionOpen: lib.func("fectp_session_open", "intptr_t", [ptr, u8, "size_t", u8, "size_t"]),
    sessionFree: lib.func("fectp_session_free", "void", [ptr]),
  };
}

const lib = load();

/** Turns a negative return into the error it stands for. */
function check(code: number): number {
  if (code >= 0) return code;
  switch (code) {
    case ERR_BUFFER:
      throw new BufferTooSmall("the output buffer was too small; nothing was written");
    case ERR_PROTOCOL:
      throw new ProtocolError("the frame was rejected: malformed, unauthentic, or out of turn");
    case ERR_NULL:
      throw new FectpError("a required argument was missing, or a handle had been consumed");
    case ERR_PANIC:
      throw new InternalPanic("a panic was caught inside FECTP; this handle is unusable");
    case ERR_TOO_LARGE:
      throw new FectpError("a length did not fit the platform's word size");
    default:
      throw new FectpError(`unrecognised error code ${code}`);
  }
}

/**
 * An owned pointer, freed exactly once.
 *
 * Freeing twice is the defect this exists to make unreachable, and it is the
 * one every hand-written binding eventually has. A flag decides, not whether
 * the pointer looks null: a pointer cleared by one path and freed by another is
 * the same bug in a different hat. There is no finaliser — JavaScript gives no
 * usable one — so a caller closes, or lets the process end.
 */
abstract class Handle {
  #ptr: unknown | null;
  readonly #free: (p: unknown) => void;

  protected constructor(ptr: unknown, free: (p: unknown) => void) {
    if (!ptr) throw new FectpError("FECTP refused to create the handle");
    this.#ptr = ptr;
    this.#free = free;
  }

  /** The pointer, for passing back in. */
  protected get raw(): unknown {
    if (this.#ptr === null) {
      throw new FectpError("this handle has already been closed or consumed");
    }
    return this.#ptr;
  }

  /** Gives the pointer up, so something else owns it from here. */
  protected take(): unknown {
    const ptr = this.raw;
    this.#ptr = null;
    return ptr;
  }

  /** Frees it. Calling twice does nothing the second time. */
  close(): void {
    if (this.#ptr !== null) {
      const ptr = this.#ptr;
      this.#ptr = null;
      this.#free(ptr);
    }
  }

  /** So `using` frees it at the end of a block, where the runtime supports it. */
  [Symbol.dispose](): void {
    this.close();
  }
}

function scratch(size = SCRATCH): Buffer {
  return Buffer.alloc(size);
}

/** A long-term X25519 identity. The secret cannot be read back out. */
export class Identity extends Handle {
  private constructor(ptr: unknown) {
    super(ptr, lib.identityFree);
  }

  /** A fresh identity from the operating system's randomness. */
  static generate(): Identity {
    return new Identity(lib.identityGenerate());
  }

  /**
   * Restores an identity from 32 stored secret bytes.
   *
   * FECTP wipes the copy it makes. What you pass is yours, and a JavaScript
   * runtime gives you no way to wipe it — which is the argument for keeping
   * the handle instead and never having the bytes here at all.
   */
  static fromSecret(secret: Uint8Array): Identity {
    if (secret.length !== KEY_LEN) {
      throw new RangeError(`a secret is ${KEY_LEN} bytes, not ${secret.length}`);
    }
    return new Identity(lib.identityFromSecret(Buffer.from(secret)));
  }

  /** The 32-byte public key, which peers need in order to reach you. */
  get publicKey(): Uint8Array {
    const out = scratch(KEY_LEN);
    check(lib.identityPublic(this.raw, out));
    return new Uint8Array(out);
  }
}

/** An established session. */
export class Session extends Handle {
  /** @internal */
  constructor(ptr: unknown) {
    super(ptr, lib.sessionFree);
  }

  /** Encrypts a payload into a frame to put on the wire. */
  seal(payload: Uint8Array = new Uint8Array()): Uint8Array {
    const out = scratch();
    const n = check(lib.sessionSeal(this.raw, Buffer.from(payload), payload.length, out, out.length));
    return new Uint8Array(out.subarray(0, n));
  }

  /**
   * Decrypts a frame from the wire.
   *
   * Throws {@link ProtocolError} for a frame that does not authenticate, which
   * is a datagram to drop rather than a fault to report.
   */
  open(frame: Uint8Array): Uint8Array {
    const out = scratch();
    const n = check(lib.sessionOpen(this.raw, Buffer.from(frame), frame.length, out, out.length));
    return new Uint8Array(out.subarray(0, n));
  }
}

/** The side that starts a handshake. */
export class Initiator extends Handle {
  constructor(identity: Identity, peerPublic: Uint8Array, sessionId: number, maxFrame = 1200) {
    if (peerPublic.length !== KEY_LEN) {
      throw new RangeError(`a public key is ${KEY_LEN} bytes, not ${peerPublic.length}`);
    }
    super(
      lib.initiatorNew(
        (identity as unknown as { raw: unknown }).raw,
        Buffer.from(peerPublic),
        sessionId,
        maxFrame,
      ),
      lib.initiatorFree,
    );
  }

  /** The opening frame, carrying `payload` inside the handshake. */
  writeInit(payload: Uint8Array = new Uint8Array()): Uint8Array {
    const out = scratch();
    const n = check(
      lib.initiatorWriteInit(this.raw, Buffer.from(payload), payload.length, out, out.length),
    );
    return new Uint8Array(out.subarray(0, n));
  }

  /**
   * Reads the peer's reply, producing a session.
   *
   * **Consumes this initiator**, whether it succeeds or not: a handshake
   * cannot be retried from a half-read state. Using it again throws.
   */
  readResponse(frame: Uint8Array): { session: Session; payload: Uint8Array } {
    const slot = [this.take()];
    const out = scratch();
    const session: unknown[] = [null];
    const n = check(
      lib.initiatorReadResponse(slot, Buffer.from(frame), frame.length, out, out.length, session),
    );
    return { session: new Session(session[0]), payload: new Uint8Array(out.subarray(0, n)) };
  }
}

/** The side that answers a handshake. */
export class Responder extends Handle {
  constructor(identity: Identity, maxFrame = 1200) {
    super(
      lib.responderNew((identity as unknown as { raw: unknown }).raw, maxFrame),
      lib.responderFree,
    );
  }

  /** Reads an opening frame, returning any payload it carried. */
  readInit(frame: Uint8Array): Uint8Array {
    const out = scratch();
    const n = check(
      lib.responderReadInit(this.raw, Buffer.from(frame), frame.length, out, out.length),
    );
    return new Uint8Array(out.subarray(0, n));
  }

  /**
   * The reply, producing a session.
   *
   * **Consumes this responder**, as {@link Initiator.readResponse} does.
   */
  writeResponse(payload: Uint8Array = new Uint8Array()): { session: Session; frame: Uint8Array } {
    const slot = [this.take()];
    const out = scratch();
    const session: unknown[] = [null];
    const n = check(
      lib.responderWriteResponse(slot, Buffer.from(payload), payload.length, out, out.length, session),
    );
    return { session: new Session(session[0]), frame: new Uint8Array(out.subarray(0, n)) };
  }
}
