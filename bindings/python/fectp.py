"""FECTP from Python, over the C ABI in ``crates/ffi``.

This is the sans-IO session layer. It turns payloads into frames and frames
back into payloads, and does no I/O at all: you own the socket, the thread and
the event loop. That is deliberate — see ``docs/OTHER-LANGUAGES.md`` — and it
is why nothing here blocks, holds the GIL over a handshake, or hands you memory
you have to remember to free.

**Not audited.** Nothing in this project has been reviewed by someone who
breaks protocols for a living. Do not put it in front of an adversary yet.

``ctypes`` rather than ``cffi`` so that this is the standard library and
nothing else. The shared library is built by cargo::

    cargo build -p fectp-ffi --release

and found automatically, or named through ``FECTP_LIBRARY``.

The secret key
--------------

There is no way to read a private key out of an :class:`Identity`. That is not
an omission: bytes handed to Python cannot be wiped. ``bytes`` is immutable, so
nothing can overwrite it; the interpreter may copy it; and it may reach swap.
The C ABI does not export such a call, and this wrapper could not add one.

:func:`Identity.from_secret` exists for restoring a key you stored elsewhere.
Whatever you pass it is yours to erase — use a ``bytearray`` and overwrite it,
because a ``bytes`` cannot be.

Better still, the key never has to be in Python at all.
:func:`Identity.from_key` takes a public key and a function that performs the
Diffie-Hellman with the private half — a secure element, an HSM, a TPM, reached
through whatever library talks to it — and FECTP calls that function and never
sees the key.
"""

from __future__ import annotations

import ctypes
import itertools
import os
import sys
import threading
from ctypes import POINTER, c_int32, c_size_t, c_ssize_t, c_ubyte, c_uint16, c_uint32, c_void_p
from pathlib import Path
from typing import Callable

__all__ = [
    "FectpError",
    "ProtocolError",
    "BufferTooSmall",
    "KeyUnavailable",
    "Identity",
    "Initiator",
    "Responder",
    "Session",
    "KEY_LEN",
]

KEY_LEN = 32

_OK = 0
_ERR_NULL = -1
_ERR_BUFFER = -2
_ERR_PROTOCOL = -3
_ERR_PANIC = -4
_ERR_TOO_LARGE = -5
_ERR_KEY = -6

# Room for a frame plus the handshake's overhead. The protocol's own limit is
# negotiated per session; this is the wrapper's scratch size and is generous.
_SCRATCH = 65535


class FectpError(Exception):
    """Something the library refused."""


class ProtocolError(FectpError):
    """A frame was malformed, failed to authenticate, or arrived out of turn.

    Ordinary rather than exceptional: anyone can send bytes to a socket, so a
    frame that does not authenticate is a datagram to discard and not a fault
    in the program. It is an exception here only because Python has no other
    way to say "no".
    """


class BufferTooSmall(FectpError):
    """An output buffer was too small. Nothing was written to it."""


class KeyUnavailable(FectpError):
    """The key function given to :func:`Identity.from_key` failed.

    The device was busy, locked or absent, or the function raised — in which
    case that exception is this one's ``__cause__``. The handshake it happened
    in is over; the identity is not, and may be used again.
    """


class _Panic(FectpError):
    """A panic was caught inside FECTP. That is a bug in FECTP.

    The handle it happened on is unusable; this is raised rather than returned
    so it cannot be mistaken for a protocol error and retried.
    """


def _library_path() -> Path:
    """Where the shared library is, by environment or by convention."""
    named = os.environ.get("FECTP_LIBRARY")
    if named:
        return Path(named)

    if sys.platform == "win32":
        name = "fectp.dll"
    elif sys.platform == "darwin":
        name = "libfectp.dylib"
    else:
        name = "libfectp.so"

    root = Path(__file__).resolve().parents[2]
    for profile in ("release", "debug"):
        candidate = root / "target" / profile / name
        if candidate.exists():
            return candidate
    raise FectpError(
        f"{name} was not found under {root / 'target'}. Build it with "
        "`cargo build -p fectp-ffi --release`, or set FECTP_LIBRARY to its path."
    )


# The two C functions every key held outside Python goes through: fixed, and
# alive for the life of the module. A ctypes callback object that is collected
# while C still holds its address is a crash at some later call, so none is
# made per key. Each key is a number in `_held_keys` instead, passed to C as
# its context and back to these.
_DH_FN = ctypes.CFUNCTYPE(c_int32, c_void_p, POINTER(c_ubyte), POINTER(c_ubyte))
_RELEASE_FN = ctypes.CFUNCTYPE(None, c_void_p)


def _bind() -> ctypes.CDLL:
    lib = ctypes.CDLL(str(_library_path()))
    u8p = POINTER(c_ubyte)

    # Every signature is declared. Without this ctypes guesses, and guesses
    # wrong on any platform where a pointer is not an int — silently, and only
    # some of the time.
    lib.fectp_identity_generate.restype = c_void_p
    lib.fectp_identity_generate.argtypes = []
    lib.fectp_identity_from_secret.restype = c_void_p
    lib.fectp_identity_from_secret.argtypes = [u8p]
    lib.fectp_identity_public.restype = c_ssize_t
    lib.fectp_identity_public.argtypes = [c_void_p, u8p]
    lib.fectp_identity_free.restype = None
    lib.fectp_identity_free.argtypes = [c_void_p]
    lib.fectp_identity_from_key.restype = c_void_p
    lib.fectp_identity_from_key.argtypes = [u8p, _DH_FN, c_void_p, _RELEASE_FN]

    lib.fectp_initiator_new.restype = c_void_p
    lib.fectp_initiator_new.argtypes = [c_void_p, u8p, c_uint32, c_uint16]
    lib.fectp_initiator_write_init.restype = c_ssize_t
    lib.fectp_initiator_write_init.argtypes = [c_void_p, u8p, c_size_t, u8p, c_size_t]
    lib.fectp_initiator_read_response.restype = c_ssize_t
    lib.fectp_initiator_read_response.argtypes = [
        POINTER(c_void_p), u8p, c_size_t, u8p, c_size_t, POINTER(c_void_p),
    ]
    lib.fectp_initiator_free.restype = None
    lib.fectp_initiator_free.argtypes = [c_void_p]

    lib.fectp_responder_new.restype = c_void_p
    lib.fectp_responder_new.argtypes = [c_void_p, c_uint16]
    lib.fectp_responder_read_init.restype = c_ssize_t
    lib.fectp_responder_read_init.argtypes = [c_void_p, u8p, c_size_t, u8p, c_size_t]
    lib.fectp_responder_write_response.restype = c_ssize_t
    lib.fectp_responder_write_response.argtypes = [
        POINTER(c_void_p), u8p, c_size_t, u8p, c_size_t, POINTER(c_void_p),
    ]
    lib.fectp_responder_free.restype = None
    lib.fectp_responder_free.argtypes = [c_void_p]

    lib.fectp_session_seal.restype = c_ssize_t
    lib.fectp_session_seal.argtypes = [c_void_p, u8p, c_size_t, u8p, c_size_t]
    lib.fectp_session_open.restype = c_ssize_t
    lib.fectp_session_open.argtypes = [c_void_p, u8p, c_size_t, u8p, c_size_t]
    lib.fectp_session_free.restype = None
    lib.fectp_session_free.argtypes = [c_void_p]
    return lib


_lib = _bind()

# Keys FECTP may still call, by the number it was given as a context. An entry
# leaves only when FECTP says it is done with that key — after the identity and
# every handshake begun from it have gone.
_held_keys: dict[int, Callable[[bytes], bytes]] = {}
_held_lock = threading.Lock()
_key_numbers = itertools.count(1)

# The exception a key function raised, kept per thread until the call that
# triggered it turns into `KeyUnavailable`. A Python exception cannot cross C;
# this is how it gets to the caller anyway.
_key_failure = threading.local()


@_DH_FN
def _dh_trampoline(context, peer_public, shared):
    try:
        with _held_lock:
            dh = _held_keys[context]
        result = dh(ctypes.string_at(peer_public, KEY_LEN))
        if len(result) != KEY_LEN:
            raise ValueError(f"a key function must return {KEY_LEN} bytes, not {len(result)}")
        ctypes.memmove(shared, bytes(result), KEY_LEN)
        if isinstance(result, bytearray):
            # The one copy this wrapper can reach. A `bytes` cannot be wiped.
            result[:] = bytes(KEY_LEN)
        return 0
    except BaseException as failure:  # noqa: BLE001 - nothing may unwind into C
        _key_failure.error = failure
        return 1


@_RELEASE_FN
def _release_trampoline(context):
    with _held_lock:
        _held_keys.pop(context, None)


def _buffer(size: int = _SCRATCH):
    return (c_ubyte * size)()


def _as_input(data: bytes | bytearray | memoryview | None):
    """A pointer and a length for `data`, accepting nothing as an empty payload."""
    if not data:
        return (None, 0)
    raw = (c_ubyte * len(data)).from_buffer_copy(bytes(data))
    return (raw, len(raw))


def _check(code: int) -> int:
    """Turns a negative return into the exception it stands for."""
    if code >= 0:
        return code
    if code == _ERR_BUFFER:
        raise BufferTooSmall("the output buffer was too small; nothing was written")
    if code == _ERR_PROTOCOL:
        raise ProtocolError("the frame was rejected: malformed, unauthentic, or out of turn")
    if code == _ERR_NULL:
        raise FectpError("a required argument was missing, or a handle had been consumed")
    if code == _ERR_PANIC:
        raise _Panic("a panic was caught inside FECTP; this handle is unusable")
    if code == _ERR_TOO_LARGE:
        raise FectpError("a length did not fit the platform's word size")
    if code == _ERR_KEY:
        cause = getattr(_key_failure, "error", None)
        _key_failure.error = None
        raise KeyUnavailable("the key function failed; this handshake is over") from cause
    raise FectpError(f"unrecognised error code {code}")


class _Handle:
    """An owned pointer freed exactly once.

    Freeing twice is the defect this class exists to make unreachable, and it
    is the one every hand-written binding eventually has. Python's `__del__`
    runs at a time nobody chooses, so the flag rather than the pointer is what
    decides — a pointer set to None by one path and freed by another is the
    same bug wearing a different hat.
    """

    __slots__ = ("_ptr", "_free")

    def __init__(self, ptr, free):
        if not ptr:
            raise FectpError("FECTP refused to create the handle")
        self._ptr = c_void_p(ptr)
        self._free = free

    @property
    def raw(self) -> c_void_p:
        if self._ptr is None:
            raise FectpError("this handle has already been closed or consumed")
        return self._ptr

    def take(self) -> c_void_p:
        """Gives the pointer up, so something else owns it from here."""
        ptr = self.raw
        self._ptr = None
        return ptr

    def close(self) -> None:
        if self._ptr is not None:
            ptr, self._ptr = self._ptr, None
            self._free(ptr)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            # An interpreter shutting down may already have torn down what this
            # needs. Raising here is never useful and hides the real exit.
            pass


class Identity(_Handle):
    """A long-term X25519 identity.

    There is no way to read the secret back out. See the module docstring.
    """

    def __init__(self, ptr):
        super().__init__(ptr, _lib.fectp_identity_free)

    @classmethod
    def generate(cls) -> "Identity":
        """A fresh identity from the operating system's randomness."""
        return cls(_lib.fectp_identity_generate())

    @classmethod
    def from_secret(cls, secret) -> "Identity":
        """Restores an identity from 32 stored secret bytes.

        The copy FECTP makes is wiped before this returns. The object you pass
        is yours: use a `bytearray` and overwrite it afterwards, since a
        `bytes` cannot be.
        """
        if len(secret) != KEY_LEN:
            raise ValueError(f"a secret is {KEY_LEN} bytes, not {len(secret)}")
        raw, _ = _as_input(secret)
        return cls(_lib.fectp_identity_from_secret(raw))

    @classmethod
    def from_key(cls, public, dh: Callable[[bytes], bytes]) -> "Identity":
        """An identity whose private key FECTP never sees.

        ``public`` is the key's 32-byte public half. ``dh`` performs X25519 with
        the private half: it is given the peer's 32-byte public key and returns
        the 32-byte shared secret. It is called synchronously, on the thread that
        drives the handshake, twice per handshake on each side.

        Raising from ``dh``, or returning the wrong length, ends the handshake
        with :class:`KeyUnavailable` carrying the original exception. Return a
        ``bytearray`` and this wrapper wipes it after copying; a ``bytes`` it
        cannot.

        ``dh`` is held until FECTP says it is done with it — which may be after
        this identity is closed, if a handshake begun from it is still running.
        """
        if len(public) != KEY_LEN:
            raise ValueError(f"a public key is {KEY_LEN} bytes, not {len(public)}")
        if not callable(dh):
            raise TypeError("dh must be callable")
        number = next(_key_numbers)
        with _held_lock:
            _held_keys[number] = dh
        raw, _ = _as_input(public)
        ptr = _lib.fectp_identity_from_key(raw, _dh_trampoline, number, _release_trampoline)
        if not ptr:
            # Refused, so FECTP will never release it; that is ours to do.
            with _held_lock:
                _held_keys.pop(number, None)
        return cls(ptr)

    @property
    def public(self) -> bytes:
        """The 32-byte public key, which peers need in order to reach you."""
        out = _buffer(KEY_LEN)
        _check(_lib.fectp_identity_public(self.raw, out))
        return bytes(out)


class Session(_Handle):
    """An established session."""

    def __init__(self, ptr):
        super().__init__(ptr, _lib.fectp_session_free)

    def seal(self, payload: bytes) -> bytes:
        """Encrypts `payload` into a frame to put on the wire."""
        data, length = _as_input(payload)
        out = _buffer()
        n = _check(_lib.fectp_session_seal(self.raw, data, length, out, len(out)))
        return bytes(out[:n])

    def open(self, frame: bytes) -> bytes:
        """Decrypts a frame from the wire.

        Raises :class:`ProtocolError` for a frame that does not authenticate,
        which is a datagram to drop rather than a fault to report.
        """
        data, length = _as_input(frame)
        out = _buffer()
        n = _check(_lib.fectp_session_open(self.raw, data, length, out, len(out)))
        return bytes(out[:n])


class Initiator(_Handle):
    """The side that starts a handshake."""

    def __init__(self, identity: Identity, peer_public: bytes, session_id: int, max_frame: int = 1200):
        if len(peer_public) != KEY_LEN:
            raise ValueError(f"a public key is {KEY_LEN} bytes, not {len(peer_public)}")
        peer, _ = _as_input(peer_public)
        super().__init__(
            _lib.fectp_initiator_new(identity.raw, peer, session_id, max_frame),
            _lib.fectp_initiator_free,
        )

    def write_init(self, payload: bytes = b"") -> bytes:
        """The opening frame, carrying `payload` inside the handshake."""
        data, length = _as_input(payload)
        out = _buffer()
        n = _check(_lib.fectp_initiator_write_init(self.raw, data, length, out, len(out)))
        return bytes(out[:n])

    def read_response(self, frame: bytes) -> tuple[Session, bytes]:
        """Reads the reply, returning the session and any payload it carried.

        **Consumes this initiator**, whether it succeeds or not: a handshake
        cannot be retried from a half-read state. Using it again raises.
        """
        slot = c_void_p(self.take().value)
        session = c_void_p()
        data, length = _as_input(frame)
        out = _buffer()
        n = _check(
            _lib.fectp_initiator_read_response(
                ctypes.byref(slot), data, length, out, len(out), ctypes.byref(session)
            )
        )
        return Session(session.value), bytes(out[:n])


class Responder(_Handle):
    """The side that answers a handshake."""

    def __init__(self, identity: Identity, max_frame: int = 1200):
        super().__init__(
            _lib.fectp_responder_new(identity.raw, max_frame),
            _lib.fectp_responder_free,
        )

    def read_init(self, frame: bytes) -> bytes:
        """Reads an opening frame, returning any payload it carried."""
        data, length = _as_input(frame)
        out = _buffer()
        n = _check(_lib.fectp_responder_read_init(self.raw, data, length, out, len(out)))
        return bytes(out[:n])

    def write_response(self, payload: bytes = b"") -> tuple[Session, bytes]:
        """The reply, returning the session and the frame to send.

        **Consumes this responder**, as :meth:`Initiator.read_response` does.
        """
        slot = c_void_p(self.take().value)
        session = c_void_p()
        data, length = _as_input(payload)
        out = _buffer()
        n = _check(
            _lib.fectp_responder_write_response(
                ctypes.byref(slot), data, length, out, len(out), ctypes.byref(session)
            )
        )
        return Session(session.value), bytes(out[:n])
