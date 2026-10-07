"""The Python binding, exercised as a caller would use it.

This is the first test in the repository that crosses the boundary from
outside Rust. `crates/ffi/tests/c_abi.rs` calls the same functions, but from
Rust, through the same compiler that built them — which cannot catch a wrong
calling convention, a mistaken pointer width, or a signature that ctypes has
guessed. Those are exactly the faults a foreign caller meets first.

`bindings/typescript/test.ts` is the second, and the pair is worth more than
either: the `void **` out-parameters below work from ctypes by default and
returned nothing at all from koffi until their direction was declared. One
foreign caller would not have found that (D69).

    python3 bindings/python/test_fectp.py

after `cargo build -p fectp-ffi --release` (or debug; either is found).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fectp  # noqa: E402


class Handshake(unittest.TestCase):
    def establish(self, from_client=b"", from_server=b""):
        """A full handshake, returning both sessions and both payloads."""
        server_id = fectp.Identity.generate()
        client_id = fectp.Identity.generate()

        initiator = fectp.Initiator(client_id, server_id.public, session_id=0x5EED)
        responder = fectp.Responder(server_id)

        opening = initiator.write_init(from_client)
        client_said = responder.read_init(opening)

        server_session, reply = responder.write_response(from_server)
        client_session, server_said = initiator.read_response(reply)

        return client_session, server_session, client_said, server_said

    def test_a_handshake_completes_and_both_sides_agree(self):
        client, server, said_by_client, said_by_server = self.establish(
            b"data with the opening frame", b"and with the reply"
        )
        self.assertEqual(said_by_client, b"data with the opening frame")
        self.assertEqual(said_by_server, b"and with the reply")

        # Both directions, to show the keys really match rather than one side
        # happening to decrypt its own traffic.
        self.assertEqual(server.open(client.seal(b"up")), b"up")
        self.assertEqual(client.open(server.seal(b"down")), b"down")

    def test_an_empty_payload_is_allowed(self):
        _, _, said_by_client, said_by_server = self.establish()
        self.assertEqual(said_by_client, b"")
        self.assertEqual(said_by_server, b"")

    def test_a_tampered_frame_is_refused(self):
        client, server, _, _ = self.establish()
        frame = bytearray(client.seal(b"genuine"))
        frame[-1] ^= 0x01
        with self.assertRaises(fectp.ProtocolError):
            server.open(bytes(frame))

    def test_a_frame_from_a_stranger_is_refused(self):
        # A third party with its own identity cannot produce a frame this
        # session accepts, which is the property the whole handshake is for.
        client, server, _, _ = self.establish()
        other_client, _, _, _ = self.establish()
        with self.assertRaises(fectp.ProtocolError):
            server.open(other_client.seal(b"not from the peer"))


class Secrets(unittest.TestCase):
    def test_there_is_no_way_to_read_a_private_key(self):
        """The property the whole binding is shaped around.

        Bytes handed to Python cannot be wiped: `bytes` is immutable, the
        interpreter copies freely, and the memory may reach swap. So the secret
        must never arrive here at all — and this asserts the absence, because
        an absence is what a future convenience method would quietly end.
        """
        identity = fectp.Identity.generate()
        for name in dir(identity):
            self.assertNotIn(
                "secret",
                name.lower().replace("from_secret", ""),
                f"Identity.{name} looks like a way to read the key back out",
            )
        self.assertFalse(
            hasattr(fectp._lib, "fectp_identity_secret"),
            "the C library exports a secret accessor; the binding cannot be the "
            "only thing keeping it in",
        )

    def test_a_restored_identity_is_the_same_one(self):
        # Persisting a key is why `from_secret` exists, and a round trip is the
        # only way to show it restores rather than merely accepts.
        secret = bytearray(32)
        for i in range(32):
            secret[i] = (i * 7 + 3) & 0xFF

        first = fectp.Identity.from_secret(secret)
        second = fectp.Identity.from_secret(secret)
        self.assertEqual(first.public, second.public)

        # And it is usable, not just constructible.
        responder = fectp.Responder(first)
        client = fectp.Identity.generate()
        initiator = fectp.Initiator(client, first.public, session_id=1)
        self.assertEqual(responder.read_init(initiator.write_init(b"x")), b"x")

    def test_a_wrong_length_key_is_refused_before_it_reaches_c(self):
        with self.assertRaises(ValueError):
            fectp.Identity.from_secret(b"too short")
        identity = fectp.Identity.generate()
        with self.assertRaises(ValueError):
            fectp.Initiator(identity, b"too short", session_id=1)


class Handles(unittest.TestCase):
    def test_a_consumed_handle_cannot_be_used_again(self):
        """The double free every hand-written binding eventually has."""
        server_id = fectp.Identity.generate()
        client_id = fectp.Identity.generate()
        initiator = fectp.Initiator(client_id, server_id.public, session_id=2)
        responder = fectp.Responder(server_id)
        responder.read_init(initiator.write_init())
        _, reply = responder.write_response()

        with self.assertRaises(fectp.FectpError):
            responder.write_response()

        initiator.read_response(reply)
        with self.assertRaises(fectp.FectpError):
            initiator.read_response(reply)

    def test_closing_twice_is_harmless(self):
        identity = fectp.Identity.generate()
        identity.close()
        identity.close()
        with self.assertRaises(fectp.FectpError):
            _ = identity.public

    def test_a_handle_works_as_a_context_manager(self):
        with fectp.Identity.generate() as identity:
            self.assertEqual(len(identity.public), 32)
        with self.assertRaises(fectp.FectpError):
            _ = identity.public

    def test_a_failed_handshake_still_consumes_the_initiator(self):
        # Failure has to consume it too: the handshake cannot be retried from a
        # half-read state, and a handle that looks alive invites a second call.
        server_id = fectp.Identity.generate()
        client_id = fectp.Identity.generate()
        initiator = fectp.Initiator(client_id, server_id.public, session_id=3)
        initiator.write_init()
        with self.assertRaises(fectp.ProtocolError):
            initiator.read_response(b"\x00" * 64)
        with self.assertRaises(fectp.FectpError):
            initiator.read_response(b"\x00" * 64)



# --------------------------------------------------------- a key held elsewhere

# X25519 as RFC 7748 writes it, in Python, standing in for a secure element.
# The standard library has none, and an implementation that shares no code
# with the Rust one is worth having for its own sake: the first test below
# checks the two agree before anything else trusts this one.
_P = 2**255 - 19


def _x25519(scalar: bytes, u: bytes) -> bytes:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3, z3 = (da + cb) ** 2 % _P, x1 * (da - cb) ** 2 % _P
        x2, z2 = aa * bb % _P, e * (aa + 121665 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


_BASE = (9).to_bytes(32, "little")


class SoftElement:
    """A device: it does Diffie-Hellman, counts the calls, and can be locked."""

    def __init__(self, fill: int):
        self._secret = bytes([fill]) * 32
        self.public = _x25519(self._secret, _BASE)
        self.calls = 0
        self.locked = False

    def dh(self, peer_public: bytes) -> bytearray:
        self.calls += 1
        if self.locked:
            raise RuntimeError("the device is locked")
        return bytearray(_x25519(self._secret, peer_public))


class HardwareKey(unittest.TestCase):
    def handshake(self, client, server):
        initiator = fectp.Initiator(client, server.public, session_id=0xE1E)
        responder = fectp.Responder(server)
        responder.read_init(initiator.write_init())
        server_session, reply = responder.write_response()
        client_session, _ = initiator.read_response(reply)
        self.assertEqual(server_session.open(client_session.seal(b"up")), b"up")
        self.assertEqual(client_session.open(server_session.seal(b"down")), b"down")

    def test_the_stand_in_agrees_with_fectp_about_x25519(self):
        # Otherwise every test below would be testing the stand-in.
        element = SoftElement(0x31)
        with fectp.Identity.from_secret(bytes([0x31]) * 32) as same_key:
            self.assertEqual(element.public, same_key.public)

    def test_a_key_held_elsewhere_works_on_either_side(self):
        element = SoftElement(0x32)
        with fectp.Identity.from_key(element.public, element.dh) as held, \
                fectp.Identity.generate() as ordinary:
            self.assertEqual(held.public, element.public)
            self.handshake(held, ordinary)
            self.assertEqual(element.calls, 2, "an initiator uses its key twice")
            self.handshake(ordinary, held)
            self.assertEqual(element.calls, 4, "and a responder twice")

    def test_a_failing_key_raises_with_its_own_exception_as_the_cause(self):
        element = SoftElement(0x33)
        with fectp.Identity.from_key(element.public, element.dh) as held, \
                fectp.Identity.generate() as ordinary:
            element.locked = True
            initiator = fectp.Initiator(held, ordinary.public, session_id=1)
            with self.assertRaises(fectp.KeyUnavailable) as raised:
                initiator.write_init()
            self.assertIsInstance(raised.exception.__cause__, RuntimeError)
            self.assertIn("locked", str(raised.exception.__cause__))
            initiator.close()

            # A refusal ends the handshake, not the identity.
            element.locked = False
            self.handshake(held, ordinary)

    def test_a_wrong_length_is_a_key_failure(self):
        with fectp.Identity.generate() as ordinary, \
                fectp.Identity.from_key(SoftElement(0x34).public, lambda _peer: b"short") as held:
            initiator = fectp.Initiator(held, ordinary.public, session_id=2)
            with self.assertRaises(fectp.KeyUnavailable) as raised:
                initiator.write_init()
            self.assertIsInstance(raised.exception.__cause__, ValueError)
            initiator.close()

    def test_the_key_function_is_held_until_fectp_lets_it_go(self):
        # A handshake can outlive the identity it began from, and its key goes
        # with it; the function has to stay reachable until FECTP says so.
        element = SoftElement(0x35)
        before = set(fectp._held_keys)
        held = fectp.Identity.from_key(element.public, element.dh)
        (number,) = set(fectp._held_keys) - before

        with fectp.Identity.generate() as ordinary:
            initiator = fectp.Initiator(held, ordinary.public, session_id=3)
            held.close()
            self.assertIn(number, fectp._held_keys, "still referenced by the handshake")
            initiator.write_init()
            self.assertEqual(element.calls, 1)
            initiator.close()
        self.assertNotIn(number, fectp._held_keys, "released once nothing can call it")

if __name__ == "__main__":
    unittest.main(verbosity=2)
