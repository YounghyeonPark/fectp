"""The Python binding, exercised as a caller would use it.

This is the first test in the repository that crosses the boundary from
outside Rust. `crates/ffi/tests/c_abi.rs` calls the same functions, but from
Rust, through the same compiler that built them — which cannot catch a wrong
calling convention, a mistaken pointer width, or a signature that ctypes has
guessed. Those are exactly the faults a foreign caller meets first.

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
