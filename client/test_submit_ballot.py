"""Regression checks for cast-or-audit using the real ElGamal library."""

import base64
from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
from math import isqrt
import unittest
from unittest.mock import Mock, patch

from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal, ElGamalCipherText

import submit_ballot as client


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Small, temporary key for tests only; never used by the election.
        cls.scheme = ElGamal.from_security_parameter(bits=600)

    def test_audit_and_decryption_preserve_text(self):
        for vote in ("", "Alice", "\x00hello", "é☑" * 30):
            with self.subTest(vote=vote):
                ballot, randomness = client._prepare_ballot(vote, self.scheme)
                digest = hashlib.sha256(ballot.encode()).hexdigest()
                self.assertTrue(client._audit_ballot(vote, ballot, randomness, self.scheme, digest))

                # Independently decode to catch mistakes shared by preparation
                # and auditing, including Unicode split across text blocks.
                recovered = b""
                for block in json.loads(ballot):
                    ciphertext = Serialization.unpack(base64.b64decode(block))[1]
                    number = isqrt(self.scheme.decrypt(ciphertext))
                    data = number.to_bytes((number.bit_length() + 7) // 8, "big")
                    self.assertEqual(data[0], 1)
                    recovered += data[1:]

                self.assertEqual(recovered.decode("utf-8"), vote)

    def test_audit_rejects_changed_openings(self):
        ballot, randomness = client._prepare_ballot("Alice", self.scheme)
        digest = hashlib.sha256(ballot.encode()).hexdigest()
        changed = [randomness[0] + 1]

        self.assertFalse(client._audit_ballot("Bob", ballot, randomness, self.scheme, digest))
        self.assertFalse(client._audit_ballot("Alice", ballot, changed, self.scheme, digest))
        self.assertFalse(client._audit_ballot("Alice", ballot, [], self.scheme, digest))
        self.assertFalse(client._audit_ballot("Alice", ballot, randomness, self.scheme, "wrong"))

    def test_audit_rejects_changed_ciphertext_even_with_updated_hash(self):
        ballot, randomness = client._prepare_ballot("Alice", self.scheme)
        blocks = json.loads(ballot)
        ciphertext = Serialization.unpack(base64.b64decode(blocks[0]))[1]
        first, second = ciphertext.peek_value()
        changed = ElGamalCipherText(
            (first, second * 2 % self.scheme.public_key.p), ciphertext.scheme, fresh=True
        )
        blocks[0] = base64.b64encode(
            Serialization.pack(changed, msg_id="", use_pickle=False)
        ).decode("ascii")
        ballot = json.dumps(blocks, separators=(",", ":"))
        digest = hashlib.sha256(ballot.encode()).hexdigest()

        self.assertFalse(client._audit_ballot("Alice", ballot, randomness, self.scheme, digest))

    def test_audit_never_posts_and_later_cast_is_fresh(self):
        public_scheme = ElGamal(self.scheme.public_key, None)
        public_data = Serialization.pack(public_scheme, msg_id="", use_pickle=False)
        response = Mock()
        response.json.return_value = {"public_key": base64.b64encode(public_data).decode("ascii")}
        prepared = []
        original_prepare = client._prepare_ballot

        def prepare(vote, scheme):
            ballot, randomness = original_prepare(vote, scheme)
            prepared.append(ballot)
            return ballot, randomness

        def accept(url, json, timeout):
            self.assertEqual(set(json), {"name", "password", "ballot"})
            result = Mock(status_code=200)
            result.json.return_value = {"hash": hashlib.sha256(json["ballot"].encode()).hexdigest()}
            return result

        with (
            patch.object(client.requests, "get", return_value=response),
            patch.object(client.requests, "post", side_effect=accept) as post,
            patch.object(client, "_prepare_ballot", side_effect=prepare),
            patch("builtins.input", return_value="audit"),
            redirect_stdout(StringIO()),
        ):
            self.assertIsNone(client._submit_ballot("Alice", "voter", "password"))
            post.assert_not_called()

            # A failed audit also must not submit anything.
            with patch.object(client, "_audit_ballot", return_value=False):
                self.assertIsNone(client._submit_ballot("Alice", "voter", "password"))
                post.assert_not_called()

            with patch("builtins.input", return_value="cast"):
                self.assertIsNotNone(client._submit_ballot("Alice", "voter", "password"))
                post.assert_called_once()

        self.assertEqual(len(set(prepared)), 3)


if __name__ == "__main__":
    unittest.main()
