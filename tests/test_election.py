"""Exercise the real shuffle, trustee proofs, and Flask election lifecycle."""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal, ElGamalCipherText
from werkzeug.security import generate_password_hash

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from client.submit_ballot import _prepare_ballot
from client.verify import verify_election
from server import server
from server.shuffle import (BALLOT_FORMAT, count_votes, create_decryption, create_shuffle,
                            decode_vote, election_rows, encode_vote, hash_record,
                            validate_key, verify_decryption, verify_shuffle)
from trustee import decrypt_ballots as trustee
import mock_election


class ElectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Test-only key: never read, replace, or decrypt the real election keys.
        cls.scheme = ElGamal.from_security_parameter(bits=600)
        validate_key(cls.scheme)
        public_scheme = ElGamal(cls.scheme.public_key, None)
        cls.public_data = Serialization.pack(public_scheme, msg_id="", use_pickle=False)
        cls.scheme.share_secret_key = True
        cls.private_data = Serialization.pack(cls.scheme, msg_id="", use_pickle=False)
        cls.scheme.share_secret_key = False
        cls.entries = []
        for vote in ("Alice", "Bob", "Alice", "😀" * 32):
            ballot, _ = _prepare_ballot(vote, cls.scheme)
            cls.entries.append({"ballot": ballot, "hash": hashlib.sha256(ballot.encode()).hexdigest()})
        cls.context = {"election_id": "test-election", "ballot_format": BALLOT_FORMAT,
                       "public_key": base64.b64encode(cls.public_data).decode("ascii"), "ballots": cls.entries}
        cls.rows = election_rows(cls.context, cls.scheme)
        cls.shuffle = create_shuffle(cls.rows, cls.scheme, cls.context)
        cls.record_hash = hash_record({"context": cls.context, "shuffle": cls.shuffle})
        cls.decryption = create_decryption(cls.shuffle["output"], cls.scheme, cls.record_hash)

    def setUp(self):
        server.public_scheme = ElGamal(self.scheme.public_key, None)
        server.public_key = self.context["public_key"]
        server.g_buletin.clear()
        server.submitted_voters.clear()
        server.voter_hashes.clear()
        for name in ("Alice", "Bob", "Chet", "Diane"):
            server.voter_hashes[name] = generate_password_hash("password")
        server.election_state = "open"
        server.election_record = None
        server.election_result = None
        self.client = server.app.test_client()

    def submit(self, name, entry):
        return self.client.post("/submit_ballot", json={"name": name, "password": "password", "ballot": entry["ballot"]})

    def test_padded_format(self):
        for vote in ("", "a", "\x00", "x" * 32, "😀" * 32):
            messages = encode_vote(vote)
            self.assertEqual(len(messages), 5)
            self.assertEqual(decode_vote(messages), vote)
        with self.assertRaises(ValueError):
            encode_vote("a" * 33)
        with self.assertRaises(ValueError):
            decode_vote([2] * 5)

    def test_shuffle_and_decryption_preserve_counts(self):
        self.assertTrue(verify_shuffle(self.rows, self.shuffle, self.scheme, self.context))
        self.assertTrue(verify_decryption(self.shuffle["output"], self.decryption, self.scheme, self.record_hash))
        tally = count_votes(self.decryption["messages"])
        self.assertEqual(tally["counts"], {"Alice": 2, "Bob": 1, "😀" * 32: 1})
        self.assertEqual(tally["total_count"], 4)
        self.assertEqual(tally["invalid_ballots"], [])

    def test_shuffle_rejects_tampering(self):
        changes = []
        changed = deepcopy(self.shuffle)
        changed["output"][0][0][1] = str(int(changed["output"][0][0][1]) * 2 % self.scheme.public_key.p)
        changes.append(changed)
        changed = deepcopy(self.shuffle)
        changed["responses"][0]["permutation"] = [0] * 4
        changes.append(changed)
        changed = deepcopy(self.shuffle)
        changed["responses"][0]["offsets"][0][0] = str((int(changed["responses"][0]["offsets"][0][0]) + 1) % (self.scheme.public_key.p - 1))
        changes.append(changed)
        changed = deepcopy(self.shuffle)
        changed["commitments"].pop()
        changes.append(changed)
        for changed in changes:
            self.assertFalse(verify_shuffle(self.rows, changed, self.scheme, self.context))
        self.assertFalse(verify_shuffle(self.rows, self.shuffle, self.scheme, {**self.context, "election_id": "different"}))
        self.assertFalse(verify_shuffle(self.rows[:-1], self.shuffle, self.scheme, self.context))

    def test_decryption_rejects_tampering_and_replay(self):
        changed = deepcopy(self.decryption)
        changed["messages"][0][0] = "1"
        self.assertFalse(verify_decryption(self.shuffle["output"], changed, self.scheme, self.record_hash))
        changed = deepcopy(self.decryption)
        changed["proof"]["responses"][0] = "0"
        self.assertFalse(verify_decryption(self.shuffle["output"], changed, self.scheme, self.record_hash))
        changed = deepcopy(self.decryption)
        changed["proof"]["commitments"].pop()
        self.assertFalse(verify_decryption(self.shuffle["output"], changed, self.scheme, self.record_hash))
        self.assertFalse(verify_decryption(self.shuffle["output"], self.decryption, self.scheme, "another-record"))

    def test_authentication_duplicates_and_malformed_ballots(self):
        response = self.client.post("/submit_ballot", json={"name": "Alice", "password": "wrong", "ballot": self.entries[0]["ballot"]})
        self.assertEqual(response.status_code, 401)
        for ballot in ("not ciphertext", "[]", json.dumps(["invalid-base64"] * 5)):
            response = self.client.post("/submit_ballot", json={"name": "Alice", "password": "password", "ballot": ballot})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.submit("Alice", self.entries[0]).status_code, 200)
        self.assertEqual(self.submit("Alice", self.entries[1]).status_code, 409)
        self.assertEqual(self.submit("Bob", self.entries[0]).status_code, 409)
        self.assertNotIn("Bob", server.submitted_voters)

    def test_concurrent_submission_only_accepts_one_ballot(self):
        def submit(_):
            with server.app.test_client() as client:
                return client.post("/submit_ballot", json={"name": "Alice", "password": "password", "ballot": self.entries[0]["ballot"]}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(submit, range(2))), [200, 409])
        self.assertEqual(len(server.g_buletin), 1)

    def test_close_race_freezes_submissions(self):
        self.assertEqual(self.submit("Alice", self.entries[0]).status_code, 200)
        original = server.create_shuffle

        def mix(rows, scheme, context):
            self.assertEqual(server.election_state, "mixing")
            self.assertEqual(self.submit("Bob", self.entries[1]).status_code, 409)
            return original(rows, scheme, context)

        with patch.object(server, "create_shuffle", side_effect=mix), redirect_stdout(StringIO()):
            server._close_election()
        self.assertEqual(server.election_state, "awaiting_trustee")
        self.assertEqual(len(server.election_record["context"]["ballots"]), 1)
        record = deepcopy(server.election_record)
        with redirect_stdout(StringIO()):
            server._close_election()
        self.assertEqual(server.election_record, record)

    def test_close_failure_stays_closed(self):
        with patch.object(server, "create_shuffle", side_effect=ValueError("test failure")), redirect_stdout(StringIO()):
            server._close_election()
        self.assertEqual(server.election_state, "failed")
        self.assertEqual(self.submit("Alice", self.entries[0]).status_code, 409)
        self.assertIsNone(server.election_result)

    def test_complete_http_trustee_flow(self):
        for name, entry in zip(("Alice", "Bob", "Chet", "Diane"), self.entries):
            self.assertEqual(self.submit(name, entry).status_code, 200)
        with redirect_stdout(StringIO()):
            server._close_election()
        self.assertEqual(server.election_state, "awaiting_trustee")
        record = self.client.get("/election").json["record"]

        # Exercise the actual trustee function, with HTTP routed through Flask's
        # test client and test-only key files in a temporary directory.
        class Response:
            def __init__(self, response):
                self.response = response
            def raise_for_status(self):
                if self.response.status_code >= 400:
                    raise ValueError(self.response.json)
            def json(self):
                return self.response.json

        def post(url, json, timeout):
            return Response(self.client.post("/trustee/tally", json=json))

        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "public_key.bin").write_bytes(self.public_data)
            Path(folder, "private_key.bin").write_bytes(self.private_data)
            with (
                patch.object(trustee, "__file__", str(Path(folder, "decrypt_ballots.py"))),
                patch.object(trustee.requests, "get", return_value=Response(self.client.get("/election"))),
                patch.object(trustee.requests, "post", side_effect=post),
                redirect_stdout(StringIO()),
            ):
                trustee.decrypt_ballots()

        self.assertEqual(server.election_state, "tallied")
        result = self.client.get("/election").json["result"]
        self.assertEqual(result["tally"]["counts"], {"Alice": 2, "Bob": 1, "😀" * 32: 1})
        self.assertEqual(self.client.post("/trustee/tally", json=result["decryption"]).status_code, 409)
        self.assertEqual(record, server.election_record)
        self.assertIsNone(server.public_scheme.secret_key)
        self.assertNotIn(str(self.scheme.secret_key.x), json.dumps(result))

    def test_server_refuses_bad_trustee_proof(self):
        server.election_record = {"context": self.context, "shuffle": self.shuffle, "record_hash": self.record_hash}
        server.election_state = "awaiting_trustee"
        result = deepcopy(self.decryption)
        result["record_hash"] = self.record_hash
        result["messages"][0][0] = "1"
        self.assertEqual(self.client.post("/trustee/tally", json=result).status_code, 400)
        self.assertEqual(server.election_state, "awaiting_trustee")
        self.assertIsNone(server.election_result)

    def test_empty_election(self):
        with redirect_stdout(StringIO()):
            server._close_election()
        record = server.election_record
        result = create_decryption([], self.scheme, record["record_hash"])
        result["record_hash"] = record["record_hash"]
        with redirect_stdout(StringIO()):
            response = self.client.post("/trustee/tally", json=result)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["tally"]["total_count"], 0)

    def test_invalid_plaintext_is_counted_separately(self):
        blocks = []
        public_scheme = ElGamal(self.scheme.public_key, None)
        for _ in range(5):
            ciphertext = public_scheme.encrypt(2)
            packed = Serialization.pack(ciphertext, msg_id="", use_pickle=False)
            blocks.append(base64.b64encode(packed).decode("ascii"))
        entry = {"ballot": json.dumps(blocks, separators=(",", ":"))}
        self.assertEqual(self.submit("Alice", entry).status_code, 200)
        with redirect_stdout(StringIO()):
            server._close_election()
        record = server.election_record
        result = create_decryption(record["shuffle"]["output"], self.scheme, record["record_hash"])
        result["record_hash"] = record["record_hash"]
        with redirect_stdout(StringIO()):
            response = self.client.post("/trustee/tally", json=result)
        self.assertEqual(response.status_code, 200)
        tally = response.json["tally"]
        self.assertEqual(tally["counts"], {})
        self.assertEqual(tally["invalid_ballots"], [0])
        self.assertEqual(tally["total_count"], 1)

    def test_terminal_close_command(self):
        with patch("builtins.input", side_effect=["close", EOFError]), patch.object(server, "_close_election") as close, redirect_stdout(StringIO()):
            server._read_commands()
        close.assert_called_once()

    def finished_election(self):
        """Build a public record from the real proofs in this test fixture."""
        decryption = deepcopy(self.decryption)
        decryption["record_hash"] = self.record_hash
        return {
            "state": "tallied",
            "record": {"context": deepcopy(self.context), "shuffle": deepcopy(self.shuffle),
                       "record_hash": self.record_hash},
            "result": {"decryption": decryption, "tally": count_votes(decryption["messages"])},
        }

    def test_client_verifies_receipt_proofs_and_tally(self):
        election = self.finished_election()
        tally = verify_election(election, self.public_data, self.entries[0]["hash"], report=lambda _: None)
        self.assertEqual(tally["counts"], {"Alice": 2, "Bob": 1, "😀" * 32: 1})

    def test_client_rejects_missing_receipt_or_untrusted_key(self):
        election = self.finished_election()
        with self.assertRaisesRegex(ValueError, "receipt is missing"):
            verify_election(election, self.public_data, "0" * 64, report=lambda _: None)
        with self.assertRaisesRegex(ValueError, "trusted public key"):
            verify_election(election, b"different public key", report=lambda _: None)
        election["state"] = "awaiting_trustee"
        with self.assertRaisesRegex(ValueError, "not finished"):
            verify_election(election, self.public_data, report=lambda _: None)

    def test_client_rejects_false_published_tally(self):
        election = self.finished_election()
        election["result"]["tally"]["counts"]["Alice"] = 100
        with self.assertRaisesRegex(ValueError, "published tally"):
            verify_election(election, self.public_data, report=lambda _: None)

    def test_client_rejects_tampered_shuffle_even_with_new_record_hash(self):
        election = self.finished_election()
        record = election["record"]
        record["shuffle"]["output"][0][0][1] = "1"
        record["record_hash"] = hash_record({"context": record["context"], "shuffle": record["shuffle"]})
        with self.assertRaisesRegex(ValueError, "shuffle proof"):
            verify_election(election, self.public_data, report=lambda _: None)

    def test_client_rejects_tampered_decryption(self):
        election = self.finished_election()
        election["result"]["decryption"]["messages"][0][0] = "1"
        with self.assertRaisesRegex(ValueError, "decryption proof"):
            verify_election(election, self.public_data, report=lambda _: None)

    def test_mock_roles_complete_election_without_a_network_socket(self):
        """Exercise the demo roles through real Flask routes in this restricted sandbox."""
        class Response:
            def __init__(self, response):
                self.response = response
                self.status_code = response.status_code
            def raise_for_status(self):
                if self.status_code >= 400:
                    raise ValueError(self.response.json)
            def json(self):
                return self.response.json

        def get(url, timeout):
            return Response(self.client.get(urlsplit(url).path))

        def post(url, json, timeout):
            return Response(self.client.post(urlsplit(url).path, json=json))

        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "client").mkdir()
            (folder / "trustee").mkdir()
            (folder / "client" / "trusted_public_key.bin").write_bytes(self.public_data)
            (folder / "trustee" / "public_key.bin").write_bytes(self.public_data)
            (folder / "trustee" / "private_key.bin").write_bytes(self.private_data)
            mock_election.write_json(folder / "demo_votes.json", mock_election.DEMO_VOTES)
            mock_election.write_json(folder / "server_info.json", {
                "url": "http://demo.local", "passwords": {name: "password" for name in mock_election.DEMO_VOTES},
            })
            output = StringIO()
            with (
                patch.object(mock_election.requests, "get", side_effect=get),
                patch.object(mock_election.requests, "post", side_effect=post),
                patch.object(trustee, "__file__", str(folder / "trustee" / "decrypt_ballots.py")),
                redirect_stdout(output),
            ):
                with patch("builtins.input", return_value="audit"):
                    mock_election.worker_client(folder, "Alice")
                self.assertFalse(server.g_buletin)
                with patch("builtins.input", return_value="cast"):
                    for name in mock_election.DEMO_VOTES:
                        mock_election.worker_client(folder, name)
                server._close_election()
                mock_election.worker_trustee(folder)
                for name in mock_election.DEMO_VOTES:
                    mock_election.worker_verify(folder, name)

            self.assertEqual(server.election_result["tally"]["counts"], {"River": 3, "Forest": 1})
            self.assertEqual(output.getvalue().count("Verification complete."), 4)
            audited = json.loads((folder / "client" / "receipts" / "Alice-audited.json").read_text())
            self.assertNotIn(audited["receipt"], [entry["hash"] for entry in server.g_buletin])


if __name__ == "__main__":
    unittest.main()
