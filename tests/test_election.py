"""Real-crypto tests for shuffling, two-of-three trustees, HTTP, and client checks."""

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
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from client.submit_ballot import _prepare_ballot
from client.verify import verify_election
from client import generate_signing_keys as signing_setup
from server.authentication import ROSTER_VERSION, public_key_text, signing_message, sign_ballot, validate_roster, verify_authorizations
from server import server
from server.shuffle import (BALLOT_FORMAT, count_votes, create_shuffle, decode_vote,
                            election_rows, encode_vote, hash_record, verify_shuffle)
from server.threshold import (combine_partials, create_partial, create_setup,
                              validate_manifest, verify_partial, verify_threshold_decryption)
from trustee import decrypt_ballots as trustee
from trustee import generate_keys as setup_script
import mock_election


class Response:
    def __init__(self, response):
        self.response = response
        self.status_code = response.status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise ValueError(self.response.json)

    def json(self):
        return self.response.json


class ElectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scheme, cls.manifest, cls.shares = create_setup(bits=600)
        cls.public_data = base64.b64decode(cls.manifest['public_key'])
        cls.names = ('Alice', 'Bob', 'Chet', 'Diane')
        cls.voter_keys = {name: Ed25519PrivateKey.generate() for name in cls.names}
        cls.roster = {'version': ROSTER_VERSION, 'voters': [
            {'name': name, 'public_key': public_key_text(cls.voter_keys[name])} for name in cls.names]}
        cls.entries = []
        for name, vote in zip(cls.names, ('Alice', 'Bob', 'Alice', '😀' * 32)):
            ballot, _ = _prepare_ballot(vote, cls.scheme)
            cls.entries.append({'name': name, 'ballot': ballot, 'hash': hashlib.sha256(ballot.encode()).hexdigest(),
                                'signature': sign_ballot(cls.voter_keys[name], 'test-election', name, ballot, cls.roster)})
        cls.context = {'election_id': 'test-election', 'ballot_format': BALLOT_FORMAT,
                       'public_key': cls.manifest['public_key'], 'trustees': cls.manifest, 'ballots': cls.entries, 'voters': cls.roster}
        cls.rows = election_rows(cls.context, cls.scheme)
        cls.shuffle = create_shuffle(cls.rows, cls.scheme, cls.context)
        cls.record_hash = hash_record({'context': cls.context, 'shuffle': cls.shuffle})
        cls.partials = [create_partial(cls.shuffle['output'], share, cls.manifest, cls.scheme, cls.record_hash)
                        for share in cls.shares]
        cls.messages = combine_partials(cls.shuffle['output'], cls.partials[:2], cls.manifest, cls.scheme, cls.record_hash)

    def setUp(self):
        server.public_scheme = ElGamal(self.scheme.public_key, None)
        server.public_key = self.manifest['public_key']
        server.trustee_manifest = deepcopy(self.manifest)
        server.trustee_partials.clear()
        server.g_buletin.clear()
        server.submitted_voters.clear()
        server.voter_roster = deepcopy(self.roster)
        server.election_id = 'test-election'
        server.election_state = 'open'
        server.election_record = None
        server.election_result = None
        self.client = server.app.test_client()

    def submit(self, name, ballot, signer=None, election_id='test-election'):
        key = self.voter_keys[signer or name]
        signature = base64.b64encode(key.sign(signing_message(election_id, name, ballot, self.roster))).decode('ascii')
        return self.client.post('/submit_ballot', json={'name': name, 'election_id': election_id,
                                                      'ballot': ballot, 'signature': signature})

    def close(self, entries=None):
        server.g_buletin.extend(deepcopy(self.entries if entries is None else entries))
        with redirect_stdout(StringIO()):
            server._close_election()
        self.assertEqual(server.election_state, 'awaiting_trustees')
        return server.election_record

    def contribute(self, record, index):
        partial = create_partial(record['shuffle']['output'], self.shares[index - 1], self.manifest,
                                 self.scheme, record['record_hash'])
        return self.client.post('/trustee/partial_decryption', json=partial)

    def finished_election(self):
        decryption = {'record_hash': self.record_hash, 'partials': deepcopy(self.partials[:2]),
                      'messages': deepcopy(self.messages)}
        return {'state': 'tallied',
                'record': {'context': deepcopy(self.context), 'shuffle': deepcopy(self.shuffle), 'record_hash': self.record_hash},
                'result': {'decryption': decryption, 'tally': count_votes(self.messages)}}

    def verify(self, election, receipt=None):
        return verify_election(election, self.public_data, receipt, report=lambda _: None, trustees=self.manifest, voters=self.roster)

    def write_setup(self, folder):
        keys = folder / 'threshold'
        keys.mkdir(parents=True)
        (keys / 'public_key.bin').write_bytes(self.public_data)
        (keys / 'trustees.json').write_text(json.dumps(self.manifest))
        for share in self.shares:
            (keys / f"trustee_{share['trustee_id']}.json").write_text(json.dumps(share))

    def get(self, url, timeout):
        return Response(self.client.get(urlsplit(url).path))

    def post(self, url, json, timeout):
        return Response(self.client.post(urlsplit(url).path, json=json))

    def test_all_pairs_and_all_three_decrypt(self):
        for indices in ((0, 1), (0, 2), (1, 2), (0, 1, 2)):
            partials = [self.partials[index] for index in indices]
            messages = combine_partials(self.shuffle['output'], partials, self.manifest, self.scheme, self.record_hash)
            self.assertEqual(messages, self.messages)
        self.assertEqual(count_votes(self.messages)['counts'], {'Alice': 2, 'Bob': 1, '😀' * 32: 1})
        self.assertIsNone(self.scheme.secret_key)

    def test_one_trustee_or_duplicate_trustee_cannot_decrypt(self):
        for partial in self.partials:
            with self.assertRaises(ValueError):
                combine_partials(self.shuffle['output'], [partial], self.manifest, self.scheme, self.record_hash)
        with self.assertRaises(ValueError):
            combine_partials(self.shuffle['output'], [self.partials[0]] * 2, self.manifest, self.scheme, self.record_hash)

    def test_partial_tampering_and_replay_are_rejected(self):
        changed = deepcopy(self.partials[0])
        changed['factors'][0][0] = str(int(changed['factors'][0][0]) * 4 % self.scheme.public_key.p)
        self.assertFalse(verify_partial(self.shuffle['output'], changed, self.manifest, self.scheme, self.record_hash))
        changed = deepcopy(self.partials[0])
        changed['trustee_id'] = 2
        self.assertFalse(verify_partial(self.shuffle['output'], changed, self.manifest, self.scheme, self.record_hash))
        self.assertFalse(verify_partial(self.shuffle['output'], self.partials[0], self.manifest, self.scheme, 'another-election'))

    def test_wrong_private_share_is_rejected(self):
        share = deepcopy(self.shares[0])
        share['share'] = str((int(share['share']) + 1) % ((self.scheme.public_key.p - 1) // 2))
        with self.assertRaises(ValueError):
            create_partial(self.shuffle['output'], share, self.manifest, self.scheme, self.record_hash)

    def test_bad_manifest_is_rejected(self):
        changed = deepcopy(self.manifest)
        changed['trustees'][0]['public_share'] = changed['trustees'][1]['public_share']
        with self.assertRaises(ValueError):
            validate_manifest(changed, self.scheme)
        changed = deepcopy(self.manifest)
        changed['threshold'] = 1
        with self.assertRaises(ValueError):
            validate_manifest(changed, self.scheme)

    def test_setup_saves_only_separate_shares_and_preserves_old_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            old = folder / 'private_key.bin'
            old.write_bytes(b'old-election-key')
            with patch.object(setup_script, '__file__', str(folder / 'generate_keys.py')), patch.object(setup_script, 'create_setup', return_value=(self.scheme, self.manifest, self.shares)), redirect_stdout(StringIO()):
                setup_script.generate_keys()
            self.assertEqual(old.read_bytes(), b'old-election-key')
            self.assertFalse((folder / 'threshold' / 'private_key.bin').exists())
            for index in (1, 2, 3):
                file = folder / 'threshold' / f'trustee_{index}.json'
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(file.read_text())['trustee_id'], index)
            with patch.object(setup_script, '__file__', str(folder / 'generate_keys.py')):
                with self.assertRaises(SystemExit):
                    setup_script.generate_keys()

    def test_http_requires_two_distinct_valid_contributions(self):
        record = self.close()
        self.assertEqual(self.contribute(record, 1).status_code, 200)
        pending = self.client.get('/election').json
        self.assertEqual(pending['trustee_progress']['received'], 1)
        self.assertIsNone(pending['result'])
        self.assertEqual(self.contribute(record, 1).status_code, 409)
        self.assertEqual(self.contribute(record, 3).status_code, 200)
        self.assertEqual(server.election_state, 'tallied')
        self.assertEqual(server.election_result['tally']['counts'], {'Alice': 2, 'Bob': 1, '😀' * 32: 1})
        self.assertEqual(self.contribute(record, 2).status_code, 409)
        self.assertEqual(self.client.post('/trustee/tally', json={'messages': self.messages}).status_code, 404)

    def test_invalid_partial_does_not_advance_threshold(self):
        server.election_record = self.finished_election()['record']
        server.election_state = 'awaiting_trustees'
        changed = deepcopy(self.partials[0])
        changed['proof']['response'] = '0'
        response = self.client.post('/trustee/partial_decryption', json=changed)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(server.trustee_partials)
        self.assertIsNone(server.election_result)

    def test_concurrent_trustees_complete_only_one_tally(self):
        server.election_record = self.finished_election()['record']
        server.election_state = 'awaiting_trustees'
        def contribute(partial):
            with server.app.test_client() as client:
                return client.post('/trustee/partial_decryption', json=partial).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(contribute, self.partials[:2])), [200, 200])
        self.assertEqual(len(server.trustee_partials), 2)
        self.assertEqual(server.election_state, 'tallied')

    def test_padded_format(self):
        for vote in ('', 'a', '\x00', 'x' * 32, '😀' * 32):
            self.assertEqual(decode_vote(encode_vote(vote)), vote)
            self.assertEqual(len(encode_vote(vote)), 5)
        with self.assertRaises(ValueError):
            encode_vote('a' * 33)

    def test_shuffle_rejects_tampering(self):
        self.assertTrue(verify_shuffle(self.rows, self.shuffle, self.scheme, self.context))
        changed = deepcopy(self.shuffle)
        changed['output'][0][0][1] = str(int(changed['output'][0][0][1]) * 4 % self.scheme.public_key.p)
        self.assertFalse(verify_shuffle(self.rows, changed, self.scheme, self.context))
        changed = deepcopy(self.shuffle)
        changed['responses'][0]['permutation'] = [0] * 4
        self.assertFalse(verify_shuffle(self.rows, changed, self.scheme, self.context))
        changed = deepcopy(self.shuffle)
        changed['commitments'].pop()
        self.assertFalse(verify_shuffle(self.rows, changed, self.scheme, self.context))
        self.assertFalse(verify_shuffle(self.rows, self.shuffle, self.scheme, {**self.context, 'election_id': 'changed'}))

    def test_authentication_duplicates_and_bad_ciphertexts(self):
        ballot = self.entries[0]['ballot']
        self.assertEqual(self.submit('Alice', ballot, signer='Bob').status_code, 401)
        for bad in ('not ciphertext', '[]', json.dumps(['bad-base64'] * 5)):
            self.assertEqual(self.submit('Alice', bad).status_code, 400)
        self.assertEqual(self.submit('Alice', ballot).status_code, 200)
        self.assertEqual(self.submit('Alice', self.entries[1]['ballot']).status_code, 409)
        self.assertEqual(self.submit('Bob', ballot).status_code, 409)

    def test_signatures_bind_identity_ciphertext_and_election(self):
        ballot = self.entries[0]['ballot']
        signature = sign_ballot(self.voter_keys['Alice'], server.election_id, 'Alice', ballot, self.roster)
        payload = {'name': 'Alice', 'ballot': ballot, 'signature': signature, 'election_id': server.election_id}
        for field, value in [('name', 'Bob'), ('ballot', self.entries[1]['ballot']),
                             ('election_id', 'old-election'), ('signature', 'not-base64')]:
            with self.subTest(field=field):
                self.assertEqual(self.client.post('/submit_ballot', json={**payload, field: value}).status_code, 401)
        self.assertEqual(self.submit('Mallory', ballot, signer='Alice').status_code, 401)
        self.assertFalse(server.g_buletin)
        self.assertEqual(self.client.post('/submit_ballot', json=payload).status_code, 200)
        self.assertEqual(self.client.post('/submit_ballot', json=payload).status_code, 409)
        # Even changing the ID in a captured request cannot reuse its signature.
        server.election_id = 'new-election'
        self.assertEqual(self.client.post('/submit_ballot', json={**payload, 'election_id': 'new-election'}).status_code, 401)

    def test_password_requests_are_not_supported(self):
        self.assertEqual(self.client.post('/authenticate', json={'name': 'Alice', 'password': 'anything'}).status_code, 404)
        self.assertEqual(self.client.post('/submit_ballot', json={
            'name': 'Alice', 'password': 'anything', 'ballot': self.entries[0]['ballot']}).status_code, 400)

    def test_public_verifier_checks_signatures_and_trusted_roster(self):
        election = self.finished_election()
        election['record']['context']['ballots'][0]['signature'] = base64.b64encode(bytes(64)).decode('ascii')
        record = election['record']
        record['record_hash'] = hash_record({'context': record['context'], 'shuffle': record['shuffle']})
        with self.assertRaisesRegex(ValueError, 'voter signature'):
            self.verify(election)
        election = self.finished_election()
        election['record']['context']['voters']['voters'][0]['public_key'] = public_key_text(Ed25519PrivateKey.generate())
        record = election['record']
        record['record_hash'] = hash_record({'context': record['context'], 'shuffle': record['shuffle']})
        with self.assertRaisesRegex(ValueError, 'trusted roster'):
            self.verify(election)

    def test_public_authorization_rejects_two_votes_by_one_signing_key(self):
        context = deepcopy(self.context)
        entry = context['ballots'][1]
        entry['name'] = 'Alice'
        entry['signature'] = sign_ballot(self.voter_keys['Alice'], context['election_id'], 'Alice', entry['ballot'], self.roster)
        with self.assertRaisesRegex(ValueError, 'repeated voter'):
            verify_authorizations(context, self.roster)

    def test_roster_rejects_duplicate_names_and_keys(self):
        for field in ('name', 'public_key'):
            roster = deepcopy(self.roster)
            roster['voters'][1][field] = roster['voters'][0][field]
            with self.assertRaises(ValueError):
                validate_roster(roster)

    def test_signing_setup_registers_public_keys_and_preserves_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'client').mkdir()
            (root / 'server').mkdir()
            voters_file = root / 'server' / 'voters_list.txt'
            voters_file.write_text('\n'.join(self.names))
            with patch.object(signing_setup, '__file__', str(root / 'client' / 'generate_signing_keys.py')), redirect_stdout(StringIO()):
                signing_setup.generate_signing_keys()
            folder = root / 'client' / 'signing_keys'
            roster = json.loads((root / 'server' / 'voter_keys.json').read_text())
            self.assertEqual(roster, json.loads((folder / 'voters.json').read_text()))
            for index, voter in enumerate(roster['voters'], start=1):
                file = folder / f'voter_{index}.pem'
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                key = serialization.load_pem_private_key(file.read_bytes(), password=None)
                self.assertEqual(public_key_text(key), voter['public_key'])
            with patch.object(signing_setup, '__file__', str(root / 'client' / 'generate_signing_keys.py')):
                with self.assertRaises(SystemExit):
                    signing_setup.generate_signing_keys()
            with patch.object(server, '__file__', str(root / 'server' / 'server.py')), patch.object(server, 'voters_file', voters_file), redirect_stdout(StringIO()):
                server._load_voters()
            self.assertEqual(server.voter_roster, roster)

    def test_close_freezes_submissions_and_cannot_repeat(self):
        self.assertEqual(self.submit('Alice', self.entries[0]['ballot']).status_code, 200)
        original = server.create_shuffle
        def mix(rows, scheme, context):
            self.assertEqual(self.submit('Bob', self.entries[1]['ballot']).status_code, 409)
            return original(rows, scheme, context)
        with patch.object(server, 'create_shuffle', side_effect=mix), redirect_stdout(StringIO()):
            server._close_election()
        self.assertEqual(server.election_state, 'awaiting_trustees')
        record = deepcopy(server.election_record)
        with redirect_stdout(StringIO()):
            server._close_election()
        self.assertEqual(server.election_record, record)

    def test_close_failure_stays_closed(self):
        with patch.object(server, 'create_shuffle', side_effect=ValueError('test failure')), redirect_stdout(StringIO()):
            server._close_election()
        self.assertEqual(server.election_state, 'failed')
        self.assertEqual(self.submit('Alice', self.entries[0]['ballot']).status_code, 409)

    def test_empty_election_still_requires_two_trustees(self):
        record = self.close([])
        self.contribute(record, 2)
        self.assertIsNone(server.election_result)
        response = self.contribute(record, 3)
        self.assertEqual(response.json['tally']['total_count'], 0)

    def test_terminal_command(self):
        with patch('builtins.input', side_effect=['close', EOFError]), patch.object(server, '_close_election') as close, redirect_stdout(StringIO()):
            server._read_commands()
        close.assert_called_once()

    def test_client_verifies_threshold_and_rejects_tampering(self):
        self.assertEqual(self.verify(self.finished_election(), self.entries[0]['hash'])['total_count'], 4)
        for change in ('one', 'duplicate', 'plaintext', 'count', 'manifest'):
            election = self.finished_election()
            result = election['result']['decryption']
            if change == 'one':
                result['partials'].pop()
            elif change == 'duplicate':
                result['partials'] = [result['partials'][0]] * 2
            elif change == 'plaintext':
                result['messages'][0][0] = '1'
            elif change == 'count':
                election['result']['tally']['counts']['Alice'] = 100
            else:
                election['record']['context']['trustees']['threshold'] = 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(election)
        with self.assertRaises(ValueError):
            self.verify(self.finished_election(), '0' * 64)

    def test_mock_roles_with_third_trustee_offline(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            self.write_setup(folder / 'trustee')
            (folder / 'client').mkdir()
            (folder / 'client' / 'trusted_public_key.bin').write_bytes(self.public_data)
            (folder / 'client' / 'trustees.json').write_text(json.dumps(self.manifest))
            signing = folder / 'client' / 'signing_keys'
            signing.mkdir()
            (signing / 'voters.json').write_text(json.dumps(self.roster))
            (folder / 'server').mkdir()
            (folder / 'server' / 'voter_keys.json').write_text(json.dumps(self.roster))
            for index, name in enumerate(self.names, start=1):
                (signing / f'voter_{index}.pem').write_bytes(self.voter_keys[name].private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

            mock_election.write_json(folder / 'demo_votes.json', mock_election.DEMO_VOTES)
            mock_election.write_json(folder / 'server_info.json', {
                'url': 'http://demo.local'})
            # Prove that trustee 3's private file is not needed by this flow.
            (folder / 'trustee' / 'threshold' / 'trustee_3.json').unlink()
            output = StringIO()
            with patch.object(mock_election.requests, 'get', side_effect=self.get), patch.object(mock_election.requests, 'post', side_effect=self.post), patch.object(trustee, '__file__', str(folder / 'trustee' / 'decrypt_ballots.py')), redirect_stdout(output):
                with patch('builtins.input', return_value='audit'):
                    mock_election.worker_client(folder, 'Alice')
                self.assertFalse(server.g_buletin)
                with patch('builtins.input', return_value='cast'):
                    for name in mock_election.DEMO_VOTES:
                        mock_election.worker_client(folder, name)
                server._close_election()
                mock_election.worker_trustee(folder, '1')
                self.assertIsNone(server.election_result)
                self.assertEqual(len(server.trustee_partials), 1)
                mock_election.worker_trustee(folder, '2')
                for name in mock_election.DEMO_VOTES:
                    mock_election.worker_verify(folder, name)
            self.assertEqual(server.election_result['tally']['counts'], {'River': 3, 'Forest': 1})
            self.assertEqual(output.getvalue().count('Verification complete.'), 4)
            audited = mock_election.read_json(folder / 'client' / 'receipts' / 'Alice-audited.json')['receipt']
            self.assertNotIn(audited, [entry['hash'] for entry in server.g_buletin])
            self.assertIsNone(server.public_scheme.secret_key)


if __name__ == '__main__':
    unittest.main()
