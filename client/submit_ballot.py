"""Encrypt a write-in ballot locally and submit it with voter credentials."""

import base64
from getpass import getpass
import hashlib
import json
import secrets

import requests
from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal, ElGamalCipherText
from tno.mpc.encryption_schemes.templates.random_sources import ContextlessSource


server_url = "http://127.0.0.1:5000"


def _encode_vote(vote):
    """Turn UTF-8 text into squared integers that fit the demo election key."""
    text = vote.encode("utf-8")
    messages = []

    # Keep 32-byte blocks for the existing 1024-bit demonstration key.
    # The prefix preserves empty text and leading zero bytes.
    for start in range(0, max(1, len(text)), 32):
        block = text[start : start + 32]
        number = int.from_bytes(b"\x01" + block, "big")
        messages.append(number * number)

    return messages


def _prepare_ballot(vote, scheme):
    """Encrypt once, keeping the secret exponents until cast or audit is chosen."""
    # Use a public-only scheme with its own randomness source for this ballot.
    scheme = ElGamal(scheme.public_key, secret_key=None)
    key = scheme.public_key
    messages = _encode_vote(vote)
    random_values = []
    random_pairs = []

    for message in messages:
        # Match TNO's ElGamal randomness generation, retaining r for auditing.
        # Never print or send these exponents for a ballot that is cast.
        exponent = secrets.randbelow(key.p - 2) + 1
        random_values.append(exponent)
        random_pairs.append((pow(key.g, exponent, key.p), pow(key.h, exponent, key.p)))

    # TNO supports supplying precomputed random pairs. Encryption and ciphertext
    # serialization still use the library; serialization must happen only once.
    source = ContextlessSource(random_pairs)
    scheme.register_randomness_source(source, priority=100)
    blocks = []

    for message in messages:
        ciphertext = scheme.encrypt(message)
        packed = Serialization.pack(ciphertext, msg_id="", use_pickle=False)
        blocks.append(base64.b64encode(packed).decode("ascii"))

    ballot = json.dumps(blocks, separators=(",", ":"))
    return ballot, random_values


def _audit_ballot(vote, ballot, random_values, scheme, expected_hash):
    """Check the committed ciphertext using only plaintext, randomness, and public key."""
    actual_hash = hashlib.sha256(ballot.encode("utf-8")).hexdigest()
    if actual_hash != expected_hash:
        return False

    blocks = json.loads(ballot)
    messages = _encode_vote(vote)

    if not isinstance(blocks, list):
        return False

    if len(blocks) != len(messages) or len(random_values) != len(messages):
        return False

    key = scheme.public_key

    for block, message, exponent in zip(blocks, messages, random_values):
        if type(exponent) is not int or not 1 <= exponent <= key.p - 2:
            return False

        packed = base64.b64decode(block, validate=True)
        ciphertext = Serialization.unpack(packed, use_pickle=False)[1]

        if not isinstance(ciphertext, ElGamalCipherText):
            return False

        if ciphertext.scheme.public_key != key:
            return False

        # Independently check both ElGamal equations against the actual saved
        # ciphertext. Re-encrypting with fresh randomness would not check it.
        first = pow(key.g, exponent, key.p)
        second = message * pow(key.h, exponent, key.p) % key.p

        if ciphertext.peek_value() != (first, second):
            return False

    return True


def _submit_ballot(vote, username, password):
    """Prepare a ballot, then either audit and discard it or cast it."""
    if not isinstance(vote, str):
        raise TypeError("The vote must be a string.")

    try:
        response = requests.get(f"{server_url}/public_key", timeout=10)
        response.raise_for_status()

        # Fetch only the public key. The private key stays with the trustee.
        public_data = base64.b64decode(response.json()["public_key"], validate=True)
        scheme = Serialization.unpack(public_data)[1]

        if not isinstance(scheme, ElGamal):
            raise ValueError("Expected an ElGamal public key.")

        # Hash exactly this string; the server stores and hashes it unchanged.
        ballot, random_values = _prepare_ballot(vote, scheme)
        expected_hash = hashlib.sha256(ballot.encode("utf-8")).hexdigest()
        print(f"Prepared ballot hash: {expected_hash}")

        # Choose only after encryption and its hash have been fixed.
        action = input("Cast or audit this ballot? [cast/audit]: ").strip().lower()
        while action not in ("cast", "audit"):
            action = input("Please enter cast or audit: ").strip().lower()

        if action == "audit":
            print(f"Audit vote: {vote!r}")
            for number, exponent in enumerate(random_values, start=1):
                print(f"Block {number} encryption randomness: {exponent}")

            if _audit_ballot(vote, ballot, random_values, scheme, expected_hash):
                print("Audit passed: the ciphertext matches the vote and randomness.")
            else:
                print("Audit failed: the ciphertext does not match.")

            # No submission request is made on either audit outcome. Running the
            # script again creates fresh randomness and a different ciphertext.
            print("Audited ballot discarded; no ballot was submitted.")
            print("Run this script again to prepare a fresh ballot for casting.")
            return None

        # The cast branch sends neither the plaintext nor its random exponents.
        random_values.clear()

        response = requests.post(
            f"{server_url}/submit_ballot",
            json={"name": username, "password": password, "ballot": ballot},
            timeout=10,
        )
        result = response.json()

        if not isinstance(result, dict):
            raise ValueError("Expected a JSON response from the server.")

        if response.status_code != 200:
            print(result.get("error", "Ballot submission failed"))
            return None

        if result.get("hash") != expected_hash:
            print("The returned hash does not match the submitted ballot.")
            return None

        print(f"Ballot hash: {expected_hash}")
        return expected_hash

    except requests.RequestException as error:
        print(f"Could not complete the request: {error}")
    except (ValueError, KeyError, TypeError) as error:
        print(f"Could not prepare or submit the ballot: {error}")

    return None


if __name__ == "__main__":
    username = input("Voter name: ")
    password = getpass("Password: ")
    vote = input("Vote (write-in text): ")

    _submit_ballot(vote, username, password)
