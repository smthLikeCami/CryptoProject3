"""Encrypt a write-in ballot locally and submit it with voter credentials."""

import base64
from getpass import getpass
import hashlib
import json

import requests
from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal


server_url = "http://127.0.0.1:5000"


def _submit_ballot(vote, username, password):
    """Encrypt text with the election public key, then print its receipt hash."""
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

        text = vote.encode("utf-8")
        blocks = []

        # Smaller blocks keep the squared message within the demo's 1024-bit key.
        # With a 2048-bit (or larger) key, 32 still works; optionally use 64.
        # Do not use 64 with a 1024-bit key: the squared message can be too large.
        block_size = 32

        # Even the empty string gets one encrypted block.
        for start in range(0, max(1, len(text)), block_size):
            block = text[start : start + block_size]

            # The leading byte preserves empty blocks and leading zero bytes.
            # Squaring puts the message in the quadratic-residue subgroup.
            # After decryption, an integer square root recovers this encoding.
            number = int.from_bytes(b"\x01" + block, "big")
            ciphertext = scheme.encrypt(number * number)

            # The library handles ciphertext serialization and fresh randomness.
            packed = Serialization.pack(ciphertext, msg_id="", use_pickle=False)
            blocks.append(base64.b64encode(packed).decode("ascii"))

        # Hash exactly this string; the server stores and hashes it unchanged.
        ballot = json.dumps(blocks, separators=(",", ":"))
        expected_hash = hashlib.sha256(ballot.encode("utf-8")).hexdigest()

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
