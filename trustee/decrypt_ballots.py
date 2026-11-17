"""Verify the server's shuffle, decrypt locally, and upload a decryption proof."""

import base64
from pathlib import Path
import sys

import requests
from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from server.shuffle import (BALLOT_FORMAT, create_decryption, election_rows,
                            hash_record, validate_key, verify_decryption, verify_shuffle)


server_url = "http://127.0.0.1:5000"


def decrypt_ballots():
    """The private key stays in this process; only plaintexts and proof are sent."""
    response = requests.get(f"{server_url}/election", timeout=30)
    response.raise_for_status()
    election = response.json()
    if election["state"] != "awaiting_trustee":
        raise ValueError("Close voting and wait for the shuffle before running this script.")
    record = election["record"]
    context = record["context"]
    if context["ballot_format"] != BALLOT_FORMAT:
        raise ValueError("Unsupported ballot format.")
    digest = hash_record({"context": context, "shuffle": record["shuffle"]})
    if digest != record["record_hash"]:
        raise ValueError("The election record hash does not match.")

    # Read the trustee's own public file rather than trusting a substituted key.
    folder = Path(__file__).resolve().parent
    expected_public = folder.joinpath("public_key.bin").read_bytes()
    received_public = base64.b64decode(context["public_key"], validate=True)
    if received_public != expected_public:
        raise ValueError("The server is using a different election public key.")
    public_scheme = Serialization.unpack(expected_public, use_pickle=False)[1]
    validate_key(public_scheme)
    rows = election_rows(context, public_scheme)
    print("Checking the shuffle proof...", flush=True)
    if not verify_shuffle(rows, record["shuffle"], public_scheme, context):
        raise ValueError("Invalid shuffle proof. No decryption was performed.")

    private_data = folder.joinpath("private_key.bin").read_bytes()
    # TNO caches schemes by public key. Remove the public-only cached instance
    # so loading the private file really restores the trustee's secret key.
    ElGamal.clear_instances()
    scheme = Serialization.unpack(private_data, use_pickle=False)[1]
    if not isinstance(scheme, ElGamal) or scheme.public_key != public_scheme.public_key:
        raise ValueError("The trustee's private key does not match the public key.")
    scheme.share_secret_key = False
    print("Shuffle verified. Decrypting and creating the trustee proof...", flush=True)
    result = create_decryption(record["shuffle"]["output"], scheme, record["record_hash"])
    result["record_hash"] = record["record_hash"]
    if not verify_decryption(record["shuffle"]["output"], result, public_scheme, record["record_hash"]):
        raise ValueError("The generated decryption proof did not verify.")

    response = requests.post(f"{server_url}/trustee/tally", json=result, timeout=120)
    response.raise_for_status()
    print(f"Server tally: {response.json()['tally']}")


if __name__ == "__main__":
    try:
        decrypt_ballots()
    except (OSError, ValueError, TypeError, KeyError, AttributeError, requests.RequestException) as error:
        raise SystemExit(f"Trustee error: {error}") from error
