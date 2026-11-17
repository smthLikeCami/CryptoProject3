"""Verify the shuffle and upload one trustee's proven partial decryptions."""

import argparse
import base64
import json
from pathlib import Path
import sys

import requests
from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from server.shuffle import BALLOT_FORMAT, election_rows, hash_record, verify_shuffle
from server.threshold import create_partial, validate_manifest, verify_partial
from server.authentication import verify_authorizations


server_url = "http://127.0.0.1:5000"


def decrypt_ballots(trustee_id):
    """Read only this trustee's private share, never another trustee's share."""
    response = requests.get(f"{server_url}/election", timeout=30)
    response.raise_for_status()
    election = response.json()
    if election["state"] != "awaiting_trustees":
        raise ValueError("Close voting and wait for the shuffle before contributing.")
    record = election["record"]
    context = record["context"]
    if context["ballot_format"] != BALLOT_FORMAT:
        raise ValueError("Unsupported ballot format.")
    digest = hash_record({"context": context, "shuffle": record["shuffle"]})
    if digest != record["record_hash"]:
        raise ValueError("The election record hash does not match.")

    folder = Path(__file__).resolve().parent / "threshold"
    public_data = (folder / "public_key.bin").read_bytes()
    manifest = json.loads((folder / "trustees.json").read_text(encoding="utf-8"))
    if base64.b64decode(context["public_key"], validate=True) != public_data:
        raise ValueError("The server is using a different election public key.")
    if hash_record(context["trustees"]) != hash_record(manifest):
        raise ValueError("The server changed the trusted trustee manifest.")
    loaded = Serialization.unpack(public_data, use_pickle=False)[1]
    scheme = ElGamal(loaded.public_key, secret_key=None)
    validate_manifest(manifest, scheme)
    roster_file = Path(__file__).resolve().parent.parent / "server" / "voter_keys.json"
    verify_authorizations(context, json.loads(roster_file.read_text(encoding="utf-8")))
    rows = election_rows(context, scheme)
    print(f"Trustee {trustee_id}: checking the shuffle proof...", flush=True)
    if not verify_shuffle(rows, record["shuffle"], scheme, context):
        raise ValueError("Invalid shuffle proof. No partial decryption was performed.")

    share = json.loads((folder / f"trustee_{trustee_id}.json").read_text(encoding="utf-8"))
    if type(trustee_id) is not int or share["trustee_id"] != trustee_id:
        raise ValueError("Incorrect trustee share file.")
    print(f"Trustee {trustee_id}: creating partial decryptions and a proof using only my share.", flush=True)
    partial = create_partial(record["shuffle"]["output"], share, manifest, scheme, digest)
    if not verify_partial(record["shuffle"]["output"], partial, manifest, scheme, digest):
        raise ValueError("The generated partial-decryption proof did not verify.")
    response = requests.post(f"{server_url}/trustee/partial_decryption", json=partial, timeout=120)
    response.raise_for_status()
    result = response.json()
    print(f"Server has {result['received']} of {result['required']} required trustee contributions.", flush=True)
    if result["tally"] is None:
        print("One contribution cannot decrypt the ballots; no plaintext or tally is available.", flush=True)
    else:
        print(f"Threshold reached. Server tally: {result['tally']}", flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trustee", type=int, choices=(1, 2, 3), required=True)
    args = parser.parse_args()
    try:
        decrypt_ballots(args.trustee)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, requests.RequestException) as error:
        raise SystemExit(f"Trustee error: {error}") from error
