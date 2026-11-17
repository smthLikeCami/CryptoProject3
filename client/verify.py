"""Check a published election using a trusted public key and optional receipt."""

import argparse
import base64
import json
from pathlib import Path
import sys

import requests
from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from server.shuffle import (BALLOT_FORMAT, count_votes, election_rows, hash_record,
                            verify_shuffle)
from server.threshold import validate_manifest, verify_threshold_decryption
from server.authentication import verify_authorizations


def verify_election(election, public_data, receipt=None, report=print, trustees=None, voters=None):
    """Verify public evidence; never request a voter password or private key."""
    if not isinstance(election, dict) or election.get("state") != "tallied":
        raise ValueError("The election has not finished tallying.")

    record = election["record"]
    context = record["context"]
    result = election["result"]

    # A key supplied by the server alone is not a trust anchor. Compare it with
    # the public key obtained independently before this verification request.
    received_key = base64.b64decode(context["public_key"], validate=True)
    if received_key != public_data:
        raise ValueError("The published election key differs from the trusted public key.")
    loaded = Serialization.unpack(public_data, use_pickle=False)[1]
    if not isinstance(loaded, ElGamal):
        raise ValueError("Expected an ElGamal public key.")
    scheme = ElGamal(loaded.public_key, secret_key=None)
    if trustees is None or hash_record(context["trustees"]) != hash_record(trustees):
        raise ValueError("The published trustees differ from the trusted trustee manifest.")
    validate_manifest(trustees, scheme)
    if trustees["public_key"] != context["public_key"]:
        raise ValueError("Trustee manifest differs from the published election key.")
    report("PASS: the election uses the trusted public key; no private key is needed.")
    report("PASS: public share commitments enforce a two-of-three trustee policy.")

    if context["ballot_format"] != BALLOT_FORMAT:
        raise ValueError("Unsupported ballot format.")
    if not isinstance(context["election_id"], str) or not context["election_id"]:
        raise ValueError("Missing election identifier.")
    digest = hash_record({"context": context, "shuffle": record["shuffle"]})
    if digest != record["record_hash"]:
        raise ValueError("The published record hash does not match its contents.")
    report(f"PASS: election record hash matches ({digest}).")

    rows = election_rows(context, scheme)
    report(f"PASS: all {len(rows)} input receipt hashes and ciphertext formats check out.")
    if voters is None:
        raise ValueError("A trusted voter public-key roster is required.")
    verify_authorizations(context, voters)
    report("PASS: every input has a valid Ed25519 signature from a distinct eligible voter.")
    if receipt is not None:
        if not any(entry["hash"] == receipt for entry in context["ballots"]):
            raise ValueError("Your receipt is missing from the frozen input bulletin.")
        report("PASS: your saved receipt appears in the election input bulletin.")
    else:
        report("No receipt supplied: individual ballot inclusion was not checked.")

    report("Checking all shuffle-proof rounds; the secret permutation is not required...")
    if not verify_shuffle(rows, record["shuffle"], scheme, context):
        raise ValueError("The shuffle proof is invalid.")
    report("PASS: the shuffled ballots are a re-encrypted permutation of the input ballots.")

    decryption = result["decryption"]
    if decryption["record_hash"] != digest:
        raise ValueError("The decryption belongs to another election record.")
    report("Checking distinct trustee proofs and combining their public decryption factors...")
    if not verify_threshold_decryption(record["shuffle"]["output"], decryption, trustees, scheme, digest):
        raise ValueError("The threshold decryption proof is invalid.")
    report("PASS: at least two valid trustee contributions reproduce the published plaintexts.")

    tally = count_votes(decryption["messages"])
    if hash_record(tally) != hash_record(result["tally"]):
        raise ValueError("The server's published tally differs from the verified plaintexts.")
    report(f"PASS: independently recomputed tally matches: {tally['counts']}.")
    report(f"Checked {tally['total_count']} ballots; {len(tally['invalid_ballots'])} invalid encodings.")
    return tally


def verify_server(server_url, public_file, receipt=None, report=print, voters_file=None):
    """Download evidence over HTTP and verify against a local public key file."""
    public_data = Path(public_file).read_bytes()
    trustees = json.loads(Path(public_file).with_name("trustees.json").read_text(encoding="utf-8"))
    if voters_file is None:
        voters_file = Path(__file__).resolve().parent / "signing_keys" / "voters.json"
    voters = json.loads(Path(voters_file).read_text(encoding="utf-8"))
    report("Downloading the published election record over HTTP...")
    response = requests.get(f"{server_url.rstrip('/')}/election", timeout=60)
    response.raise_for_status()
    return verify_election(response.json(), public_data, receipt, report, trustees, voters)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="http://127.0.0.1:5000")
    parser.add_argument("--public-key", type=Path,
                        default=Path(__file__).resolve().parent.parent / "trustee" / "threshold" / "public_key.bin")
    parser.add_argument("--receipt", help="The SHA-256 receipt printed when your ballot was cast")
    parser.add_argument("--voters", type=Path, help="Independently trusted voter public-key roster")
    args = parser.parse_args()

    try:
        verify_server(args.server, args.public_key, args.receipt, voters_file=args.voters)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, requests.RequestException) as error:
        raise SystemExit(f"Verification failed: {error}") from error
