"""Accept ballots, publish a verified shuffle, and tally trustee decryptions."""

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import secrets
from threading import Lock, Thread

from flask import Flask, jsonify, request
from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal

# Support both `python server/server.py` and importing the module in tests.
if __package__:
    from .shuffle import (BALLOT_FORMAT, count_votes, create_shuffle, election_rows,
                          hash_record, read_ballot, validate_key, verify_shuffle)
    from .threshold import REQUIRED, combine_partials, validate_manifest, verify_partial
    from .authentication import validate_roster, verify_authorizations, verify_signature
else:
    from shuffle import (BALLOT_FORMAT, count_votes, create_shuffle, election_rows,
                         hash_record, read_ballot, validate_key, verify_shuffle)
    from threshold import REQUIRED, combine_partials, validate_manifest, verify_partial
    from authentication import validate_roster, verify_authorizations, verify_signature


app = Flask(__name__)

# Resolve the file from this script, regardless of where Python is started.
voters_file = Path(__file__).resolve().parent / "voters_list.txt"

# Only public signing keys are registered with the server.
voter_roster = None

# Global variable of the bulletin, all ballots being cast
g_buletin = []

# Keep voter eligibility separate from the list of encrypted ballots.
submitted_voters = set()
ballot_lock = Lock()
public_key = None
public_scheme = None

# Closing is final for this in-memory election. A restart starts a new election.
election_id = secrets.token_hex(16)
election_state = "open"
election_record = None
election_result = None
trustee_manifest = None
trustee_partials = {}


def _load_voters():
    """Load the public signing roster created by trusted voter setup."""
    global voter_roster
    file = Path(__file__).resolve().parent / "voter_keys.json"
    try:
        roster = json.loads(file.read_text(encoding="utf-8"))
        names = voters_file.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError("Run client/generate_signing_keys.py before starting the server.") from error
    validate_roster(roster)
    if names != [voter["name"] for voter in roster["voters"]]:
        raise ValueError("Registered signing keys do not match the eligible voter list.")
    voter_roster = roster
    print(f"Registered {len(names)} voter public signing keys; no passwords are used.", flush=True)


def _start_server():
    """Listen locally without restarting the in-memory election automatically."""
    Thread(target=_read_commands, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


@app.get("/public_key")
def get_public_key():
    """Publish the trustee's public key, never the private key."""
    if public_scheme is None:
        return jsonify(error="Election public key is not loaded"), 503

    return jsonify(public_key=public_key, election_id=election_id, voters=deepcopy(voter_roster))


@app.post("/submit_ballot")
def submit_ballot():
    """Authenticate, store the ciphertext, and return its SHA-256 hash."""
    print("Received a ballot submission.", flush=True)

    if public_scheme is None or voter_roster is None:
        return jsonify(error="Election setup is not loaded"), 503
    data = request.get_json(silent=True)
    fields = ("name", "election_id", "ballot", "signature")
    if not isinstance(data, dict) or any(not isinstance(data.get(field), str) for field in fields):
        return jsonify(error="Expected name, election_id, ballot, and signature strings"), 400
    name = data["name"]
    ballot = data["ballot"]
    try:
        ballot_hash = hashlib.sha256(ballot.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        return jsonify(error="The ballot must be valid UTF-8 text"), 400
    if data["election_id"] != election_id or not verify_signature(
        election_id, name, ballot, data["signature"], voter_roster
    ):
        return jsonify(error="Invalid voter signature or election identifier"), 401

    # Validate the fixed-width ciphertext format before accepting it. This does
    # not prove a valid plaintext; invalid encodings are reported after decryption.
    try:
        read_ballot(ballot, public_scheme)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError, NotImplementedError):
        return jsonify(error="Invalid ballot: expected five blocks using this election key"), 400

    # Keep the check and insertion together so simultaneous requests cannot
    # submit two ballots for the same voter in this single-process server.
    with ballot_lock:
        if election_state != "open":
            return jsonify(error="Voting is closed"), 409

        if name in submitted_voters:
            return jsonify(error="You have already submitted a ballot"), 409

        if any(entry["hash"] == ballot_hash for entry in g_buletin):
            return jsonify(error="This ciphertext has already been submitted"), 409

        g_buletin.append({"name": name, "ballot": ballot, "hash": ballot_hash, "signature": data["signature"]})
        submitted_voters.add(name)

    return jsonify(hash=ballot_hash), 200


def _close_election():
    """Freeze the bulletin, shuffle its ballots, and publish the proof."""
    global election_state, election_record

    with ballot_lock:
        if election_state != "open":
            print("Voting has already been closed.", flush=True)
            return
        if public_scheme is None:
            print("Cannot close: the election key is not loaded.", flush=True)
            return
        election_state = "mixing"
        context = {"election_id": election_id, "public_key": public_key,
                   "ballot_format": BALLOT_FORMAT, "ballots": deepcopy(g_buletin),
                   "trustees": deepcopy(trustee_manifest), "voters": deepcopy(voter_roster)}

    print("Voting closed. Creating the verifiable shuffle...", flush=True)
    try:
        verify_authorizations(context, voter_roster)
        rows = election_rows(context, public_scheme)
        proof = create_shuffle(rows, public_scheme, context)
        if not verify_shuffle(rows, proof, public_scheme, context):
            raise ValueError("The generated shuffle proof did not verify.")
        record = {"context": context, "shuffle": proof}
        record["record_hash"] = hash_record(record)
        with ballot_lock:
            election_record = record
            election_state = "awaiting_trustees"
        print("Shuffle verified. Waiting for partial decryptions from two of three trustees.", flush=True)
    except Exception as error:
        # Stay closed on failure; never silently reopen voting or publish a tally.
        with ballot_lock:
            election_state = "failed"
        print(f"Election processing failed: {error}", flush=True)


def _read_commands():
    """Read operator commands while Flask continues serving HTTP requests."""
    print("Type close and press Enter to close voting and start the shuffle.", flush=True)
    while True:
        try:
            command = input().strip().lower()
        except EOFError:
            return
        if command == "close":
            _close_election()
        elif command:
            print("Unknown command. Type close to close voting.", flush=True)


@app.get("/election")
def get_election():
    """Expose the public record for trustee processing and later verification."""
    with ballot_lock:
        return jsonify(state=election_state, record=deepcopy(election_record), result=deepcopy(election_result),
                       trustee_progress={"required": REQUIRED, "received": len(trustee_partials),
                                         "trustees": sorted(trustee_partials)})


@app.post("/trustee/partial_decryption")
def receive_decryption():
    """Verify one trustee's factors; only two distinct trustees unlock a tally."""
    global election_state, election_result

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Expected a trustee partial-decryption object"), 400
    with ballot_lock:
        if election_state != "awaiting_trustees":
            return jsonify(error="The election is not awaiting trustee decryption"), 409
        record = election_record

    if data.get("record_hash") != record["record_hash"]:
        return jsonify(error="Trustee result belongs to a different election record"), 400
    if not verify_partial(record["shuffle"]["output"], data, trustee_manifest, public_scheme, record["record_hash"]):
        return jsonify(error="Trustee partial-decryption proof did not verify"), 400

    with ballot_lock:
        if election_state != "awaiting_trustees":
            return jsonify(error="The election has already been tallied"), 409
        index = data["trustee_id"]
        if index in trustee_partials:
            return jsonify(error="This trustee has already contributed"), 409
        trustee_partials[index] = deepcopy(data)
        received = len(trustee_partials)
        print(f"Verified trustee {index}: {received} of {REQUIRED} required contributions.", flush=True)
        if received < REQUIRED:
            return jsonify(state=election_state, received=received, required=REQUIRED, tally=None), 200

        partials = list(trustee_partials.values())
        messages = combine_partials(record["shuffle"]["output"], partials, trustee_manifest,
                                    public_scheme, record["record_hash"])
        decryption = {"record_hash": record["record_hash"], "partials": partials, "messages": messages}
        tally = count_votes(messages)
        election_result = {"decryption": decryption, "tally": tally}
        election_state = "tallied"
    print(f"Tally complete: {tally['counts']} | Invalid ballots: {len(tally['invalid_ballots'])}", flush=True)
    return jsonify(state=election_state, received=received, required=REQUIRED, tally=tally), 200


def _load_public_key():
    """Load only the public file produced by the separate trustee script."""
    global public_key, public_scheme, trustee_manifest

    folder = Path(__file__).resolve().parent.parent / "trustee" / "threshold"
    file = folder / "public_key.bin"
    try:
        data = file.read_bytes()
    except OSError as error:
        raise ValueError("Run trustee/generate_keys.py before starting the server.") from error

    if not data:
        raise ValueError("The election public key file is empty.")

    scheme = Serialization.unpack(data, use_pickle=False)[1]
    if not isinstance(scheme, ElGamal):
        raise ValueError("Expected an ElGamal election public key.")
    validate_key(scheme)
    # Retain a public-only instance even if another local module used this key.
    public_scheme = ElGamal(scheme.public_key, secret_key=None)
    public_key = base64.b64encode(data).decode("ascii")
    trustee_manifest = json.loads((folder / "trustees.json").read_text(encoding="utf-8"))
    if trustee_manifest["public_key"] != public_key:
        raise ValueError("Public key file differs from the trustee manifest.")
    validate_manifest(trustee_manifest, public_scheme)


if __name__ == "__main__":
    try:
        _load_public_key()
        _load_voters()
    except ValueError as error:
        raise SystemExit(f"Startup error: {error}") from error

    _start_server()
