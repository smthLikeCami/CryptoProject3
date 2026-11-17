"""Accept ballots, publish a verified shuffle, and tally trustee decryptions."""

import base64
from copy import deepcopy
import hashlib
from pathlib import Path
import secrets
from threading import Lock, Thread

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash
from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal

# Support both `python server/server.py` and importing the module in tests.
if __package__:
    from .shuffle import (BALLOT_FORMAT, count_votes, create_shuffle, election_rows,
                          hash_record, read_ballot, validate_key, verify_decryption, verify_shuffle)
else:
    from shuffle import (BALLOT_FORMAT, count_votes, create_shuffle, election_rows,
                         hash_record, read_ballot, validate_key, verify_decryption, verify_shuffle)


app = Flask(__name__)

# Resolve the file from this script, regardless of where Python is started.
voters_file = Path(__file__).resolve().parent / "voters_list.txt"

# Store password hashes, indexed by the exact voter name.
voter_hashes = {}

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


def _print_authenticated_users():
    """Load voters, generate new passwords, and print them once at startup."""
    try:
        names = voters_file.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError(f"Cannot read voters file: {voters_file}") from error

    if not names:
        raise ValueError("The voters file must contain at least one voter.")

    # Validate the entire list before generating or printing any credentials.
    seen_names = set()

    for line, name in enumerate(names, start=1):
        if not name.strip():
            raise ValueError(f"Empty voter name on line {line}.")

        if name in seen_names:
            raise ValueError(f"Duplicate voter name on line {line}: {name}")

        seen_names.add(name)

    voter_hashes.clear()
    passwords = {}

    for name in names:
        password = secrets.token_urlsafe(16)
        voter_hashes[name] = generate_password_hash(password)
        passwords[name] = password

        # For this prototype, display passwords instead of emailing them.
        print(f"Voter: {name} | Password: {password}", flush=True)

    # The mock-election runner uses this to simulate delivering credentials.
    # Normal server startup ignores the return value.
    return passwords


def _start_server():
    """Listen locally without a reloader that would regenerate passwords."""
    Thread(target=_read_commands, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


def _check_credentials(name, password):
    """Check the credentials supplied with an HTTP request."""
    password_hash = voter_hashes.get(name)

    if password_hash is None:
        return False

    return check_password_hash(password_hash, password)


def _handle_client(request):
    """Validate the request and authenticate without creating a session."""
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return _invalid_request()

    name = data.get("name")
    password = data.get("password")

    if not isinstance(name, str) or not name.strip():
        return _invalid_request()

    if not isinstance(password, str) or not password.strip():
        return _invalid_request()

    # Use the same response for unknown voters and incorrect passwords.
    if not _check_credentials(name, password):
        return jsonify(error="Invalid name or password"), 401

    return jsonify(message="Authentication successful"), 200


def _invalid_request():
    """Keep the validation response consistent for all invalid input."""
    return jsonify(error="Expected nonempty name and password strings"), 400


@app.post("/authenticate")
def authenticate():
    """Accept JSON containing a voter name and password."""
    return _handle_client(request)


@app.get("/public_key")
def get_public_key():
    """Publish the trustee's public key, never the private key."""
    if public_scheme is None:
        return jsonify(error="Election public key is not loaded"), 503

    return jsonify(public_key=public_key)


@app.post("/submit_ballot")
def submit_ballot():
    """Authenticate, store the ciphertext, and return its SHA-256 hash."""
    print("Received a ballot submission.", flush=True)

    # Reuse the same authentication checks as the temporary login endpoint.
    response, status = _handle_client(request)
    if status != 200:
        return response, status

    if public_scheme is None:
        return jsonify(error="Election public key is not loaded"), 503

    data = request.get_json()
    name = data["name"]
    ballot = data.get("ballot")

    if not isinstance(ballot, str):
        return jsonify(error="Expected a ballot string"), 400

    try:
        ballot_bytes = ballot.encode("utf-8")
    except UnicodeEncodeError:
        return jsonify(error="The ballot must be valid UTF-8 text"), 400

    ballot_hash = hashlib.sha256(ballot_bytes).hexdigest()

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

        g_buletin.append({"ballot": ballot, "hash": ballot_hash})
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
                   "ballot_format": BALLOT_FORMAT, "ballots": deepcopy(g_buletin)}

    print("Voting closed. Creating the verifiable shuffle...", flush=True)
    try:
        rows = election_rows(context, public_scheme)
        proof = create_shuffle(rows, public_scheme, context)
        if not verify_shuffle(rows, proof, public_scheme, context):
            raise ValueError("The generated shuffle proof did not verify.")
        record = {"context": context, "shuffle": proof}
        record["record_hash"] = hash_record(record)
        with ballot_lock:
            election_record = record
            election_state = "awaiting_trustee"
        print("Shuffle verified. Run trustee/decrypt_ballots.py to finish tallying.", flush=True)
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
        return jsonify(state=election_state, record=deepcopy(election_record), result=deepcopy(election_result))


@app.post("/trustee/tally")
def receive_decryption():
    """Accept plaintexts only when their proof verifies against the frozen shuffle."""
    global election_state, election_result

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Expected a trustee result object"), 400
    with ballot_lock:
        if election_state != "awaiting_trustee":
            return jsonify(error="The election is not awaiting trustee decryption"), 409
        record = election_record

    if data.get("record_hash") != record["record_hash"]:
        return jsonify(error="Trustee result belongs to a different election record"), 400
    if not verify_decryption(record["shuffle"]["output"], data, public_scheme, record["record_hash"]):
        return jsonify(error="Trustee decryption proof did not verify"), 400

    tally = count_votes(data["messages"])
    with ballot_lock:
        # Another concurrent trustee upload may have finished while we verified.
        if election_state != "awaiting_trustee":
            return jsonify(error="The election has already been tallied"), 409
        election_result = {"decryption": data, "tally": tally}
        election_state = "tallied"
    print(f"Tally complete: {tally['counts']} | Invalid ballots: {len(tally['invalid_ballots'])}", flush=True)
    return jsonify(tally=tally), 200


def _load_public_key():
    """Load only the public file produced by the separate trustee script."""
    global public_key, public_scheme

    file = Path(__file__).resolve().parent.parent / "trustee" / "public_key.bin"
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


if __name__ == "__main__":
    try:
        _load_public_key()
        _print_authenticated_users()
    except ValueError as error:
        raise SystemExit(f"Startup error: {error}") from error

    _start_server()
