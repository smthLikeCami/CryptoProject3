"""Authenticate voters and accept one encrypted ballot per voter."""

import base64
import hashlib
from pathlib import Path
import secrets
from threading import Lock

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash


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

    for name in names:
        password = secrets.token_urlsafe(16)
        voter_hashes[name] = generate_password_hash(password)

        # For this prototype, display passwords instead of emailing them.
        print(f"Voter: {name} | Password: {password}", flush=True)


def _start_server():
    """Listen locally without a reloader that would regenerate passwords."""
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
    if public_key is None:
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

    if public_key is None:
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

    # Keep the check and insertion together so simultaneous requests cannot
    # submit two ballots for the same voter in this single-process server.
    with ballot_lock:
        if name in submitted_voters:
            return jsonify(error="You have already submitted a ballot"), 409

        g_buletin.append({"ballot": ballot, "hash": ballot_hash})
        submitted_voters.add(name)

    return jsonify(hash=ballot_hash), 200


def _load_public_key():
    """Load only the public file produced by the separate trustee script."""
    global public_key

    file = Path(__file__).resolve().parent.parent / "trustee" / "public_key.bin"
    try:
        data = file.read_bytes()
    except OSError as error:
        raise ValueError("Run trustee/generate_keys.py before starting the server.") from error

    if not data:
        raise ValueError("The election public key file is empty.")

    public_key = base64.b64encode(data).decode("ascii")


if __name__ == "__main__":
    try:
        _load_public_key()
        _print_authenticated_users()
    except ValueError as error:
        raise SystemExit(f"Startup error: {error}") from error

    _start_server()
