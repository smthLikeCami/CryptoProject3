"""Run the voting server's first step: voter authentication over HTTP."""

from pathlib import Path
import secrets

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)

# Resolve the file from this script, regardless of where Python is started.
voters_file = Path(__file__).resolve().parent / "voters_list.txt"

# Store password hashes, indexed by the exact voter name.
voter_hashes = {}

# Global variable of the bulletin, all ballots being cast
g_buletin = []


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
    """Check credentials; later, ballot submission can reuse this function."""
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


if __name__ == "__main__":
    try:
        _print_authenticated_users()
    except ValueError as error:
        raise SystemExit(f"Startup error: {error}") from error

    _start_server()
