"""Ed25519 voter authorization shared by clients, server, and public verifiers."""

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


ROSTER_VERSION = "ed25519-voters-v1"


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def public_key_text(private_key):
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def validate_roster(roster):
    """Reject ambiguous identities or a signing key registered for two voters."""
    if roster["version"] != ROSTER_VERSION or not isinstance(roster["voters"], list) or not roster["voters"]:
        raise ValueError("Expected a nonempty Ed25519 voter roster.")
    names = set()
    keys = set()
    for voter in roster["voters"]:
        if set(voter) != {"name", "public_key"}:
            raise ValueError("Expected a voter name and public signing key.")
        name = voter["name"]
        if not isinstance(name, str) or not name.strip() or name in names:
            raise ValueError("Voter names must be nonempty and unique.")
        raw = base64.b64decode(voter["public_key"], validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
        if raw in keys:
            raise ValueError("Each voter must have a different signing key.")
        names.add(name)
        keys.add(raw)


def _voter_key(roster, name):
    for voter in roster["voters"]:
        if voter["name"] == name:
            return Ed25519PublicKey.from_public_bytes(base64.b64decode(voter["public_key"], validate=True))
    raise ValueError("Unknown voter.")


def signing_message(election_id, name, ballot, roster):
    """Bind the signature to the action, election, voter, roster, and exact ciphertext."""
    return _json_bytes({
        "purpose": "cast-encrypted-ballot-v1", "election_id": election_id, "name": name,
        "ballot_hash": hashlib.sha256(ballot.encode("utf-8")).hexdigest(),
        "roster_hash": hashlib.sha256(_json_bytes(roster)).hexdigest(),
    })


def sign_ballot(private_key, election_id, name, ballot, roster):
    """Return a signature only; the private key never leaves the client."""
    expected = _voter_key(roster, name).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    actual = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if actual != expected:
        raise ValueError("Private signing key does not match the registered voter.")
    signature = private_key.sign(signing_message(election_id, name, ballot, roster))
    return base64.b64encode(signature).decode("ascii")


def load_signing_key(file):
    key = serialization.load_pem_private_key(file.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private signing key.")
    return key


def verify_signature(election_id, name, ballot, signature, roster):
    try:
        raw = base64.b64decode(signature, validate=True)
        if len(raw) != 64:
            return False
        _voter_key(roster, name).verify(raw, signing_message(election_id, name, ballot, roster))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False


def verify_authorizations(context, trusted_roster):
    """Public check: every input was signed by a distinct registered voter."""
    validate_roster(trusted_roster)
    if _json_bytes(context["voters"]) != _json_bytes(trusted_roster):
        raise ValueError("Published voter roster differs from the trusted roster.")
    seen = set()
    for entry in context["ballots"]:
        name = entry["name"]
        if name in seen or not verify_signature(context["election_id"], name, entry["ballot"], entry["signature"], trusted_roster):
            raise ValueError("Invalid voter signature or repeated voter in the input bulletin.")
        if hashlib.sha256(entry["ballot"].encode("utf-8")).hexdigest() != entry["hash"]:
            raise ValueError("Signed ballot receipt hash is incorrect.")
        seen.add(name)
