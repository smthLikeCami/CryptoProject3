"""Trusted voter setup: generate signing keys and distribute the public roster."""

import json
import os
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from server.authentication import ROSTER_VERSION, public_key_text, validate_roster


def generate_signing_keys():
    project = Path(__file__).resolve().parent.parent
    folder = project / "client" / "signing_keys"
    public_file = project / "server" / "voter_keys.json"
    if folder.exists() or public_file.exists():
        raise SystemExit("Voter signing setup already exists; existing keys will not be overwritten.")
    names = (project / "server" / "voters_list.txt").read_text(encoding="utf-8").splitlines()
    keys = [Ed25519PrivateKey.generate() for _ in names]
    roster = {"version": ROSTER_VERSION,
              "voters": [{"name": name, "public_key": public_key_text(key)} for name, key in zip(names, keys)]}
    validate_roster(roster)
    folder.mkdir(mode=0o700)
    for index, (name, key) in enumerate(zip(names, keys), start=1):
        file = folder / f"voter_{index}.pem"
        data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        descriptor = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
        print(f"{name}: deliver private signing file {file}", flush=True)
    public_text = json.dumps(roster, indent=2)
    (folder / "voters.json").write_text(public_text, encoding="utf-8")
    public_file.write_text(public_text, encoding="utf-8")
    print("Public roster registered with the server. Distribute each private file only to its voter.", flush=True)


if __name__ == "__main__":
    generate_signing_keys()
