"""Trusted setup for a two-of-three trustee election. No full private key is saved."""

import base64
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from server.threshold import create_setup


def generate_keys():
    folder = Path(__file__).resolve().parent / "threshold"
    # A separate directory preserves the old single-trustee election keys.
    if folder.exists():
        raise SystemExit("Threshold setup already exists. Keep it for this election.")
    print("Generating a public key and three shares; any two trustees can decrypt.", flush=True)
    scheme, manifest, shares = create_setup(bits=1024)
    folder.mkdir(mode=0o700)
    (folder / "public_key.bin").write_bytes(base64.b64decode(manifest["public_key"]))
    (folder / "trustees.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    for share in shares:
        file = folder / f"trustee_{share['trustee_id']}.json"
        descriptor = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(share, output, indent=2)
        print(f"Trustee {share['trustee_id']} private share: {file}", flush=True)
    print(f"Public key and trustee commitments: {folder}", flush=True)
    print("Distribute each private share to its trustee. No complete private key was saved.", flush=True)


if __name__ == "__main__":
    generate_keys()
