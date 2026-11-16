"""Generate the election keys separately from the voting server."""

from pathlib import Path
import os

from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal


def generate_keys():
    """Save the public key for the server and keep the private key here."""
    folder = Path(__file__).resolve().parent
    public_file = folder / "public_key.bin"
    private_file = folder / "private_key.bin"

    # Do not accidentally replace the keys for an election already in progress.
    if public_file.exists() or private_file.exists():
        raise SystemExit("Key files already exist. Keep them for this election.")

    print("Generating the election keys. This may take a while.")
    # Use a smaller key to speed up safe-prime generation for this demonstration.
    # This is a prototype setting, not a recommended key size for a real election.
    # To restore the stronger version, change 1024 to 2048 (or larger) and
    # generate a fresh key pair for a new election. Never replace active keys.
    scheme = ElGamal.from_security_parameter(bits=1024)

    # TNO's serialization excludes the secret key unless explicitly enabled.
    scheme.share_secret_key = False
    public_data = Serialization.pack(scheme, msg_id="", use_pickle=False)

    scheme.share_secret_key = True
    private_data = Serialization.pack(scheme, msg_id="", use_pickle=False)
    scheme.share_secret_key = False

    # Only the file owner should be able to read the private key.
    file_number = os.open(private_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(file_number, "wb") as file:
        file.write(private_data)

    with public_file.open("xb") as file:
        file.write(public_data)

    print(f"Public key: {public_file}")
    print(f"Private key: {private_file} (keep this with the trustee)")


if __name__ == "__main__":
    generate_keys()
