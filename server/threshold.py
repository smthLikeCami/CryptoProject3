"""Two-of-three ElGamal sharing, verifiable partial decryption, and combination.

Setup knows the full secret temporarily. After setup, each trustee uses only
its own share; combining partial decryptions never reconstructs the secret.
"""

import base64
import secrets

from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal
from tno.mpc.encryption_schemes.elgamal.elgamal_base import ElGamalPublicKey
from tno.mpc.encryption_schemes.utils import pow_mod

if __package__:
    from .shuffle import BLOCK_COUNT, _number, hash_record, read_rows, validate_key
else:
    from shuffle import BLOCK_COUNT, _number, hash_record, read_rows, validate_key


VERSION = "threshold-elgamal-2of3-v1"
REQUIRED = 2
TRUSTEE_COUNT = 3


def create_setup(bits=1024):
    """Trusted setup: return a public scheme, public manifest, and three shares."""
    base = ElGamal.from_security_parameter(bits=bits)
    prime = base.public_key.p
    order = (prime - 1) // 2
    generator = pow_mod(base.public_key.g, 2, prime)
    secret = secrets.randbelow(order - 1) + 1

    # A degree-one Shamir polynomial makes any two points sufficient.
    # Reject zero coefficients/shares, which would weaken this concrete setup.
    while True:
        slope = secrets.randbelow(order - 1) + 1
        values = [(secret + slope * index) % order for index in range(1, 4)]
        if all(values):
            break

    public = pow_mod(generator, secret, prime)
    scheme = ElGamal(ElGamalPublicKey(prime, generator, public), secret_key=None)
    public_data = Serialization.pack(scheme, msg_id="", use_pickle=False)
    manifest = {
        "version": VERSION, "threshold": REQUIRED, "trustee_count": TRUSTEE_COUNT,
        "public_key": base64.b64encode(public_data).decode("ascii"),
        "commitments": [str(public), str(pow_mod(generator, slope, prime))],
        "trustees": [{"id": index, "public_share": str(pow_mod(generator, value, prime))}
                     for index, value in enumerate(values, start=1)],
    }
    shares = [{"version": VERSION, "trustee_id": index, "share": str(value),
               "manifest_hash": hash_record(manifest)}
              for index, value in enumerate(values, start=1)]
    validate_manifest(manifest, scheme)
    return scheme, manifest, shares


def _member(value, scheme, identity=True):
    """Read a group element and reject elements outside the prime-order subgroup."""
    prime = scheme.public_key.p
    number = _number(value, prime, minimum=1 if identity else 2)
    if pow_mod(number, (prime - 1) // 2, prime) != 1:
        raise ValueError("Element is outside the election subgroup.")
    return number


def validate_manifest(manifest, scheme):
    """Check the threshold policy and public commitments to all three shares."""
    validate_key(scheme)
    if manifest["version"] != VERSION or type(manifest["threshold"]) is not int or manifest["threshold"] != REQUIRED:
        raise ValueError("Expected the two-of-three trustee policy.")
    if type(manifest["trustee_count"]) is not int or manifest["trustee_count"] != TRUSTEE_COUNT:
        raise ValueError("Expected exactly three trustees.")
    public = Serialization.unpack(base64.b64decode(manifest["public_key"], validate=True), use_pickle=False)[1]
    if not isinstance(public, ElGamal) or public.public_key != scheme.public_key:
        raise ValueError("Trustee manifest uses a different election key.")
    commitments = manifest["commitments"]
    trustees = manifest["trustees"]
    if not isinstance(commitments, list) or len(commitments) != REQUIRED:
        raise ValueError("Expected two polynomial commitments.")
    constant, slope = [_member(value, scheme, identity=False) for value in commitments]
    if constant != scheme.public_key.h:
        raise ValueError("Polynomial commitment differs from the election key.")
    if not isinstance(trustees, list) or len(trustees) != TRUSTEE_COUNT:
        raise ValueError("Expected three public trustee shares.")
    for index, trustee in enumerate(trustees, start=1):
        if set(trustee) != {"id", "public_share"} or type(trustee["id"]) is not int or trustee["id"] != index:
            raise ValueError("Trustee identifiers must be exactly 1, 2, and 3.")
        value = _member(trustee["public_share"], scheme, identity=False)
        if value != constant * pow_mod(slope, index, scheme.public_key.p) % scheme.public_key.p:
            raise ValueError("Public share does not match the committed polynomial.")


def _public_share(manifest, trustee_id):
    if type(trustee_id) is not int or trustee_id not in (1, 2, 3):
        raise ValueError("Unknown trustee identifier.")
    return int(manifest["trustees"][trustee_id - 1]["public_share"])


def _challenge(rows, partial, manifest, context):
    statement = {"domain": "threshold-partial-decryption-v1", "record_hash": context,
                 "manifest_hash": hash_record(manifest), "trustee_id": partial["trustee_id"],
                 "ciphertexts": rows, "factors": partial["factors"],
                 "commitments": partial["proof"]["commitments"]}
    return int(hash_record(statement), 16)


def create_partial(rows, share, manifest, scheme, context):
    """One trustee proves its partial decryptions without revealing its share."""
    validate_manifest(manifest, scheme)
    pairs = read_rows(rows, scheme)
    key = scheme.public_key
    order = (key.p - 1) // 2
    if share["version"] != VERSION or share["manifest_hash"] != hash_record(manifest):
        raise ValueError("This private share belongs to a different trustee setup.")
    index = share["trustee_id"]
    secret = _number(share["share"], order, minimum=1)
    if pow_mod(key.g, secret, key.p) != _public_share(manifest, index):
        raise ValueError("Private trustee share does not match its public share.")
    nonce = secrets.randbelow(order)
    partial = {
        "trustee_id": index, "record_hash": context,
        "factors": [[str(pow_mod(pair[0], secret, key.p)) for pair in row] for row in pairs],
        "proof": {"commitments": {
            "generator": str(pow_mod(key.g, nonce, key.p)),
            "blocks": [[str(pow_mod(pair[0], nonce, key.p)) for pair in row] for row in pairs],
        }},
    }
    challenge = _challenge(rows, partial, manifest, context) % order
    partial["proof"]["response"] = str((nonce + challenge * secret) % order)
    return partial


def verify_partial(rows, partial, manifest, scheme, context):
    """Verify a Chaum-Pedersen equality-of-discrete-log proof for every factor."""
    try:
        if set(partial) != {"trustee_id", "record_hash", "factors", "proof"}:
            return False
        if set(partial["proof"]) != {"commitments", "response"}:
            return False
        if set(partial["proof"]["commitments"]) != {"generator", "blocks"}:
            return False
        validate_manifest(manifest, scheme)
        pairs = read_rows(rows, scheme)
        if partial["record_hash"] != context:
            return False
        key = scheme.public_key
        order = (key.p - 1) // 2
        public = _public_share(manifest, partial["trustee_id"])
        commitments = partial["proof"]["commitments"]
        response = _number(partial["proof"]["response"], order)
        challenge = _challenge(rows, partial, manifest, context) % order
        generator = _member(commitments["generator"], scheme)
        if pow_mod(key.g, response, key.p) != generator * pow_mod(public, challenge, key.p) % key.p:
            return False
        factors = partial["factors"]
        blocks = commitments["blocks"]
        if not isinstance(factors, list) or not isinstance(blocks, list) or len(factors) != len(pairs) or len(blocks) != len(pairs):
            return False
        for row, values, proofs in zip(pairs, factors, blocks):
            if not isinstance(values, list) or not isinstance(proofs, list) or len(values) != BLOCK_COUNT or len(proofs) != BLOCK_COUNT:
                return False
            for pair, value, proof in zip(row, values, proofs):
                factor = _member(value, scheme)
                commitment = _member(proof, scheme)
                if pow_mod(pair[0], response, key.p) != commitment * pow_mod(factor, challenge, key.p) % key.p:
                    return False
        return True
    except (ValueError, TypeError, KeyError, IndexError, AttributeError):
        return False


def _weight(index, indices, order):
    """Lagrange coefficient for recovering the polynomial's value at zero."""
    result = 1
    for other in indices:
        if other != index:
            result = result * other * pow(other - index, -1, order) % order
    return result


def combine_partials(rows, partials, manifest, scheme, context):
    """Combine public factors from distinct trustees, never their secret shares."""
    validate_manifest(manifest, scheme)
    pairs = read_rows(rows, scheme)
    if not isinstance(partials, list) or not REQUIRED <= len(partials) <= TRUSTEE_COUNT:
        raise ValueError("At least two distinct trustees are required to decrypt.")
    indices = [partial["trustee_id"] for partial in partials]
    if any(type(index) is not int for index in indices) or len(set(indices)) != len(indices):
        raise ValueError("Trustee contributions must come from distinct trustees.")
    for partial in partials:
        if not verify_partial(rows, partial, manifest, scheme, context):
            raise ValueError("Invalid trustee partial-decryption proof.")
    key = scheme.public_key
    weights = [_weight(index, indices, (key.p - 1) // 2) for index in indices]
    messages = []
    for row_index, row in enumerate(pairs):
        plaintexts = []
        for block_index, pair in enumerate(row):
            factor = 1
            for partial, weight in zip(partials, weights):
                value = int(partial["factors"][row_index][block_index])
                factor = factor * pow_mod(value, weight, key.p) % key.p
            plaintexts.append(str(pair[1] * pow(factor, -1, key.p) % key.p))
        messages.append(plaintexts)
    return messages


def verify_threshold_decryption(rows, result, manifest, scheme, context):
    try:
        if result["record_hash"] != context:
            return False
        messages = combine_partials(rows, result["partials"], manifest, scheme, context)
        return hash_record(messages) == hash_record(result["messages"])
    except (ValueError, TypeError, KeyError, IndexError, AttributeError):
        return False
