"""Readable, experimental ElGamal shuffle proofs and padded ballot encoding.

Each of 128 cut-and-choose rounds opens one of two links through a fresh
intermediate shuffle. Never publish both links: that would reveal the shuffle.
SHA-256 binds the challenges to the complete election transcript (Fiat-Shamir).
This is teaching code, not a reviewed cryptographic library.
"""

import base64
import hashlib
import json
from math import isqrt
import secrets

from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal, ElGamalCipherText
from tno.mpc.encryption_schemes.utils import is_prime, pow_mod


PROOF_ROUNDS = 128
BLOCK_COUNT = 5
BLOCK_SIZE = 32
MAX_CHARACTERS = 32
BALLOT_FORMAT = "padded-32-v1"


def hash_record(value):
    """Hash JSON in a consistent order on the server, trustee, and verifier."""
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _challenges(domain, statement, commitments):
    """Commit to every round before deriving any of the challenge bits."""
    digest = hash_record({"domain": domain, "statement": statement, "commitments": commitments})
    bits = bin(int(digest, 16))[2:].zfill(256)
    return [int(bit) for bit in bits[:PROOF_ROUNDS]]


def validate_key(scheme):
    """Require a prime-order subgroup, allowing Shamir interpolation modulo q."""
    key = scheme.public_key
    prime = key.p
    half = (prime - 1) // 2
    if not 600 <= prime.bit_length() <= 8192 or not is_prime(prime) or not is_prime(half):
        raise ValueError("Expected a safe-prime ElGamal key of at least 600 bits.")
    if not 1 < key.g < prime or pow_mod(key.g, half, prime) != 1:
        raise ValueError("The ElGamal generator must have prime order q.")
    if not 1 < key.h < prime or pow_mod(key.h, half, prime) != 1:
        raise ValueError("Invalid ElGamal public key.")


def encode_vote(vote):
    """Encode at most 32 Unicode code points into exactly five padded blocks."""
    if not isinstance(vote, str) or len(vote) > MAX_CHARACTERS:
        raise ValueError("A write-in must contain at most 32 characters.")
    text = vote.encode("utf-8")
    # 32 Unicode characters require at most 128 UTF-8 bytes. Two bytes record
    # the actual byte length; zero padding fills the remaining space to 160.
    data = len(text).to_bytes(2, "big") + text
    data = data.ljust(BLOCK_COUNT * BLOCK_SIZE, b"\x00")
    return [
        int.from_bytes(b"\x01" + data[start : start + BLOCK_SIZE], "big") ** 2
        for start in range(0, len(data), BLOCK_SIZE)
    ]


def decode_vote(messages):
    """Reject malformed plaintexts rather than guessing a vote from them."""
    if len(messages) != BLOCK_COUNT:
        raise ValueError("Incorrect number of plaintext blocks.")
    data = b""
    for message in messages:
        number = isqrt(message)
        if number * number != message or number.bit_length() > 8 * (BLOCK_SIZE + 1):
            raise ValueError("Invalid squared plaintext block.")
        block = number.to_bytes(BLOCK_SIZE + 1, "big")
        if block[0] != 1:
            raise ValueError("Invalid plaintext prefix.")
        data += block[1:]
    size = int.from_bytes(data[:2], "big")
    if size > 128 or any(data[2 + size :]):
        raise ValueError("Invalid text length or padding.")
    vote = data[2 : 2 + size].decode("utf-8")
    if len(vote) > MAX_CHARACTERS:
        raise ValueError("Write-in exceeds 32 characters.")
    return vote


def read_ballot(ballot, scheme):
    """Read the client's serialized ciphertexts and check the election key."""
    blocks = json.loads(ballot)
    if not isinstance(blocks, list) or len(blocks) != BLOCK_COUNT:
        raise ValueError("Expected exactly five encrypted ballot blocks.")
    row = []
    for block in blocks:
        if not isinstance(block, str):
            raise ValueError("Expected a base64 ciphertext string.")
        ciphertext = Serialization.unpack(base64.b64decode(block, validate=True), use_pickle=False)[1]
        if not isinstance(ciphertext, ElGamalCipherText) or ciphertext.scheme.public_key != scheme.public_key:
            raise ValueError("Ballot uses a different election key.")
        row.append([str(value) for value in ciphertext.peek_value()])
    return read_rows([row], scheme)[0]


def _number(value, limit, minimum=0):
    """Use canonical decimal strings for large integers in public JSON."""
    if not isinstance(value, str) or len(value) > len(str(limit)):
        raise ValueError("Expected a decimal integer string.")
    number = int(value)
    if str(number) != value or not minimum <= number < limit:
        raise ValueError("Integer is outside its allowed range.")
    return number


def read_rows(rows, scheme):
    """Validate a list of fixed-width ballots without decrypting them."""
    if not isinstance(rows, list):
        raise ValueError("Expected a ballot list.")
    prime = scheme.public_key.p
    result = []
    for row in rows:
        if not isinstance(row, list) or len(row) != BLOCK_COUNT:
            raise ValueError("Incorrect number of ciphertext blocks.")
        ballot = []
        for pair in row:
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("Expected an ElGamal pair.")
            values = [_number(value, prime, minimum=1) for value in pair]
            if any(pow_mod(value, (prime - 1) // 2, prime) != 1 for value in values):
                raise ValueError("Ciphertext is outside the election subgroup.")
            ballot.append(values)
        result.append(ballot)
    return result


def _wire(rows):
    return [[[str(value) for value in pair] for pair in row] for row in rows]


def _random_order(size):
    order = list(range(size))
    secrets.SystemRandom().shuffle(order)
    return order


def _random_offsets(size, order):
    return [[secrets.randbelow(order) for _ in range(BLOCK_COUNT)] for _ in range(size)]


def _reencrypt(rows, permutation, offsets, scheme):
    """Move whole ballots together and independently re-encrypt every block."""
    key = scheme.public_key
    output = []
    for source, random_values in zip(permutation, offsets):
        ballot = []
        for pair, exponent in zip(rows[source], random_values):
            ciphertext = ElGamalCipherText(tuple(pair), scheme)
            ciphertext.apply_randomness((pow_mod(key.g, exponent, key.p), pow_mod(key.h, exponent, key.p)))
            ballot.append(list(ciphertext.peek_value()))
        output.append(ballot)
    return output


def create_shuffle(rows, scheme, context):
    """Return a re-encrypted permutation and a public cut-and-choose proof."""
    rows = read_rows(rows, scheme)
    size = len(rows)
    order = (scheme.public_key.p - 1) // 2
    permutation = _random_order(size)
    offsets = _random_offsets(size, order)
    output = _reencrypt(rows, permutation, offsets, scheme)
    commitments = []
    witnesses = []

    for _ in range(PROOF_ROUNDS):
        other_permutation = _random_order(size)
        other_offsets = _random_offsets(size, order)
        intermediate = _reencrypt(rows, other_permutation, other_offsets, scheme)
        commitments.append(_wire(intermediate))
        witnesses.append((other_permutation, other_offsets))

    statement = {"context": context, "input": _wire(rows), "output": _wire(output)}
    challenges = _challenges("shuffle-cut-and-choose-v1", statement, commitments)
    inverse = [0] * size
    for destination, source in enumerate(permutation):
        inverse[source] = destination
    responses = []

    for bit, (other_permutation, other_offsets) in zip(challenges, witnesses):
        if bit == 0:
            # Open input -> intermediate, keeping output -> intermediate secret.
            link = other_permutation
            random_values = other_offsets
        else:
            # Open output -> intermediate, keeping input -> intermediate secret.
            link = [inverse[source] for source in other_permutation]
            random_values = [
                [(value - offsets[source][block]) % order for block, value in enumerate(values)]
                for source, values in zip(link, other_offsets)
            ]
        responses.append({"permutation": link, "offsets": [[str(value) for value in row] for row in random_values]})

    # Neither the real permutation nor its re-encryption offsets are returned.
    return {"output": _wire(output), "commitments": commitments, "responses": responses}


def verify_shuffle(rows, proof, scheme, context):
    """Reject a changed statement, missing round, non-permutation, or bad link."""
    try:
        rows = read_rows(rows, scheme)
        output = read_rows(proof["output"], scheme)
        commitments = proof["commitments"]
        responses = proof["responses"]
        size = len(rows)
        if len(output) != size or len(commitments) != PROOF_ROUNDS or len(responses) != PROOF_ROUNDS:
            return False
        statement = {"context": context, "input": _wire(rows), "output": _wire(output)}
        challenges = _challenges("shuffle-cut-and-choose-v1", statement, commitments)
        for bit, commitment, response in zip(challenges, commitments, responses):
            intermediate = read_rows(commitment, scheme)
            permutation = response["permutation"]
            values = response["offsets"]
            if len(intermediate) != size or not isinstance(permutation, list):
                return False
            if any(type(value) is not int for value in permutation) or sorted(permutation) != list(range(size)):
                return False
            if not isinstance(values, list) or len(values) != size:
                return False
            offsets = []
            for row in values:
                if not isinstance(row, list) or len(row) != BLOCK_COUNT:
                    return False
                offsets.append([_number(value, (scheme.public_key.p - 1) // 2) for value in row])
            reference = rows if bit == 0 else output
            if _reencrypt(reference, permutation, offsets, scheme) != intermediate:
                return False
        return True
    except (ValueError, TypeError, KeyError, IndexError, AttributeError):
        return False


def election_rows(context, scheme):
    """Bind the input ciphertexts to the exact receipt strings accepted by the server."""
    rows = []
    hashes = set()
    for entry in context["ballots"]:
        digest = hashlib.sha256(entry["ballot"].encode("utf-8")).hexdigest()
        if digest != entry["hash"] or digest in hashes:
            raise ValueError("Invalid or repeated ballot receipt in election record.")
        hashes.add(digest)
        rows.append(_wire([read_ballot(entry["ballot"], scheme)])[0])
    return rows



def count_votes(messages):
    """Count exact write-in strings; publish invalid encodings separately."""
    counts = {}
    invalid = []
    for index, row in enumerate(messages):
        try:
            vote = decode_vote([int(value) for value in row])
        except (ValueError, OverflowError):
            invalid.append(index)
            continue
        counts[vote] = counts.get(vote, 0) + 1
    return {"counts": counts, "invalid_ballots": invalid,
            "valid_count": sum(counts.values()), "total_count": len(messages)}
