# Voting prototype

## Narrated mock election

Run the complete example from the project root:

```bash
.venv/bin/python mock_election.py
```

The script creates a temporary workspace and fresh keys, starts a background
HTTP server on an automatically selected local port, and runs the clients and
trustee in separate processes. It requires permission to bind a local socket.
It leaves your existing keys, voter file, and running election untouched.

Alice audits and discards a ballot, then prepares a fresh one to cast. Alice,
Bob, Chet, and Diane each cast once. The runner sends `close` to the server,
runs trustee decryption, and has each client verify their receipt, the shuffle
proof, the decryption proof, and the final count. Step numbers and actor labels
explain each action. The known mock choices and expected counts are public for
this demonstration; an actual server receives encrypted ballots only.

Edit `DEMO_VOTES` near the top of `mock_election.py` to change the write-ins.
The default result is `River: 3, Forest: 1`. On completion or failure, started
processes are stopped and the temporary files are removed.

## Manual operation

Install the dependencies in your virtual environment:

```bash
.venv/bin/python -m pip install -r server/requirements.txt -r client/requirements.txt -r trustee/requirements.txt
```

Generate the election keys once, using the separate trustee script:

```bash
.venv/bin/python trustee/generate_keys.py
```

The script writes `trustee/public_key.bin` and `trustee/private_key.bin`.
The server reads only the public file. The private file stays with the trustee
and is excluded from Git. Existing key files are never overwritten.

For faster demonstration setup, key generation uses 1024 bits and the client
uses 32-byte text blocks. The requirements also enable GMPY2 acceleration.
To restore the stronger configuration, change `bits=1024` to `bits=2048` in
`trustee/generate_keys.py`. The padded ballot format still uses 32-byte blocks.
Use a fresh key pair for a new election; changing the code does not resize
existing keys. These demonstration parameters are not a deployment security
recommendation.

Start the server, then use another terminal to submit a ballot:

```bash
.venv/bin/python server/server.py
```

```bash
.venv/bin/python client/submit_ballot.py
```

Enter a voter name and the password printed by the server, then at most 32
Unicode characters of write-in text. The client encrypts with the public key and
displays the prepared ciphertext's hash. Then choose `cast` or `audit`:

- `cast` submits that exact ciphertext with the credentials to
  `POST /submit_ballot`. The plaintext and random exponents are not sent.
- `audit` reveals the plaintext and each block's random exponent in the terminal,
  then checks the saved ciphertext against the public key and both ElGamal
  encryption equations. It also checks the previously displayed hash.
  The audited ballot is discarded, whether the check passes or fails, and no
  submission request is made. Run the script again for fresh encryption before
  casting. Auditing therefore does not consume the voter's one submission.

This is a local Helios-style cast-or-audit check of ballot preparation.
After tallying, `verify.py` checks the public record and proofs as described
below. Discarding audited ballots is enforced by this client flow; the server
does not yet track spoiled ballots.

Run the audit and election regression tests with:

```bash
.venv/bin/python -m unittest discover -s client -p 'test_*.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

The server stores the ciphertext string unchanged and returns its SHA-256 hash
in `{"hash": "..."}`. The client checks that hash against the ciphertext it sent
and prints it. A second submission by the same voter receives HTTP 409.

Ballots, proofs, and election results are held in memory. Restarting the server
clears them, creates a new election ID, and generates new voter passwords.
Restart before using this updated ballot format; old variable-width ballots are
not compatible. Existing key files are preserved.

## Close, shuffle, and tally

In the running server's terminal, enter:

```text
close
```

Closing freezes the accepted bulletin before any mixing work starts. Further
submissions are rejected. The server randomly permutes whole ballots and
re-encrypts every block, generates a 128-round cut-and-choose proof, and checks
that proof. It then prints that it is awaiting the trustee. Run:

```bash
.venv/bin/python trustee/decrypt_ballots.py
```

The trustee fetches `GET /election`, checks the local public key against the
record, checks receipt hashes, and verifies the shuffle proof. Only then does
it load the private key and decrypt. TNO caches schemes by public key, so the
script clears the public-only cache before loading the private file.

The trustee uploads the plaintext block values and a decryption proof to
`POST /trustee/tally`. The proof demonstrates that the same private exponent
behind the election public key explains every decryption. The private key is
never sent. The server checks the proof and the frozen record hash before
decoding write-ins and publishing counts. Repeat tally uploads are rejected.

Counts use exact text: `Alice` and `alice` are different write-ins, whitespace
is preserved, and the empty string is counted as its own entry. Plaintexts with
invalid UTF-8, padding, length, or block encoding are recorded by shuffled index
in `invalid_ballots`. They are not silently assigned to a candidate.

`GET /election` publishes the state, the frozen input ballots and receipt hashes,
the shuffled ciphertexts and proof, and, after tallying, the decryption proof and
counts. It publishes no voter names or passwords.

To verify a completed election with your saved receipt:

```bash
.venv/bin/python client/verify.py --receipt YOUR_BALLOT_HASH
```

The verifier uses the local `trustee/public_key.bin` as its trusted public key.
For another deployment, use `--server URL --public-key PATH` and obtain that
public key independently. It never needs a voter password or private key.
It checks the frozen input hashes, your receipt's inclusion, the entire shuffle
proof, the trustee decryption proof, and the recomputed tally including invalid
ballot indices. Without `--receipt`, it checks public evidence but explicitly
reports that individual inclusion was not checked.

## Fixed-width text encoding

The shared format in `server/shuffle.py` permits 32 Unicode code points, which
can occupy up to 128 UTF-8 bytes. A two-byte byte-length header is followed by
the text and zero padding to exactly 160 bytes. This is always five 32-byte
blocks, including for empty text. Each block is prefixed with `0x01`, converted
to an integer, squared, and encrypted. All five blocks move together when mixed.

Decryption takes integer square roots, checks the prefixes, reads the byte
length, checks zero padding, and decodes UTF-8. It preserves zero bytes within
the actual text and Unicode characters split across blocks.

Each encrypted block is serialized by TNO and base64-encoded. The submitted
ballot string is a compact JSON array of those strings. Re-encryption changes
the ciphertext representation; original receipt hashes continue to identify
the input bulletin. The shuffle proof connects that bulletin to the outputs
without publishing the secret permutation.

## Proof design and current limits

For each shuffle-proof round, the server creates an independent intermediate
shuffle. A Fiat-Shamir challenge chooses whether to open the input-to-intermediate
or output-to-intermediate link. Only one is revealed per round. The challenge
hash includes the election ID, public key, exact accepted input records, output,
and all intermediate commitments. The real input-to-output permutation is not
published. The idea follows the cut-and-choose approach to shuffle proofs;
see [Sako and Kilian's paper](https://doi.org/10.1007/3-540-49264-X_32).

The decryption proof uses 128 binary equality-of-discrete-log challenges. This
avoids division in the composite-order `p-1` group used by TNO. Both protocols
require exactly 128 rounds; verifiers reject shortened or modified transcripts.
This experimental proof code is written for learning and has not been reviewed
as a production cryptographic implementation.

There is one mixing stage in the server. It knows its own shuffle, so anonymity
against the server would require additional independently operated mixing
stages with at least one honest operator. The trustee has the complete private
key and must be trusted not to decrypt original ballots. Threshold trustees are
not implemented. Proofs cover the frozen published record; they do not establish
that a dishonest server published every accepted ballot, or authenticated every
input correctly. Voters still need to check their receipts in that record.

The server validates ciphertext structure, width, group elements, and key, but
clients do not yet prove knowledge of the encrypted vote or its valid encoding.
This leaves related-ballot attacks outside this prototype's guarantees. Audit
discarding is enforced locally, not by server-side spoiled-ballot tracking.
