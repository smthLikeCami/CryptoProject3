# Voting prototype

## Narrated mock election

Run the complete example from the project root:

```bash
.venv/bin/python mock_election.py
```

The script creates a temporary workspace and fresh keys, starts a background
HTTP server on an automatically selected local port, and runs the clients and
trustees in separate processes. It requires permission to bind a local socket.
It leaves your existing keys, voter file, and running election untouched.

Alice audits and discards a ballot, then prepares a fresh one to cast. Alice,
Bob, Chet, and Diane each cast once. The runner sends `close` to the server,
runs trustee 1 and confirms that no plaintext or tally is available. Trustee 2
then contributes, allowing tallying while trustee 3 stays offline. Each client
checks its receipt, the shuffle proof, both trustee proofs, and the final count.
Voter signing keys are also generated in the temporary workspace. Each client
signs its encrypted submission, and public verification checks the signatures
and eligible-voter roster as well as the shuffle, decryption, and tally.
Step numbers and actor labels
explain each action. The known mock choices and expected counts are public for
this demonstration; an actual server receives encrypted ballots only.

Edit `DEMO_VOTES` near the top of `mock_election.py` to change the write-ins.
Adjust `PAUSE_SECONDS` for pauses between phases and client turns, and
`LINE_PAUSE` for the spacing between output lines. Set both to `0` for a fast
run. Routine HTTP access logs are hidden; election events and errors remain.
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

Generate voter signing keys separately, using the eligible names already in
`server/voters_list.txt`:

```bash
.venv/bin/python client/generate_signing_keys.py
```

This trusted setup writes private Ed25519 keys to
`client/signing_keys/voter_1.pem`, `voter_2.pem`, and so on, in voter-list order.
Each private file has owner-only permissions. Deliver only the correct private
file and the public `voters.json` to each voter, keeping them beside each other.
The same public roster is registered in `server/voter_keys.json`. Setup refuses
to overwrite existing signing keys or a registered roster. Signing keys are
separate from the trustees' ElGamal decryption shares.

The setup operator temporarily controls all signing keys and must be trusted
not to retain private copies. Public roster copies must be distributed to
clients and trustees independently, so a malicious server cannot substitute its
own eligible signing keys.

The script creates `trustee/threshold/` containing:

- `public_key.bin`: the shared public encryption key.
- `trustees.json`: the public two-of-three policy, share commitments, and IDs.
- `trustee_1.json`, `trustee_2.json`, `trustee_3.json`: separate private shares,
  saved with owner-only read/write permissions.

Distribute one private file to each trustee. Distribute the public key and
public manifest to the server and clients independently. The setup process
temporarily knows the complete secret but never writes it to a file. It also
publishes commitments that let anyone check that the three public shares fit
the same degree-one sharing polynomial. This is trusted setup, not distributed
key generation; the setup operator must be trusted not to retain the secret.

The server reads only the public files. The threshold directory is excluded
from Git, and setup refuses to overwrite an existing threshold directory. Old
`trustee/public_key.bin` and `trustee/private_key.bin` files remain untouched and
are no longer used by the program. Start a fresh election using threshold keys;
previous single-trustee ciphertexts cannot be migrated automatically.

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

Enter a voter name, the path to that voter's private signing file, and at most
32 Unicode characters of write-in text. The client encrypts with the election public key and
displays the prepared ciphertext's hash. Then choose `cast` or `audit`:

- `cast` signs the election ID, voter name, exact ciphertext's SHA-256 hash,
  public-roster hash, and a fixed casting-purpose label. It sends the name,
  election ID, ciphertext, and signature to `POST /submit_ballot`. Neither the
  private signing key, plaintext, nor encryption randomness is sent.
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
clears them and creates a new election ID. Signing keys persist until a new
trusted setup is deliberately performed. A signature from an earlier election
is rejected, even when the same signing keys are reused.
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
that proof. It then waits for distinct trustees. For example, run these commands
separately (trustee 3 can replace either trustee):

```bash
.venv/bin/python trustee/decrypt_ballots.py --trustee 1
.venv/bin/python trustee/decrypt_ballots.py --trustee 2
```

Each trustee fetches `GET /election`, checks the locally trusted public key and
manifest, checks receipt hashes, and verifies the shuffle proof. Only then does
it load its own private share. It produces a partial decryption factor for each
block and a Chaum-Pedersen proof that these factors use the same exponent as its
public share. It never opens another trustee's private file or uploads a share.

Trustees upload factors and proofs to `POST /trustee/partial_decryption`. After
one valid contribution, the server remains in `awaiting_trustees`, publishes
progress, and has no plaintext or tally. Two distinct verified contributions
allow Lagrange interpolation of the decryption factors. The complete secret key
is never reconstructed. Duplicate, unknown, forged, and replayed contributions
are rejected. The old single-trustee `/trustee/tally` endpoint no longer exists.

Counts use exact text: `Alice` and `alice` are different write-ins, whitespace
is preserved, and the empty string is counted as its own entry. Plaintexts with
invalid UTF-8, padding, length, or block encoding are recorded by shuffled index
in `invalid_ballots`. They are not silently assigned to a candidate.

`GET /election` publishes the state, the frozen input ballots and receipt hashes,
the shuffled ciphertexts and proof, and, after tallying, both partial-decryption
proofs, combined plaintexts, and counts. `trustee_progress` shows the required
and received contribution counts and trustee IDs. As selected for this design,
the frozen input record also publishes voter names, signatures, and the public
signing-key roster. These identify who authorized each encrypted input, not its
plaintext choice. No private signing keys or decryption shares are published.

Password authentication and the old `/authenticate` endpoint have been removed.
The server verifies each ballot signature against the pre-registered public
key and accepts at most one ballot per voter. A client-supplied public key does
not replace the registered key. Trustees check these public authorizations
against their trusted roster before contributing partial decryptions.

To verify a completed election with your saved receipt:

```bash
.venv/bin/python client/verify.py --receipt YOUR_BALLOT_HASH
```

The verifier uses `trustee/threshold/public_key.bin` and the adjacent
`trustees.json` as its trust anchors. For another deployment, use
`--server URL --public-key PATH` and independently obtain both public files,
keeping `trustees.json` beside the key file. It never needs a password or share.
The verifier also loads the independently trusted voter roster from
`client/signing_keys/voters.json`; use `--voters PATH` for another copy.
It checks the frozen input hashes, your receipt's inclusion, the entire shuffle
proof, voter signatures and unique eligible identities, trustee IDs and proofs,
the combination of their factors, and the recomputed tally including invalid
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

Threshold operations use the prime-order quadratic-residue subgroup of order
`q = (p-1)/2`. Setup squares TNO's original full-order generator. Shares use
`s_i = x + a*i (mod q)`, with public commitments to `x` and `a`. Each trustee
computes `d_i = c_1 ** s_i (mod p)` and proves equality of discrete logs.
Combining any two valid factors with Lagrange coefficients gives `c_1 ** x`,
which removes the encryption mask from `c_2`. One factor is insufficient.

Shuffle proofs retain exactly 128 cut-and-choose rounds. Partial-decryption
proofs use Fiat-Shamir challenges bound to the entire frozen record, public
trustee manifest, trustee ID, ciphertexts, factors, and commitments. This
experimental proof code is written for learning and has not been reviewed as a
production cryptographic implementation.

There is one mixing stage in the server. It knows its own shuffle, so anonymity
against the server would require additional independently operated mixing
stages with at least one honest operator. Any two colluding trustees can decrypt
original ballots if they obtain them. The demo uses separate processes under
one operating-system user; real trustees must hold their share files on
independently controlled systems. Signatures make input authorization publicly
checkable against the trusted roster. Proofs cover the frozen published record;
they do not establish that a dishonest server published every accepted ballot.
Voters still need to check their receipts in that record.

The server validates ciphertext structure, width, group elements, and key, but
clients do not yet prove knowledge of the encrypted vote or its valid encoding.
This leaves related-ballot attacks outside this prototype's guarantees. Audit
discarding is enforced locally, not by server-side spoiled-ballot tracking.
