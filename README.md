# Voting prototype

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
`trustee/generate_keys.py`. The 32-byte blocks still work; with the larger key,
you may optionally change `block_size` to 64 in `client/submit_ballot.py`.
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

Enter a voter name and the password printed by the server, then the write-in
text. The client encrypts the text with the shared election public key and
displays the prepared ciphertext's hash. Then choose `cast` or `audit`:

- `cast` submits that exact ciphertext with the credentials to
  `POST /submit_ballot`. The plaintext and random exponents are not sent.
- `audit` reveals the plaintext and each block's random exponent in the terminal,
  then checks the saved ciphertext against the public key and both ElGamal
  encryption equations. It also checks the previously displayed hash.
  The audited ballot is discarded, whether the check passes or fails, and no
  submission request is made. Run the script again for fresh encryption before
  casting. Auditing therefore does not consume the voter's one submission.

This is a local Helios-style cast-or-audit check of ballot preparation. It does
not verify the server's complete election record, tally, or mixnet proofs; those
checks are reserved for the later `verify.py` step. Discarding audited ballots
is enforced by this client flow; the server does not yet track spoiled ballots.

Run the audit regression tests with:

```bash
.venv/bin/python -m unittest discover -s client -p 'test_*.py' -v
```

The server stores the ciphertext string unchanged and returns its SHA-256 hash
in `{"hash": "..."}`. The client checks that hash against the ciphertext it sent
and prints it. A second submission by the same voter receives HTTP 409.

Ballots and the set of voters who submitted are held in memory. Restarting the
server clears them and generates new voter passwords.

## Text encoding for later decryption

The client splits UTF-8 bytes into 32-byte blocks, prefixes each block with byte
`0x01`, converts it to an integer, and squares it before ElGamal encryption.
The square fits below the modulus of the generated 1024-bit key and places the
message in the quadratic-residue subgroup. Even empty text has one block.

After library decryption, take the integer square root of each message, convert
it to its shortest big-endian byte representation, and remove the leading
`0x01`. Join all blocks before decoding UTF-8. This preserves leading zero bytes
and Unicode characters split between blocks.

Each encrypted block is serialized by TNO and base64-encoded. The submitted
ballot string is a compact JSON array of those strings. A future mixnet must
keep each ballot's blocks together and re-randomize them. Block counts reveal
approximate text length; padding is not implemented in this step.

Shuffling, decryption, and cryptographic validity proofs are not implemented
yet. The server currently accepts any string as an opaque ciphertext; the hash
confirms the submitted bytes, not that the ballot was included in a tally.
