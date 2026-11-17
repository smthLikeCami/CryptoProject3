# Voting Protocol Example
Design details: [Design document](DesignDocument.pdf).

## Setup

Run these commands from the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r server/requirements.txt -r client/requirements.txt
```

## Run the mock election

```bash
python mock_election.py
```

The demo runs automatically and cleans up its temporary files. Edit `DEMO_VOTES`,
`PAUSE_SECONDS`, and `LINE_PAUSE` near the top of the script to adjust the example.

## Run manually

Generate keys once, then start the server:

```bash
python trustee/generate_keys.py
python client/generate_signing_keys.py
python server/server.py
```

In another terminal, activate the same virtual environment and run:

```bash
python client/submit_ballot.py
```

Enter the voter name, private signing-key file printed during setup, and write-in
text. Choose `cast` or `audit`. Run the client again for each voter.

In the server terminal, type `close` and press Enter. Wait for the shuffle to
finish, then run two trustees in another terminal:

```bash
python trustee/decrypt_ballots.py --trustee 1
python trustee/decrypt_ballots.py --trustee 2
```

Verify the result using the receipt printed when casting:

```bash
python client/verify.py --receipt YOUR_BALLOT_HASH
```

Keep generated keys for subsequent manual runs; setup refuses to overwrite them.

## Run tests

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
python -m unittest discover -s client -p 'test_*.py' -v
```
