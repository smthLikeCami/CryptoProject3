"""Run a narrated mock election: .venv/bin/python mock_election.py"""

import argparse
import base64
from collections import Counter
from contextlib import contextmanager, redirect_stdout
from io import StringIO
import json
import logging
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Lock, Thread
import time

import requests


# Edit these example votes and reading speeds as needed. Use 0 for no pauses.
DEMO_VOTES = {"Alice": "River", "Bob": "Forest", "Chet": "River", "Diane": "River"}
PAUSE_SECONDS = 1.0
LINE_PAUSE = 0.08
print_lock = Lock()


def say(actor, message):
    with print_lock:
        print(f"[{actor}] {message}", flush=True)


def step(number, message):
    say("DEMO", f"\n--- {number}. {message} ---")
    time.sleep(PAUSE_SECONDS)


def read_json(file):
    return json.loads(file.read_text(encoding="utf-8"))


def write_json(file, value):
    """Publish complete private handoff files, never partially written JSON."""
    file.parent.mkdir(parents=True, exist_ok=True)
    temporary = file.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(file)


def get_election(url):
    response = requests.get(f"{url}/election", timeout=30)
    response.raise_for_status()
    return response.json()


def background_output(process, actor):
    for line in process.stdout:
        line = line.rstrip("\n")
        if "encryption randomness:" in line:
            line = line[:100] + "... (nonce shortened for display)"
        say(actor, line)
        time.sleep(LINE_PAUSE)


@contextmanager
def background(role, folder, name=None):
    """Start one role, label its output, and always clean up its process."""
    actor = f"{role.upper()} {name or ''}".strip()
    command = [sys.executable, "-u", str(Path(__file__).resolve()),
               "--worker", role, "--workspace", str(folder)]
    if name:
        command.extend(["--name", name])
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, bufsize=1)
    reader = Thread(target=background_output, args=(process, actor), daemon=True)
    reader.start()
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        process.stdin.close()
        reader.join()
        process.stdout.close()


def run_worker(role, folder, name=None, answer=None):
    """Keep clients sequential so their explanations do not overlap."""
    with background(role, folder, name) as process:
        if answer:
            process.stdin.write(answer + "\n")
        process.stdin.close()
        if process.wait(timeout=300) != 0:
            raise RuntimeError(f"The {role} process failed.")


def wait_for_state(folder, process, wanted):
    """Wait for startup or shuffle completion, checking actual server state."""
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("The demo server stopped unexpectedly.")
        if (folder / "server_info.json").exists():
            info = read_json(folder / "server_info.json")
            try:
                state = get_election(info["url"])["state"]
                if state == wanted:
                    return info
                if state == "failed":
                    raise RuntimeError("The server could not verify its shuffle.")
            except requests.RequestException:
                pass
        time.sleep(0.2)
    raise RuntimeError(f"Timed out waiting for election state: {wanted}.")


def run_demo():
    """Read this function for the election's complete sequence of actions."""
    project = Path(__file__).resolve().parent
    say("DEMO", f"Fictional votes, public for this example: {DEMO_VOTES}")
    with tempfile.TemporaryDirectory(prefix="mock-election-") as temporary:
        folder = Path(temporary)
        step(1, "Create isolated files and trustee keys")
        for name in ("client", "server", "trustee"):
            shutil.copytree(project / name, folder / name,
                            ignore=shutil.ignore_patterns("*.bin", "threshold", "signing_keys", "voter_keys.json", "__pycache__", "test_*.py"))
        (folder / "server" / "voters_list.txt").write_text("\n".join(DEMO_VOTES) + "\n", encoding="utf-8")
        write_json(folder / "demo_votes.json", DEMO_VOTES)
        run_worker("keys", folder)
        run_worker("voter_keys", folder)
        keys = folder / "trustee" / "threshold"
        shutil.copyfile(keys / "public_key.bin", folder / "client" / "trusted_public_key.bin")
        shutil.copyfile(keys / "trustees.json", folder / "client" / "trustees.json")

        step(2, "Start the server with registered public signing keys")
        with background("server", folder) as server:
            info = wait_for_state(folder, server, "open")
            say("DEMO", f"HTTP server ready at {info['url']}.")

            step(3, "Alice audits a ballot and discards it")
            run_worker("client", folder, "Alice", "audit")

            step(4, "Clients cast ballots; Alice uses fresh encryption")
            for name in DEMO_VOTES:
                run_worker("client", folder, name, "cast")
                time.sleep(PAUSE_SECONDS)

            step(5, "Close voting, shuffle ballots, and prove the shuffle")
            server.stdin.write("close\n")
            server.stdin.flush()
            wait_for_state(folder, server, "awaiting_trustees")

            step(6, "Trustee 1 contributes; one share cannot decrypt")
            run_worker("trustee", folder, "1")
            pending = get_election(info["url"])
            if (pending["state"] != "awaiting_trustees" or pending["result"] is not None
                    or pending["trustee_progress"]["received"] != 1):
                raise RuntimeError("One trustee incorrectly unlocked the tally.")
            say("DEMO", "Still locked with one trustee. Trustee 3 will remain offline.")
            time.sleep(PAUSE_SECONDS)
            run_worker("trustee", folder, "2")
            election = get_election(info["url"])
            audited = read_json(folder / "client" / "receipts" / "Alice-audited.json")["receipt"]
            if any(entry["hash"] == audited for entry in election["record"]["context"]["ballots"]):
                raise RuntimeError("The audited ballot incorrectly appeared in the bulletin.")
            say("DEMO", "Alice's audited ciphertext is absent from the input bulletin.")

            step(7, "Clients verify voter signatures, receipts, shuffle, trustee proofs, and tally")
            for name in DEMO_VOTES:
                run_worker("verify", folder, name)
                time.sleep(PAUSE_SECONDS)

            tally = election["result"]["tally"]
            expected = dict(Counter(DEMO_VOTES.values()))
            if tally["counts"] != expected or tally["invalid_ballots"]:
                raise RuntimeError("The final tally does not match the mock choices.")
            step(8, f"SUCCESS: every client verified the tally {expected}")
    say("DEMO", "Background processes stopped; temporary keys and files removed.")


def worker_server(folder):
    """Run the real application, showing election events instead of access logs."""
    from flask import request
    from werkzeug.serving import make_server
    from server import server

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    server._load_public_key()
    server._load_voters()
    print("Public key loaded. Two of three private trustee shares are needed to decrypt.", flush=True)
    print("Only voter public keys are registered; private signing keys stay with clients.", flush=True)

    @server.app.after_request
    def explain_response(response):
        if request.path == "/submit_ballot":
            if response.status_code == 200:
                print(f"Authenticated and stored ciphertext. Receipt: {response.get_json()['hash']}", flush=True)
            else:
                print(f"Submission rejected (HTTP {response.status_code}).", flush=True)
        return response

    http = make_server("127.0.0.1", 0, server.app, threaded=True)
    Thread(target=server._read_commands, daemon=True).start()
    write_json(folder / "server_info.json", {"url": f"http://127.0.0.1:{http.server_port}"})
    try:
        http.serve_forever()
    finally:
        http.server_close()


def worker_client(folder, name):
    from client import submit_ballot

    info = read_json(folder / "server_info.json")
    vote = read_json(folder / "demo_votes.json")[name]
    submit_ballot.server_url = info["url"]
    print(f"Mock vote: {vote!r}. Checking the trusted election key before encrypting.", flush=True)
    response = requests.get(f"{info['url']}/public_key", timeout=10)
    response.raise_for_status()
    trusted_key = (folder / "client" / "trusted_public_key.bin").read_bytes()
    if base64.b64decode(response.json()["public_key"], validate=True) != trusted_key:
        raise ValueError("Unexpected election public key.")
    print("Encrypting five padded blocks locally; no plaintext is sent to the server.", flush=True)

    output = StringIO()
    keys = folder / "client" / "signing_keys"
    roster = read_json(keys / "voters.json")
    index = [voter["name"] for voter in roster["voters"]].index(name) + 1
    with redirect_stdout(output):
        receipt = submit_ballot._submit_ballot(vote, name, keys / f"voter_{index}.pem")
    print(output.getvalue(), end="", flush=True)
    file_name = f"{name}.json"
    if receipt is None:
        if "Audit passed:" not in output.getvalue():
            raise ValueError("Client auditing or submission failed.")
        for line in output.getvalue().splitlines():
            if line.startswith("Prepared ballot hash: "):
                receipt = line.removeprefix("Prepared ballot hash: ")
                break
        else:
            raise ValueError("Missing audited ballot hash.")
        file_name = f"{name}-audited.json"
        print("Audit passed. Discarded this ballot without submitting it.", flush=True)
    else:
        print("Server receipt matches. Saving it for verification after tallying.", flush=True)
    write_json(folder / "client" / "receipts" / file_name, {"receipt": receipt})


def worker_trustee(folder, name):
    from trustee import decrypt_ballots

    decrypt_ballots.server_url = read_json(folder / "server_info.json")["url"]
    print("Checking the shuffle and using only my private share; uploading factors and proof.", flush=True)
    decrypt_ballots.decrypt_ballots(int(name))


def worker_verify(folder, name):
    from client.verify import verify_server

    receipt = read_json(folder / "client" / "receipts" / f"{name}.json")["receipt"]
    verify_server(read_json(folder / "server_info.json")["url"], folder / "client" / "trusted_public_key.bin", receipt,
                  voters_file=folder / "client" / "signing_keys" / "voters.json")
    print("Verification complete. No private key or secret shuffle mapping was needed.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=("keys", "voter_keys", "server", "client", "trustee", "verify"), help=argparse.SUPPRESS)
    parser.add_argument("--workspace", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--name", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker is None:
        return run_demo()
    sys.path.insert(0, str(args.workspace))
    if args.worker == "keys":
        from trustee.generate_keys import generate_keys
        generate_keys()
    elif args.worker == "voter_keys":
        from client.generate_signing_keys import generate_signing_keys
        generate_signing_keys()
    elif args.worker == "server":
        worker_server(args.workspace)
    elif args.worker == "client":
        worker_client(args.workspace, args.name)
    elif args.worker == "trustee":
        worker_trustee(args.workspace, args.name)
    elif args.worker == "verify":
        worker_verify(args.workspace, args.name)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Mock election interrupted; background processes stopped.")
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.TimeoutExpired, requests.RequestException) as error:
        raise SystemExit(f"Mock election failed: {error}") from error
