"""Run an isolated, narrated election with real HTTP and cryptographic proofs.

Run with the project's Python environment:
    .venv/bin/python mock_election.py

Edit DEMO_VOTES below to change the example. Every role runs in its own process.
The internal --worker options let this same file launch those background roles.
"""

import argparse
import base64
from collections import Counter
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Lock, Thread
import time

import requests


# These are public, fictional choices for the demonstration only.
DEMO_VOTES = {
    "Alice": "River",
    "Bob": "Forest",
    "Chet": "River",
    "Diane": "River",
}

print_lock = Lock()


def say(actor, message):
    """Label every line so background output remains easy to follow."""
    with print_lock:
        print(f"[{actor}] {message}", flush=True)


def write_json(file, value):
    """Write complete handoff files before other demo processes read them."""
    file.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = file.with_suffix(".tmp")
    temporary_file.write_text(json.dumps(value), encoding="utf-8")
    temporary_file.chmod(0o600)
    temporary_file.replace(file)


def read_info(folder):
    return json.loads((folder / "server_info.json").read_text(encoding="utf-8"))


def start_worker(role, folder, actor, name=None):
    """Start a real subprocess and forward its console output with a label."""
    command = [sys.executable, "-u", str(Path(__file__).resolve()),
               "--worker", role, "--workspace", str(folder)]
    if name is not None:
        command.extend(["--name", name])
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1,
    )

    def forward_output():
        for line in process.stdout:
            say(actor, line.rstrip("\n"))

    reader = Thread(target=forward_output, daemon=True)
    reader.start()
    return process, reader


def stop_worker(process, reader):
    """Never leave a background server behind, including after a failure."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    if process.stdin is not None:
        process.stdin.close()
    reader.join(timeout=5)
    if process.stdout is not None:
        process.stdout.close()


def run_worker(role, folder, actor, name=None, answer=None):
    """Finish one background role before explaining the next step."""
    process, reader = start_worker(role, folder, actor, name)
    try:
        if answer is not None:
            process.stdin.write(answer + "\n")
            process.stdin.flush()
        process.stdin.close()
        code = process.wait(timeout=300)
        reader.join(timeout=5)
        if code != 0:
            raise RuntimeError(f"{actor} failed with exit code {code}.")
    finally:
        stop_worker(process, reader)


def wait_for_server(folder, process):
    """Wait for the private handoff containing the chosen HTTP port."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("The demo server stopped during startup.")
        if (folder / "server_info.json").exists():
            info = read_info(folder)
            try:
                response = requests.get(f"{info['url']}/election", timeout=2)
                response.raise_for_status()
                return info
            except requests.RequestException:
                pass
        time.sleep(0.1)
    raise RuntimeError("Timed out waiting for the demo server.")


def wait_for_shuffle(url, process):
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("The demo server stopped during mixing.")
        response = requests.get(f"{url}/election", timeout=30)
        response.raise_for_status()
        state = response.json()["state"]
        if state == "awaiting_trustee":
            return
        if state == "failed":
            raise RuntimeError("The server could not produce a verified shuffle.")
        time.sleep(0.2)
    raise RuntimeError("Timed out waiting for the shuffle proof.")


def run_demo():
    """Coordinate a complete election without touching the existing election."""
    project = Path(__file__).resolve().parent
    say("DEMO", "Mock choices are fictional and printed for teaching purposes.")
    say("DEMO", f"Editable example votes: {DEMO_VOTES}")

    with tempfile.TemporaryDirectory(prefix="mock-election-") as temporary_folder:
        folder = Path(temporary_folder)
        say("DEMO", f"1. Creating an isolated workspace: {folder}")
        for name in ("client", "server", "trustee"):
            shutil.copytree(
                project / name, folder / name,
                ignore=shutil.ignore_patterns("*.bin", "__pycache__", "test_*.py"),
            )
        (folder / "server" / "voters_list.txt").write_text("\n".join(DEMO_VOTES) + "\n", encoding="utf-8")
        write_json(folder / "demo_votes.json", DEMO_VOTES)

        say("DEMO", "2. Trustee setup: generate temporary election keys in a separate process.")
        run_worker("keys", folder, "TRUSTEE SETUP")
        # Simulate giving voters an independently trusted public key before voting.
        shutil.copyfile(folder / "trustee" / "public_key.bin", folder / "client" / "trusted_public_key.bin")

        say("DEMO", "3. Starting the background HTTP server and issuing mock credentials.")
        server, reader = start_worker("server", folder, "SERVER")
        try:
            info = wait_for_server(folder, server)
            say("DEMO", f"The demo's HTTP address is {info['url']}.")

            say("DEMO", "4. Alice audits a prepared ballot. It must never be submitted.")
            run_worker("client", folder, "CLIENT Alice / AUDIT", "Alice", "audit")

            say("DEMO", "5. Each client casts one ballot. Alice starts again with fresh encryption.")
            for name in DEMO_VOTES:
                run_worker("client", folder, f"CLIENT {name} / CAST", name, "cast")

            say("DEMO", "6. Sending the real close command to the background server's terminal.")
            say("DEMO", "The server freezes submissions, shuffles whole ballots, and proves re-encryption.")
            server.stdin.write("close\n")
            server.stdin.flush()
            wait_for_shuffle(info["url"], server)

            say("DEMO", "7. Trustee verifies the shuffle, decrypts locally, and uploads a public proof.")
            run_worker("trustee", folder, "TRUSTEE")

            response = requests.get(f"{info['url']}/election", timeout=30)
            response.raise_for_status()
            election = response.json()
            audited = json.loads((folder / "client" / "receipts" / "Alice-audited.json").read_text())
            if any(entry["hash"] == audited["receipt"] for entry in election["record"]["context"]["ballots"]):
                raise RuntimeError("The audited ballot incorrectly appeared in the input bulletin.")
            say("DEMO", "Confirmed: Alice's audited ciphertext is absent from the frozen bulletin.")

            say("DEMO", "8. Every client independently downloads and verifies the public evidence.")
            say("DEMO", "Clients use only their receipt and trusted public key, not the trustee's secret.")
            for name in DEMO_VOTES:
                run_worker("verify", folder, f"CLIENT {name} / VERIFY", name)

            expected = dict(Counter(DEMO_VOTES.values()))
            tally = election["result"]["tally"]
            if tally["counts"] != expected or tally["invalid_ballots"]:
                raise RuntimeError("The final tally does not match the mock choices.")
            say("DEMO", f"9. SUCCESS: expected and verified tally both equal {expected}.")
            say("DEMO", "Receipt inclusion, shuffle correctness, trustee decryption, and counting all passed.")
        finally:
            stop_worker(server, reader)
    say("DEMO", "Background processes stopped and temporary keys and election files removed.")


def worker_server(folder):
    """Serve the copied application on an OS-selected free local port."""
    from flask import request
    from werkzeug.serving import make_server
    from server import server

    server._load_public_key()
    # Simulate private delivery to the mock clients instead of printing passwords.
    with redirect_stdout(StringIO()):
        passwords = server._print_authenticated_users()
    for name in passwords:
        print(f"Issued a temporary password to {name}; only its hash is kept by the application.", flush=True)
    print("Loaded the public election key. No private election key is loaded here.", flush=True)

    # Extra narration belongs to this demo, leaving normal server output small.
    @server.app.after_request
    def explain_response(response):
        if request.path == "/submit_ballot":
            if response.status_code == 200:
                print("Credentials and ciphertext structure passed. Stored one encrypted ballot.", flush=True)
                print(f"Returning its SHA-256 receipt: {response.get_json()['hash']}", flush=True)
            else:
                print(f"Submission rejected with HTTP {response.status_code}.", flush=True)
        elif request.path == "/trustee/tally" and response.status_code == 200:
            print("Verified the trustee's proof against the frozen shuffle; published the tally.", flush=True)
        return response

    http_server = make_server("127.0.0.1", 0, server.app, threaded=True)
    url = f"http://127.0.0.1:{http_server.server_port}"
    Thread(target=server._read_commands, daemon=True).start()
    write_json(folder / "server_info.json", {"url": url, "passwords": passwords})
    print("Mock credential delivery is complete. Ready to receive encrypted ballots over HTTP.", flush=True)
    try:
        http_server.serve_forever()
    finally:
        http_server.server_close()


def worker_client(folder, name):
    """Run the existing client code with a scripted cast-or-audit terminal answer."""
    from client import submit_ballot

    info = read_info(folder)
    votes = json.loads((folder / "demo_votes.json").read_text())
    vote = votes[name]
    submit_ballot.server_url = info["url"]
    print(f"Mock write-in: {vote!r}. Preparing five equally sized plaintext blocks.", flush=True)
    print("Checking the server's public key against the public key delivered before voting.", flush=True)
    response = requests.get(f"{info['url']}/public_key", timeout=10)
    response.raise_for_status()
    trusted_key = (folder / "client" / "trusted_public_key.bin").read_bytes()
    if base64.b64decode(response.json()["public_key"], validate=True) != trusted_key:
        raise ValueError("Unexpected election public key.")
    print("The client encrypts locally; the server will receive no plaintext or random exponents.", flush=True)

    output = StringIO()
    with redirect_stdout(output):
        receipt = submit_ballot._submit_ballot(vote, name, info["passwords"][name])
    print(output.getvalue(), end="", flush=True)
    if receipt is None:
        if "Audit passed:" not in output.getvalue():
            raise ValueError("Client auditing or submission failed.")
        for line in output.getvalue().splitlines():
            if line.startswith("Prepared ballot hash: "):
                digest = line.removeprefix("Prepared ballot hash: ")
                write_json(folder / "client" / "receipts" / f"{name}-audited.json", {"receipt": digest})
                break
        else:
            raise ValueError("The audited ballot did not produce a hash.")
        print("Audit complete. This preparation was discarded; no casting HTTP request was made.", flush=True)
    else:
        write_json(folder / "client" / "receipts" / f"{name}.json", {"receipt": receipt})
        print("Server accepted the credentials and ciphertext; its hash matches the local hash.", flush=True)
        print("Saved the receipt for verification after the election closes.", flush=True)


def worker_trustee(folder):
    from trustee import decrypt_ballots

    decrypt_ballots.server_url = read_info(folder)["url"]
    print("Downloading the frozen record and checking receipt hashes and the shuffle proof.", flush=True)
    print("The private key stays in this process; only plaintext blocks and a proof are uploaded.", flush=True)
    decrypt_ballots.decrypt_ballots()


def worker_verify(folder, name):
    from client.verify import verify_server

    receipt = json.loads((folder / "client" / "receipts" / f"{name}.json").read_text())["receipt"]
    print(f"Saved receipt: {receipt}", flush=True)
    verify_server(read_info(folder)["url"], folder / "client" / "trusted_public_key.bin", receipt)
    print("Verification complete. No secret shuffle mapping or private decryption key was used.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=("keys", "server", "client", "trustee", "verify"), help=argparse.SUPPRESS)
    parser.add_argument("--workspace", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--name", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker is None:
        run_demo()
        return

    # The copied modules resolve their own voters and key paths inside this folder.
    sys.path.insert(0, str(args.workspace))
    if args.worker == "keys":
        from trustee.generate_keys import generate_keys
        generate_keys()
    elif args.worker == "server":
        worker_server(args.workspace)
    elif args.worker == "client":
        worker_client(args.workspace, args.name)
    elif args.worker == "trustee":
        worker_trustee(args.workspace)
    elif args.worker == "verify":
        worker_verify(args.workspace, args.name)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Mock election interrupted; background processes were stopped.")
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.TimeoutExpired, requests.RequestException) as error:
        raise SystemExit(f"Mock election failed: {error}") from error
