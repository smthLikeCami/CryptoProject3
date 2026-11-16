"""Temporarily check voter credentials before ballot submission is added."""

from getpass import getpass

import requests


def authenticate():
    """Prompt for credentials and send them to the local voting server."""
    name = input("Voter name: ")
    password = getpass("Password: ")

    # Match the JSON fields expected by the server.
    credentials = {"name": name, "password": password}

    try:
        response = requests.post(
            "http://127.0.0.1:5000/authenticate",
            json=credentials,
            timeout=10,
        )
    except requests.RequestException:
        print("Could not reach the server. Check that it is running and try again.")
        return False

    try:
        result = response.json()
    except ValueError:
        print("The server returned an unexpected response.")
        return False

    if not isinstance(result, dict):
        print("The server returned an unexpected response.")
        return False

    if response.status_code == 200:
        print(result.get("message", "Authentication successful"))
        return True

    print(result.get("error", "Authentication failed"))
    return False


if __name__ == "__main__":
    authenticate()
