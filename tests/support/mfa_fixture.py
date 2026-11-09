"""Dedicated synthetic keyring material for disposable fixtures, never production."""
import base64
import json
import os
from pathlib import Path
import uuid


def write_keyring(directory: Path) -> tuple[str, Path]:
    identifier = str(uuid.uuid4())
    path = directory / "mfa-keyring.json"
    document = {"format_version": 1, "keys": [{
        "id": identifier,
        "key": base64.b64encode(os.urandom(32)).decode("ascii"),
    }]}
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(document, output)
        output.write("\n")
    return identifier, path
