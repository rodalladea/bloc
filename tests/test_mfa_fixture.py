"""Synthetic fixtures provision a dedicated, valid keyring without inline secrets."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from support.mfa_fixture import write_keyring


class MfaFixtureTests(unittest.TestCase):
    def test_generated_keyring_has_exact_operator_file_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            identifier, path = write_keyring(Path(temporary))
            self.assertEqual(str(uuid.UUID(identifier)), identifier)
            document = json.loads(path.read_text())
            self.assertEqual(set(document), {"format_version", "keys"})
            self.assertEqual(document["format_version"], 1)
            self.assertEqual(len(document["keys"]), 1)
            self.assertEqual(set(document["keys"][0]), {"id", "key"})
            self.assertEqual(document["keys"][0]["id"], identifier)
            encoded = document["keys"][0]["key"]
            decoded = base64.b64decode(encoded, validate=True)
            self.assertEqual(len(decoded), 32)
            self.assertEqual(base64.b64encode(decoded).decode(), encoded)

    def test_keyring_neither_reuses_nor_changes_existing_abuse_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            abuse = bytes(range(32))
            (directory / "abuse-key").write_bytes(abuse)
            _, path = write_keyring(directory)
            decoded = base64.b64decode(json.loads(path.read_text())["keys"][0]["key"])
            self.assertNotEqual(decoded, abuse)
            self.assertEqual((directory / "abuse-key").read_bytes(), abuse)

    def test_existing_keyring_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, path = write_keyring(directory)
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_keyring(directory)
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
