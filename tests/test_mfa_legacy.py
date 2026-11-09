"""Retain a real pre-MFA executable rather than silently skipping upgrade proofs."""
import os
import io
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest import mock

from support.mfa_legacy import BASE_REVISION, ensure_binary


class MfaLegacyTests(unittest.TestCase):
    def test_explicit_executable_is_resolved_without_a_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            binary = root / "retained-bloc"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o700)
            alias = root / "alias"
            alias.symlink_to(binary)
            with mock.patch.dict(os.environ, {"BLOC_MFA_LEGACY_BINARY": str(alias)}):
                with mock.patch("support.mfa_legacy.subprocess.run") as run:
                    self.assertEqual(ensure_binary(root), str(binary.resolve()))
                    run.assert_not_called()

    def test_invalid_explicit_binary_does_not_fall_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for path in [root / "missing", root, root / "not-executable"]:
                if path.name == "not-executable":
                    path.write_text("invalid")
                    path.chmod(0o600)
                with self.subTest(path=path):
                    with mock.patch.dict(os.environ, {"BLOC_MFA_LEGACY_BINARY": str(path)}):
                        with self.assertRaises((OSError, ValueError)):
                            ensure_binary(root)
            self.assertFalse((root / "mfa-baseline").exists())

    def test_default_requests_exact_base_and_builds_outside_current_target(self):
        self.assertEqual(BASE_REVISION, "db767253d83913396ca71fff90337f72cfe8f7e8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            def execute(command, **kwargs):
                if command[0] == "git":
                    self.assertIn(BASE_REVISION, command)
                    # Ordinary check jobs use shallow clones; real history is tested by
                    # the explicit upgrade proof, not a unit test's archive fixture.
                    archive = Path(command[command.index("--output") + 1])
                    with tarfile.open(archive, "w") as contents:
                        for name, data in {
                            "Cargo.toml": b'[package]\nname="baseline"\n',
                            "migrations/0005_realm_authentication.sql": b"-- synthetic baseline archive\n",
                        }.items():
                            info = tarfile.TarInfo(name)
                            info.size = len(data)
                            contents.addfile(info, io.BytesIO(data))
                    return subprocess.CompletedProcess(command, 0)
                self.assertEqual(command[:5], ["cargo", "build", "--locked", "--bin", "bloc"])
                self.assertEqual(Path(kwargs["cwd"]), root / "mfa-baseline")
                self.assertEqual(command[5], "--target-dir")
                target = Path(command[6])
                self.assertEqual(target, root / "mfa-baseline-target")
                source = root / "mfa-baseline"
                self.assertTrue((source / "migrations/0005_realm_authentication.sql").is_file())
                self.assertFalse((source / "migrations/0006_realm_mfa.sql").exists())
                self.assertNotIn("webauthn-rs", (source / "Cargo.toml").read_text())
                executable = target / "debug/bloc"
                executable.parent.mkdir(parents=True)
                executable.write_text("#!/bin/sh\nexit 0\n")
                executable.chmod(0o700)
                kwargs["stdout"].write(b"synthetic build diagnostics\n")
                return subprocess.CompletedProcess(command, 0)
            with mock.patch.dict(os.environ, {"BLOC_MFA_LEGACY_BINARY": ""}):
                with mock.patch("support.mfa_legacy.subprocess.run", side_effect=execute):
                    result = ensure_binary(root)
            self.assertEqual(result, str(root / "mfa-baseline-target/debug/bloc"))
            self.assertEqual((root / "mfa-baseline-build.txt").read_text(), "synthetic build diagnostics\n")

    def test_build_failure_is_preserved_and_propagates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            def execute(command, **kwargs):
                if command[0] == "git":
                    archive = Path(command[command.index("--output") + 1])
                    with tarfile.open(archive, "w"):
                        pass
                    return subprocess.CompletedProcess(command, 0)
                kwargs["stdout"].write(b"synthetic dependency build failure\n")
                raise subprocess.CalledProcessError(101, command)
            with mock.patch.dict(os.environ, {"BLOC_MFA_LEGACY_BINARY": ""}):
                with mock.patch("support.mfa_legacy.subprocess.run", side_effect=execute):
                    with self.assertRaises(subprocess.CalledProcessError) as failure:
                        ensure_binary(root)
            self.assertEqual(failure.exception.returncode, 101)
            self.assertIn("dependency build failure", (root / "mfa-baseline-build.txt").read_text())
            self.assertFalse((root / "mfa-baseline-target/debug/bloc").exists())


if __name__ == "__main__":
    unittest.main()
