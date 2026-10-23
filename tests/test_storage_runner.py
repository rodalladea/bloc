"""Check live fixture diagnostics and subprocess failure propagation."""

import io
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from run_storage import run_logged


class StorageRunnerTests(unittest.TestCase):
    def test_partial_output_is_visible_before_child_exits(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_path = Path(temporary) / "postgres.txt"
            acknowledged = Path(temporary) / "acknowledged"

            class Console(io.BytesIO):
                def flush(self):
                    if self.getvalue() == b"test slow_case ... ":
                        acknowledged.touch()

            console = Console()
            script = """
import pathlib, sys, time
output, acknowledged = map(pathlib.Path, sys.argv[1:])
sys.stdout.write('test slow_case ... ')
sys.stdout.flush()
deadline = time.monotonic() + 3
while not (acknowledged.exists() and output.exists()
           and output.read_bytes() == b'test slow_case ... '):
    if time.monotonic() > deadline:
        raise SystemExit('partial output was buffered until process exit')
    time.sleep(0.01)
print('ok')
"""
            with mock.patch("run_storage.sys.stdout", types.SimpleNamespace(buffer=console)):
                result = run_logged(
                    [sys.executable, "-c", script, str(output_path), str(acknowledged)],
                    output_path,
                )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(result.stdout, "test slow_case ... ok\n")
            self.assertEqual(output_path.read_bytes(), console.getvalue())

    def test_stderr_is_retained_and_failure_propagates(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_path = Path(temporary) / "postgres.txt"
            console = io.BytesIO()
            with mock.patch("run_storage.sys.stdout", types.SimpleNamespace(buffer=console)):
                result = run_logged(
                    [sys.executable, "-c",
                     "import sys; print('started', flush=True); "
                     "print('failed', file=sys.stderr, flush=True); sys.exit(7)"],
                    output_path,
                )
            self.assertEqual(result.stdout, "started\nfailed\n")
            self.assertEqual(output_path.read_bytes(), console.getvalue())
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                result.check_returncode()
            self.assertEqual(failure.exception.returncode, 7)


if __name__ == "__main__":
    unittest.main()
