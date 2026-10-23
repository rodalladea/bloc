"""Reuse only the pinned auditor and keep installation failures fatal."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AuditorTests(unittest.TestCase):
    def test_correct_version_reuses_binary_and_missing_or_wrong_version_installs(self):
        for version in (None, '0.22.1', '0.22.2'):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                (work / 'tools/bin').mkdir(parents=True)
                (work / 'bin').mkdir()
                if version:
                    binary = work / 'tools/bin/cargo-audit'
                    binary.write_text(f'#!/bin/sh\nprintf "cargo-audit {version}\\n"\n')
                    binary.chmod(0o755)
                cargo = work / 'bin/cargo'
                cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$INSTALL_LOG"\nexit "${INSTALL_EXIT:-0}"\n')
                cargo.chmod(0o755)
                env = {**os.environ, 'BLOC_CI_TOOLS_DIR': str(work / 'tools'),
                       'GITHUB_PATH': str(work / 'github-path'), 'INSTALL_LOG': str(work / 'installed'),
                       'PATH': str(work / 'bin') + os.pathsep + os.environ['PATH']}
                command = ['bash', str(ROOT / 'scripts/ci/install-auditor.sh')]
                subprocess.run(command, env=env, check=True, capture_output=True)
                self.assertEqual((work / 'github-path').read_text(), str(work / 'tools/bin') + '\n')
                self.assertEqual((work / 'installed').exists(), version != '0.22.2')
                if version != '0.22.2':
                    arguments = (work / 'installed').read_text().splitlines()
                    self.assertIn('--locked', arguments)
                    self.assertEqual(arguments[arguments.index('--version') + 1], '0.22.2')
                    failed = subprocess.run(command, env={**env, 'INSTALL_EXIT': '7'}, capture_output=True)
                    self.assertEqual(failed.returncode, 7)


if __name__ == '__main__':
    unittest.main()
