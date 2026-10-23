"""Verify concurrent source validation cannot bypass the candidate gate."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ValidationTests(unittest.TestCase):
    def test_source_checks_overlap_and_every_failure_blocks_candidate_evidence(self):
        phases = ['fmt', 'clippy', 'test', 'doc', 'install', 'audit', 'capacity']
        for failure in ['init', '', *phases, 'source-smoke']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                for directory in ('bin', 'scripts/distribution', 'scripts/ci', 'tests/distribution',
                                  'platforms/amd64', 'platforms/arm64'):
                    (work/directory).mkdir(parents=True)
                (work/'scripts/ci/install-auditor.sh').write_text(
                    (ROOT/'scripts/ci/install-auditor.sh').read_text())
                (work/'tests/distribution/setup-cluster.sh').write_text('exit 0\n')
                for arch in ('amd64', 'arm64'):
                    (work/f'platforms/{arch}/smoke.log').write_text('fixture passed\n')
                (work/'bin/rustup').write_text(f'#!{sys.executable}\n' + '''
import os, pathlib, sys
assert sys.argv[1:] == ['show', 'active-toolchain']
assert not pathlib.Path('source-started').exists()
assert not pathlib.Path('distribution-started').exists()
pathlib.Path('toolchain-started').touch()
if os.environ['FAIL_SOURCE'] == 'init': raise SystemExit(1)
pathlib.Path('toolchain-ready').touch()
''')
                (work/'bin/cargo').write_text(f'#!{sys.executable}\n' + '''
import os, pathlib, sys, time
assert pathlib.Path('toolchain-ready').exists(), 'cargo preceded toolchain initialization'
phase = 'capacity' if 'native_service_capacity' in sys.argv else sys.argv[1]
with open('cargo-commands', 'a') as log: log.write(phase + '\\n')
if phase == 'fmt':
    pathlib.Path('source-started').touch()
    deadline = time.monotonic() + 3
    while not pathlib.Path('distribution-started').exists():
        if time.monotonic() > deadline: raise SystemExit('source checks did not overlap')
        time.sleep(0.01)
if phase == os.environ['FAIL_SOURCE']: raise SystemExit(1)
if phase == 'capacity': pathlib.Path('source-passed').touch()
''')
                (work/'bin/python3').write_text(f'#!{sys.executable}\n' + '''
import os, pathlib, sys
assert pathlib.Path('toolchain-ready').exists(), 'distribution preceded toolchain initialization'
args = sys.argv[1:]
if args[0] == '-m': pathlib.Path('distribution-started').touch()
elif args[0] == '-c': print('0.0.1')
elif args[0] == 'scripts/distribution/candidate.py': pathlib.Path('candidate').mkdir()
elif args[0] == 'tests/distribution/source.py':
    assert pathlib.Path('source-passed').exists(), 'source smoke overlaps source checks'
    pathlib.Path('source-smoke-passed').touch()
    if os.environ['FAIL_SOURCE'] == 'source-smoke': raise SystemExit(1)
elif args[0] == '-':
    assert pathlib.Path('source-passed').exists(), 'evidence preceded source success'
    assert pathlib.Path('source-smoke-passed').exists(), 'evidence preceded source smoke'
    pathlib.Path('candidate/evidence.json').write_text('{}')
''')
                (work/'bin/git').write_text('#!/bin/sh\nprintf "fixture-revision\\n"\n')
                for executable in (work/'bin').iterdir():
                    executable.chmod(0o755)
                result = subprocess.run(['bash', str(ROOT/'scripts/distribution/validate.sh')],
                    cwd=work, env={**os.environ, 'FAIL_SOURCE':failure,
                                   'BLOC_CI_TOOLS_DIR':str(work/'tools'),
                                   'GITHUB_PATH':str(work/'github-path'),
                                   'PATH':str(work/'bin')+os.pathsep+os.environ['PATH']},
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
                self.assertEqual(result.returncode, 1 if failure else 0, result.stdout)
                self.assertTrue((work/'toolchain-started').exists())
                if failure == 'init':
                    self.assertFalse((work/'cargo-commands').exists())
                    self.assertFalse((work/'distribution-started').exists())
                    self.assertFalse((work/'candidate/evidence.json').exists())
                    continue
                executed = (work/'cargo-commands').read_text().splitlines()
                self.assertEqual(executed, phases[:phases.index(failure)+1] if failure in phases else phases)
                self.assertEqual((work/'candidate/evidence.json').exists(), not failure)



if __name__ == '__main__':
    unittest.main(verbosity=2)
