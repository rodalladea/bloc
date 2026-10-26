"""Exercise the shell coordinators with isolated child-process fixtures."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ParallelTests(unittest.TestCase):

    def test_cluster_lanes_overlap_cover_all_checks_and_propagate_failures(self):
        for failure in ('', 'lifecycle', 'resilience', 'recovery'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                (work/'tests/distribution').mkdir(parents=True)
                (work/'tests/distribution/cluster.py').write_text('''
import os, pathlib, sys, time
checks = sys.argv[1:]
selected = checks[1::2]
lane = 'recovery' if selected == ['C19'] else 'resilience' if selected == ['C16','C18'] else 'lifecycle'
pathlib.Path(lane + '.started').write_text(' '.join(checks))
deadline = time.monotonic() + 3
while len(list(pathlib.Path('.').glob('*.started'))) != 3:
    if time.monotonic() > deadline:
        raise SystemExit('cluster lanes did not start concurrently')
    time.sleep(0.01)
pathlib.Path(lane + '.finished').touch()
raise SystemExit(1 if os.environ['FAIL_LANE'] == lane else 0)
''')
                result = subprocess.run(['bash', str(ROOT/'tests/distribution/cluster-suites.sh')],
                    cwd=work, env={**os.environ, 'FAIL_LANE':failure}, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
                self.assertEqual(result.returncode, 1 if failure else 0, result.stdout)
                self.assertEqual({p.stem for p in work.glob('*.finished')}, {'lifecycle','resilience','recovery'})
                lifecycle = (work/'lifecycle.started').read_text().split()[1::2]
                recovery = (work/'recovery.started').read_text().split()[1::2]
                resilience = (work/'resilience.started').read_text().split()[1::2]
                self.assertEqual(set(lifecycle), {f'C{i}' for i in range(9,22)} - {'C16','C18','C19'})
                self.assertEqual(recovery, ['C19'])
                self.assertEqual(resilience, ['C16','C18'])
                self.assertEqual(len(lifecycle+resilience+recovery),13)


if __name__ == '__main__':
    unittest.main(verbosity=2)
