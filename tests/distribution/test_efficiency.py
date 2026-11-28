"""Release scheduling and fixture budgets preserve every publication gate."""
from pathlib import Path
import sys
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'tests/distribution'))


class EfficiencyTests(unittest.TestCase):
    def workflow(self, name):
        return yaml.safe_load((ROOT/f'.github/workflows/{name}.yml').read_text())

    def test_release_builds_in_parallel_with_unit_checks(self):
        jobs = self.workflow('distribution')['jobs']
        self.assertEqual(set(jobs), {'prepare', 'check', 'build', 'package', 'publish'})
        self.assertEqual(jobs['build']['needs'], 'prepare')
        self.assertEqual(jobs['check']['needs'], 'prepare')
        self.assertEqual(jobs['check']['uses'], './.github/workflows/ci.yml')
        self.assertEqual(set(jobs['package']['needs']), {'prepare', 'build', 'check'})
        self.assertIn("needs.package.result == 'success'", jobs['publish']['if'])
        self.assertIn("needs.prepare.outputs.reuse == 'true'", jobs['publish']['if'])
        original = next(s for s in jobs['package']['steps']
                        if s.get('uses','').startswith('actions/upload-artifact@'))
        self.assertEqual(original['with']['retention-days'],90)
        self.assertFalse(original['with'].get('overwrite',False))

    def test_deliberate_failed_upgrades_use_one_minute_without_shortening_normal_operations(self):
        from cluster import failed_upgrade_arguments
        arguments = failed_upgrade_arguments('fixture-chart', 'fixture-values')
        self.assertEqual(arguments[arguments.index('--timeout')+1], '60s')
        self.assertIn('--rollback-on-failure', arguments)
        self.assertIn('--wait=watcher', arguments)
        source = (ROOT/'tests/distribution/cluster.py').read_text()
        self.assertEqual(source.count('failed_upgrade_arguments(packages[\'B\'], failed)'), 2)
        self.assertIn("'--timeout','5m'", source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
