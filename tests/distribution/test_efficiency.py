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

    def test_cluster_validation_and_native_measurements_share_builds_without_waiting_for_each_other(self):
        jobs = self.workflow('distribution')['jobs']
        self.assertIn('build', jobs['platform']['needs'])
        self.assertIn('build', jobs['validate']['needs'])
        self.assertNotIn('platform', jobs['validate']['needs'])
        self.assertNotIn('validate', jobs['platform']['needs'])
        self.assertEqual(set(jobs['complete']['needs']), {'prepare', 'platform', 'validate'})
        self.assertIn('needs.platform.result == \'success\'', jobs['complete']['if'])
        self.assertIn('needs.validate.result == \'success\'', jobs['complete']['if'])
        self.assertIn('complete', jobs['publish']['needs'])
        self.assertIn("needs.complete.result == 'success'", jobs['publish']['if'])
        self.assertIn("needs.prepare.outputs.reuse == 'true'", jobs['publish']['if'])
        self.assertNotIn('reuse', jobs['complete']['if'])
        original = next(s for s in jobs['complete']['steps']
                        if s.get('uses','').startswith('actions/upload-artifact@'))
        self.assertEqual(original['with']['retention-days'],90)
        self.assertFalse(original['with'].get('overwrite',False))
        for job in ('platform', 'validate'):
            downloads = [s['with']['name'] for s in jobs[job]['steps']
                         if s.get('uses', '').startswith('actions/download-artifact@')]
            self.assertTrue(any('platform-build-' in name for name in downloads))

    def test_main_warms_the_same_native_build_cache_as_releases(self):
        jobs = self.workflow('distribution')['jobs']
        warming = self.workflow('release-cache')
        # PyYAML 1.1 treats the YAML key "on" as boolean true.
        self.assertEqual(warming[True]['push']['branches'], ['main'])
        self.assertNotIn('pull_request', warming[True])
        self.assertEqual(jobs['build']['uses'], warming['jobs']['images']['uses'])
        build = self.workflow('build-images')['jobs']['build']
        self.assertEqual({row['arch'] for row in build['strategy']['matrix']['include']}, {'amd64', 'arm64'})
        cache = next(s['with'] for s in build['steps'] if s.get('uses', '').startswith('actions/cache@'))
        self.assertIn('runner.arch', cache['key'])
        self.assertIn('github.sha', cache['key'])
        self.assertEqual(cache['restore-keys'].splitlines()[-1],
                         'buildkit-${{ runner.os }}-${{ runner.arch }}-')
        self.assertNotIn('packages: write', (ROOT/'.github/workflows/release-cache.yml').read_text())

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
