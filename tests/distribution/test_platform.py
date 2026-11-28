"""Measure the retained image and propagate failures to the release gate."""
from pathlib import Path
import json
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/distribution'))
import smoke_platform


class PlatformTests(unittest.TestCase):
    def test_capacity_measures_the_same_digest_without_rebuilding(self):
        for arch in ('amd64', 'arm64'):
            with self.subTest(arch=arch), patch.object(smoke_platform, 'Registry'), \
                    patch.object(smoke_platform, 'Layout') as layout, \
                    patch.object(smoke_platform.subprocess, 'run') as run, \
                    tempfile.TemporaryDirectory() as temporary:
                capacity = Path(temporary)
                (capacity/'record.json').write_text('{}')
                layout.return_value.read.return_value = json.dumps({'manifests':[
                    {'platform':{'os':'linux','architecture':arch},'digest':'sha256:'+'b'*64}]})
                layout.return_value.root.return_value = {'digest': 'sha256:' + 'a' * 64}
                smoke_platform.exercise(Path('image'), 'linux/' + arch, capacity)
                self.assertEqual(json.loads((capacity/'record.json').read_text())['image_manifest_digest'],
                                 'sha256:'+'b'*64)
                commands = [call.args[0] for call in run.call_args_list]
                images = [command[command.index('--image') + 1]
                          for command in commands if '--image' in command]
                self.assertEqual(images, ['localhost:5001/bloc@sha256:' + 'a' * 64] * 2)
                self.assertIn('--skip-build', commands[-1])
                self.assertTrue(all(call.kwargs['check'] for call in run.call_args_list))

    def test_pull_smoke_or_capacity_failure_cannot_pass_the_platform(self):
        for failed_step in range(3):
            with self.subTest(failed_step=failed_step), patch.object(smoke_platform, 'Registry'), \
                    patch.object(smoke_platform, 'Layout') as layout, \
                    patch.object(smoke_platform.subprocess, 'run') as run:
                layout.return_value.root.return_value = {'digest': 'sha256:' + 'a' * 64}
                run.side_effect = [None] * failed_step + [subprocess.CalledProcessError(1, 'fixture')]
                with self.assertRaises(subprocess.CalledProcessError):
                    smoke_platform.exercise(Path('image'), 'linux/arm64', Path('capacity'))
                self.assertEqual(run.call_count, failed_step + 1)

    def test_distribution_packages_both_native_builds(self):
        jobs = yaml.safe_load((ROOT / '.github/workflows/distribution.yml').read_text())['jobs']
        build_job = yaml.safe_load((ROOT/'.github/workflows/build-images.yml').read_text())['jobs']['build']
        runners = {entry['arch']: entry['runner']
                   for entry in build_job['strategy']['matrix']['include']}
        self.assertEqual(set(runners), {'amd64', 'arm64'})
        self.assertTrue(runners['arm64'].endswith('-arm'))
        self.assertFalse(runners['amd64'].endswith('-arm'))
        build = next(step['run'] for step in build_job['steps']
                     if 'docker buildx build' in step.get('run', ''))
        self.assertIn('org.bloc.source-tree-sha256=', build)
        downloads = [step['with']['name'] for step in jobs['package']['steps']
                     if step.get('uses', '').startswith('actions/download-artifact@')]
        self.assertEqual(set(downloads), {'platform-build-amd64', 'platform-build-arm64'})


if __name__ == '__main__':
    unittest.main()
