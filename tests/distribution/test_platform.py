"""Measure the retained image and propagate failures to the release gate."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/distribution'))
import smoke_platform


class PlatformTests(unittest.TestCase):
    def test_capacity_measures_the_same_digest_without_rebuilding(self):
        for arch in ('amd64', 'arm64'):
            with self.subTest(arch=arch), patch.object(smoke_platform, 'Registry'), \
                    patch.object(smoke_platform, 'Layout') as layout, \
                    patch.object(smoke_platform.subprocess, 'run') as run:
                layout.return_value.root.return_value = {'digest': 'sha256:' + 'a' * 64}
                smoke_platform.exercise(Path('image'), 'linux/' + arch, Path('capacity'))
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

    def test_distribution_waits_for_both_measured_platforms(self):
        workflow = (ROOT / '.github/workflows/distribution.yml').read_text()
        platform = workflow.split('  platform:\n')[1].split('  validate:\n')[0]
        validate = workflow.split('  validate:\n')[1].split('  publish:\n')[0]
        self.assertIn('--capacity-output platform/service-capacity', platform)
        self.assertIn('org.bloc.source-tree-sha256=$fingerprint', platform)
        self.assertNotIn('  native-capacity:', workflow)
        self.assertIn('needs: [prepare, platform]', validate)
        self.assertIn("needs.platform.result == 'success'", validate)
        self.assertIn('combine_native_service_evidence.py platforms', validate)


if __name__ == '__main__':
    unittest.main()
