"""Keep expensive checks tied to the files that can affect their behavior."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ci_changes", ROOT / "scripts/ci/changes.py")
changes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(changes)


class ChangesTests(unittest.TestCase):
    def test_documentation_and_repository_metadata_skip_compilation_and_databases(self):
        for path in ("README.md", "docs/security.md", "CONTRIBUTING.md", "LICENSE",
                     ".github/pull_request_template.md", ".github/ISSUE_TEMPLATE/bug_report.yml"):
            with self.subTest(path=path):
                self.assertEqual(changes.classify([path]), (False, False))

    def test_runtime_and_shared_fixtures_keep_both_database_suites(self):
        for path in ("src/storage.rs", "migrations/0003_directory.sql", "templates/login.html",
                     "assets/app.css", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
                     "Dockerfile", "charts/bloc/templates/deployment.yaml", "tests/run_storage.py",
                     "tests/support/postgres.py", "tests/administrator_access.rs",
                     ".github/workflows/ci.yml", "scripts/ci/changes.py"):
            with self.subTest(path=path):
                self.assertEqual(changes.classify([path]), (True, True))

    def test_distribution_and_unrelated_workflows_do_not_start_database_fixtures(self):
        for path in ("scripts/distribution/validate.sh", "tests/distribution/test_release.py",
                     ".dockerignore", ".github/workflows/audit.yml", ".github/workflows/pr-title.yml",
                     ".github/workflows/distribution.yml", ".github/workflows/administrator-service-capacity.yml"):
            with self.subTest(path=path):
                self.assertEqual(changes.classify([path]), (True, False))

    def test_mixed_or_unknown_changes_cannot_hide_runtime_validation(self):
        self.assertEqual(changes.classify(["README.md", "src/storage.rs"]), (True, True))
        self.assertEqual(changes.classify(["new-build-config.toml"]), (True, True))

    def test_missing_base_runs_full_checks_without_attempting_a_diff(self):
        for base in ('', '0' * 40):
            with self.subTest(base=base), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / 'output'
                subprocess.run([sys.executable, str(ROOT / 'scripts/ci/changes.py')],
                               env={**os.environ, 'BASE': base, 'GITHUB_OUTPUT': str(output)}, check=True)
                self.assertEqual(output.read_text(), 'check=true\nintegration=true\n')

    def test_selection_failure_keeps_source_and_database_jobs_enabled(self):
        jobs = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())['jobs']
        for job, output in (('check', 'check'), ('setup-storage', 'integration')):
            with self.subTest(job=job):
                needs = jobs[job]['needs']
                self.assertIn('changes', [needs] if isinstance(needs, str) else needs)
                condition = ''.join(jobs[job]['if'].split()).replace('"', "'")
                terms = condition.removeprefix('${{').removesuffix('}}').split('&&')
                self.assertCountEqual(terms, [
                    '!cancelled()', f"needs.changes.outputs.{output}!='false'"
                ])

    def test_renaming_runtime_into_documentation_still_selects_database_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            git = work / 'git'
            git.write_text(f'#!{sys.executable}\n' + '''
import sys
assert sys.argv[1:] == ['diff', '--no-renames', '--name-only', '-z', 'base', 'head']
sys.stdout.write('src/old.rs\\0docs/moved.md\\0')
''')
            git.chmod(0o755)
            output = work / 'output'
            subprocess.run([sys.executable, str(ROOT / 'scripts/ci/changes.py')], check=True,
                           env={**os.environ, 'BASE': 'base', 'HEAD': 'head', 'GITHUB_OUTPUT': str(output),
                                'PATH': str(work) + os.pathsep + os.environ['PATH']})
            self.assertEqual(output.read_text(), 'check=true\nintegration=true\n')


if __name__ == "__main__":
    unittest.main()
