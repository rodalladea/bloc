"""Run storage, operator CLI and TLS regression tests on PostgreSQL 17 and 18."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from support import postgres as fixtures

ROOT = Path(__file__).resolve().parents[1]
TESTS = (
    "migration_contract", "capability_roles", "issue_and_replace", "unusable_codes",
    "competing_claims", "audit_failure_rolls_back", "expiry_after_lock",
    "authority_failure", "durable_output_and_failures", "claim_and_replacement_serialize",
    "verified_tls_connects_to_expected_major", "untrusted_ca_is_rejected",
    "wrong_hostname_is_rejected", "plaintext_server_is_rejected",
)

ROLES = """
CREATE ROLE bloc_runtime NOLOGIN NOINHERIT;
CREATE ROLE bloc_operator NOLOGIN NOINHERIT;
CREATE ROLE bloc_maintenance NOLOGIN NOINHERIT;
CREATE ROLE migrator_user LOGIN PASSWORD 'synthetic-setup-only';
CREATE ROLE runtime_user LOGIN PASSWORD 'synthetic-setup-only';
CREATE ROLE operator_user LOGIN PASSWORD 'synthetic-setup-only';
CREATE ROLE maintenance_user LOGIN PASSWORD 'synthetic-setup-only';
CREATE ROLE public_user LOGIN PASSWORD 'synthetic-setup-only';
GRANT bloc_runtime TO runtime_user;
GRANT bloc_operator TO operator_user;
GRANT bloc_maintenance TO maintenance_user;
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for major, image in zip((17, 18), fixtures.IMAGES):
        identity = json.loads(fixtures.command("docker", "image", "inspect", image))[0]
        containers = []
        try:
            with tempfile.TemporaryDirectory(prefix="bloc-setup-fixture-") as temporary:
                directory = Path(temporary)
                fixtures.certificate(directory, "ca")
                fixtures.certificate(directory, "other-ca")
                fixtures.certificate(directory, "matching", "127.0.0.1")
                fixtures.certificate(directory, "wrong-name", "127.0.0.2")
                ports = [fixtures.start_fixture(identity["Id"], directory, name, containers)
                         for name in ("matching", "wrong-name", "plain")]
                subprocess.run(["docker", "exec", "-i", containers[0], "psql", "-U", "probe",
                                "-d", "probe", "-v", "ON_ERROR_STOP=1"],
                               input=ROLES, text=True, check=True, capture_output=True)
                environment = os.environ | {
                    "BLOC_SETUP_MAJOR": str(major),
                    "BLOC_SETUP_PORT": ports[0], "BLOC_SETUP_CA": str(directory / "ca.crt"),
                    "BLOC_SETUP_OTHER_CA": str(directory / "other-ca.crt"),
                    "BLOC_SETUP_WRONG_NAME_PORT": ports[1], "BLOC_SETUP_PLAIN_PORT": ports[2],
                }
                run = subprocess.run(["cargo", "test", "--locked", "--test", "setup_storage",
                                      "--test", "operator", "--test", "storage_tls",
                                      "--", "--ignored", "--test-threads=1"],
                                     cwd=ROOT, env=environment, capture_output=True, text=True)
                output = run.stdout + run.stderr
                (args.output / f"postgres-{major}.txt").write_text(output)
                print(output, flush=True)
                version = fixtures.command("docker", "exec", containers[0], "psql", "-U", "probe",
                                           "-d", "probe", "-Atc", "SHOW server_version")
                results.append({"major": major, "version": version, "image_id": identity["Id"],
                                "repo_digests": identity.get("RepoDigests"), "exit_code": run.returncode})
                (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                run.check_returncode()
                for test in TESTS:
                    if f"test {test} ... ok" not in run.stdout:
                        raise RuntimeError(f"named proof did not run: {test}")
        finally:
            for container in containers:
                subprocess.run(["docker", "rm", "--force", "--volumes", container],
                               check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
