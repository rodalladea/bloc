"""Run storage, operator CLI and TLS regression tests on PostgreSQL 17 and 18."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from support import postgres as fixtures

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY_TESTS = tuple(f"directory_c{i:02}" for i in range(1,38)) + ("directory_input_refusals", "directory_response_policy", "directory_realm_upgrade")
DIRECTORY_BROWSER_TESTS = tuple("directory_screen_"+s for s in ("t1","t2","t3","u1","u2","u3")) + ("directory_browser_interactions",)

ADMIN_TESTS = (
    "throttled_post_forms_remain_usable", "throttled_form_issuance_requires_reload", "admission_full_contract", "admission_http_retry_capacity", "authority_http_matrix", "streaming_form_bounds",
    "credential_validation_http", "enhanced_success_navigation", "administration_home", "admission_capacity", "admission_races", "audit_data_bounds",
    "authority_outage", "authorization_matrix", "capability_roles_extended", "credential_atomicity",
    "credential_change_race", "csrf_capacity", "csrf_lifecycle", "email_semantics",
    "expiry_navigation", "hash_backpressure", "login_generic_failure", "login_recovery_race",
    "login_success_rotation", "logout_failure", "logout_replay", "maintenance_retention",
    "operator_code_boundaries", "origin_csrf", "password_change_refusal", "password_change_success",
    "readiness_liveness", "recovery_issue", "recovery_refusal", "recovery_success",
    "request_security_http", "restore_invalidation", "restore_two_instances", "root_navigation",
    "security_audit_atomicity", "session_activity_races", "session_cookie", "session_deadlines",
    "session_restart", "setup_abandonment", "setup_cli_contract", "setup_closed", "setup_code_refusal",
    "setup_http_race", "setup_page", "setup_success", "shared_admission", "two_instance_service",
)
OPERATIONS_TESTS = ("startup_outage", "runtime_log_secrecy", "restore_cli_atomicity", "restore_failure_fencing", "maintenance_failure", "deployment_assembly")
WORKER_TESTS = ("administrator::tests::dummy_work_equivalence", "administrator::tests::request_rejections_precede_password_work", "administrator::tests::http_worker_saturation_and_authority_order")
BROWSER_TESTS = ("browser_loading_network", "browser_no_javascript", "browser_preview", "browser_session_expiry", "browser_validation")

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


def run_logged(command, output_path, *, cwd=None, env=None):
    with output_path.open("wb") as log, subprocess.Popen(
        command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as process:
        while chunk := process.stdout.read1(65536):
            log.write(chunk)
            log.flush()
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        returncode = process.wait()
    return subprocess.CompletedProcess(command, returncode, stdout=output_path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cached-images", action="store_true", help="Use already present pinned fixture images without pulling")
    parser.add_argument("--proof", choices=DIRECTORY_TESTS+DIRECTORY_BROWSER_TESTS, help="Run one exact directory proof with --target")
    parser.add_argument("--target", choices=("realm_user_management",), help="Run only the directory feature target")
    parser.add_argument("--major", type=int, choices=(17, 18), help="Run one database major; default runs both")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--browser-python", help="Playwright Python; requires a pinned local HTTPS proxy on4443")
    parser.add_argument("--tls-spki", help="Explicit synthetic local HTTPS SPKI pin; never disable verification globally")
    args = parser.parse_args()
    if bool(args.browser_python) != bool(args.tls_spki):
        parser.error("--browser-python and --tls-spki are required together")
    if args.proof and not args.target:
        parser.error("--proof requires --target")
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for major, image in zip((17, 18), fixtures.IMAGES):
        if args.major and args.major != major:
            continue
        print(f"Preparing PostgreSQL {major} fixtures", flush=True)
        if not args.cached_images:
            subprocess.run(["docker", "pull", image], check=True)
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
                    "BLOC_SETUP_MAJOR": str(major), "BLOC_SETUP_CONTAINER": containers[0],
                    "BLOC_SETUP_PORT": ports[0], "BLOC_SETUP_CA": str(directory / "ca.crt"),
                    "BLOC_SETUP_OTHER_CA": str(directory / "other-ca.crt"),
                    "BLOC_SETUP_WRONG_NAME_PORT": ports[1], "BLOC_SETUP_PLAIN_PORT": ports[2],
                }
                if args.browser_python:
                    environment |= {"BLOC_BROWSER_PYTHON": args.browser_python, "BLOC_TEST_SPKI": args.tls_spki, "BLOC_DIRECTORY_BROWSER_EVIDENCE":str(args.output / f"browser-{major}")}
                selection = ["--skip", "native_service_capacity"]
                if not args.browser_python:
                    selection += ["--skip", "browser_", "--skip", "directory_screen_"]
                targets = ["--test", "realm_user_management"] if args.target else ["--lib", "--test", "setup_storage", "--test", "operator", "--test", "storage_tls", "--test", "administrator_access", "--test", "administrator_operations", "--test", "realm_user_management"]
                print(f"Running PostgreSQL {major} regression tests", flush=True)
                run = run_logged(
                    ["cargo", "test", "--locked", *targets, *([args.proof] if args.proof else []),
                     "--", "--ignored", "--test-threads=1", *(["--exact"] if args.proof else []), *selection],
                    args.output / f"postgres-{major}.txt", cwd=ROOT, env=environment,
                )
                version = fixtures.command("docker", "exec", containers[0], "psql", "-U", "probe",
                                           "-d", "probe", "-Atc", "SHOW server_version")
                results.append({"major": major, "version": version, "image_id": identity["Id"],
                                "repo_digests": identity.get("RepoDigests"), "exit_code": run.returncode})
                (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                run.check_returncode()
                inventory = (args.proof,) if args.proof else DIRECTORY_TESTS if args.target else TESTS + ADMIN_TESTS + OPERATIONS_TESTS + WORKER_TESTS + DIRECTORY_TESTS
                for test in inventory + (() if args.proof else (DIRECTORY_BROWSER_TESTS if args.target else BROWSER_TESTS + DIRECTORY_BROWSER_TESTS) if args.browser_python else ()):
                    if f"test {test} ... ok" not in run.stdout:
                        raise RuntimeError(f"named proof did not run: {test}")
        finally:
            for container in containers:
                subprocess.run(["docker", "rm", "--force", "--volumes", container],
                               check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
