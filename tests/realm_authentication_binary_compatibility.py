"""Prove both executable/schema compatibility directions on disposable PostgreSQL."""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from support import postgres as fixtures
from run_storage import ROLES

ROOT = Path(__file__).resolve().parents[1]


def response(port, path):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", path)
        result = connection.getresponse()
        return {"status": result.status, "body": result.read().decode()}
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-binary", required=True, type=Path,
                        help="Executable built from the pre-realm-authentication revision")
    parser.add_argument("--current-binary", required=True, type=Path,
                        help="Executable built from the revision being verified")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--major", type=int, choices=(17,18))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    binaries = {}
    for name, source in (("legacy", args.legacy_binary), ("current", args.current_binary)):
        destination = args.output.resolve() / f"{name}-bloc"
        shutil.copy2(source.resolve(strict=True), destination)
        binaries[name] = destination
    fingerprints = {name: hashlib.sha256(binary.read_bytes()).hexdigest()
                    for name, binary in binaries.items()}
    revision = fixtures.command("git", "-C", str(ROOT), "rev-parse", "HEAD")
    records = []
    for major, image in zip((17, 18), fixtures.IMAGES):
        if args.major and major != args.major:
            continue
        containers, children = [], []
        try:
            with tempfile.TemporaryDirectory(prefix="bloc-realm-auth-compatibility-") as temporary:
                directory = Path(temporary)
                fixtures.certificate(directory, "ca")
                fixtures.certificate(directory, "matching", "127.0.0.1")
                identity = json.loads(fixtures.command("docker", "image", "inspect", image))[0]
                port = fixtures.start_fixture(identity["Id"], directory, "matching", containers)
                subprocess.run(["docker", "exec", "-i", containers[0], "psql", "-U", "probe",
                                "-d", "probe", "-v", "ON_ERROR_STOP=1"],
                               input=ROLES + "\nCREATE DATABASE directory_compatibility OWNER migrator_user;",
                               text=True, check=True, capture_output=True)

                def sql(statement):
                    return fixtures.command("docker", "exec", containers[0], "psql", "-U", "probe",
                                            "-d", "directory_compatibility", "-Atc", statement)

                for role in ("migrator_user", "runtime_user"):
                    secret = directory / role
                    secret.write_text(f"postgres://{role}:synthetic-setup-only@127.0.0.1:{port}/directory_compatibility")
                    secret.chmod(0o600)
                abuse = directory / "abuse"
                abuse.write_bytes(bytes([7]) * 32)
                abuse.chmod(0o600)
                environment = os.environ | {
                    "BLOC_DATABASE_CA_FILE": str(directory / "ca.crt"),
                    "BLOC_ABUSE_KEY_FILE": str(abuse),
                    "BLOC_CANONICAL_ORIGIN": "https://bloc.example.test:4443",
                    "BLOC_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
                }
                migrations = []

                def migrate(name):
                    run = subprocess.run([str(binaries[name]), "database", "migrate"],
                                         env=environment | {"BLOC_DATABASE_URL_FILE": str(directory / "migrator_user")},
                                         capture_output=True, text=True)
                    migrations.append({"binary": name, "exit_code": run.returncode,
                                       "stdout": run.stdout, "stderr": run.stderr})
                    assert run.returncode == 0, migrations[-1]

                migrate("legacy")
                assert sql("SELECT string_agg(version::text,',' ORDER BY version) FROM public._sqlx_migrations") == "1,2,3,4"
                before_checksums = sql("SELECT version||':'||encode(checksum,'hex') FROM public._sqlx_migrations ORDER BY version")
                sql("INSERT INTO bloc.security_audit_event(installation_id,action,outcome) VALUES(1,'code_issue','success')")
                sql("INSERT INTO bloc.realm(id,name,created_at,updated_at) VALUES('11111111-1111-4111-8111-111111111111','Retained',clock_timestamp(),clock_timestamp())")
                sql("INSERT INTO bloc.realm_user(id,realm_id,email,status,created_at,updated_at) VALUES('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111','Retained@example.test','suspended',clock_timestamp(),clock_timestamp())")
                directory_before = sql("SELECT row_to_json(r)::text FROM bloc.realm r UNION ALL SELECT row_to_json(u)::text FROM bloc.realm_user u")
                for name, listen in (("legacy", 38001), ("current", 38002)):
                    handle = (args.output / f"postgres-{major}-{name}.log").open("w")
                    child = subprocess.Popen([str(binaries[name])], stdout=handle, stderr=handle,
                                             env=environment | {"BLOC_DATABASE_URL_FILE": str(directory / "runtime_user"),
                                                                "BLOC_BIND_ADDR": f"127.0.0.1:{listen}"})
                    children.append((child, handle))
                    deadline = time.monotonic() + 15
                    while True:
                        try:
                            response(listen, "/healthz")
                            break
                        except OSError:
                            assert time.monotonic() < deadline and child.poll() is None, "service did not start"
                            time.sleep(0.05)
                before = {name: response(port, "/readyz") for name, port in (("legacy", 38001), ("current", 38002))}
                assert before["legacy"]["status"] == 200
                assert before["current"]["status"] == 503
                migrate("current")
                after = {name: response(port, "/readyz") for name, port in (("legacy", 38001), ("current", 38002))}
                assert after["legacy"]["status"] == 503
                assert after["current"]["status"] == 200
                live = {name: response(port, "/healthz") for name, port in (("legacy", 38001), ("current", 38002))}
                assert live["legacy"]["status"] == live["current"]["status"] == 200
                assert sql("SELECT version||':'||encode(checksum,'hex') FROM public._sqlx_migrations WHERE version<=4 ORDER BY version") == before_checksums
                assert sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='code_issue' AND realm_id IS NULL AND realm_user_id IS NULL") == "1"
                assert sql("SELECT string_agg(version::text,',' ORDER BY version) FROM public._sqlx_migrations") == "1,2,3,4,5"
                assert sql("SELECT row_to_json(r)::text FROM bloc.realm r UNION ALL SELECT row_to_json(u)::text FROM bloc.realm_user u") == directory_before
                assert sql("SELECT count(*) FROM bloc.realm_user_credential") == "0"
                assert sql("SELECT count(*) FROM bloc.realm_authentication_settings WHERE NOT registration_enabled AND password_min_length=16 AND NOT require_uppercase AND NOT require_lowercase AND NOT require_number AND NOT require_special AND activation_ttl_seconds=86400 AND reset_ttl_seconds=1800 AND session_idle_seconds=1800 AND session_absolute_seconds=43200 AND session_limit=10") == "1"
                record = {"major": major, "image_id": identity["Id"], "repo_digests": identity.get("RepoDigests"),
                          "revision": revision, "binary_sha256": fingerprints, "before_upgrade": before,
                          "after_upgrade": after, "liveness": live, "migrations": migrations, "result": "PASS"}
                records.append(record)
                (args.output / "records.json").write_text(json.dumps(records, indent=2) + "\n")
                print(f"test realm_auth_binary_compatibility_postgres_{major} ... ok", flush=True)
        finally:
            for child, handle in children:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                handle.close()
            for container in containers:
                subprocess.run(["docker", "rm", "--force", "--volumes", container],
                               check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
