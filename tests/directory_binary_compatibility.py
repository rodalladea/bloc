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
                        help="Executable built from the pre-directory revision")
    parser.add_argument("--current-binary", required=True, type=Path,
                        help="Executable built from the revision being verified")
    parser.add_argument("--output", required=True, type=Path)
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
        containers, children = [], []
        try:
            with tempfile.TemporaryDirectory(prefix="bloc-directory-compatibility-") as temporary:
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
                assert sql("SELECT string_agg(version::text,',' ORDER BY version) FROM public._sqlx_migrations") == "1,2"
                before_checksums = sql("SELECT version||':'||encode(checksum,'hex') FROM public._sqlx_migrations ORDER BY version")
                sql("INSERT INTO bloc.security_audit_event(installation_id,action,outcome) VALUES(1,'code_issue','success')")
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
                assert sql("SELECT version||':'||encode(checksum,'hex') FROM public._sqlx_migrations WHERE version<=2 ORDER BY version") == before_checksums
                assert sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='code_issue' AND realm_id IS NULL AND realm_user_id IS NULL") == "1"
                assert sql("SELECT string_agg(version::text,',' ORDER BY version) FROM public._sqlx_migrations") == "1,2,3,4"
                record = {"major": major, "image_id": identity["Id"], "repo_digests": identity.get("RepoDigests"),
                          "revision": revision, "binary_sha256": fingerprints, "before_upgrade": before,
                          "after_upgrade": after, "liveness": live, "migrations": migrations, "result": "PASS"}
                records.append(record)
                (args.output / "records.json").write_text(json.dumps(records, indent=2) + "\n")
                print(f"test directory_binary_compatibility_postgres_{major} ... ok", flush=True)
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
