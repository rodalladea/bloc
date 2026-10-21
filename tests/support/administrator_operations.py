"""Process, CLI, audit and rendered-manifest assertions for administrator access.

Only disposable databases, synthetic identifiers and loopback service ports are
used. Helm parses its rendered objects itself; no extra YAML dependency is needed.
"""
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from http.cookies import SimpleCookie
from urllib.parse import urlencode

BINARY = os.environ["BLOC_TEST_BINARY"]
ORIGIN = "https://operations.example.test"
EMAIL = "AuditMarker+owner@example.test"
PASSWORD = "  operations password marker  "
NEW_PASSWORD = "replacement operations marker"
SOURCE = "198.51.100.187"


def sql(statement, database=None):
    result = subprocess.run(
        ["docker", "exec", "-i", os.environ["BLOC_SETUP_CONTAINER"], "psql",
         "-U", "probe", "-d", database or os.environ["BLOC_TEST_DATABASE"],
         "-At", "-v", "ON_ERROR_STOP=1", "-c", statement],
        text=True, capture_output=True, check=True,
    )
    return result.stdout.strip()


def owner():
    return json.loads(sql(
        "SELECT json_build_object('id',a.id::text,'hash',password_hash,"
        "'version',credential_version,'fenced',i.recovery_required)"
        " FROM bloc.installation_administrator a JOIN bloc.installation i"
        " ON i.id=a.installation_id"
    ))


def fail_audit(enabled):
    if enabled:
        sql("CREATE FUNCTION public.ops_fail_audit() RETURNS trigger LANGUAGE plpgsql"
            " AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$;"
            " CREATE TRIGGER ops_fail_audit BEFORE INSERT ON bloc.security_audit_event"
            " FOR EACH ROW EXECUTE FUNCTION public.ops_fail_audit()")
    else:
        sql("DROP TRIGGER ops_fail_audit ON bloc.security_audit_event;"
            " DROP FUNCTION public.ops_fail_audit()")


class Environment:
    def __init__(self, directory):
        self.directory = Path(directory)
        port = os.environ["BLOC_SETUP_PORT"]
        database = os.environ["BLOC_TEST_DATABASE"]
        self.urls = {}
        for role in ("runtime", "operator", "maintenance"):
            path = self.directory / (role + "-url")
            path.write_text(
                f"postgres://{role}_user:synthetic-setup-only@127.0.0.1:{port}/{database}"
            )
            self.urls[role] = path
        self.abuse = self.directory / "abuse"
        self.abuse.write_bytes(bytes(range(32)))

    def variables(self, role="runtime"):
        return os.environ | {
            "BLOC_DATABASE_URL_FILE": str(self.urls[role]),
            "BLOC_DATABASE_CA_FILE": os.environ["BLOC_TEST_CA"],
            "BLOC_ABUSE_KEY_FILE": str(self.abuse),
            "BLOC_CANONICAL_ORIGIN": ORIGIN,
            "BLOC_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
            "RUST_LOG": "info",
        }

    def cli(self, *arguments, role="operator"):
        return subprocess.run(
            [BINARY, *arguments], env=self.variables(role),
            capture_output=True, text=True, check=False,
        )

    def code(self, purpose):
        output = self.cli("admin", purpose + "-code")
        assert output.returncode == 0, output.stderr
        assert output.stderr == ""
        rows = output.stdout.splitlines()
        assert len(rows) == 2
        assert re.fullmatch(r"code=[A-Za-z0-9_-]{43}", rows[0])
        assert rows[1].startswith("expires_at=")
        return rows[0][5:]


class Server:
    def __init__(self, environment, overrides=None):
        self.environment = environment
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.stdout = tempfile.TemporaryFile()
        self.stderr = tempfile.TemporaryFile()
        variables = environment.variables() | {
            "BLOC_BIND_ADDR": f"127.0.0.1:{self.port}"
        }
        variables.update(overrides or {})
        self.process = subprocess.Popen(
            [BINARY], env=variables, stdout=self.stdout, stderr=self.stderr,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert self.process.poll() is None, self.logs()
            try:
                if self.request("GET", "/healthz")[0] == 200:
                    return
            except OSError:
                pass
            time.sleep(0.05)
        raise AssertionError("configured process did not become live")

    def request(self, method, path, fields=None, cookie=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        headers = {
            "Host": "operations.example.test", "Origin": ORIGIN,
            "X-Forwarded-For": SOURCE, "X-Forwarded-Proto": "https",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if cookie:
            headers["Cookie"] = cookie
        body = urlencode(fields) if fields is not None else None
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read().decode(), response.getheaders()
        finally:
            connection.close()

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=15)
        assert self.process.returncode == 0, self.logs()

    def logs(self):
        result = []
        for stream in (self.stdout, self.stderr):
            stream.flush()
            stream.seek(0)
            result.append(stream.read().decode(errors="replace"))
        return "\n".join(result)


@contextlib.contextmanager
def serving(environment, overrides=None):
    server = Server(environment, overrides)
    try:
        yield server
    finally:
        server.stop()


class Browser:
    def __init__(self, server):
        self.server = server
        self.cookies = {}

    def request(self, method, path, fields=None):
        result = self.server.request(method, path, fields, "; ".join(
            f"{name}={value}" for name, value in self.cookies.items()
        ))
        for name, value in result[2]:
            if name.lower() == "set-cookie":
                cookie = SimpleCookie()
                cookie.load(value)
                for key, morsel in cookie.items():
                    if not morsel.value or morsel["max-age"] == "0":
                        self.cookies.pop(key, None)
                    else:
                        self.cookies[key] = morsel.value
        return result

    def token(self, path):
        status, body, _ = self.request("GET", path)
        assert status == 200, (path, status, body)
        return re.search(r'name="csrf" value="([^"]+)"', body).group(1)

    def post(self, path, **fields):
        fields["csrf"] = self.token(path)
        return self.request("POST", path, fields)

    def login(self, password=PASSWORD):
        result = self.post("/admin/login", email=EMAIL, password=password)
        assert result[0] == 303
        assert dict(result[2])["location"] == "/admin"
        return result


def seed(environment, server):
    browser = Browser(server)
    code = environment.code("setup")
    response = browser.post(
        "/admin/setup", code=code, email=EMAIL, password=PASSWORD,
        password_confirmation=PASSWORD,
    )
    assert response[0] == 303
    assert dict(response[2])["location"] == "/admin/login"
    return browser, code


def startup(environment):
    unavailable = environment.directory / "unavailable"
    unavailable.write_text(
        "postgres://runtime_user:synthetic-setup-only@127.0.0.1:1/unavailable"
    )
    with serving(environment, {"BLOC_DATABASE_URL_FILE": str(unavailable)}) as server:
        assert server.request("GET", "/healthz")[:2] == (200, "ok\n")
        assert server.request("GET", "/readyz")[:2] == (503, "unavailable\n")
        assert server.process.poll() is None
    short_key = environment.directory / "short-key"
    short_key.write_bytes(b"x" * 31)
    invalid_url = environment.directory / "invalid-url"
    invalid_url.write_text("not a database URL")
    cases = [
        ("BLOC_DATABASE_URL_FILE", str(invalid_url)),
        ("BLOC_DATABASE_CA_FILE", str(environment.directory / "absent-ca")),
        ("BLOC_CANONICAL_ORIGIN", "http://operations.example.test"),
        ("BLOC_TRUSTED_PROXY_CIDRS", "invalid proxy"),
        ("BLOC_ABUSE_KEY_FILE", str(short_key)),
    ]
    for key, value in cases:
        variables = environment.variables() | {key: value}
        output = subprocess.run([BINARY], env=variables, capture_output=True, text=True)
        assert output.returncode == 2, (key, output)
        assert output.stdout == ""
        assert output.stderr == "bloc: invalid server configuration\n"
    for key, _ in cases:
        variables = environment.variables()
        variables.pop(key)
        output = subprocess.run([BINARY], env=variables, capture_output=True, text=True)
        assert output.returncode == 2, key
        assert output.stderr == "bloc: invalid server configuration\n"


def logs(environment):
    with serving(environment) as server:
        browser, setup_code = seed(environment, server)
        browser.login()
        bearers = list(browser.cookies.values())
        token = browser.token("/admin/password")
        body_marker = "ARBITRARY_BODY_SECRET_MARKER"
        denied = browser.request("POST", "/admin/password", {
            "csrf": token, "current_password": body_marker, "password": NEW_PASSWORD,
            "password_confirmation": NEW_PASSWORD,
        })
        assert denied[0] == 400
        recovery_code = environment.code("recovery")
        bad_login = Browser(server).post(
            "/admin/login", email="unknown-marker@example.test", password=PASSWORD
        )
        assert bad_login[0] == 401
        audit = sql("SELECT coalesce(json_agg(e)::text,'[]') FROM bloc.security_audit_event e")
        denial = sql("SELECT coalesce(json_agg(e)::text,'[]') FROM bloc.administrator_denial_aggregate e")
        assert json.loads(audit), "positive audited actions are required"
        assert json.loads(denial), "positive denial aggregate is required"
        server.stop()
        captured = server.logs()
        assert "bloc listening" in captured
        secrets = [EMAIL, PASSWORD, NEW_PASSWORD, owner()["hash"], setup_code, recovery_code, token,
                   SOURCE, body_marker, "unknown-marker@example.test", *bearers]
        for secret in [*secrets, *[hashlib.sha256(x.encode()).hexdigest() for x in secrets]]:
            assert secret not in audit
            assert secret not in denial
            assert secret not in captured, "submitted material entered runtime logs"


def restore(environment):
    with serving(environment) as server:
        first, _ = seed(environment, server)
        first.login()
        second = Browser(server)
        second.login()
        environment.code("recovery")
        anonymous = Browser(server)
        anonymous.token("/admin/recovery")
        before = owner()
        assert int(sql("SELECT count(*) FROM bloc.administrator_session WHERE revoked_at IS NULL")) == 2
        assert int(sql("SELECT count(*) FROM bloc.administrator_form_state")) >= 3
        output = environment.cli("admin", "invalidate-access")
        assert (output.returncode, output.stdout, output.stderr) == (0, "", "")
        after = owner()
        assert after["id"] == before["id"]
        assert after["hash"] == before["hash"]
        assert after["version"] == before["version"] + 1
        assert after["fenced"] is True
        assert int(sql("SELECT count(*) FROM bloc.administrator_session WHERE revoked_at IS NULL")) == 0
        assert int(sql("SELECT count(*) FROM bloc.operator_code")) == 0
        assert int(sql("SELECT count(*) FROM bloc.administrator_form_state")) == 0
        assert int(sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='restore'")) == 1
        for browser in (first, second):
            assert browser.request("GET", "/admin")[0] == 303
        blocked = Browser(server).post("/admin/login", email=EMAIL, password=PASSWORD)
        assert blocked[0] == 401
        replacement = environment.code("recovery")
        recovered = Browser(server).post(
            "/admin/recovery", code=replacement, password=NEW_PASSWORD,
            password_confirmation=NEW_PASSWORD,
        )
        assert recovered[0] == 303
        assert dict(recovered[2])["location"] == "/admin/login"
        assert owner()["fenced"] is False
        assert owner()["id"] == before["id"]
        Browser(server).login(NEW_PASSWORD)


def assert_port_fenced(port):
    with socket.socket() as probe:
        probe.settimeout(1)
        assert probe.connect_ex(("127.0.0.1", port)) != 0


def fencing(environment):
    server = Server(environment)
    other = Server(environment)
    try:
        first, _ = seed(environment, server)
        first.login()
        before = owner()
        server.stop()
        other.stop()
        fail_audit(True)
        output = environment.cli("admin", "invalidate-access")
        assert output.returncode == 1
        assert output.stdout == ""
        assert output.stderr == "bloc: database operation unavailable\n"
        assert owner() == before
        assert_port_fenced(server.port)
        assert_port_fenced(other.port)
        fail_audit(False)
        output = environment.cli("admin", "invalidate-access")
        assert output.returncode == 0
        recovery = environment.code("recovery")
        fail_audit(True)
        with serving(environment) as recovery_server:
            refused = Browser(recovery_server).post(
                "/admin/recovery", code=recovery, password=NEW_PASSWORD,
                password_confirmation=NEW_PASSWORD,
            )
            assert refused[0] == 503
            assert owner()["fenced"] is True
            assert owner()["hash"] == before["hash"]
            assert Browser(recovery_server).post(
                "/admin/login", email=EMAIL, password=PASSWORD,
            )[0] == 401
        assert_port_fenced(server.port)
        assert_port_fenced(other.port)
        fail_audit(False)
    finally:
        server.stop()
        other.stop()
    # Pre-ownership restoration cannot retain old setup authority.
    empty = os.environ["BLOC_TEST_DATABASE"] + "_empty"
    assert re.fullmatch(r"[a-z0-9_]+", empty)
    sql("CREATE DATABASE " + empty + " OWNER migrator_user")
    port = os.environ["BLOC_SETUP_PORT"]
    url = environment.directory / "empty-operator"
    migrator = environment.directory / "empty-migrator"
    url.write_text(f"postgres://operator_user:synthetic-setup-only@127.0.0.1:{port}/{empty}")
    migrator.write_text(f"postgres://migrator_user:synthetic-setup-only@127.0.0.1:{port}/{empty}")
    variables = environment.variables() | {"BLOC_DATABASE_URL_FILE": str(migrator)}
    assert subprocess.run([BINARY, "database", "migrate"], env=variables, capture_output=True).returncode == 0
    variables["BLOC_DATABASE_URL_FILE"] = str(url)
    issued = subprocess.run([BINARY, "admin", "setup-code"], env=variables, capture_output=True)
    assert issued.returncode == 0
    invalidated = subprocess.run([BINARY, "admin", "invalidate-access"], env=variables, capture_output=True)
    assert invalidated.returncode == 0
    assert sql("SELECT count(*) FROM bloc.operator_code", empty) == "0"
    assert sql("SELECT count(*) FROM bloc.installation_administrator", empty) == "0"
    fresh = subprocess.run([BINARY, "admin", "setup-code"], env=variables, capture_output=True)
    assert fresh.returncode == 0
    assert fresh.stdout != issued.stdout
    sql("DROP DATABASE " + empty)


def maintenance(environment):
    with serving(environment) as server:
        seed(environment, server)
    before = owner()
    sql("CREATE FUNCTION public.ops_fail_cleanup() RETURNS trigger LANGUAGE plpgsql"
        " AS $$ BEGIN RAISE EXCEPTION 'synthetic cleanup failure'; END $$;"
        " CREATE TRIGGER ops_fail_cleanup BEFORE DELETE ON bloc.security_audit_event"
        " FOR EACH ROW EXECUTE FUNCTION public.ops_fail_cleanup();"
        " UPDATE bloc.security_audit_event SET occurred_at=clock_timestamp()-interval '91 days'")
    before_count = int(sql("SELECT count(*) FROM bloc.security_audit_event"))
    output = environment.cli("database", "maintain", role="maintenance")
    assert output.returncode == 1
    assert output.stdout == ""
    assert output.stderr == "bloc: database operation unavailable\n"
    assert owner() == before
    assert int(sql("SELECT count(*) FROM bloc.security_audit_event")) == before_count
    denied = environment.cli("admin", "recovery-code", role="maintenance")
    assert denied.returncode == 1 and denied.stdout == ""
    sql("DROP TRIGGER ops_fail_cleanup ON bloc.security_audit_event;"
        " DROP FUNCTION public.ops_fail_cleanup()")
    completed = environment.cli("database", "maintain", role="maintenance")
    assert (completed.returncode, completed.stdout, completed.stderr) == (0, "", "")
    assert int(sql("SELECT count(*) FROM bloc.security_audit_event")) == 0
    assert owner() == before


DEPLOYMENT_CONTRACT = r"""
{{- $deployment := include (print $.Template.BasePath "/deployment.yaml") . | fromYaml -}}
{{- $pod := $deployment.spec.template.spec -}}
{{- if ne (len $pod.containers) 1 -}}{{ fail "one runtime container" }}{{- end -}}
{{- $runtime := first $pod.containers -}}
{{- if or (hasKey $runtime "command") (hasKey $runtime "args") (hasKey $pod "initContainers") -}}{{ fail "runtime must not migrate" }}{{- end -}}
{{- if ne (toString $runtime.resources.limits.cpu) "1" -}}{{ fail "runtime CPU1" }}{{- end -}}
{{- if ne $runtime.resources.limits.memory "512Mi" -}}{{ fail "runtime512Mi" }}{{- end -}}
{{- if ne $runtime.readinessProbe.httpGet.path "/readyz" -}}{{ fail "database readiness" }}{{- end -}}
{{- $env := dict -}}{{- range $runtime.env -}}{{- $_ := set $env .name .value -}}{{- end -}}
{{- range $key, $expected := dict "BLOC_DATABASE_URL_FILE" "/run/bloc/runtime-url" "BLOC_DATABASE_CA_FILE" "/run/bloc/ca.crt" "BLOC_ABUSE_KEY_FILE" "/run/bloc/abuse-key" "BLOC_CANONICAL_ORIGIN" "https://ops.example.test:9443" "BLOC_TRUSTED_PROXY_CIDRS" "192.0.2.0/24" "MALLOC_MMAP_THRESHOLD_" "131072" -}}
{{- if ne (index $env $key) $expected -}}{{ fail (print "runtime env " $key) }}{{- end -}}{{- end -}}
{{- $secret := (first $pod.volumes).secret -}}
{{- if ne $secret.secretName "ops-authority" -}}{{ fail "operator-owned runtime Secret" }}{{- end -}}
{{- $keys := list -}}{{- range $secret.items -}}{{- $keys = append $keys .key -}}{{- end -}}
{{- if ne (join "," (sortAlpha $keys)) "abuse-key,ca.crt,runtime-url" -}}{{ fail "runtime-only credentials" }}{{- end -}}
{{- $seen := dict -}}
{{- range $fragment := splitList "---" (include (print $.Template.BasePath "/access-operations.yaml") .) -}}
{{- if trim $fragment -}}
{{- $object := fromYaml $fragment -}}{{- $role := "" -}}{{- $spec := $object.spec -}}
{{- if eq $object.kind "Job" -}}{{- $role = "migrator" -}}{{- $spec = $spec.template.spec -}}
{{- else if eq $object.kind "CronJob" -}}{{- $role = "maintenance" -}}{{- $spec = $spec.jobTemplate.spec.template.spec -}}
{{- else if eq $object.kind "Pod" -}}{{- $role = "operator" -}}
{{- else -}}{{ fail "unexpected operational workload" }}{{- end -}}
{{- $_ := set $seen $role true -}}
{{- $container := first $spec.containers -}}{{- $secret := (first $spec.volumes).secret -}}
{{- if ne $secret.secretName "ops-authority" -}}{{ fail "operator-owned operation Secret" }}{{- end -}}
{{- $keys := list -}}{{- range $secret.items -}}{{- $keys = append $keys .key -}}{{- end -}}
{{- if ne (join "," (sortAlpha $keys)) (print "ca.crt," $role "-url") -}}{{ fail (print "separated " $role " credentials") }}{{- end -}}
{{- if eq $role "operator" -}}
{{- if ne (join "," $container.command) "/bin/sleep,infinity" -}}{{ fail "codes must not be logged as entrypoint" }}{{- end -}}
{{- else -}}
{{- $operation := ternary "migrate" "maintain" (eq $role "migrator") -}}
{{- if ne (join "," $container.args) (print "database," $operation) -}}{{ fail "explicit database operation" }}{{- end -}}
{{- end -}}
{{- if $spec.automountServiceAccountToken -}}{{ fail "no service-account authority" }}{{- end -}}
{{- if not (first $container.volumeMounts).readOnly -}}{{ fail "read-only credentials" }}{{- end -}}
{{- end -}}{{- end -}}
{{- if ne (len $seen) 3 -}}{{ fail "all three credential identities required" }}{{- end -}}
{"result":"structured deployment and credential-assembly assertions passed"}
"""


def deployment():
    helm = os.environ.get("BLOC_HELM", "helm")
    with tempfile.TemporaryDirectory(prefix="bloc-ops-chart-") as directory:
        chart = Path(directory) / "bloc"
        shutil.copytree("charts/bloc", chart)
        (chart / "templates" / "contract.json").write_text(DEPLOYMENT_CONTRACT)
        result = subprocess.run(
            [helm, "template", "ops", str(chart), "--show-only", "templates/contract.json",
             "--set", "image.digest=sha256:" + "1" * 64,
             "--set", "access.secretName=ops-authority",
             "--set", "access.canonicalOrigin=https://ops.example.test:9443",
             "--set", "access.trustedProxyCIDRs=192.0.2.0/24",
             "--set", "access.migrationJob=true", "--set", "access.operatorPod=true",
             "--set", "access.maintenanceJob=true"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        content = "\n".join(line for line in result.stdout.splitlines() if not line.startswith("#") and line != "---")
        assert json.loads(content) == {
            "result": "structured deployment and credential-assembly assertions passed"
        }


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "deployment":
        deployment()
    else:
        with tempfile.TemporaryDirectory(prefix="bloc-ops-proof-") as directory:
            environment = Environment(directory)
            {"startup": startup, "logs": logs, "restore": restore,
             "fencing": fencing, "maintenance": maintenance}[mode](environment)
    print(json.dumps({"mode": mode, "result": "passed"}))
