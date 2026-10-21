"""Disposable TLS PostgreSQL fixtures for application integration tests."""

import json
import subprocess
import time


IMAGES = ("postgres:17.11-bookworm", "postgres:18.6-bookworm")


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def certificate(directory, name, ip=None):
    key = directory / f"{name}.key"
    cert = directory / f"{name}.crt"
    args = ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(directory / f"{name}.csr"),
            "-subj", f"/CN={name}"]
    subprocess.run(args, check=True, capture_output=True)
    if ip is None:
        subprocess.run(["openssl", "req", "-new", "-x509", "-key", str(key),
                        "-out", str(cert), "-days", "2", "-subj", f"/CN={name}",
                        "-addext", "basicConstraints=critical,CA:TRUE",
                        "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
                       check=True, capture_output=True)
    else:
        extensions = directory / f"{name}.ext"
        extensions.write_text(f"subjectAltName=IP:{ip}\nbasicConstraints=critical,CA:FALSE\n"
                              "keyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=serverAuth\n")
        subprocess.run(["openssl", "x509", "-req", "-in", str(directory / f"{name}.csr"),
                        "-CA", str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"),
                        "-CAcreateserial", "-out", str(cert), "-days", "2",
                        "-extfile", str(extensions)], check=True, capture_output=True)
    key.chmod(0o600)


def start_fixture(image, directory, name, containers):
    tls = name != "plain"
    startup = "exec docker-entrypoint.sh postgres -c ssl=off"
    if tls:
        startup = ("chown postgres:postgres /tmp/probe.key && chmod 600 /tmp/probe.key && "
                   "exec docker-entrypoint.sh postgres -c ssl=on "
                   "-c ssl_cert_file=/tmp/probe.crt -c ssl_key_file=/tmp/probe.key")
    container = command("docker", "create", "--publish", "127.0.0.1::5432",
                        "--memory", "1g", "--memory-swap", "1g", "--cpus", "0.5",
                        "--env", "POSTGRES_USER=probe", "--env", "POSTGRES_DB=probe",
                        "--env", "POSTGRES_PASSWORD=synthetic-probe-only",
                        "--env", "PGDATA=/var/lib/postgresql/data/probe",
                        "--entrypoint", "sh", image, "-c", startup)
    containers.append(container)
    if tls:
        command("docker", "cp", str(directory / f"{name}.crt"), f"{container}:/tmp/probe.crt")
        command("docker", "cp", str(directory / f"{name}.key"), f"{container}:/tmp/probe.key")
    command("docker", "start", container)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        # The image's temporary initialization server has no TCP listener.
        ready = subprocess.run(["docker", "exec", container, "pg_isready", "-h", "127.0.0.1",
                                "-U", "probe", "-d", "probe"], capture_output=True)
        if ready.returncode == 0:
            binding = json.loads(command("docker", "inspect", container))[0]["NetworkSettings"]["Ports"]["5432/tcp"]
            assert len(binding) == 1 and binding[0]["HostIp"] == "127.0.0.1"
            return binding[0]["HostPort"]
        time.sleep(0.25)
    raise RuntimeError(f"PostgreSQL {name} fixture readiness timed out")
