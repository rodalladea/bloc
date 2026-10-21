"""Real Docker auto-IP/TLS regression. Run explicitly; never uses the kind network.

python3 tests/distribution/authority_live.py
"""
import concurrent.futures
import ipaddress
import json
import queue
import subprocess
import threading
import uuid

from authority import docker_primary
from support import postgres


def main():
    network = "bloc-authority-live-" + uuid.uuid4().hex[:10]
    postgres.command("docker", "network", "create", "--driver", "bridge",
                     "--label", "bloc.fixture=authority-auto-ip", network)
    entries = queue.Queue()
    release = threading.Event()
    containers = []

    def primary():
        try:
            with docker_primary(network) as entry:
                entries.put(entry)
                if not release.wait(90):
                    raise RuntimeError("concurrent authority verification timed out")
        except BaseException as error:
            entries.put(error)
            raise

    try:
        metadata = json.loads(postgres.command("docker", "network", "inspect", network))[0]
        subnets = [ipaddress.ip_network(c["Subnet"]) for c in metadata["IPAM"]["Config"]]
        assert any(subnet.version == 4 for subnet in subnets)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(primary) for _ in range(2)]
            try:
                authorities = []
                for _ in range(2):
                    entry = entries.get(timeout=90)
                    if isinstance(entry, BaseException):
                        raise entry
                    authorities.append(entry)
                    containers.append(entry[0])
                assert len({entry[1] for entry in authorities}) == 2
                client = authorities[0][0]
                verified = []
                for index, (container, address, directory) in enumerate(authorities):
                    assert any(ipaddress.ip_address(address) in subnet for subnet in subnets
                               if subnet.version == 4)
                    ca = f"/tmp/authority-{index}-ca.crt"
                    postgres.command("docker", "cp", str(directory / "ca.crt"), client + ":" + ca)
                    result = postgres.command("docker", "exec", "--env",
                        "PGPASSWORD=synthetic-probe-only", client, "psql",
                        f"host={address} port=5432 dbname=probe user=probe sslmode=verify-full sslrootcert={ca}",
                        "-At", "-v", "ON_ERROR_STOP=1", "-c",
                        "SELECT host(inet_server_addr())||'|'||ssl::text FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
                    assert result == address + "|true", result
                    verified.append({"address": address, "verify_full_tls": True})
                # Both live addresses have been validated while both contexts remain open.
                print(json.dumps({"network": network, "ipam": metadata["IPAM"],
                                  "concurrent_authorities": verified}), flush=True)
            finally:
                release.set()
            for future in futures:
                future.result()
        for container in containers:
            assert subprocess.run(["docker", "inspect", container], capture_output=True).returncode != 0
        print("PASS: concurrent auto-assigned IPv4 authorities verify TLS; owned containers removed", flush=True)
    finally:
        postgres.command("docker", "network", "rm", network)


if __name__ == "__main__":
    main()
