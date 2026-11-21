"""Use the actual Docker network address, independent of metadata ordering."""
import ipaddress
import json
import contextlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from authority import assigned_address, docker_primary, source_configuration, configuration, cluster_authority


class AuthorityTests(unittest.TestCase):
    def test_dual_stack_order_does_not_change_ipv4_selection(self):
        for fields in (("GlobalIPv6Address", "IPAddress"), ("IPAddress", "GlobalIPv6Address")):
            with self.subTest(fields=fields):
                values = {"IPAddress": "172.22.0.101", "GlobalIPv6Address": "fd00::101"}
                endpoint = {field: values[field] for field in fields}
                network = {"NetworkSettings": {"Networks": {"other": {"IPAddress": "172.23.0.4"},
                                                            "kind": endpoint}}}
                address = ipaddress.ip_address(assigned_address(network))
                self.assertEqual(address.version, 4)
                self.assertIn(address, ipaddress.ip_network("172.22.0.0/16"))
                self.assertEqual(str(address), values["IPAddress"])

    def test_occupied_address_is_never_reused(self):
        # Docker owns reservation; do not synthesize another address from the subnet.
        # authority_live.py proves simultaneous real reservations are distinct.
        first = {"NetworkSettings": {"Networks": {"kind": {"IPAddress": "172.22.0.101"}}}}
        second = {"NetworkSettings": {"Networks": {"kind": {"IPAddress": "172.22.0.102"}}}}
        original = assigned_address(first)
        replacement = assigned_address(second)
        self.assertNotEqual(replacement, original)
        self.assertEqual(replacement, "172.22.0.102")
        self.assertIn(ipaddress.ip_address(replacement), ipaddress.ip_network("172.22.0.0/16"))

    def test_ipv6_only_or_missing_address_is_refused_before_tls(self):
        for endpoint in ({"GlobalIPv6Address": "fd00::101"}, {"IPAddress": "fd00::101"},
                         {"IPAddress": "invalid"}, {"IPAddress": ""},
                         {"IPAddress": None}, {"IPAddress": "0.0.0.0"}, {}):
            with self.subTest(endpoint=endpoint):
                network = {"NetworkSettings": {"Networks": {"kind": endpoint}}}
                with self.assertRaisesRegex(ValueError, "assigned IPv4"):
                    assigned_address(network)
        for missing in ({}, {"NetworkSettings": {}},
                        {"NetworkSettings": {"Networks": {"other": {"IPAddress": "172.22.0.101"}}}}):
            with self.assertRaisesRegex(ValueError, "assigned IPv4"):
                assigned_address(missing)


class AuthorityLifecycleTests(unittest.TestCase):
    def test_invalid_assignment_cleans_only_owned_container_without_issuing_certificate(self):
        metadata={"NetworkSettings":{"Networks":{"isolated":{"IPAddress":"fd00::101"}}}}
        with mock.patch("authority.postgres.command",side_effect=["owned-container","owned-container",json.dumps([metadata])]) as command, mock.patch("authority.postgres.certificate") as certificate, mock.patch("authority.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError,"assigned IPv4"):
                with docker_primary("isolated"):
                    self.fail("invalid authority must never become usable")
            create=command.call_args_list[0].args
            self.assertNotIn("--ip",create)
            self.assertIn("isolated",create)
            certificate.assert_not_called()
            run.assert_called_once_with(["docker","rm","--force","--volumes","owned-container"],capture_output=True,check=True)


    def test_certificate_failure_removes_waiting_container_without_releasing_postgres(self):
        metadata={"NetworkSettings":{"Networks":{"isolated":{"IPAddress":"172.22.0.101"}}}}
        with mock.patch("authority.postgres.command",side_effect=["owned-container","owned-container",json.dumps([metadata])]) as command, mock.patch("authority.postgres.certificate",side_effect=RuntimeError("synthetic certificate failure")), mock.patch("authority.subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError,"synthetic certificate failure"):
                with docker_primary("isolated"):
                    self.fail("uncertified authority must never become usable")
            self.assertEqual(command.call_count,3)
            run.assert_called_once_with(["docker","rm","--force","--volumes","owned-container"],capture_output=True,check=True)


class MfaAuthorityConfigurationTests(unittest.TestCase):
    def test_source_and_container_receive_file_references_to_dedicated_keyrings(self):
        with mock.patch("authority.postgres.certificate"):
            with source_configuration() as environment:
                path = Path(environment["BLOC_MFA_KEYRING_FILE"])
                document = json.loads(path.read_text())
                self.assertEqual(document["format_version"], 1)
                self.assertEqual(len(document["keys"]), 1)
                self.assertNotEqual(path, Path(environment["BLOC_ABUSE_KEY_FILE"]))
                self.assertNotIn(document["keys"][0]["key"], environment.values())
            with configuration() as arguments:
                self.assertIn("BLOC_MFA_KEYRING_FILE=/run/bloc/mfa-keyring.json", arguments)
                mount = next(a for a in arguments if a.startswith("type=bind,src="))
                directory = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
                document = json.loads((directory / "mfa-keyring.json").read_text())
                self.assertNotIn(document["keys"][0]["key"], arguments)
                self.assertIn("readonly", mount)

    def test_cluster_migrates_without_keys_then_initializes_with_operator_role(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "ca.crt").write_text("synthetic fixture CA")
            @contextlib.contextmanager
            def primary():
                yield "fixture-container", "172.22.0.101", directory
            with mock.patch("authority.docker_primary", primary), \
                    mock.patch("authority.subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="")) as run:
                with cluster_authority("kubectl", "fixture", "bloc:synthetic"):
                    pass
            pods = [json.loads(c.kwargs["input"]) for c in run.call_args_list
                    if "apply" in c.args[0]]
            self.assertEqual([p["metadata"]["name"] for p in pods],
                             ["bloc-fixture-migrate", "bloc-fixture-mfa-initialize"])
            migrator, operator = [p["spec"]["containers"][0] for p in pods]
            self.assertEqual(migrator["args"], ["database", "migrate"])
            self.assertNotIn("BLOC_MFA_KEYRING_FILE", [e["name"] for e in migrator["env"]])
            self.assertEqual(len(pods[0]["spec"]["volumes"]), 1)
            identifier = json.loads((directory / "mfa-keyring.json").read_text())["keys"][0]["id"]
            self.assertEqual(operator["args"], ["mfa", "keys", "initialize", "--key-id", identifier])
            self.assertIn({"name":"BLOC_DATABASE_URL_FILE","value":"/run/bloc/operator-url"}, operator["env"])
            self.assertIn({"name":"BLOC_MFA_KEYRING_FILE","value":"/run/bloc-mfa/keyring.json"}, operator["env"])
            self.assertEqual(pods[1]["spec"]["volumes"][1]["secret"]["secretName"], "bloc-mfa-keyring")
            self.assertTrue(operator["volumeMounts"][1]["readOnly"])
            commands = [c.args[0] for c in run.call_args_list]
            self.assertTrue(any("create" in c and "bloc-mfa-keyring" in c for c in commands))
            self.assertTrue(any("wait" in c and "pod/bloc-fixture-mfa-initialize" in c for c in commands))

    def test_failed_key_initialization_never_yields_a_ready_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            @contextlib.contextmanager
            def primary():
                yield "fixture-container", "172.22.0.101", directory
            def execute(command, **kwargs):
                if "wait" in command and "pod/bloc-fixture-mfa-initialize" in command:
                    raise subprocess.CalledProcessError(1, command)
                return subprocess.CompletedProcess(command, 0, stdout="synthetic initialization failure")
            with mock.patch("authority.docker_primary", primary), mock.patch("authority.subprocess.run", side_effect=execute):
                with self.assertRaises(subprocess.CalledProcessError):
                    with cluster_authority("kubectl", "fixture", "bloc:synthetic"):
                        self.fail("failed key initialization must stop fixture readiness")
