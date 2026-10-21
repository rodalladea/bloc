"""Use the actual Docker network address, independent of metadata ordering."""
import ipaddress
import json
import unittest
from unittest import mock

from authority import assigned_address, docker_primary


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
