"""Cluster authority addresses must match Docker's IPv4 allocation option."""
import ipaddress
import unittest

from authority import cluster_address


class AuthorityTests(unittest.TestCase):
    def test_dual_stack_order_does_not_change_ipv4_selection(self):
        for subnets in (("fd00::/64", "172.22.0.0/16"),
                        ("172.22.0.0/16", "fd00::/64")):
            with self.subTest(subnets=subnets):
                network = {"IPAM": {"Config": [{"Subnet": subnet} for subnet in subnets]},
                           "Containers": {}}
                address = ipaddress.ip_address(cluster_address(network))
                self.assertEqual(address.version, 4)
                self.assertIn(address, ipaddress.ip_network("172.22.0.0/16"))

    def test_occupied_address_is_never_reused(self):
        network = {"IPAM": {"Config": [{"Subnet": "172.22.0.0/16"}]},
                   "Containers": {}}
        first = cluster_address(network)
        network["Containers"]["existing"] = {"IPv4Address": first + "/16"}
        replacement = cluster_address(network)
        self.assertNotEqual(replacement, first)
        self.assertIn(ipaddress.ip_address(replacement), ipaddress.ip_network("172.22.0.0/16"))

    def test_ipv6_only_network_fails_before_docker_allocation(self):
        network = {"IPAM": {"Config": [{"Subnet": "fd00::/64"}]}, "Containers": {}}
        with self.assertRaisesRegex(ValueError, "IPv4 subnet"):
            cluster_address(network)
