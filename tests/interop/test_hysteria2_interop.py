"""Offline native HY2 fixture contracts; never start network services."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from container_benchmark.interop import hysteria2_interop as interop


class Hysteria2InteropTests(unittest.TestCase):
    def test_five_explicit_native_cases_keep_auth_and_hop_requirements(self):
        self.assertEqual(interop.cases(["vless"]), [])
        selected = interop.cases(["hysteria2"])
        self.assertEqual(
            [case["id"] for case in selected],
            [
                "hysteria2-native-mtls",
                "hysteria2-native-mtls-required",
                "hysteria2-native-hop",
                "hysteria2-native-hop-salamander",
                "hysteria2-native-udp-disabled",
            ],
        )
        self.assertEqual({case["backend"] for case in selected}, {"hysteria2"})
        self.assertEqual({case["protocol"] for case in selected}, {"hysteria2"})

    def test_hop_fixture_maps_sixteen_ports_to_one_authentic_server(self):
        case = next(c for c in interop.cases(["hysteria2"]) if c["variant"] == "hop")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guest = SimpleNamespace(root=root, ipv4="192.0.2.10")
            servers = interop.configure([case], root, "192.0.2.20", "a" * 64, guest)
            config = json.loads(servers[0]["config"].read_text())
        self.assertEqual(config["listen"], "192.0.2.10:25020-25035")
        self.assertEqual(config["auth"]["type"], "password")
        self.assertEqual(config["tls"]["cert"], "/work/peer/cert.pem")
        self.assertEqual(case["node_overrides"]["ports"], "25020-25035")
        self.assertEqual(case["node_overrides"]["hop-interval"], 5)
        self.assertFalse(case["node_overrides"]["skip-cert-verify"])
        self.assertEqual(
            case["probe_options"], {"hold_seconds": 16.5, "interval_seconds": 5.5}
        )
        self.assertEqual(servers[0]["required_capabilities"], ["NET_ADMIN"])
        self.assertIn("HYSTERIA_FIREWALL_BACKEND=nftables", servers[0]["command"])

    def test_mtls_is_required_but_client_identity_only_sent_in_the_positive_case(self):
        def openssl(argv, **kwargs):
            if "-keyout" in argv:
                path = Path(argv[argv.index("-keyout") + 1])
                path.write_text("-----BEGIN PRIVATE KEY-----\nfixture\n")
            if "-out" in argv:
                path = Path(argv[argv.index("-out") + 1])
                path.write_text("-----BEGIN CERTIFICATE-----\nfixture\n")

        selected = interop.cases(["hysteria2"])[:2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guest = SimpleNamespace(root=root, ipv4="192.0.2.10")
            servers = interop.configure(
                selected,
                root,
                "192.0.2.20",
                "a" * 64,
                guest,
                certificate_command=openssl,
            )
            configs = [json.loads(server["config"].read_text()) for server in servers]
        self.assertTrue(all(config["tls"]["clientCA"] for config in configs))
        self.assertTrue(
            selected[0]["node_overrides"]["certificate"].startswith("-----")
        )
        self.assertTrue(
            selected[0]["node_overrides"]["private-key"].startswith("-----")
        )
        self.assertNotIn("certificate", selected[1]["node_overrides"])
        self.assertNotIn("private-key", selected[1]["node_overrides"])
        self.assertEqual(selected[1]["expected"], "tls-client-auth-rejection")

    def test_disabled_udp_is_an_explicit_negative_not_a_skipped_udp_check(self):
        case = interop.cases(["hysteria2"])[-1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guest = SimpleNamespace(root=root, ipv4="192.0.2.10")
            server = interop.configure([case], root, "192.0.2.20", "a" * 64, guest)[0]
            config = json.loads(server["config"].read_text())
        self.assertTrue(config["disableUDP"])
        self.assertTrue(case["node_overrides"]["udp"])
        self.assertEqual(case["expected"], "udp-disabled")

    def test_hop_proof_requires_packets_on_distinct_declared_ports(self):
        case = interop.cases(["hysteria2"])[2]
        counters = {
            "nftables": [
                {
                    "rule": {
                        "family": "ip",
                        "table": "vcore_hy2_25020",
                        "chain": "ingress",
                        "comment": f"p{port}",
                        "expr": [{"counter": {"packets": int(port == 25020)}}],
                    }
                }
                for port in range(25020, 25036)
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def execute(argv, log, **kwargs):
                if "-j" in argv:
                    Path(log).write_text(json.dumps(counters))

            guest = SimpleNamespace(
                root=root, ipv4="192.0.2.10", execute=Mock(side_effect=execute)
            )
            interop.configure([case], root, "192.0.2.20", "a" * 64, guest)
            interop.setup_hop_witness(guest, case)
            self.assertEqual(
                interop.collect_hop_witness(guest, case)["status"], "FAIL_WITNESS"
            )
            counters["nftables"][1]["rule"]["expr"][0]["counter"]["packets"] = 2
            proof = interop.collect_hop_witness(guest, case)
            self.assertEqual(proof["status"], "PASS")
            self.assertEqual(proof["observed_port_count"], 2)
            rules = (
                root / "hysteria2/hysteria2-native-hop/hop-witness.nft"
            ).read_text()
            self.assertIn("hook prerouting priority -150", rules)
            self.assertIn('udp dport 25035 counter comment "p25035"', rules)


if __name__ == "__main__":
    unittest.main()
