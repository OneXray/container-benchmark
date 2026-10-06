"""Offline protocol fixture/ownership checks; never start listeners or containers."""

import contextlib
import importlib.util
import io
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.cli import main
from container_benchmark.interop import mihomo_interop as interop
from container_benchmark.interop import mihomo_lab as lab


class InteropTests(unittest.TestCase):
    def test_all_eight_protocols_and_three_ss_algorithms_are_explicit(self):
        cases = interop.cases(interop.PROTOCOLS)
        self.assertEqual(len(cases), 26)
        self.assertEqual(len({case["port"] for case in cases}), 26)
        self.assertEqual({case["protocol"] for case in cases}, set(interop.PROTOCOLS))
        self.assertEqual(
            [
                case["cipher"]
                for case in cases
                if case["id"] in dict(interop.SS_CIPHERS)
            ],
            [cipher for cipher, _ in interop.SS_CIPHERS],
        )

    def test_list_is_offline_and_does_not_create_a_lab(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(
                main(["interop", "--backend", "mihomo", "--list"]),
                0,
            )
        self.assertEqual(len(output.getvalue().splitlines()), 26)

    def test_native_backend_selection_is_offline_and_explicit(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(
                main(["interop", "--backend", "xray", "--list"]),
                0,
            )
        rows = output.getvalue().splitlines()
        self.assertEqual(len(rows), 20)
        self.assertTrue(all("xray" in row for row in rows))

    def test_default_catalog_retains_all_native_supplements_without_duplicates(self):
        catalog = interop.selected_cases(interop.PROTOCOLS, interop.BACKENDS)
        self.assertEqual(len(catalog), 64)
        self.assertEqual(len({case["id"] for case in catalog}), 64)
        self.assertEqual(
            {
                name: sum(case["backend"] == name for case in catalog)
                for name in interop.BACKENDS
            },
            {"mihomo": 26, "xray": 20, "hysteria2": 5, "v2ray": 10, "caddy": 3},
        )
        self.assertEqual(
            sum(case.get("expected", "pass") != "pass" for case in catalog), 6
        )
        self.assertEqual(len(interop.selected_cases(["hysteria2"], ["hysteria2"])), 5)
        with self.assertRaisesRegex(ValueError, "empty"):
            interop.selected_cases(["socks5"], ["caddy"])

    def test_named_listeners_and_client_certificate_policy_match(self):
        for case in interop.cases(interop.PROTOCOLS):
            with self.subTest(case=case["id"]):
                server = interop.listener(
                    case, "/work/peer/cert.pem", "/work/peer/key.pem", "192.0.2.2:24501"
                )
                client = interop.node(case, "192.0.2.1", "a" * 64)
                self.assertEqual(server["port"], client["port"])
                self.assertEqual(server["proxy"], "DIRECT")
                self.assertTrue(client["udp"])
                if case["protocol"] in ("anytls", "trojan", "hysteria2", "tuic"):
                    self.assertEqual(client["fingerprint"], "a" * 64)
                    self.assertFalse(client["skip-cert-verify"])
                if case["protocol"] in ("hysteria2", "tuic"):
                    self.assertEqual(server["alpn"], client["alpn"])
                    self.assertEqual(client["alpn"], ["h3"])
                if case["protocol"] == "vless":
                    self.assertTrue(server["allow-insecure"])
                if case["protocol"] == "vmess":
                    self.assertNotIn("allow-insecure", server)

    def test_production_requests_use_only_public_lifecycle_and_loopback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = interop.requests(
                Path(directory), interop.cases(["tuic"])[0], "192.0.2.1", "b" * 64
            )
            rows = [json.loads(row) for row in path.read_text().splitlines()]
        self.assertEqual(
            [row["method"] for row in rows],
            ["initialize", "createInstance", "prepare", "start"],
        )
        self.assertEqual(rows[-1]["payload"], {})
        config = json.loads(rows[2]["payload"]["configYaml"])
        self.assertFalse(config["allow-lan"])
        self.assertFalse(config["tun"]["enable"])
        self.assertEqual(config["rules"], ["MATCH,edge"])

    def test_socks_pipelines_nonempty_first_payload_before_reading_reply(self):
        spec = importlib.util.spec_from_file_location(
            "mihomo_probe", interop.FIXTURE_ROOT / "mihomo_probe.py"
        )
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)
        stream = Mock()
        stream.recv.side_effect = [
            b"\x05\x00",
            b"\x05\x00\x00\x01",
            socket.inet_aton("127.0.0.1"),
            struct.pack("!H", 24502),
        ]
        self.assertEqual(
            probe.socks(stream, 1, "192.0.2.1", 24500, b"nonempty"),
            ("127.0.0.1", 24502),
        )
        self.assertTrue(stream.sendall.call_args_list[1].args[0].endswith(b"nonempty"))

    def test_daily_cache_does_not_refresh_today_and_rejects_corruption(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(lab, "CACHE", Path(directory)),
        ):
            prepare = Mock(
                side_effect=lambda staging: (
                    (staging / "binary").write_bytes(b"official"),
                    {"identity": "latest"},
                )[1]
            )
            cached, identity = lab.daily("example", prepare)
            self.assertEqual(lab.daily("example", prepare)[1], identity)
            self.assertEqual(prepare.call_count, 1)
            (cached / "binary").write_bytes(b"corrupted")
            lab.daily("example", prepare)
            self.assertEqual(prepare.call_count, 2)

    def test_capability_variants_are_current_and_no_native_udp_fallback(self):
        cases = interop.cases(interop.PROTOCOLS)
        self.assertEqual(sum(bool(case.get("upgrade")) for case in cases), 6)
        self.assertEqual(sum(bool(case.get("shadow_tls")) for case in cases), 6)
        self.assertEqual(sum(bool(case.get("uot")) for case in cases), 6)
        for case in cases:
            client = interop.node(case, "192.0.2.1", "a" * 64)
            server = interop.listener(case, "cert", "key", "192.0.2.2:24501")
            if case.get("uot"):
                self.assertFalse(server["udp"])
                self.assertEqual(client["udp-over-tcp-version"], 2)
            if case.get("shadow_tls"):
                self.assertEqual(client["plugin-opts"]["version"], 3)
                self.assertTrue(server["shadow-tls"]["strict-mode"])
                self.assertFalse(client["plugin-opts"]["skip-cert-verify"])
            if case.get("upgrade"):
                self.assertEqual(
                    client["ws-opts"]["v2ray-http-upgrade-fast-open"], case["fast"]
                )
        self.assertEqual(
            interop.node(
                next(case for case in cases if case["id"] == "tuic-quic"),
                "192.0.2.1",
                "a" * 64,
            )["udp-relay-mode"],
            "quic",
        )

    def test_cache_does_not_follow_symlink_or_relative_paths(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(lab, "CACHE", Path(directory)),
        ):
            entry = Path(directory) / "example"
            entry.mkdir()
            lab.save(entry / "identity.json", {"files": {"../outside": "a" * 64}})
            with self.assertRaisesRegex(ValueError, "single-level"):
                lab.daily("example", Mock())

    def test_safe_reasons_never_copy_native_error_or_credentials(self):
        self.assertEqual(
            interop._safe_reason(ValueError("password=do-not-print")), "ValueError"
        )

    def test_offline_apt_install_uses_the_actual_deb_cache_path(self):
        guest = SimpleNamespace(root=Path("/owned"), name="fake", execute=Mock())
        lab.install_tools(guest)
        command = guest.execute.call_args.args[0]
        self.assertIn("-o Dir::Cache::archives=/work/builder-tools", command[2])
        self.assertIn("--no-download", command[2])
        self.assertEqual(
            interop._safe_reason(ValueError("UDP origin source differs")),
            "UDP origin source differs",
        )

    def test_failed_artifact_cleanup_cannot_leave_a_passing_conclusion(self):
        with (
            patch.object(lab.platform, "system", return_value="Darwin"),
            patch.object(lab.platform, "machine", return_value="arm64"),
            tempfile.TemporaryDirectory() as directory,
            patch.object(lab, "SCRATCH", Path(directory) / "work"),
            patch.object(lab, "CONCLUSIONS", Path(directory) / "results"),
        ):
            session = lab.Session().__enter__()
            session.status = "PASS"
            with (
                patch.object(lab.shutil, "rmtree", side_effect=OSError),
                self.assertRaises(RuntimeError),
            ):
                session.__exit__(None, None, None)
            reports = list(lab.CONCLUSIONS.glob("*.md"))
            self.assertEqual(len(reports), 1)
            self.assertIn("Overall result: ERROR", reports[0].read_text())
            self.assertIn("artifact cleanup failed", reports[0].read_text())

    def test_report_write_failure_does_not_skip_owned_disk_cleanup(self):
        with (
            patch.object(lab.platform, "system", return_value="Darwin"),
            patch.object(lab.platform, "machine", return_value="arm64"),
            tempfile.TemporaryDirectory() as directory,
            patch.object(lab, "SCRATCH", Path(directory) / "work"),
            patch.object(lab, "CONCLUSIONS", Path(directory) / "results"),
        ):
            session = lab.Session().__enter__()
            original = Path.write_text

            def fail_report(path, text, *args, **kwargs):
                if path.parent == lab.CONCLUSIONS:
                    raise OSError("fixture report failure")
                return original(path, text, *args, **kwargs)

            with (
                patch.object(Path, "write_text", fail_report),
                self.assertRaises(OSError),
            ):
                session.__exit__(None, None, None)
            self.assertFalse(session.work.exists())


if __name__ == "__main__":
    unittest.main()
