"""Offline official V2Ray/Caddy configuration checks; never start listeners."""

import contextlib
import io
import json
import stat
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.interop import extended_interop as extended
from container_benchmark.interop import mihomo_lab as lab


class ExtendedInteropTests(unittest.TestCase):
    def test_selects_only_representative_native_listener_gaps(self):
        cases = extended.cases(["vmess", "vless"])
        self.assertEqual(len(cases), 13)
        self.assertEqual(len({case["id"] for case in cases}), 13)
        self.assertEqual(len({case["port"] for case in cases}), 13)
        self.assertEqual(len(extended.cases(["vmess"])), 5)
        self.assertEqual(len(extended.cases(["vless"])), 8)
        self.assertEqual(extended.cases(["ss", "trojan", "hysteria2"]), [])
        self.assertEqual(
            {case["variant"] for case in cases if case["backend"] == "v2ray"},
            {"http-cover", "h2-plain", "h2-tls", "ws-ed-header", "ws-ed-path"},
        )
        self.assertEqual(
            [case["variant"] for case in cases if case["backend"] == "caddy"],
            ["xhttp-h3-mtls", "xhttp-h3-mtls-missing", "xhttp-h3-mtls-untrusted-ca"],
        )
        self.assertEqual(
            [case["expected"] for case in cases if case["backend"] == "caddy"],
            ["pass", "tls-client-auth-rejection", "tls-client-auth-rejection"],
        )

    def test_v2ray_transport_configuration_preserves_tcp_and_udp_protocols(self):
        selected = [
            case
            for case in extended.cases(["vmess", "vless"])
            if case["backend"] == "v2ray"
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = extended.configure(
                selected, Path(directory), "192.0.2.5", "a" * 64, None
            )
            config = json.loads(path.read_text())
            self.assertEqual(path.name, "v2ray.json")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(config["inbounds"]), 10)
        self.assertEqual(config["outbounds"], [{"protocol": "freedom"}])
        for case, inbound in zip(selected, config["inbounds"], strict=True):
            with self.subTest(case=case["id"]):
                stream = inbound["streamSettings"]
                client = case["node_overrides"]
                self.assertEqual(inbound["listen"], "0.0.0.0")
                self.assertEqual(inbound["port"], case["port"])
                self.assertEqual(inbound["protocol"], case["protocol"])
                self.assertEqual(client["uuid"], "07070707-0707-4707-8707-070707070707")
                if case["protocol"] == "vless":
                    self.assertEqual(inbound["settings"]["decryption"], "none")
                    self.assertEqual(client["packet-encoding"], "none")
                else:
                    self.assertEqual(client["cipher"], "aes-128-gcm")
                if case["variant"] == "http-cover":
                    self.assertEqual(client["network"], "http")
                    self.assertEqual(stream["network"], "tcp")
                    request = stream["tcpSettings"]["header"]["request"]
                    self.assertEqual(request["path"], ["/interop-transport/"])
                    self.assertEqual(request["headers"], {"Host": ["fixture.invalid"]})
                    self.assertEqual(client["http-opts"]["headers"], request["headers"])
                elif case["variant"].startswith("h2-"):
                    self.assertEqual(client["network"], "h2")
                    self.assertEqual(stream["network"], "http")
                    self.assertEqual(
                        stream["httpSettings"]["host"], ["fixture.invalid"]
                    )
                    self.assertEqual(
                        stream["httpSettings"]["path"], "/interop-transport/"
                    )
                    self.assertEqual(client["h2-opts"]["host"], ["fixture.invalid"])
                else:
                    self.assertEqual(client["network"], "ws")
                    options = client["ws-opts"]
                    peer_options = stream["wsSettings"]
                    self.assertEqual(options["max-early-data"], 256)
                    self.assertEqual(peer_options["maxEarlyData"], 256)
                    self.assertEqual(options["path"], "/interop-transport/")
                    self.assertEqual(
                        options["early-data-header-name"],
                        "X-Interop-Early-Data"
                        if case["variant"] == "ws-ed-header"
                        else "",
                    )
                    self.assertEqual(
                        peer_options["earlyDataHeaderName"],
                        options["early-data-header-name"],
                    )
                if case["variant"] == "h2-tls":
                    self.assertTrue(client["tls"])
                    self.assertFalse(client["skip-cert-verify"])
                    self.assertEqual(client["fingerprint"], "a" * 64)
                    self.assertEqual(client["alpn"], ["h2"])
                    self.assertEqual(stream["tlsSettings"]["alpn"], ["h2"])
                else:
                    self.assertFalse(client["tls"])
                    self.assertNotIn("fingerprint", client)
                    self.assertNotIn("tlsSettings", stream)

    def test_caddy_requires_verified_client_identity_and_one_xray_handler(self):
        selected = [
            case for case in extended.cases(["vless"]) if case["backend"] == "caddy"
        ]
        certificate = (
            "-----BEGIN CERTIFICATE-----\nY2xpZW50\n-----END CERTIFICATE-----\n"
        )
        private_key = (
            "-----BEGIN PRIVATE KEY-----\ncHJpdmF0ZQ==\n-----END PRIVATE KEY-----\n"
        )
        untrusted_certificate = certificate.replace("Y2xpZW50", "dW50cnVzdGVk")
        untrusted_key = private_key.replace("cHJpdmF0ZQ==", "d3Jvbmcta2V5")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def execute(argv, log, *, timeout):
                self.assertEqual(timeout, 30)
                self.assertEqual(argv[0], "openssl")
                untrusted = any("mtls-untrusted" in value for value in argv)
                for flag in ("-keyout", "-out"):
                    if flag in argv:
                        destination = root / argv[argv.index(flag) + 1].removeprefix(
                            "/work/"
                        )
                        destination.write_text(
                            (untrusted_key if untrusted else private_key)
                            if flag == "-keyout"
                            else (untrusted_certificate if untrusted else certificate)
                        )
                log.write_text("")

            guest = SimpleNamespace(execute=Mock(side_effect=execute))
            startup = extended.configure(selected, root, "192.0.2.5", "a" * 64, guest)
            config = json.loads(startup["config_path"].read_text())
            xray = json.loads((root / "peer/caddy-xray.json").read_text())
            self.assertEqual(
                (root / "peer/mtls-client.key").stat().st_mode & 0o777, 0o600
            )
            self.assertEqual((root / "peer/mtls-ca.key").stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (root / "peer/mtls-untrusted-ca.key").stat().st_mode & 0o777, 0o600
            )
            self.assertEqual(
                (root / "peer/mtls-untrusted-client.key").stat().st_mode & 0o777, 0o600
            )
            signing = [
                call.args[0]
                for call in guest.execute.call_args_list
                if "-CA" in call.args[0]
            ]
            self.assertEqual(
                [argv[argv.index("-CA") + 1] for argv in signing],
                ["/work/peer/mtls-ca.pem", "/work/peer/mtls-untrusted-ca.pem"],
            )
            self.assertEqual(
                [argv[argv.index("-CAkey") + 1] for argv in signing],
                ["/work/peer/mtls-ca.key", "/work/peer/mtls-untrusted-ca.key"],
            )
        self.assertTrue(config["admin"]["disabled"])
        self.assertEqual(len(xray["inbounds"]), 1)
        self.assertEqual(xray["inbounds"][0]["listen"], "127.0.0.1")
        self.assertEqual(xray["inbounds"][0]["port"], 24780)
        self.assertEqual(xray["inbounds"][0]["streamSettings"]["security"], "none")
        server = config["apps"]["http"]["servers"]["gateway"]
        self.assertEqual(server["listen"], [":24760", ":24761", ":24762"])
        self.assertEqual(server["protocols"], ["h3"])
        self.assertTrue(server["automatic_https"]["disable"])
        policy = server["tls_connection_policies"][0]
        self.assertEqual(policy["protocol_min"], "tls1.3")
        self.assertEqual(policy["protocol_max"], "tls1.3")
        self.assertEqual(policy["client_authentication"]["mode"], "require_and_verify")
        self.assertEqual(
            policy["client_authentication"]["ca"],
            {"provider": "file", "pem_files": ["/work/peer/mtls-ca.pem"]},
        )
        handler = server["routes"][0]["handle"][0]
        self.assertEqual(handler["handler"], "reverse_proxy")
        self.assertEqual(
            handler["transport"], {"protocol": "http", "versions": ["h2c"]}
        )
        self.assertEqual(handler["upstreams"], [{"dial": "127.0.0.1:24780"}])
        self.assertEqual(handler["load_balancing"], {"retries": 0, "try_duration": 0})
        self.assertEqual(
            [process["name"] for process in startup["processes"]],
            ["xray-handler", "caddy-gateway"],
        )
        self.assertEqual(
            startup["processes"][0]["argv"][0:2], ["env", "XRAY_BUF_SPLICE=disable"]
        )
        client = selected[0]["node_overrides"]
        self.assertEqual(client["alpn"], ["h3"])
        self.assertFalse(client["skip-cert-verify"])
        self.assertEqual(client["fingerprint"], "a" * 64)
        self.assertEqual(client["certificate"], certificate)
        self.assertEqual(client["private-key"], private_key)
        self.assertEqual(client["xhttp-opts"]["mode"], "packet-up")
        self.assertNotIn("download-settings", client["xhttp-opts"])
        self.assertEqual(selected[0]["expected"], "pass")
        for case in selected[1:]:
            self.assertEqual(case["expected"], "tls-client-auth-rejection")
            remaining = {
                name: value
                for name, value in case["node_overrides"].items()
                if name not in ("certificate", "private-key")
            }
            self.assertEqual(
                remaining,
                {
                    name: value
                    for name, value in client.items()
                    if name not in ("certificate", "private-key")
                },
            )
        self.assertNotIn("certificate", selected[1]["node_overrides"])
        self.assertNotIn("private-key", selected[1]["node_overrides"])
        self.assertEqual(
            selected[2]["node_overrides"]["certificate"], untrusted_certificate
        )
        self.assertEqual(selected[2]["node_overrides"]["private-key"], untrusted_key)

    def test_caddy_cannot_generate_identity_without_an_owned_guest(self):
        selected = [
            case for case in extended.cases(["vless"]) if case["backend"] == "caddy"
        ]
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "owned gateway guest"),
        ):
            extended.configure(selected, Path(directory), "192.0.2.5", "a" * 64, None)

    def test_official_downloads_use_daily_public_caches_and_not_host_execution(self):
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", header, 16, 2, 183)
        binary = bytes(header) + b"offline-official-binary"
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def download(url, path, *, limit):
                self.assertEqual(limit, 128 * 1024**2)
                calls.append(url)
                if url == extended.V2RAY_URL:
                    with zipfile.ZipFile(path, "w") as package:
                        package.writestr("v2ray", binary)
                        package.writestr("../not-extracted", "untrusted")
                        package.writestr("geosite.dat", "not needed")
                else:
                    self.assertEqual(
                        url,
                        "https://github.com/caddyserver/caddy/releases/latest/download/"
                        "caddy_97.1.2_linux_arm64.tar.gz",
                    )
                    with tarfile.open(path, "w:gz") as package:
                        entry = tarfile.TarInfo("caddy")
                        entry.size = len(binary)
                        package.addfile(entry, io.BytesIO(binary))
                        entry = tarfile.TarInfo("../not-extracted")
                        entry.size = 9
                        package.addfile(entry, io.BytesIO(b"untrusted"))

            with (
                patch.object(lab, "CACHE", root / "cache"),
                patch.object(extended, "download", side_effect=download),
                patch(
                    "urllib.request.urlopen",
                    return_value=contextlib.nullcontext(
                        SimpleNamespace(
                            geturl=lambda: (
                                "https://github.com/caddyserver/caddy/"
                                "releases/tag/v97.1.2"
                            )
                        )
                    ),
                ) as latest,
            ):
                v2ray = extended.official_v2ray(root)
                caddy = extended.official_caddy(root)
                self.assertEqual(extended.official_v2ray(root), v2ray)
                self.assertEqual(extended.official_caddy(root), caddy)
            self.assertEqual(
                calls,
                [
                    extended.V2RAY_URL,
                    "https://github.com/caddyserver/caddy/releases/latest/download/"
                    "caddy_97.1.2_linux_arm64.tar.gz",
                ],
            )
            self.assertEqual(latest.call_count, 1)
            request = latest.call_args.args[0]
            self.assertEqual(request.get_method(), "HEAD")
            self.assertEqual(
                request.full_url,
                "https://github.com/caddyserver/caddy/releases/latest",
            )
            self.assertEqual((root / "artifacts/v2ray").read_bytes(), binary)
            self.assertEqual((root / "artifacts/caddy").read_bytes(), binary)
            self.assertTrue(v2ray["official_release_binary"])
            self.assertTrue(caddy["official_release_binary"])
            self.assertEqual(
                caddy["binary_sha256"], lab.sha256(root / "artifacts/caddy")
            )
            self.assertFalse((root / "cache/not-extracted").exists())
            self.assertFalse((root / "cache/v2ray-linux-arm64/v2ray.zip").exists())
            self.assertEqual(caddy["release"], "v97.1.2")
            self.assertTrue(
                (root / "cache/caddy-official-release-linux-arm64/caddy").is_file()
            )
            self.assertFalse(
                (
                    root / "cache/caddy-official-release-linux-arm64/caddy.tar.gz"
                ).exists()
            )

    def test_v2ray_download_rejects_missing_binary_and_symlink_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for symlink in (False, True):
                with self.subTest(symlink=symlink):

                    def download(url, path, *, limit, symlink=symlink):
                        with zipfile.ZipFile(path, "w") as package:
                            entry = zipfile.ZipInfo("v2ray" if symlink else "other")
                            entry.create_system = 3
                            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                            package.writestr(entry, b"../../unrelated")

                    with (
                        patch.object(lab, "CACHE", root / "cache"),
                        patch.object(extended, "download", side_effect=download),
                        self.assertRaises(ValueError),
                    ):
                        extended.official_v2ray(root)
                    self.assertFalse((root / "artifacts/v2ray").exists())

    def test_caddy_rejects_nonstable_or_nonofficial_latest_redirects(self):
        for destination in (
            "https://github.com/caddyserver/caddy/releases/tag/v97.1.2-rc.1",
            "https://untrusted.invalid/releases/tag/v97.1.2",
            "http://github.com/caddyserver/caddy/releases/tag/v97.1.2",
            "https://github.com/caddyserver/caddy/releases/latest",
        ):
            with (
                self.subTest(destination=destination),
                tempfile.TemporaryDirectory() as directory,
                patch.object(lab, "CACHE", Path(directory) / "cache"),
                patch(
                    "urllib.request.urlopen",
                    return_value=contextlib.nullcontext(
                        SimpleNamespace(
                            geturl=lambda destination=destination: destination
                        )
                    ),
                ),
                self.assertRaisesRegex(ValueError, "stable release"),
            ):
                extended.official_caddy(Path(directory))

    def test_caddy_extracts_only_one_bounded_regular_root_binary(self):
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", header, 16, 2, 183)
        binary = bytes(header) + b"offline-official-binary"
        for variant in (
            "missing",
            "symlink",
            "hardlink",
            "nested",
            "duplicate",
            "large",
        ):
            with (
                self.subTest(variant=variant),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)

                def download(url, path, *, limit, variant=variant):
                    with tarfile.open(path, "w:gz") as package:
                        entry = tarfile.TarInfo(
                            "other"
                            if variant == "missing"
                            else "nested/caddy"
                            if variant == "nested"
                            else "caddy"
                        )
                        if variant in ("symlink", "hardlink"):
                            entry.type = (
                                tarfile.SYMTYPE
                                if variant == "symlink"
                                else tarfile.LNKTYPE
                            )
                            entry.linkname = "../unrelated"
                            package.addfile(entry)
                        elif variant == "large":
                            entry.size = 256 * 1024**2 + 1
                            package.addfile(entry)
                        else:
                            entry.size = len(binary)
                            package.addfile(entry, io.BytesIO(binary))
                            if variant == "duplicate":
                                package.addfile(entry, io.BytesIO(binary))

                with (
                    patch.object(lab, "CACHE", root / "cache"),
                    patch.object(extended, "download", side_effect=download),
                    patch(
                        "urllib.request.urlopen",
                        return_value=contextlib.nullcontext(
                            SimpleNamespace(
                                geturl=lambda: (
                                    "https://github.com/caddyserver/caddy/"
                                    "releases/tag/v97.1.2"
                                )
                            )
                        ),
                    ),
                    self.assertRaises(ValueError),
                ):
                    extended.official_caddy(root)
                self.assertFalse((root / "artifacts/caddy").exists())
                self.assertFalse((root / "unrelated").exists())


if __name__ == "__main__":
    unittest.main()
