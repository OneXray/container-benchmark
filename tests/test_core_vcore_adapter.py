"""All pressure and comparison configurations are fixed to complete CN rules."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from container_benchmark import core_vcore_adapter as vcore


class VCoreAdapterTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.assets = self.root / "assets"
        self.assets.mkdir()
        for kind in ("geosite", "geoip"):
            (self.assets / f"{kind}.dat").write_bytes(kind.encode())
        self.origins = [
            SimpleNamespace(ipv4="192.0.2.2"),
            SimpleNamespace(ipv4="192.0.2.3"),
        ]
        self.witnesses = {"domain_positive": "example.cn"}

    def configure(self, *, geodata_update=False):
        result = vcore.configure(
            self.root / "vcore",
            self.assets,
            self.witnesses,
            self.origins,
            self.origins[1],
            SimpleNamespace(fd=11, device="tun0"),
            geodata_update=geodata_update,
        )
        return json.loads(result["config"].read_text())

    def test_update_sampling_is_unavailable_before_configuration_or_build(self):
        with self.assertRaisesRegex(ValueError, "no live state observer"):
            self.configure(geodata_update=True)
        self.assertFalse((self.root / "vcore").exists())
        guest = Mock()
        with self.assertRaisesRegex(ValueError, "no live state observer"):
            vcore.build(guest, self.root, geodata_update=True)
        guest.execute.assert_not_called()

    def test_normal_cli_declares_and_inherits_the_host_owned_raw_ip_fd(self):
        root = self.root / "vcore"
        result = vcore.configure(
            root,
            self.assets,
            self.witnesses,
            self.origins,
            self.origins[1],
            SimpleNamespace(fd=11, device="tun0"),
        )
        config = json.loads(result["config"].read_text())
        self.assertEqual(
            config["tun"],
            {
                "enable": True,
                "file-descriptor": 11,
                "device": "tun0",
                "mtu": 1500,
                "dns-hijack": ["198.18.0.1:53"],
                "udp-timeout": 60,
            },
        )
        self.assertEqual(
            result["argv"],
            [
                str(root / "artifacts/vcore"),
                "-d",
                str(root / "data"),
                "-f",
                str(root / "config.json"),
            ],
        )
        self.assertEqual(result["pass_fds"], (11,))
        self.assertFalse((root / "requests.jsonl").exists())
        for name in ("geosite.dat", "geoip.dat"):
            copied = root / "data/geodata" / name
            self.assertFalse(copied.is_symlink())
            self.assertEqual(copied.read_bytes(), (self.assets / name).read_bytes())

    def test_comparison_remains_cn_only_without_extra_selectors(self):
        config = self.configure()
        self.assertNotIn("nameserver-policy", config["dns"])
        self.assertEqual(
            config["rules"],
            [
                "GEOSITE,cn,DIRECT",
                "DOMAIN,example.cn,REJECT",
                "GEOIP,cn,REJECT",
                "IP-CIDR,192.0.2.2/32,DIRECT,no-resolve",
                "IP-CIDR,192.0.2.3/32,DIRECT,no-resolve",
                "MATCH,blocked",
            ],
        )

    def test_extra_witness_categories_never_change_the_cn_workload(self):
        self.witnesses.update(
            geosite_codes=["cn", "google", "!cn", "google@ads"],
            geoip_codes=["cn", "us", "!cn"],
        )
        config = self.configure()
        self.assertNotIn("nameserver-policy", config["dns"])
        self.assertEqual(
            config["rules"],
            [
                "GEOSITE,cn,DIRECT",
                "DOMAIN,example.cn,REJECT",
                "GEOIP,cn,REJECT",
                "IP-CIDR,192.0.2.2/32,DIRECT,no-resolve",
                "IP-CIDR,192.0.2.3/32,DIRECT,no-resolve",
                "MATCH,blocked",
            ],
        )

    def prepare_build(self):
        root = self.root / "build"
        release = root / "vcore-target/release"
        release.mkdir(parents=True)
        (root / "artifacts").mkdir()
        header = bytearray(20)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (183).to_bytes(2, "little")
        identity = b"VCore;engine=rust;coreVersion=0.1.0"
        (root / "artifacts/vcore").write_bytes(header + identity)
        (root / "vcore-version.log").write_text("VCore 0.1.0\n" + identity.decode())
        (release / "libvcore.rlib").write_bytes(b"builder-only Rust library")
        source = self.root / "source"
        source.mkdir()
        (source / "Cargo.toml").write_text('[package]\nversion = "0.1.0"\n')
        (source / "Cargo.lock").write_text("locked dependencies")
        return root, Mock(sources={"vcore": source})

    def test_build_records_cli_identity_and_builder_only_rlib(self):
        root, guest = self.prepare_build()
        identity = vcore.build(guest, root)

        self.assertEqual(guest.execute.call_count, 2)
        command = guest.execute.call_args_list[0].args[0][-1]
        self.assertIn(
            "cargo build --locked --release --no-default-features "
            "--features cli --lib --bin vcore ",
            command,
        )
        self.assertIn("--message-format=json-render-diagnostics", command)
        self.assertNotIn("ffi", command)
        self.assertNotIn("launcher.c", command)
        self.assertNotIn("cc -", command)
        self.assertEqual(identity["library_name"], "libvcore.rlib")
        self.assertEqual(identity["library_format"], "rlib")
        self.assertEqual(identity["binary_format"], "ELF64 little-endian aarch64")
        self.assertEqual(
            identity["build_identity"], "VCore;engine=rust;coreVersion=0.1.0"
        )
        self.assertEqual(
            identity["library_sha256"],
            hashlib.sha256(b"builder-only Rust library").hexdigest(),
        )
        self.assertEqual(
            identity["lockfile_sha256"],
            hashlib.sha256(b"locked dependencies").hexdigest(),
        )

    def test_build_rejects_wrong_binary_architecture_or_identity(self):
        root, guest = self.prepare_build()
        binary = root / "artifacts/vcore"
        original = binary.read_bytes()
        binary.write_bytes(original[:18] + (62).to_bytes(2, "little") + original[20:])
        with self.assertRaisesRegex(ValueError, "native Linux arm64 ELF"):
            vcore.build(guest, root)
        binary.write_bytes(original)
        (root / "vcore-version.log").write_text("VCore 0.2.0")
        with self.assertRaisesRegex(ValueError, "build identity"):
            vcore.build(guest, root)
        (root / "vcore-version.log").write_text("VCore;engine=rust;coreVersion=0.1.0")
        binary.write_bytes(original[:20] + b"other executable")
        with self.assertRaisesRegex(ValueError, "build identity"):
            vcore.build(guest, root)
