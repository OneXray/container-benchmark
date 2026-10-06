"""Offline official-release cache/extraction checks; never execute native peers."""

import hashlib
import json
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from container_benchmark.interop import mihomo_lab as lab
from container_benchmark.interop import native_peer_releases as releases


def elf(machine=183):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", header, 16, 2, machine)
    return bytes(header) + b"offline-native-peer-fixture"


class NativePeerReleasesTests(unittest.TestCase):
    def test_new_release_source_cannot_reuse_the_old_api_daily_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def prepare(staging):
                (staging / "caddy").write_bytes(elf())
                return {"binary_sha256": hashlib.sha256(elf()).hexdigest()}

            with patch.object(lab, "CACHE", root / "cache"):
                releases._copy_cached(
                    root,
                    "caddy",
                    prepare,
                    cache_key="caddy-official-release-linux-arm64",
                )
            self.assertTrue(
                (root / "cache/caddy-official-release-linux-arm64/caddy").is_file()
            )
            self.assertFalse((root / "cache/caddy-linux-arm64").exists())

    def test_xray_extracts_only_expected_binary_and_binds_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def download(url, path, *, limit):
                self.assertEqual(url, releases.XRAY_URL)
                self.assertEqual(limit, releases.MAX_DOWNLOAD)
                with zipfile.ZipFile(path, "w") as package:
                    package.writestr("../not-extracted", "untrusted path")
                    package.writestr("geoip.dat", "not needed")
                    package.writestr("xray", elf())
                self.archive_sha = lab.sha256(path)

            with (
                patch.object(lab, "CACHE", root / "cache"),
                patch.object(releases, "download", side_effect=download),
            ):
                record = releases.official_xray(root)
            self.assertEqual((root / "artifacts/xray").read_bytes(), elf())
            self.assertEqual(record["archive_sha256"], self.archive_sha)
            self.assertEqual(record["binary_sha256"], hashlib.sha256(elf()).hexdigest())
            self.assertTrue(record["official_release_binary"])
            self.assertEqual(
                list((root / "artifacts").iterdir()), [root / "artifacts/xray"]
            )
            self.assertFalse((root / "cache/xray-linux-arm64/xray.zip").exists())
            self.assertFalse((root / "cache/not-extracted").exists())

    def test_hysteria_daily_cache_reuses_only_intact_current_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.object(lab, "CACHE", root / "cache"),
                patch.object(
                    releases,
                    "download",
                    side_effect=lambda url, path, **_: path.write_bytes(elf()),
                ) as download,
            ):
                first = releases.official_hysteria2(root)
                self.assertEqual(releases.official_hysteria2(root), first)
                self.assertEqual(download.call_count, 1)
                (root / "cache/hysteria2-linux-arm64/hysteria2").write_bytes(b"bad")
                releases.official_hysteria2(root)
                self.assertEqual(download.call_count, 2)
            self.assertEqual(first["url"], releases.HYSTERIA2_URL)
            self.assertEqual(first["archive_sha256"], first["binary_sha256"])

    def test_stale_cache_refresh_failure_propagates_without_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.object(lab, "CACHE", root / "cache"),
                patch.object(
                    releases,
                    "download",
                    side_effect=lambda url, path, **_: path.write_bytes(elf()),
                ),
            ):
                releases.official_hysteria2(root)
            path = root / "cache/hysteria2-linux-arm64/identity.json"
            record = json.loads(path.read_text())
            record["checked_day"] = "2000-01-01"
            path.write_text(json.dumps(record))
            with (
                patch.object(lab, "CACHE", root / "cache"),
                patch.object(releases, "download", side_effect=OSError("offline")),
                self.assertRaises(OSError),
            ):
                releases.official_hysteria2(root)
            self.assertFalse(
                any(
                    path.name.startswith("refresh-")
                    for path in (root / "cache").iterdir()
                )
            )

    def test_xray_missing_or_duplicate_expected_binary_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for names in (["nested/xray"], ["xray", "xray"]):
                with self.subTest(names=names), warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(root / "input.zip", "w") as package:
                        for name in names:
                            package.writestr(name, elf())
                    with self.assertRaisesRegex(ValueError, "exactly one"):
                        releases._extract_xray(root / "input.zip", root / "xray")

    def test_xray_symlink_entry_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = zipfile.ZipInfo("xray")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(root / "input.zip", "w") as package:
                package.writestr(entry, elf())
            with self.assertRaisesRegex(ValueError, "entry is invalid"):
                releases._extract_xray(root / "input.zip", root / "xray")

    def test_xray_extracted_size_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with zipfile.ZipFile(root / "input.zip", "w") as package:
                package.writestr("xray", elf())
            with (
                patch.object(releases, "MAX_BINARY", 64),
                self.assertRaisesRegex(ValueError, "entry is invalid"),
            ):
                releases._extract_xray(root / "input.zip", root / "xray")

    def test_wrong_platform_and_error_page_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "native"
            for content in (elf(62), b"error page", b"", b"x" * 128):
                with self.subTest(content=content[:8]):
                    binary.write_bytes(content)
                    with self.assertRaisesRegex(ValueError, "Linux ARM64 ELF"):
                        releases._check_binary(binary)


if __name__ == "__main__":
    unittest.main()
