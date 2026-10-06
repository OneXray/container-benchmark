"""Official latest ARM64 native peers for cases absent from Mihomo listeners."""

from __future__ import annotations

import shutil
import stat
import zipfile
from pathlib import Path

from .mihomo_lab import daily, download, sha256

XRAY_URL = (
    "https://github.com/XTLS/Xray-core/releases/latest/download/"
    "Xray-linux-arm64-v8a.zip"
)
HYSTERIA2_URL = (
    "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-arm64"
)
MAX_DOWNLOAD = 128 * 1024**2
MAX_BINARY = 256 * 1024**2


def _check_binary(path):
    """Reject empty/error-page/wrong-platform downloads without host execution."""
    with path.open("rb") as stream:
        header = stream.read(64)
    if (
        not 64 <= path.stat().st_size <= MAX_BINARY
        or len(header) != 64
        or header[:7] != b"\x7fELF\x02\x01\x01"
        or int.from_bytes(header[16:18], "little") not in (2, 3)
        or int.from_bytes(header[18:20], "little") != 183
    ):
        raise ValueError("official native peer is not a bounded Linux ARM64 ELF binary")


def _extract_xray(archive, binary):
    """Read only the expected regular entry; never extract package paths."""
    with zipfile.ZipFile(archive) as package:
        matches = [entry for entry in package.infolist() if entry.filename == "xray"]
        if len(matches) != 1:
            raise ValueError(
                "official Xray archive must contain exactly one xray entry"
            )
        entry = matches[0]
        kind = stat.S_IFMT(entry.external_attr >> 16)
        if (
            not 64 <= entry.file_size <= MAX_BINARY
            or kind not in (0, stat.S_IFREG)
            or entry.flag_bits & 1
        ):
            raise ValueError("official Xray binary archive entry is invalid")
        with package.open(entry) as source, binary.open("wb") as output:
            size = 0
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_BINARY:
                    raise ValueError("official Xray binary exceeded bounds")
                output.write(chunk)
        if size != entry.file_size:
            raise ValueError("official Xray binary archive size differs")
    _check_binary(binary)


def _copy_cached(root, name, prepare, *, cache_key=None):
    directory, identity = daily(cache_key or name + "-linux-arm64", prepare)
    cached = directory / name
    _check_binary(cached)
    if sha256(cached) != identity["binary_sha256"]:
        raise ValueError("official native peer cached binary identity differs")
    artifacts = Path(root) / "artifacts"
    artifacts.mkdir(exist_ok=True)
    binary = artifacts / name
    shutil.copyfile(cached, binary)
    binary.chmod(0o755)
    return identity | {"binary_sha256": sha256(binary), "official_release_binary": True}


def official_xray(root):
    """Copy latest official Xray to root/artifacts/xray; version runs in guest."""

    def prepare(staging):
        archive, binary = staging / "xray.zip", staging / "xray"
        download(XRAY_URL, archive, limit=MAX_DOWNLOAD)
        archive_sha = sha256(archive)
        _extract_xray(archive, binary)
        archive.unlink()
        return {
            "peer": "Xray-core",
            "url": XRAY_URL,
            "architecture": "linux-arm64",
            "archive_sha256": archive_sha,
            "binary_sha256": sha256(binary),
        }

    return _copy_cached(root, "xray", prepare)


def official_hysteria2(root):
    """Copy latest official Hysteria to root/artifacts/hysteria2; no host exec."""

    def prepare(staging):
        binary = staging / "hysteria2"
        download(HYSTERIA2_URL, binary, limit=MAX_DOWNLOAD)
        _check_binary(binary)
        checksum = sha256(binary)
        return {
            "peer": "Hysteria2",
            "url": HYSTERIA2_URL,
            "architecture": "linux-arm64",
            "archive_sha256": checksum,
            "binary_sha256": checksum,
        }

    return _copy_cached(root, "hysteria2", prepare)
