"""Official Mihomo Linux ARM64 binary used by the native-TUN comparison."""

from __future__ import annotations

import gzip
import hashlib
import os
import re
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

from .download_cache import daily

MAX_ARCHIVE_BYTES = 128 * 1024**2
MAX_BINARY_BYTES = 256 * 1024**2


def _https_response(response):
    if urllib.parse.urlsplit(response.geturl()).scheme != "https":
        raise ValueError("official download left HTTPS")


def _copy_and_hash(source, output, limit):
    digest, size = hashlib.sha256(), 0
    deadline = time.monotonic() + 180
    read = getattr(source, "read1", source.read)
    while chunk := read(65536):
        size += len(chunk)
        if size > limit or time.monotonic() > deadline:
            raise ValueError("official payload exceeded download bounds")
        digest.update(chunk)
        output.write(chunk)
    if not size:
        raise ValueError("empty official payload")
    return digest.hexdigest()


def _read(url, limit=4096):
    request = urllib.request.Request(url, headers={"User-Agent": "container-benchmark"})
    with urllib.request.urlopen(request, timeout=30) as response:
        _https_response(response)
        raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("official metadata exceeded bounds")
        return raw, response.geturl()


def prepare_binary(directory):
    directory = Path(directory)

    def latest(_):
        raw, _ = _read(
            "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"
        )
        return {"release": raw.decode().strip()}

    release = daily("mihomo-latest-release", latest)["release"]
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release) is None:
        raise ValueError("invalid stable Mihomo release")
    asset = f"mihomo-linux-arm64-{release}.gz"
    url = f"https://github.com/MetaCubeX/mihomo/releases/download/{release}/{asset}"
    key = f"mihomo-linux-arm64-{release}"

    def prepare(staging):
        archive, binary = staging / asset, staging / "mihomo"
        request = urllib.request.Request(
            url, headers={"User-Agent": "container-benchmark"}
        )
        with (
            urllib.request.urlopen(request, timeout=30) as response,
            archive.open("wb") as output,
        ):
            _https_response(response)
            resolved = response.geturl()
            archive_sha = _copy_and_hash(response, output, MAX_ARCHIVE_BYTES)
        with gzip.open(archive, "rb") as source, binary.open("wb") as output:
            binary_sha = _copy_and_hash(source, output, MAX_BINARY_BYTES)
        archive.unlink()
        binary.chmod(0o755)
        return {
            "core": "mihomo",
            "release": release,
            "asset": asset,
            "url": url,
            "resolved_url": resolved,
            "archive_sha256": archive_sha,
            "binary_sha256": binary_sha,
            "official_release_binary": True,
        }

    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".download-", dir=directory) as temporary:
        metadata = daily(key, prepare, directory=Path(temporary), immutable=True)
        os.replace(Path(temporary) / "mihomo", directory / "mihomo")
    return {"binary": directory / "mihomo", "identity": metadata}
