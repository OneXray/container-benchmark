"""Small input identities and structured files shared by every core adapter."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


def save(path: Path, value) -> None:
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".partial")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact(text: str) -> str:
    """Remove private key blocks and obvious URL/user credential fields from text."""
    text = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
        r"(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
        "<private-key>",
        str(text),
        flags=re.S,
    )
    text = re.sub(r"(https?://)[^\s/@]+:[^\s/@]+@", r"\1<credentials>@", text)
    return re.sub(
        r"(?i)(password|secret|token)(\s*[=:]\s*)[^\s,;]+", r"\1\2<redacted>", text
    )


def source_identity(source: Path) -> dict:
    """Record the selected checkout, never import its build/test machinery."""
    source = Path(source).resolve(strict=True)

    def git(*argv):
        return subprocess.check_output(
            ["git", *argv], cwd=source, stderr=subprocess.PIPE, timeout=20
        )

    try:
        return {
            "path": str(source),
            "commit": git("rev-parse", "HEAD").decode().strip(),
            "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "dirty": bool(git("status", "--porcelain")),
        }
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("explicit source must be a readable Git checkout") from error


def protobuf_fields(data):
    """Decode the official GeoData protobuf's supported scalar/message wire types."""
    data = memoryview(data)
    position = 0

    def varint():
        nonlocal position
        value = 0
        for shift in range(0, 70, 7):
            if position >= len(data):
                raise ValueError("truncated protobuf varint")
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
        raise ValueError("oversized protobuf varint")

    while position < len(data):
        tag = varint()
        field, wire = tag >> 3, tag & 7
        if field == 0:
            raise ValueError("invalid protobuf field")
        if wire == 0:
            yield field, wire, varint()
            continue
        size = varint() if wire == 2 else {1: 8, 5: 4}.get(wire)
        if size is None or position + size > len(data):
            raise ValueError("invalid or truncated protobuf field")
        value = data[position : position + size]
        position += size
        yield field, wire, value
