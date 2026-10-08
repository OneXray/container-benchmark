"""Normal Vole foreground CLI adapter for the common native-TUN workload."""

from __future__ import annotations

import os
import shutil
import subprocess
import tomllib
from pathlib import Path, PurePosixPath

from .inputs import save, sha256


def source_mounts(source):
    """Mount actual external Cargo path dependencies without workspace guesses."""
    source = Path(source).resolve(strict=True)
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    mounts = {}
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        for dependency in manifest.get(table, {}).values():
            if not isinstance(dependency, dict) or "path" not in dependency:
                continue
            package = (source / dependency["path"]).resolve(strict=True)
            if package.is_relative_to(source):
                continue
            repository = Path(
                subprocess.check_output(
                    ["git", "-C", str(package), "rev-parse", "--show-toplevel"],
                    text=True,
                    timeout=20,
                ).strip()
            ).resolve(strict=True)
            destination = PurePosixPath(
                os.path.normpath("/src/cores/vole/" + dependency["path"])
            )
            for _ in package.relative_to(repository).parts:
                destination = destination.parent
            if str(destination) in (
                "/",
                "/src",
                "/src/cores",
                "/src/cores/vole",
                "/src/benchmark",
            ):
                raise ValueError(
                    "external Cargo dependency overlaps shared source mounts"
                )
            if destination in mounts and mounts[destination] != repository:
                raise ValueError("external Cargo dependency mount collision")
            mounts[destination] = repository
    return [(str(host), str(guest)) for guest, host in sorted(mounts.items())]


def build(guest, root, *, geodata_update=False):
    root = Path(root)
    if geodata_update:
        raise ValueError("CLI GeoData update pressure has no live state observer")
    guest.execute(
        [
            "/bin/sh",
            "-ec",
            "cd /src/cores/vole; "
            "CARGO_TARGET_DIR=/run/benchmark/vole-target "
            "cargo build --locked --release --no-default-features "
            "--features cli --lib --bin vole "
            "--message-format=json-render-diagnostics "
            "> /run/benchmark/vole-build-artifacts.jsonl; "
            "cp /run/benchmark/vole-target/release/vole "
            "/run/benchmark/artifacts/vole",
        ],
        root / "vole-build.log",
        timeout=4000,
    )
    guest.execute(
        ["/run/benchmark/artifacts/vole", "-v"],
        root / "vole-version.log",
        timeout=30,
    )
    source = Path(guest.sources["vole"])
    package = tomllib.loads((source / "Cargo.toml").read_text())["package"]
    expected = f"Vole;engine=rust;coreVersion={package['version']}"
    binary = root / "artifacts/vole"
    with binary.open("rb") as stream:
        header = stream.read(20)
    if (
        len(header) != 20
        or header[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(header[18:20], "little") != 183
    ):
        raise ValueError("Vole DUT must be a native Linux arm64 ELF executable")
    version = (root / "vole-version.log").read_text().strip()
    if expected not in version or expected.encode() not in binary.read_bytes():
        raise ValueError("Vole CLI build identity does not match the selected source")
    return {
        "binary_sha256": sha256(binary),
        "binary_format": "ELF64 little-endian aarch64",
        "build_identity": expected,
        "runtime_version": version,
        "lockfile_sha256": sha256(source / "Cargo.lock"),
        "library_sha256": sha256(root / "vole-target/release/libvole.rlib"),
        "library_format": "rlib",
        "library_name": "libvole.rlib",
        "library_use": "builder-only offline GeoData probe; not the measured process",
        "build": "locked Release production cli features; no FFI or interop features",
        "source_changes": False,
    }


def configure(root, assets, witnesses, origins, dns, tun, *, geodata_update=False):
    if geodata_update:
        raise ValueError("CLI GeoData update pressure has no live state observer")
    root, assets = Path(root), Path(assets)
    data = root / "data"
    geodata = data / "geodata"
    geodata.mkdir(parents=True)
    for name in ("geosite.dat", "geoip.dat"):
        # Vole deliberately rejects symlinked assets; keep real per-run files.
        shutil.copyfile(assets / name, geodata / name)
    nameserver = f"udp://{dns.ipv4}:24004#DIRECT"
    config = {
        "tun": {
            "enable": True,
            "file-descriptor": tun.fd,
            "device": tun.device,
            "mtu": 1500,
            "dns-hijack": ["198.18.0.1:53"],
            "udp-timeout": 60,
        },
        "ipv6": False,
        "proxies": [
            {
                "name": "unused",
                "type": "socks5",
                "server": origins[0].ipv4,
                "port": 24003,
                "udp": True,
            }
        ],
        "proxy-groups": [{"name": "blocked", "type": "select", "proxies": ["REJECT"]}],
        "dns": {
            "enable": True,
            "ipv6": False,
            "nameserver": [nameserver],
        },
        "rules": [
            "GEOSITE,cn,DIRECT",
            f"DOMAIN,{witnesses['domain_positive']},REJECT",
            "GEOIP,cn,REJECT",
            *[f"IP-CIDR,{row.ipv4}/32,DIRECT,no-resolve" for row in origins],
            "MATCH,blocked",
        ],
    }
    save(root / "config.json", config)
    return {
        "config": root / "config.json",
        "argv": [
            str(root / "artifacts/vole"),
            "-d",
            str(data),
            "-f",
            str(root / "config.json"),
        ],
        "pass_fds": (tun.fd,),
        "env": {},
        "differences": [
            "Normal production Vole CLI; the host-owned single raw-IP TUN fd "
            "is declared in YAML and inherited at exec.",
            "Vole requires an unused concrete node and a declared REJECT group; "
            "neither introduces an additional traffic path.",
        ],
    }
