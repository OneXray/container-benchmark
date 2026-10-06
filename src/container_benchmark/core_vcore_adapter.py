"""Normal VCore production-ABI launch adapter for the common CLI workload."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import tomllib
from pathlib import Path, PurePosixPath

from .inputs import save, sha256
from .paths import FIXTURE_ROOT


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
                os.path.normpath("/src/cores/vcore/" + dependency["path"])
            )
            for _ in package.relative_to(repository).parts:
                destination = destination.parent
            if str(destination) in (
                "/",
                "/src",
                "/src/cores",
                "/src/cores/vcore",
                "/src/benchmark",
            ):
                raise ValueError(
                    "external Cargo dependency overlaps shared source mounts"
                )
            if destination in mounts and mounts[destination] != repository:
                raise ValueError("external Cargo dependency mount collision")
            mounts[destination] = repository
    return [(str(host), str(guest)) for guest, host in sorted(mounts.items())]


def build(guest, root):
    root = Path(root)
    guest.execute(
        [
            "/bin/sh",
            "-ec",
            "cd /src/cores/vcore; "
            "CARGO_TARGET_DIR=/run/benchmark/vcore-target "
            "cargo build --locked --release --lib --features ffi; "
            "cc -O2 -Wall -Wextra -Werror -I /src/cores/vcore/include "
            "/src/benchmark/fixtures/vcore/launcher.c "
            "/run/benchmark/vcore-target/release/libvcore.a "
            "-pthread -ldl -lm -lstdc++ -o /run/benchmark/artifacts/vcore",
        ],
        root / "vcore-build.log",
        timeout=4000,
    )
    return {
        "binary_sha256": sha256(root / "artifacts/vcore"),
        "library_sha256": sha256(root / "vcore-target/release/libvcore.a"),
        "build": "normal Release default protocol features plus production ffi",
        "launcher_sha256": sha256(FIXTURE_ROOT / "vcore/launcher.c"),
        "source_changes": False,
    }


def configure(root, assets, witnesses, origins, dns, tun):
    root, assets = Path(root), Path(assets)
    data = root / "data"
    geodata = data / "geodata"
    geodata.mkdir(parents=True)
    for name in ("geosite.dat", "geoip.dat"):
        # VCore deliberately rejects symlinked assets; keep real per-run files.
        shutil.copyfile(assets / name, geodata / name)
    config = {
        "tun": {"enable": True},
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
            "nameserver": [f"udp://{dns.ipv4}:24004#DIRECT"],
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
    requests = [
        {"apiVersion": 5, "method": "initialize", "payload": {"dataDir": str(data)}},
        {"apiVersion": 5, "method": "createInstance", "payload": {}},
        {
            "apiVersion": 5,
            "method": "prepare",
            "instanceId": "@INSTANCE@",
            "payload": {"configYaml": json.dumps(config, separators=(",", ":"))},
        },
        {
            "apiVersion": 5,
            "method": "start",
            "instanceId": "@INSTANCE@",
            "payload": {"tunFd": tun.fd, "tunFraming": "rawIp"},
        },
    ]
    request_path = root / "requests.jsonl"
    request_path.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in requests)
    )
    return {
        "config": root / "config.json",
        "argv": [str(root / "artifacts/vcore"), str(request_path)],
        "pass_fds": (tun.fd,),
        "env": {},
        "differences": [
            "VCore has no stock Linux CLI; minimal C adapter invokes only the public "
            "production lifecycle ABI and uses the same external PID observer.",
            "VCore requires an unused concrete node and a declared REJECT group; "
            "neither introduces an additional traffic path.",
        ],
    }


def wait_ready(process, log, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        process.sample()
        if "benchmark-ready" in Path(log).read_text(errors="replace"):
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("VCore production lifecycle startup did not complete")
        time.sleep(0.1)
