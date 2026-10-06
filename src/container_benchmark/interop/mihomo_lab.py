"""Self-contained official downloads and owned Apple-container interop resources."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import tomllib
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

from ..paths import BENCHMARK_ROOT, FIXTURE_ROOT
from .processes import run_command

CACHE = BENCHMARK_ROOT / ".cache/interop"
SCRATCH = BENCHMARK_ROOT / ".work/interop"
CONCLUSIONS = BENCHMARK_ROOT / "conclusions/interop"
NETWORK = "benchmark-interop-nat"
PURPOSE = "container-benchmark-interop"
IMAGE = "docker.io/library/ubuntu:latest"
TARGET = "aarch64-unknown-linux-gnu"
PACKAGES = (
    "build-essential",
    "git",
    "clang",
    "libclang-dev",
    "cmake",
    "ninja-build",
    "pkg-config",
    "perl",
    "patch",
    "curl",
    "ca-certificates",
    "python3",
    "file",
    "xz-utils",
    "nftables",
)


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(*arguments, timeout=60):
    result = run_command(["container", *map(str, arguments)], timeout=timeout)
    if result.returncode or not result.cleanup:
        raise RuntimeError(f"owned container operation failed: {arguments[0]}")
    return result.stdout.decode()


def download(url, path, *, limit=768 * 1024**2):
    if not url.startswith("https://"):
        raise ValueError("official dependency download requires HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "VCore-interop"})
    deadline, total = time.monotonic() + 900, 0
    with (
        urllib.request.urlopen(request, timeout=30) as response,
        Path(path).open("wb") as output,
    ):
        if not response.geturl().startswith("https://"):
            raise ValueError("official dependency redirect left HTTPS")
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > limit or time.monotonic() > deadline:
                raise ValueError("official dependency download exceeded bounds")
            output.write(chunk)
    if not total:
        raise ValueError("official dependency download was empty")


def daily(name, prepare):
    """Check once per local calendar day; stale/partial artifacts never pass."""
    CACHE.mkdir(parents=True, exist_ok=True)
    if CACHE.is_symlink() or CACHE.parent.is_symlink():
        raise ValueError("interop cache must not use a symlink")
    directory = CACHE / name
    metadata = directory / "identity.json"
    if directory.is_symlink() or metadata.is_symlink():
        raise ValueError("interop cache entry must not use a symlink")
    today = datetime.now().astimezone().date().isoformat()
    if metadata.is_file():
        record = json.loads(metadata.read_text())
        if not isinstance(record.get("files"), dict) or any(
            Path(filename).name != filename or (directory / filename).is_symlink()
            for filename in record["files"]
        ):
            raise ValueError("interop cached files must be regular single-level names")
        if record.get("checked_day") == today and all(
            (directory / filename).is_file()
            and sha256(directory / filename) == checksum
            for filename, checksum in record.get("files", {}).items()
        ):
            return directory, record
    staging = Path(tempfile.mkdtemp(prefix="refresh-", dir=CACHE))
    try:
        record = prepare(staging)
        record.update(
            checked_day=today,
            files={
                path.name: sha256(path) for path in staging.iterdir() if path.is_file()
            },
        )
        save(staging / "identity.json", record)
        if directory.exists():
            if directory.is_symlink() or directory.parent != CACHE:
                raise ValueError("shared cache path is not owned")
            shutil.rmtree(directory)
        staging.replace(directory)
        return directory, record
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def official_mihomo(root):
    def prepare(staging):
        latest = "https://github.com/MetaCubeX/mihomo/releases/latest/download/"
        version = staging / "version.txt"
        download(latest + "version.txt", version, limit=4096)
        release = version.read_text().strip()
        if not re.fullmatch(r"v\d+\.\d+\.\d+", release):
            raise ValueError("official Mihomo latest is not a stable version")
        asset = f"mihomo-linux-arm64-{release}.gz"
        archive = staging / "mihomo.gz"
        download(latest + asset, archive, limit=128 * 1024**2)
        archive_sha = sha256(archive)
        with (
            gzip.open(archive, "rb") as source,
            (staging / "mihomo").open("wb") as output,
        ):
            size = 0
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > 256 * 1024**2:
                    raise ValueError("official Mihomo binary exceeded bounds")
                output.write(chunk)
        archive.unlink()
        if not size:
            raise ValueError("official Mihomo binary is empty")
        return {
            "release": release,
            "url": latest + asset,
            "archive_sha256": archive_sha,
        }

    directory, identity = daily("mihomo", prepare)
    binary = root / "artifacts/mihomo"
    shutil.copyfile(directory / "mihomo", binary)
    binary.chmod(0o755)
    return identity | {"binary_sha256": sha256(binary), "official_release_binary": True}


def official_rust():
    def prepare(staging):
        manifest = staging / "channel.toml"
        download(
            "https://static.rust-lang.org/dist/channel-rust-stable.toml",
            manifest,
            limit=4 * 1024**2,
        )
        data = tomllib.loads(manifest.read_text())
        target = data["pkg"]["rust"]["target"][TARGET]
        if target["available"] is not True or not target["xz_url"].startswith(
            "https://static.rust-lang.org/dist/"
        ):
            raise ValueError("official Rust stable target unavailable")
        archive = staging / "rust.tar.xz"
        download(target["xz_url"], archive)
        if sha256(archive) != target["xz_hash"]:
            raise ValueError("official Rust archive checksum mismatch")
        version = data["pkg"]["rust"]["version"].split()[0]
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError("official Rust stable version is invalid")
        with tarfile.open(archive, "r:xz") as package:
            installer_files = [
                member.name
                for member in package.getmembers()
                if member.isfile()
                and Path(member.name).parent == Path(f"rust-{version}-{TARGET}")
            ]
        return {
            "version": version,
            "target": TARGET,
            "archive_root": f"rust-{version}-{TARGET}",
            "archive_sha256": target["xz_hash"],
            "installer_files": installer_files,
        }

    return daily("rust", prepare)


def owned_network():
    rows = json.loads(command("network", "list", "--format", "json"))
    if not any(row["id"] == NETWORK for row in rows):
        command("network", "create", "--label", f"purpose={PURPOSE}", NETWORK)
    row = json.loads(command("network", "inspect", NETWORK))[0]
    if (
        row["configuration"]["mode"] != "nat"
        or row["configuration"].get("labels", {}).get("purpose") != PURPOSE
    ):
        raise RuntimeError("owned Mihomo NAT network required")


class Guest:
    def __init__(
        self, session, image, role, *, cache=None, source=False, capabilities=()
    ):
        self.session, self.root, self.image = session, session.work, image
        self.name = f"vcore-interop-{session.run_id}-{role}"
        self.cache, self.source = cache, source
        self.capabilities = tuple(capabilities)
        if set(self.capabilities) - {"NET_ADMIN"}:
            raise ValueError("unsupported interop container capability")
        self.record = {"role": role, "name": self.name, "joined": False}
        session.guests.append(self)

    def __enter__(self):
        mounts = [
            (self.root, "/work", False),
            (BENCHMARK_ROOT / "src", "/benchmark/src", True),
            (FIXTURE_ROOT / "interop", "/benchmark/fixtures/interop", True),
        ]
        if self.cache is not None:
            mounts.append((self.cache, "/cache", False))
        if self.source:
            source_dir = self.session.source_dir
            if source_dir is None:
                raise ValueError("interop builder requires an explicit VCore source")
            mounts.append((source_dir, "/src/vcore", True))
            manifest = tomllib.loads((source_dir / "Cargo.toml").read_text())
            for table in ("dependencies", "build-dependencies", "dev-dependencies"):
                for dependency in manifest.get(table, {}).values():
                    if not isinstance(dependency, dict) or "path" not in dependency:
                        continue
                    host = (source_dir / dependency["path"]).resolve(strict=True)
                    if host.is_relative_to(source_dir):
                        continue
                    target = os.path.normpath("/src/vcore/" + dependency["path"])
                    if target in (
                        "/",
                        "/src",
                        "/src/vcore",
                        "/benchmark",
                        "/benchmark/src",
                        "/benchmark/fixtures",
                        "/benchmark/fixtures/interop",
                        "/work",
                        "/cache",
                    ):
                        raise ValueError(
                            "external Cargo path dependency overlaps owned mounts"
                        )
                    mounts.append((host, target, True))
        cargo = CACHE / "cargo"
        if cargo.is_symlink() or cargo.parent.is_symlink():
            raise ValueError("interop cargo cache must not use a symlink")
        cargo.mkdir(exist_ok=True)
        command(
            "run",
            "--detach",
            "--name",
            self.name,
            "--label",
            f"purpose={PURPOSE}",
            "--label",
            f"vcore-run={self.session.run_id}",
            "--network",
            f"{NETWORK},mtu=1500",
            "--cpus",
            "5",
            "--memory",
            "8G",
            "--arch",
            "arm64",
            *[
                argument
                for item in self.capabilities
                for argument in ("--cap-add", item)
            ],
            "--env",
            "VCORE_INTEROP_ISOLATED=1",
            "--env",
            "BENCHMARK_INTEROP_WORK=/work",
            "--env",
            "CARGO_HOME=/cargo",
            "--env",
            "DEBIAN_FRONTEND=noninteractive",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "PATH=/work/rust/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "--mount",
            f"type=bind,source={cargo},target=/cargo",
            *[
                value
                for host, guest, readonly in mounts
                for value in (
                    "--mount",
                    f"type=bind,source={host},target={guest}"
                    + (",readonly" if readonly else ""),
                )
            ],
            "--entrypoint",
            "/bin/sh",
            self.image,
            "-ec",
            "exec sleep infinity",
        )
        row = json.loads(command("inspect", self.name))[0]
        resources = row["configuration"]["resources"]
        if resources["cpus"] != 5 or resources["memoryInBytes"] != 8 * 1024**3:
            raise RuntimeError(
                "interop container allocation differs from 5 CPU / 8 GiB"
            )
        self.ipv4 = row["status"]["networks"][0]["ipv4Address"].split("/")[0]
        release = command("exec", self.name, "/bin/cat", "/etc/os-release")
        if "ID=ubuntu" not in release or "LTS" not in release:
            raise RuntimeError("official Ubuntu latest must identify itself as LTS")
        self.record.update(cpus=5, memory_bytes=8 * 1024**3, network="NAT")
        return self

    def execute(self, argv, log, *, timeout=1800):
        result = run_command(
            ["container", "exec", self.name, *map(str, argv)],
            timeout=timeout,
            limit=4 * 1024**2,
        )
        Path(log).write_bytes(result.stdout)
        if result.returncode or not result.cleanup:
            raise RuntimeError(
                f"owned interop command failed: {Path(log).name}; "
                f"exit={result.returncode}; reason={result.reason or 'exit-status'}"
            )

    def python(self, mode, *, timeout=1200):
        self.execute(
            [
                "env",
                "PYTHONPATH=/benchmark/src",
                "python3",
                "-m",
                "container_benchmark.interop.mihomo_interop",
                mode,
                "/work",
            ],
            self.root / (mode + ".log"),
            timeout=timeout,
        )

    def stop(self):
        rows = json.loads(command("list", "--all", "--format", "json"))
        row = next((row for row in rows if row["id"] == self.name), None)
        if row is not None:
            labels = row["configuration"].get("labels", {})
            if (
                labels.get("purpose") != PURPOSE
                or labels.get("vcore-run") != self.session.run_id
            ):
                raise RuntimeError("container ownership mismatch; refusing cleanup")
            if row["status"]["state"] == "running":
                command("stop", "--time", "5", self.name, timeout=15)
            command("delete", "--force", self.name, timeout=15)
        self.record["joined"] = not any(
            row["id"] == self.name
            for row in json.loads(command("list", "--all", "--format", "json"))
        )
        if not self.record["joined"]:
            raise RuntimeError("owned interop container cleanup incomplete")

    def __exit__(self, *_):
        self.stop()


def prepare_tools(session):
    def image_refresh(_):
        command("image", "pull", IMAGE, timeout=180)
        digest = json.loads(command("image", "inspect", IMAGE))[0]["configuration"][
            "descriptor"
        ]["digest"]
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise ValueError("official Ubuntu image digest is invalid")
        return {"tag": IMAGE, "digest": digest}

    print("Protocol interop dependencies: official Ubuntu LTS image", flush=True)
    _, image_identity = daily("image", image_refresh)
    image = IMAGE.rsplit(":", 1)[0] + "@" + image_identity["digest"]
    # The pinned image must still exist, including after a shared-cache hit.
    command("image", "inspect", image)

    def packages(staging):
        with Guest(session, image, "packages", cache=staging) as guest:
            guest.execute(
                ["apt-get", "update"], session.work / "apt-update.log", timeout=300
            )
            guest.execute(
                [
                    "/bin/sh",
                    "-ec",
                    "mkdir -p /tmp/interop-debs; "
                    "apt-get -o Dir::Cache::archives=/tmp/interop-debs "
                    "install --yes --download-only "
                    + " ".join(PACKAGES)
                    + "; cp /tmp/interop-debs/*.deb /cache/",
                ],
                session.work / "apt-download.log",
                timeout=600,
            )
        return {"image": image_identity["digest"], "packages": list(PACKAGES)}

    print("Protocol interop dependencies: Ubuntu build/runtime packages", flush=True)
    package_set = hashlib.sha256(json.dumps(PACKAGES).encode()).hexdigest()[:12]
    packages_path, packages_identity = daily(
        "packages-" + image_identity["digest"][-12:] + "-" + package_set, packages
    )
    print("Protocol interop dependencies: official Rust stable archive", flush=True)
    rust_path, rust_identity = official_rust()
    (session.work / "builder-tools").mkdir()
    for path in packages_path.glob("*.deb"):
        shutil.copyfile(path, session.work / "builder-tools" / path.name)
    shutil.copyfile(rust_path / "rust.tar.xz", session.work / "rust.tar.xz")
    return image, {
        "image": image_identity,
        "packages": packages_identity,
        "rust": rust_identity,
    }


def install_tools(guest, *, rust=None):
    guest.execute(
        [
            "/bin/sh",
            "-ec",
            "apt-get -o Dir::Cache::archives=/work/builder-tools "
            "--no-download --yes install /work/builder-tools/*.deb",
        ],
        guest.root / (guest.name + "-install.log"),
        timeout=300,
    )
    if rust:
        package = rust["archive_root"]
        selected = rust["installer_files"] + [
            package + "/" + component
            for component in ("rustc", "cargo", "rust-std-" + TARGET)
        ]
        guest.execute(
            [
                "/bin/sh",
                "-ec",
                "mkdir -p /work/rust-unpack; "
                "tar -xJf /work/rust.tar.xz -C /work/rust-unpack "
                + " ".join(selected)
                + "; "
                f"cd /work/rust-unpack/{package}; "
                f"./install.sh --components=rustc,cargo,rust-std-{TARGET} "
                "--prefix=/work/rust --disable-ldconfig",
            ],
            guest.root / "rust-install.log",
            timeout=600,
        )


class Session:
    def __init__(self, source_dir=None):
        # The CLI/run entry requires a source for execution. Allow a source-free
        # Session only for offline ownership/cleanup regression tests.
        self.source_dir = (
            Path(source_dir).resolve(strict=True) if source_dir is not None else None
        )

    def __enter__(self):
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise RuntimeError(
                "Protocol interop currently requires Apple Silicon and Apple container"
            )
        SCRATCH.mkdir(parents=True, exist_ok=True)
        if SCRATCH.is_symlink() or SCRATCH.parent.is_symlink():
            raise ValueError("interop scratch must not use a symlink")
        self.work = Path(tempfile.mkdtemp(prefix="run-", dir=SCRATCH))
        self.run_id, self.guests, self.status = uuid.uuid4().hex[:12], [], "ERROR"
        (self.work / ".owned-session").write_text(self.run_id)
        self.previous_work = os.environ.get("BENCHMARK_INTEROP_WORK")
        os.environ["BENCHMARK_INTEROP_WORK"] = str(self.work)
        return self

    def __exit__(self, kind, error, _traceback):
        try:
            return self._finish(error)
        finally:
            if self.previous_work is None:
                os.environ.pop("BENCHMARK_INTEROP_WORK", None)
            else:
                os.environ["BENCHMARK_INTEROP_WORK"] = self.previous_work

    def _finish(self, error):
        failures = []
        for guest in reversed(self.guests):
            try:
                guest.stop()
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                failures.append("owned container cleanup failed")
        summary = self.work / "summary.md"
        containers_clean = not failures
        try:
            text = (
                summary.read_text()
                if summary.is_file()
                else "No case summary available.\n"
            )
        except OSError:
            text = "Case summary could not be read.\n"
            failures.append("owned interop summary read failed")
        # Final PASS is written only after both process and disk cleanup. A
        # report-path I/O failure must not leave private keys or build products.
        if containers_clean:
            try:
                if (
                    self.work.is_symlink()
                    or self.work.parent != SCRATCH
                    or (self.work / ".owned-session").read_text() != self.run_id
                ):
                    raise ValueError("interop scratch ownership mismatch")
                shutil.rmtree(self.work)
            except (OSError, ValueError):
                failures.append("owned interop artifact cleanup failed")
        if CONCLUSIONS.is_symlink() or CONCLUSIONS.parent.is_symlink():
            raise ValueError("interop conclusions must not use a symlink")
        CONCLUSIONS.mkdir(parents=True, exist_ok=True)
        report = CONCLUSIONS / (
            datetime.now().astimezone().strftime("%Y%m%dT%H%M%S")
            + "-"
            + self.run_id
            + ".md"
        )
        overall = "ERROR" if failures or error is not None else self.status
        report.write_text(
            "Overall result: "
            + overall
            + "\n\n"
            + text
            + "\nCleanup: "
            + ("; ".join(failures) or "complete")
            + "\n"
        )
        print(f"Text conclusion: {report}", flush=True)
        if failures:
            raise RuntimeError("; ".join(failures))
        return False
