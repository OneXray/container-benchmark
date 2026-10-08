"""Official listener/native-peer interoperability, separate from pressure."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import ssl
import subprocess
import sys
import time
from pathlib import Path

from ..paths import FIXTURE_ROOT as BENCHMARK_FIXTURE_ROOT
from .mihomo_lab import save, sha256

FIXTURE_ROOT = BENCHMARK_FIXTURE_ROOT / "interop"

PROTOCOLS = (
    "socks5",
    "anytls",
    "ss",
    "trojan",
    "vmess",
    "vless",
    "hysteria2",
    "tuic",
)
BACKENDS = ("mihomo", "xray", "hysteria2", "v2ray", "caddy")
UUID = "07070707-0707-4707-8707-070707070707"
PASSWORD = "synthetic-interop-password"
CERTIFICATE_NAME = "fixture.invalid"
SOCKS_PORT = 24502
SS_CIPHERS = (
    ("2022-blake3-aes-128-gcm", 16),
    ("2022-blake3-aes-256-gcm", 32),
    ("2022-blake3-chacha20-poly1305", 32),
)


def cases(protocols):
    result = []

    def add(protocol, identifier, **fields):
        result.append(
            {
                "id": identifier,
                "protocol": protocol,
                "port": 24510 + len(result),
                **fields,
            }
        )

    for protocol in protocols:
        for cipher, size in SS_CIPHERS if protocol == "ss" else ((None, None),):
            add(
                protocol,
                cipher or protocol,
                **({"cipher": cipher, "key_bytes": size} if cipher else {}),
            )
            if protocol == "ss":
                for label, shadow_tls, uot in (
                    ("shadowtls-v3", True, False),
                    ("uot-v2", False, True),
                    ("shadowtls-v3-uot-v2", True, True),
                ):
                    add(
                        protocol,
                        cipher + "-" + label,
                        cipher=cipher,
                        key_bytes=size,
                        shadow_tls=shadow_tls,
                        uot=uot,
                    )
        if protocol == "tuic":
            add(protocol, "tuic-quic", udp_mode="quic")
        if protocol in ("vmess", "trojan"):
            for tls in (False, True) if protocol == "vmess" else (True,):
                for fast in (False, True):
                    add(
                        protocol,
                        protocol
                        + "-httpupgrade-"
                        + ("tls" if tls else "plain")
                        + ("-fast" if fast else "-normal"),
                        upgrade=True,
                        tls=tls,
                        fast=fast,
                    )
    return result


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="container-benchmark interop")
    parser.add_argument("--source", action="append", default=[], metavar="vole=PATH")
    parser.add_argument(
        "--protocol", nargs="+", choices=PROTOCOLS, default=list(PROTOCOLS)
    )
    parser.add_argument("--list", action="store_true")
    parser.add_argument(
        "--backend", nargs="+", choices=BACKENDS, default=list(BACKENDS)
    )
    args = parser.parse_args(argv)
    args.protocol = list(dict.fromkeys(args.protocol))
    args.backend = list(dict.fromkeys(args.backend))
    args.cases = selected_cases(args.protocol, args.backend)
    args.source_dir = None
    for value in args.source:
        name, separator, raw = value.partition("=")
        if not separator or name != "vole" or not raw or args.source_dir is not None:
            parser.error("--source requires a unique vole=PATH")
        source = Path(raw).resolve(strict=True)
        if not source.is_dir() or not all(
            (source / name).is_file()
            for name in ("Cargo.toml", "Cargo.lock", "include/vole.h")
        ):
            parser.error("--source must point to a Vole source checkout")
        args.source_dir = source
    if not args.list and args.source_dir is None:
        parser.error("Vole interoperability requires --source vole=PATH")
    return args


def selected_cases(protocols, backends):
    """One catalog; missing Mihomo capabilities retain native peer coverage."""
    result = []
    if "mihomo" in backends:
        result.extend(dict(case, backend="mihomo") for case in cases(protocols))
    if "xray" in backends:
        from .xray_interop import cases as xray_cases

        result.extend(xray_cases(protocols))
    if "hysteria2" in backends:
        from .hysteria2_interop import cases as hysteria_cases

        result.extend(hysteria_cases(protocols))
    if set(backends) & {"v2ray", "caddy"}:
        from .extended_interop import cases as extended_cases

        result.extend(
            case for case in extended_cases(protocols) if case["backend"] in backends
        )
    if not result or len({case["id"] for case in result}) != len(result):
        raise ValueError("interop selection is empty or has duplicate cases")
    return result


def listener(case, cert, key, cover=None):
    protocol = case["protocol"]
    result = {
        "name": case["id"],
        "type": "shadowsocks" if protocol == "ss" else protocol,
        "listen": "0.0.0.0",
        "port": case["port"],
        "proxy": "DIRECT",
    }
    if protocol == "socks5":
        result.update(type="socks", udp=True, users=[])
    elif protocol == "ss":
        result.update(
            cipher=case["cipher"],
            password=base64.b64encode(bytes([7]) * case["key_bytes"]).decode(),
            udp=not case.get("uot", False),
        )
    elif protocol in ("vmess", "vless"):
        result.update(users=[{"username": "fixture", "uuid": UUID}])
        if protocol == "vmess":
            result["users"][0]["alterId"] = 0
        else:
            result["allow-insecure"] = True
    else:
        result.update(certificate=str(cert), **{"private-key": str(key)})
        if protocol == "trojan":
            result["users"] = [{"username": "fixture", "password": PASSWORD}]
        elif protocol == "tuic":
            result.update(users={UUID: PASSWORD}, alpn=["h3"])
        else:
            result["users"] = {"fixture": PASSWORD}
            if protocol == "hysteria2":
                result["alpn"] = ["h3"]
    if case.get("upgrade"):
        result["ws-path"] = "/interop-upgrade"
        if case["tls"]:
            result.update(certificate=str(cert), **{"private-key": str(key)})
    if case.get("shadow_tls"):
        if cover is None:
            raise ValueError("ShadowTLS v3 requires an isolated TLS cover")
        result["shadow-tls"] = {
            "enable": True,
            "version": 3,
            "users": [{"name": "fixture", "password": PASSWORD}],
            "handshake": {"dest": cover, "proxy": "DIRECT"},
            "strict-mode": True,
        }
    return result


def node(case, host, pin):
    protocol = case["protocol"]
    result = {
        "name": "edge",
        "type": protocol,
        "server": host,
        "port": case["port"],
        "udp": True,
    }
    if protocol == "ss":
        result.update(
            cipher=case["cipher"],
            password=base64.b64encode(bytes([7]) * case["key_bytes"]).decode(),
        )
    elif protocol in ("vmess", "vless"):
        result.update(uuid=UUID, network="tcp", tls=False)
        if protocol == "vmess":
            result.update(alterId=0, cipher="aes-128-gcm")
    elif protocol != "socks5":
        result.update(
            password=PASSWORD,
            sni=CERTIFICATE_NAME,
            fingerprint=pin,
            **{"skip-cert-verify": False},
        )
        if protocol == "tuic":
            result.update(uuid=UUID, alpn=["h3"], **{"udp-relay-mode": "native"})
        elif protocol == "hysteria2":
            result["alpn"] = ["h3"]
    if case.get("uot"):
        result.update({"udp-over-tcp": True, "udp-over-tcp-version": 2})
    if case.get("shadow_tls"):
        result.update(
            plugin="shadow-tls",
            **{
                "plugin-opts": {
                    "version": 3,
                    "host": CERTIFICATE_NAME,
                    "password": PASSWORD,
                    "fingerprint": pin,
                    "skip-cert-verify": False,
                }
            },
        )
    if case.get("udp_mode"):
        result["udp-relay-mode"] = case["udp_mode"]
    if case.get("upgrade"):
        result.update(
            network="ws",
            **{
                "ws-opts": {
                    "path": "/interop-upgrade",
                    "headers": {"Host": CERTIFICATE_NAME},
                    "v2ray-http-upgrade": True,
                    "v2ray-http-upgrade-fast-open": case["fast"],
                }
            },
        )
        if protocol == "vmess":
            result["tls"] = case["tls"]
            if case["tls"]:
                result.update(
                    servername=CERTIFICATE_NAME,
                    fingerprint=pin,
                    **{"skip-cert-verify": False},
                )
    result.update(case.get("node_overrides", {}))
    return result


def requests(root, case, peer, pin):
    root = Path(root)
    config = {
        "ipv6": False,
        "mixed-port": SOCKS_PORT,
        "allow-lan": False,
        "tun": {"enable": False},
        "dns": {"enable": False},
        "proxies": [node(case, peer, pin)],
        "rules": ["MATCH,edge"],
    }
    data = root / "data"
    data.mkdir()
    rows = [
        {"method": "initialize", "payload": {"dataDir": str(data)}},
        {"method": "createInstance", "payload": {}},
        {
            "method": "start",
            "instanceId": "@INSTANCE@",
            "payload": {"configYaml": json.dumps(config, separators=(",", ":"))},
        },
    ]
    path = root / "requests.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return path


def _load_probe():
    spec = importlib.util.spec_from_file_location(
        "interop_probe", FIXTURE_ROOT / "mihomo_probe.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _guest(root):
    from .processes import OwnedProcess

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("interoperability consumer requires the owned Linux guest")
    fixture = json.loads((root / "interop.json").read_text())
    result_path = root / fixture.get("result_file", "result.json")
    result = {"status": "ERROR", "cases": []}
    try:
        for case in fixture["cases"]:
            directory = root / "cases" / case["id"]
            directory.mkdir(parents=True)
            path = requests(directory, case, fixture["peer"], fixture["pin"])
            record = {
                "id": case["id"],
                "protocol": case["protocol"],
                "backend": case.get("backend", "mihomo"),
                "topology": (
                    "Xray H3 gateway to loopback Mihomo VLESS decoder"
                    if case.get("decoder")
                    else "Caddy mTLS H3 gateway to loopback Xray XHTTP handler"
                    if case.get("backend") == "caddy"
                    else "official native protocol listener"
                ),
                "phase": "public-lifecycle-startup",
                "status": "NOT_COMPLETED",
            }
            result["cases"].append(record)
            with OwnedProcess(
                [str(root / "artifacts/vole"), str(path), str(directory / "ready")],
                directory / "core.log",
                record,
            ) as process:
                deadline = time.monotonic() + 30
                while not (directory / "ready").is_file():
                    process.ensure_alive()
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Vole public lifecycle readiness failed")
                    time.sleep(0.05)
                record["phase"] = "tcp-udp-payload-and-origin-witness"
                record.update(
                    _load_probe().probe(
                        fixture["origin"],
                        fixture["peer"],
                        expected=case.get("expected", "pass"),
                        **case.get("probe_options", {}),
                    )
                )
                if record["status"] != "PASS":
                    raise RuntimeError("official peer business exchange did not pass")
                record["phase"] = "public-lifecycle-stop"
            if record["exit_code"] != 0 or not record["joined"]:
                record["status"] = "FAIL_CLEANUP"
                raise RuntimeError("Vole lifecycle did not stop cleanly")
            save(result_path, result)
        result["status"] = "PASS"
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        result["failure"] = type(error).__name__
        result["reason"] = _safe_reason(error)
        if result["cases"]:
            result["cases"][-1]["status"] = "FAIL"
        raise
    finally:
        save(result_path, result)


def _peer(root):
    from .processes import OwnedProcess

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("official protocol peer requires the owned Linux guest")
    commands = json.loads((root / "peer-processes.json").read_text())
    ready = root / "peer/ready"
    try:
        with contextlib.ExitStack() as stack:
            processes = []
            for index, definition in enumerate(commands):
                process = stack.enter_context(
                    OwnedProcess(
                        definition["argv"], root / "peer" / f"server-{index}.log", {}
                    )
                )
                processes.append(process)
                for port in definition.get("ready_ports", []):
                    process.wait_tcp(
                        port, seconds=30, host=definition.get("ready_host", "127.0.0.1")
                    )
                if definition.get("ready_port"):
                    process.wait_tcp(
                        definition["ready_port"],
                        seconds=30,
                        host=definition.get("ready_host", "127.0.0.1"),
                    )
                for port in definition.get("udp_ports", []):
                    deadline = time.monotonic() + 30
                    while True:
                        process.ensure_alive()
                        addresses = (
                            row.split()[1]
                            for name in ("udp", "udp6")
                            for row in Path("/proc/net/" + name)
                            .read_text()
                            .splitlines()[1:]
                        )
                        if any(
                            int(address.rsplit(":", 1)[1], 16) == port
                            for address in addresses
                        ):
                            break
                        if time.monotonic() >= deadline:
                            raise TimeoutError(
                                "official peer UDP bind readiness failed"
                            )
                        time.sleep(0.05)
            ready.touch()
            while True:
                for process in processes:
                    process.ensure_alive()
                time.sleep(0.1)
    except BaseException as error:
        save(
            root / "peer/status.json",
            {"failure": type(error).__name__, "reason": _safe_reason(error)},
        )
        raise
    finally:
        ready.unlink(missing_ok=True)


def _summary(root, report):
    (root / "summary.md").write_text(
        "# Vole / official protocol-peer interoperability\n\n```json\n"
        + json.dumps(report, indent=2)
        + "\n```\n"
    )


def _safe_reason(error):
    # Only our fixed diagnosis strings may survive log/config cleanup. Native
    # errors are reduced to type/errno, never arbitrary config or endpoint text.
    text = str(error)
    allowed = (
        "SOCKS5 ",
        "TCP ",
        "UDP ",
        "partial UDP ",
        "truncated ",
        "Vole public ",
        "Vole lifecycle ",
        "Mihomo actual ",
        "owned interop ",
        "isolated service ",
        "official ",
        "native peer ",
    )
    if text.startswith(allowed) and len(text) <= 180:
        return text
    return type(error).__name__ + (
        f" errno={error.errno}"
        if isinstance(error, OSError) and error.errno is not None
        else ""
    )


def _phase(report, name):
    report["phase"] = name
    print("Protocol interop: " + name, flush=True)


def _certificate(root):
    directory = root / "peer"
    directory.mkdir()
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            f"/CN={CERTIFICATE_NAME}",
            "-addext",
            f"subjectAltName=DNS:{CERTIFICATE_NAME}",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))
    ).hexdigest()


def _source_identity(source_dir):
    return {
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=source_dir, text=True
        ).strip(),
        "dirty": bool(
            subprocess.check_output(["git", "status", "--porcelain"], cwd=source_dir)
        ),
        "lockfile_sha256": sha256(source_dir / "Cargo.lock"),
        "tracked_diff_sha256": hashlib.sha256(
            subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=source_dir)
        ).hexdigest(),
        "untracked_files": {
            name: sha256(source_dir / name)
            for name in subprocess.check_output(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=source_dir,
                text=True,
            ).splitlines()
            if (source_dir / name).is_file()
        },
    }


def _configure_peer(backend, selected, root, origin, pin, peer):
    """Official server configs; the consumer always uses production Invoke ABI."""
    if backend == "mihomo":
        path = root / "peer/config.json"
        save(
            path,
            {
                "mode": "rule",
                "log-level": "silent",
                "ipv6": False,
                "listeners": [
                    listener(
                        case,
                        "/work/peer/cert.pem",
                        "/work/peer/key.pem",
                        f"{origin.ipv4}:24501",
                    )
                    for case in selected
                ],
                "rules": ["MATCH,DIRECT"],
            },
        )
        command = [
            "/work/artifacts/mihomo",
            "-d",
            "/work/peer",
            "-f",
            "/work/peer/config.json",
        ]
        peer.execute(
            [command[0], "-t", *command[1:]], root / "peer/config-check.log", timeout=30
        )

        def quic(case):
            return case["protocol"] in ("hysteria2", "tuic")

        return [
            {
                "argv": command,
                "ready_ports": [case["port"] for case in selected if not quic(case)],
                "udp_ports": [case["port"] for case in selected if quic(case)],
            }
        ]
    if backend == "xray":
        from .xray_interop import configure

        config = configure(selected, root, origin.ipv4, pin, peer)
        path = config["config_path"] if isinstance(config, dict) else config
        guest_path = "/work/" + path.relative_to(root).as_posix()
        peer.execute(
            ["/work/artifacts/xray", "run", "-test", "-c", guest_path],
            root / "peer/config-check.log",
            timeout=30,
        )
        if isinstance(config, dict):
            for process in config["processes"]:
                if process["argv"][0] == "/work/artifacts/mihomo":
                    peer.execute(
                        [process["argv"][0], "-t", *process["argv"][1:]],
                        root / "peer/decoder-config-check.log",
                        timeout=30,
                    )
            return config["processes"]
        return [
            {
                "argv": [
                    "env",
                    "XRAY_BUF_SPLICE=disable",
                    "/work/artifacts/xray",
                    "run",
                    "-c",
                    guest_path,
                ],
                "ready_ports": [
                    case["port"]
                    for case in selected
                    if case["protocol"] in ("trojan", "ss")
                ],
                "udp_ports": [
                    case["port"]
                    for case in selected
                    if case["protocol"] in ("vless", "ss")
                ],
            }
        ]
    if backend == "hysteria2":
        from .hysteria2_interop import configure, setup_hop_witness

        servers = configure(selected, root, origin.ipv4, pin, peer)
        for case in selected:
            if case["variant"].startswith("hop"):
                setup_hop_witness(peer, case)
        return [
            {
                "argv": server["command"],
                "ready_port": server["ready_port"],
                "ready_host": peer.ipv4,
            }
            for server in servers
        ]
    from .extended_interop import configure

    config = configure(selected, root, origin.ipv4, pin, peer)
    if backend == "v2ray":
        guest_path = "/work/" + config.relative_to(root).as_posix()
        peer.execute(
            ["/work/artifacts/v2ray", "test", "-c", guest_path],
            root / "peer/config-check.log",
            timeout=30,
        )
        return [
            {
                "argv": ["/work/artifacts/v2ray", "run", "-c", guest_path],
                "ready_ports": [case["port"] for case in selected],
            }
        ]
    peer.execute(
        [
            "/work/artifacts/caddy",
            "validate",
            "--config",
            "/work/" + config["config_path"].relative_to(root).as_posix(),
        ],
        root / "peer/config-check.log",
        timeout=30,
    )
    return config["processes"]


def _run_backend(session, image, backend, selected, pin, report):
    from .mihomo_lab import Guest, install_tools

    root = session.work
    result_path = root / "results" / (backend + ".json")
    capabilities = (
        ["NET_ADMIN"]
        if any(case.get("variant", "").startswith("hop") for case in selected)
        else []
    )
    try:
        with contextlib.ExitStack() as stack:
            guests = {
                role: stack.enter_context(
                    Guest(
                        session,
                        image,
                        backend + "-" + role,
                        capabilities=capabilities if role == "peer" else (),
                    )
                )
                for role in ("origin", "peer", "consumer")
            }
            report["containers"][backend] = {
                role: guest.record for role, guest in guests.items()
            }
            _phase(report, backend + "-install")
            for guest in guests.values():
                install_tools(guest)
            origin, peer, consumer = (guests[role] for role in guests)
            (root / "peer/ready").unlink(missing_ok=True)
            (root / "peer/status.json").unlink(missing_ok=True)
            _phase(report, backend + "-official-config")
            commands = _configure_peer(backend, selected, root, origin, pin, peer)
            save(root / "peer-processes.json", commands)
            _phase(report, backend + "-origin-readiness")
            origin.execute(
                [
                    "/bin/sh",
                    "-ec",
                    "nohup python3 -B /benchmark/fixtures/interop/mihomo_echo.py "
                    ">/work/origin.log 2>&1 </dev/null &",
                ],
                root / "origin-launch.log",
                timeout=15,
            )
            _wait_tcp(origin.ipv4, 24500)
            _wait_tcp(origin.ipv4, 24503)
            if any(case.get("shadow_tls") for case in selected):
                _wait_tcp(origin.ipv4, 24501)
            _phase(report, backend + "-peer-readiness")
            peer.execute(
                [
                    "/bin/sh",
                    "-ec",
                    "nohup env PYTHONPATH=/benchmark/src python3 -m "
                    "container_benchmark.interop.mihomo_interop peer /work "
                    ">/work/peer/supervisor.log 2>&1 </dev/null &",
                ],
                root / "peer-launch.log",
                timeout=15,
            )
            deadline = time.monotonic() + 60
            while not (root / "peer/ready").is_file():
                if (root / "peer/status.json").is_file():
                    report.setdefault("backend_failures", {})[backend] = json.loads(
                        (root / "peer/status.json").read_text()
                    )
                    raise RuntimeError(
                        "official peer supervisor failed before readiness"
                    )
                if time.monotonic() >= deadline:
                    raise TimeoutError("official peer supervisor readiness failed")
                time.sleep(0.05)
            save(
                root / "interop.json",
                {
                    "cases": selected,
                    "peer": peer.ipv4,
                    "origin": origin.ipv4,
                    "pin": pin,
                    "result_file": result_path.relative_to(root).as_posix(),
                },
            )
            _phase(report, backend + "-public-consumer-cases")
            consumer.python("guest", timeout=120 * len(selected) + 60)
            result = json.loads(result_path.read_text())
            if (
                result["status"] != "PASS"
                or [record["id"] for record in result["cases"]]
                != [case["id"] for case in selected]
                or any(record["status"] != "PASS" for record in result["cases"])
                or not (root / "peer/ready").is_file()
            ):
                raise RuntimeError("official peer or consumer did not complete")
            if backend == "hysteria2":
                from .hysteria2_interop import collect_hop_witness

                for case, record in zip(selected, result["cases"], strict=True):
                    if case["variant"].startswith("hop"):
                        record["port_hop_witness"] = collect_hop_witness(peer, case)
                        if record["port_hop_witness"]["status"] != "PASS":
                            record["status"] = "FAIL_WITNESS"
                save(result_path, result)
                if any(record["status"] != "PASS" for record in result["cases"]):
                    raise RuntimeError("official Hysteria2 port hopping witness failed")
    finally:
        if result_path.is_file():
            result = json.loads(result_path.read_text())
            report["cases"].extend(result["cases"])
            if result.get("failure"):
                report.setdefault("backend_failures", {})[backend] = {
                    key: result[key] for key in ("failure", "reason")
                }


def run(protocols=PROTOCOLS, *, backends=BACKENDS, list_only=False, source_dir=None):
    selected = selected_cases(protocols, backends)
    if list_only:
        for case in selected:
            expected = case.get("expected", "pass")
            print(
                case["id"]
                + ": "
                + case["backend"]
                + "; "
                + ("TCP + UDP" if expected == "pass" else expected)
                + "; origin witness"
            )
        return
    if source_dir is None:
        raise ValueError("Vole interoperability requires an explicit source checkout")
    from .mihomo_lab import (
        Guest,
        Session,
        install_tools,
        official_mihomo,
        owned_network,
        prepare_tools,
    )

    with Session(source_dir) as session:
        root = session.work
        report = {
            "status": "ERROR",
            "scope": (
                "representative TCP/UDP and native supplementary interoperability, "
                "not exhaustive field/fingerprint acceptance"
            ),
            "inputs": {"cpus": 5, "memory_bytes": 8 * 1024**3, "network": "NAT"},
            "cases": [],
            "phase": "source-identity",
            "requested_cases": [case["id"] for case in selected],
            "command": [
                "container-benchmark",
                "interop",
                "--source",
                "vole=" + str(session.source_dir),
                "--backend",
                *backends,
                "--protocol",
                *protocols,
            ],
            "source": _source_identity(session.source_dir),
            "containers": {},
            "peers": {},
        }
        try:
            _phase(report, "owned-nat-network")
            owned_network()
            (root / "artifacts").mkdir()
            (root / "results").mkdir()
            from .extended_interop import official_caddy, official_v2ray
            from .native_peer_releases import official_hysteria2, official_xray

            downloads = {
                "mihomo": official_mihomo,
                "xray": official_xray,
                "hysteria2": official_hysteria2,
                "v2ray": official_v2ray,
                "caddy": official_caddy,
            }
            needed = {case["backend"] for case in selected}
            if "caddy" in needed:
                needed.add("xray")
            if any(case.get("decoder") for case in selected):
                needed.add("mihomo")
            for name in BACKENDS:
                if name in needed:
                    _phase(report, "official-" + name + "-download")
                    report["peers"][name] = downloads[name](root)
            _phase(report, "synthetic-certificate")
            pin = _certificate(root)
            _phase(report, "official-builder-tools")
            image, report["builder"] = prepare_tools(session)
            with Guest(session, image, "builder", source=True) as guest:
                _phase(report, "builder-install")
                install_tools(guest, rust=report["builder"]["rust"])
                _phase(report, "production-vole-build")
                guest.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "cd /src/vole; "
                        "CARGO_TARGET_DIR=/work/target cargo build --locked --release "
                        "--lib --features ffi; cc -O2 -Wall -Wextra -Werror "
                        "-I /src/vole/include "
                        "/benchmark/fixtures/interop/mihomo_launcher.c "
                        "/work/target/release/libvole.a -pthread -ldl -lm -lstdc++ "
                        "-o /work/artifacts/vole",
                    ],
                    root / "vole-build.log",
                    timeout=4000,
                )
                report["vole"] = {
                    "binary_sha256": sha256(root / "artifacts/vole"),
                    "library_sha256": sha256(root / "target/release/libvole.a"),
                    "features": "normal release default protocol features plus ffi",
                    "test_only_features": False,
                }
                for name in BACKENDS:
                    if name not in needed:
                        continue
                    _phase(report, "official-" + name + "-version")
                    log = root / (name + "-version.log")
                    guest.execute(
                        [
                            "/work/artifacts/" + name,
                            "-v" if name == "mihomo" else "version",
                        ],
                        log,
                        timeout=30,
                    )
                    version = log.read_text().strip()
                    match = re.search(r"\bv?(\d+\.\d+\.\d+)(?:\s|$)", version)
                    if not match or len(version) > 4096:
                        raise RuntimeError(
                            "official peer actual stable version is invalid"
                        )
                    if name == "hysteria2" and not match[1].startswith("2."):
                        raise RuntimeError(
                            "official Hysteria download is not version 2"
                        )
                    release = report["peers"][name].get("release")
                    if release and match[1] != release.removeprefix("v"):
                        raise RuntimeError(
                            "official peer binary version differs from latest metadata"
                        )
                    report["peers"][name]["runtime_version"] = version
            report["fixtures"] = {
                name: sha256(FIXTURE_ROOT / name)
                for name in ("mihomo_echo.py", "mihomo_probe.py", "mihomo_launcher.c")
            }
            if _source_identity(session.source_dir) != report["source"]:
                raise RuntimeError("official interop source changed during build")
            for backend in BACKENDS:
                group = [case for case in selected if case["backend"] == backend]
                if group:
                    _run_backend(session, image, backend, group, pin, report)
            if _source_identity(session.source_dir) != report["source"]:
                raise RuntimeError(
                    "official interop source changed during verification"
                )
            report["status"] = "PASS"
            _phase(report, "complete")
            session.status = report["status"]
        except BaseException as error:
            report.update(
                status="ERROR", failure=type(error).__name__, reason=_safe_reason(error)
            )
            raise
        finally:
            _summary(root, report)


def _wait_tcp(host, port):
    import socket

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("isolated service TCP readiness failed")


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] in ("guest", "peer"):
        return (_guest if values[0] == "guest" else _peer)(Path(values[1]))
    parsed = parse_args(values)
    run(
        parsed.protocol,
        backends=parsed.backend,
        list_only=parsed.list,
        source_dir=parsed.source_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
