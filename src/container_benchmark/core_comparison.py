"""One matched workload and Linux observer for Vole and Mihomo."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

CORES = ("vole", "mihomo")
QUEUE_LENGTH = 4096


def parse_args(argv=None, *, stress=False):
    parser = argparse.ArgumentParser(
        prog="container-benchmark " + ("stress" if stress else "compare"),
        description=__doc__,
    )
    parser.add_argument(
        "--core",
        nargs="+",
        choices=("vole",) if stress else CORES,
        default=["vole"] if stress else list(CORES),
    )
    parser.add_argument("--source", action="append", default=[], metavar="vole=PATH")
    parser.add_argument(
        "--rates",
        nargs="+",
        type=int,
        choices=(1000, 1500, 2000),
        default=[2000] if stress else [1000, 1500, 2000],
    )
    parser.add_argument("--seconds", type=int, default=60)
    parser.set_defaults(geodata_codes={"geosite_codes": ["cn"], "geoip_codes": ["cn"]})
    if stress:
        parser.add_argument(
            "--geodata-update",
            action="store_true",
            help="unavailable: CLI pressure has no live GeoData state observer",
        )
    args = parser.parse_args(argv)
    args.transport, args.dns_qps = "mixed", 1000
    if not 1 <= args.seconds <= 1800:
        parser.error("duration must be 1..1800 seconds")
    if stress and args.geodata_update:
        parser.error(
            "--geodata-update is unavailable without a CLI live state observer"
        )
    args.stress = stress
    args.core, args.rates = (
        list(dict.fromkeys(args.core)),
        list(dict.fromkeys(args.rates)),
    )
    args.sources = {}
    for value in args.source:
        name, separator, path = value.partition("=")
        if not separator or name != "vole" or not path or name in args.sources:
            parser.error("--source requires a unique vole=PATH")
        source = Path(path).resolve(strict=True)
        if not source.is_dir():
            parser.error("--source must point to a source directory")
        args.sources[name] = source
    if "vole" in args.core and "vole" not in args.sources:
        parser.error("Vole requires --source vole=PATH")
    return args


def _summary(root, report):
    (root / "summary.md").write_text(
        "# Native TUN comparison\n\n```json\n"
        + json.dumps(report, indent=2)
        + "\n```\n"
    )


def _annotate_stress_memory(result):
    # Use the final process observation, not a copy taken before the drain/close
    # sampling completes. Missing/failed observations cannot pass the target.
    measurement = result.get("measurement", {})
    peak = measurement.get("peak_bytes")
    for case in result.get("cases", []):
        case["peak_bytes"] = peak
        case["memory_target_met"] = (
            measurement.get("status") == "PASS"
            and isinstance(peak, int)
            and 0 < peak < 50_000_000
        )


def _configure(core, root, assets, samples, origins, dns, tun, *, geodata_update=False):
    from . import core_mihomo_adapter, core_vole_adapter

    if core == "vole":
        return core_vole_adapter.configure(
            root, assets, samples, origins, dns, tun, geodata_update=geodata_update
        )
    if core != "mihomo":
        raise ValueError("unsupported comparison core")
    result = core_mihomo_adapter.configure(root, assets, samples, origins, dns, tun)
    result["argv"] = core_mihomo_adapter.command(
        root / "artifacts/mihomo", result["config"]
    )
    return result


def _wait_ready(process, probe, *, timeout=60, record=None):
    """Run bounded native-TUN business probes against the observed executable."""
    from .workload import ReadinessPending, check_readiness

    deadline = time.monotonic() + timeout
    record = {} if record is None else record
    record.update(kind="native-tun-traffic", attempts=0, retries=[], status="WAITING")
    try:
        while time.monotonic() < deadline:
            # PID/observer failures are never startup retries.
            process.sample()
            record["attempts"] += 1
            try:
                rows, _ = probe(record["attempts"], deadline)
                check_readiness(rows)
            except ReadinessPending as error:
                record["retries"].append(
                    {"attempt": record["attempts"], "reason": str(error)}
                )
                time.sleep(min(0.2, max(0, deadline - time.monotonic())))
                continue
            process.sample()
            if time.monotonic() >= deadline:
                break
            record["status"] = "READY"
            return record
        raise TimeoutError("native TUN traffic readiness total deadline exceeded")
    except Exception as error:
        record.update(status="ERROR", failure=f"{type(error).__name__}: {error}")
        raise


def _check_sources(sources, expected):
    from .inputs import source_identity

    for name, path in sources.items():
        if source_identity(path) != expected[name]:
            raise RuntimeError(f"selected source changed during the session: {name}")


def _guest_run(root, core):
    from . import workload
    from .inputs import save
    from .native_process import NativeProcess
    from .paths import FIXTURE_ROOT

    request = json.loads((root / "request.json").read_text())
    args = SimpleNamespace(**request["args"])
    samples = request["witnesses"]
    samples["ip_positive"] = {
        int(key): value for key, value in samples["ip_positive"].items()
    }
    origins = [SimpleNamespace(**row) for row in request["origins"]]
    dns = SimpleNamespace(**request["dns"])
    report = {"core": core, "status": "ERROR", "cases": []}
    spec = importlib.util.spec_from_file_location(
        "real_tun", FIXTURE_ROOT / "workload/tun.py"
    )
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    try:
        with fixture.RealTun() as tun:
            tun.configure_queue_lengths(QUEUE_LENGTH)
            configured = _configure(
                core,
                root,
                root / "rules" / request["assets_directory"],
                samples,
                origins,
                dns,
                tun,
                geodata_update=getattr(args, "geodata_update", False),
            )
            report["differences"] = configured.get("differences", [])
            before_host = tun.record_host_state()
            process = NativeProcess(
                configured["argv"],
                root / "process",
                pass_fds=configured.get("pass_fds", ()),
                env=os.environ | configured.get("env", {}),
            )
            report["measurement"] = process.record
            try:
                report["readiness"] = {}
                _wait_ready(
                    process,
                    lambda attempt, deadline: workload.run(
                        root,
                        root / f"readiness-{attempt}",
                        args,
                        "tcp",
                        tun,
                        samples,
                        origins,
                        request["source"],
                        probe=True,
                        deadline=deadline,
                    ),
                    record=report["readiness"],
                )
                tun.reject(samples["ip_positive"][4])
                report["route_checks"] = {
                    "passed": True,
                    "geoip_reject": True,
                    "domain_matching": "see adapter differences",
                }
                for scene in (args.transport,):
                    before, clock = process.boundary(scene + ":start"), time.monotonic()
                    traffic, dns_result = workload.run(
                        root,
                        root / scene,
                        args,
                        scene,
                        tun,
                        samples,
                        origins,
                        request["source"],
                    )
                    after = process.boundary(scene + ":end")
                    elapsed = time.monotonic() - clock
                    case = workload.summarize(
                        traffic,
                        transport=scene,
                        mbps=args.mbps,
                        seconds=args.seconds,
                        flows=args.flows,
                        dns=dns_result,
                        dns_qps=args.dns_qps,
                    )
                    cpu = (
                        after["user_ns"]
                        + after["system_ns"]
                        - before["user_ns"]
                        - before["system_ns"]
                    ) / 1e9
                    case.update(
                        cpu_seconds=cpu,
                        cpu_window_seconds=elapsed,
                        cpu_percent=100 * cpu / elapsed,
                        peak_bytes=process.record["peak_bytes"],
                    )
                    if scene in ("udp", "mixed"):
                        case["direction_packets"] = workload.directional_packets(
                            traffic
                        )
                    report["cases"].append(case)
                    save(root / "report.json", report)
                    time.sleep(1)
            finally:
                process.close()
                for case in report["cases"]:
                    case["peak_bytes"] = process.record["peak_bytes"]
                after_host = tun.record_host_state()
                report["host_tun_preserved"] = after_host == before_host
                if not report["host_tun_preserved"]:
                    raise RuntimeError(
                        "core changed its host-owned TUN/eth0 profile or TUN fd flags"
                    )
                report["tun"] = tun.record
            report["status"] = (
                "MEASURED" if process.record["status"] == "PASS" else "ERROR"
            )
    except Exception as error:
        report.update(failure=type(error).__name__, failure_message=str(error))
        log = root / "process/core.log"
        if log.is_file():
            report["failure_details"] = log.read_text(errors="replace").splitlines()[
                -12:
            ]
        raise
    finally:
        save(root / "report.json", report)


def main(argv=None, *, stress=False):
    parsed = parse_args(argv, stress=stress)
    from . import core_mihomo_adapter, core_vole_adapter, workload
    from .geodata import (
        acquire,
        contains_ip,
        selection_statistics,
        witnesses,
    )
    from .inputs import save, sha256, source_identity
    from .linux_builder import LinuxGuest, build_traffic, builder_inputs, install_tools
    from .session import Session

    with Session(
        ["stress" if stress else "compare", *(argv or [])], sources=parsed.sources
    ) as session:
        root = session.work / "comparison"
        root.mkdir()
        report = {
            "inputs": {
                "rates_mbps": parsed.rates,
                "seconds": parsed.seconds,
                "transport": parsed.transport,
                "flows": 64,
                "udp_destinations": 64,
                "dns_qps": parsed.dns_qps,
                "cpus": 5,
                "memory_bytes": 8 * 1024**3,
                "network": "NAT",
                "queue_overrides": {
                    "tun0_txqueuelen": QUEUE_LENGTH,
                    "eth0_txqueuelen": QUEUE_LENGTH,
                },
                "geodata_update": getattr(parsed, "geodata_update", False),
            },
            "identities": {},
            "runs": {},
        }
        try:
            if any(
                key.startswith(("Malloc", "DYLD_", "CARGO_PROFILE_"))
                or key
                in (
                    "RUSTFLAGS",
                    "CARGO_ENCODED_RUSTFLAGS",
                    "RUSTC_WRAPPER",
                    "LD_PRELOAD",
                    "LD_AUDIT",
                )
                for key in os.environ
            ):
                raise ValueError("unset inherited measurement/build overrides")
            acquired = acquire(root / "rules")
            assets = root / "rules" / acquired["directory"]
            stress_selection = None
            if stress:
                stress_selection = {
                    "mode": "fixed-cn",
                    "codes": parsed.geodata_codes,
                    "source_assets_unmodified": True,
                }
            samples = witnesses(assets)
            if stress:
                report["inputs"]["memory_target_bytes"] = 50_000_000
            report["geodata"] = selection_statistics(
                assets, codes=parsed.geodata_codes
            ) | {"assets": acquired, "stress_selection": stress_selection}
            report["inputs"]["go"] = build_traffic(root)
            report["inputs"]["traffic_sha256"] = sha256(
                root / "artifacts/traffic-linux"
            )
            if "mihomo" in parsed.core:
                prepared = core_mihomo_adapter.prepare(root / "artifacts")
                report["identities"]["mihomo"] = prepared["identity"]
            image, builder = builder_inputs(root)
            report["inputs"]["builder"] = builder
            mounts = (
                core_vole_adapter.source_mounts(parsed.sources["vole"])
                if "vole" in parsed.core
                else []
            )
            report["path_dependencies"] = {
                target: source_identity(Path(host)) for host, target in mounts
            }
            path_sources = {target: Path(host) for host, target in mounts}

            def check_sources():
                _check_sources(parsed.sources, session.identities)
                _check_sources(path_sources, report["path_dependencies"])

            check_sources()
            with LinuxGuest(
                root,
                image,
                sources=parsed.sources,
                extra_mounts=mounts,
                network="default",
                role="builder",
            ) as guest:
                install_tools(guest, toolchain="vole" in parsed.core)
                for core in parsed.core:
                    if core == "vole":
                        report["identities"][core] = core_vole_adapter.build(
                            guest,
                            root,
                            geodata_update=getattr(parsed, "geodata_update", False),
                        )
                        if stress:
                            from .geodata_probe import run as probe_geodata

                            report["geodata_probe"] = probe_geodata(
                                guest, root, assets=assets
                            )
                    else:
                        guest.execute(
                            core_mihomo_adapter.version_command(
                                "/run/benchmark/artifacts/mihomo"
                            ),
                            root / (core + "-version.log"),
                            timeout=30,
                        )
                        report["identities"][core]["runtime_version"] = (
                            (root / (core + "-version.log")).read_text().strip()
                        )
            check_sources()
            _summary(root, report)
            args = workload.fixed_args(
                parsed.rates[0], parsed.seconds, parsed.transport, parsed.dns_qps
            )
            args.geodata_update = getattr(parsed, "geodata_update", False)
            with workload.origins(root, args, samples, image) as (origins, dns, peers):
                report["origins"] = peers
                if any(contains_ip(assets, row.ipv4) for row in origins):
                    raise RuntimeError(
                        "DIRECT origins must be outside selected CN GeoIP"
                    )
                for rate in parsed.rates:
                    for core in parsed.core:
                        check_sources()
                        args = workload.fixed_args(
                            rate, parsed.seconds, parsed.transport, parsed.dns_qps
                        )
                        args.geodata_update = getattr(parsed, "geodata_update", False)
                        job = root / f"{core}-{rate}"
                        job.mkdir()
                        for name in ("artifacts", "rules"):
                            (job / name).symlink_to(
                                "../" + name, target_is_directory=True
                            )
                        with LinuxGuest(root, image, role="core") as guest:
                            install_tools(guest, toolchain=False)
                            save(
                                job / "request.json",
                                {
                                    "args": vars(args),
                                    "witnesses": samples,
                                    "origins": [{"ipv4": row.ipv4} for row in origins],
                                    "dns": {"ipv4": dns.ipv4},
                                    "source": guest.ipv4,
                                    "assets_directory": assets.relative_to(
                                        root / "rules"
                                    ).as_posix(),
                                },
                            )
                            save(job / "report.json", {"status": "ERROR", "cases": []})
                            print(
                                f"Running {core}: {rate} Mbps / "
                                f"{args.seconds}s / {args.transport}",
                                flush=True,
                            )
                            try:
                                guest.python(
                                    "--guest-run",
                                    "/run/benchmark/" + job.name,
                                    job / "run.log",
                                    core,
                                    timeout=parsed.seconds * 3 + 180,
                                )
                            except Exception as error:
                                print(f"{core} {rate}: {error}", flush=True)
                            result = json.loads((job / "report.json").read_text())
                            if stress:
                                _annotate_stress_memory(result)
                            result["environment"] = guest.record
                            report["runs"][job.name] = result
                            _summary(root, report)
            check_sources()
            report["source_unchanged"] = True
            complete = len(report["runs"]) == len(parsed.core) * len(
                parsed.rates
            ) and all(
                len(row.get("cases", [])) == 1 and row.get("status") == "MEASURED"
                for row in report["runs"].values()
            )
            session.status = "COMPLETED" if complete else "INCOMPLETE"
            session.reason = (
                "Measurements recorded independently; unavailable data is not zero."
            )
            return 0 if complete else 1
        finally:
            _summary(root, report)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--guest-run":
        _guest_run(Path(sys.argv[2]), sys.argv[3])
    else:
        raise SystemExit(main())
