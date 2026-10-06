"""One shared native-TUN workload and metric accounting for every core."""

from __future__ import annotations

import contextlib
import json
import math
import shutil
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

ENDPOINT_ERROR_KINDS = frozenset(
    (
        "timeout",
        "eof",
        "unexpected-eof",
        "connection-reset",
        "broken-pipe",
        "short-write",
        "closed",
        "no-progress",
        "short-record",
        "payload-corruption",
        "sequence-mismatch",
        "duplicate-datagram",
        "datagram-source-or-size",
        "workload-bound",
        "drain-bound",
        "other-io",
    )
)
FLOW_PHASE_ERRORS = {
    "control connect": "flow-control-connect",
    "control request": "flow-control-request",
    "data port": "flow-data-port",
    "data connect": "flow-data-connect",
    "UDP hello": "flow-udp-hello",
    "data readiness": "flow-data-readiness",
    "missing origin route witness": "flow-origin-route-witness",
    "control deadline": "flow-control-deadline",
    "start": "flow-start",
    "remote counters": "flow-remote-counters",
    "incomplete or incorrect payload": "flow-incomplete-payload",
}


def summarize(traffic, *, transport, mbps, seconds, flows, dns=None, dns_qps=0):
    """UDP loss is a metric, not a prerequisite; corruption remains a failure."""
    rows = [row for branch in traffic for row in branch.get("flows", [])]
    duration = max(
        [float(seconds)]
        + [branch.get("elapsed_seconds", seconds) for branch in traffic]
    )
    sent = sum(row.get("sent", {}).get("bytes", 0) for row in rows)
    received = sum(row.get("received", {}).get("bytes", 0) for row in rows)

    def active_bytes(end):
        total, available = 0, True
        for row in rows:
            histogram = row.get(end, {}).get("bytes_per_second")
            valid = isinstance(histogram, list) and all(
                type(value) is int and value >= 0 for value in histogram
            )
            available &= valid
            if valid:
                total += sum(histogram[:seconds])
        return total, available

    # Keep active-window throughput separate from drain. Failed Go flows have
    # null histograms: preserve known partial totals, but never call them valid.
    active_sent, sent_available = active_bytes("sent")
    active_received, received_available = active_bytes("received")
    active_available = sent_available and received_available
    errors = Counter()
    corrupt = 0
    loss = 0
    for row in rows:
        if phase := row.get("error"):
            errors[
                FLOW_PHASE_ERRORS.get(phase, "unclassified")
                if isinstance(phase, str)
                else "unclassified"
            ] += 1
        for end in ("sent", "received"):
            if kind := row.get(end, {}).get("error_kind"):
                errors[
                    kind
                    if isinstance(kind, str) and kind in ENDPOINT_ERROR_KINDS
                    else "unclassified"
                ] += 1
        kind = row.get("transport")
        left, right = row.get("sent", {}), row.get("received", {})
        if kind == "udp":
            loss += max(0, left.get("packets", 0) - right.get("packets", 0))
        if kind == "tcp" and (
            row.get("error")
            or left.get("bytes") is None
            or left.get("bytes") != right.get("bytes")
            or left.get("sha256") != right.get("sha256")
        ):
            corrupt += 1
        if any(
            endpoint.get("error_kind")
            and not (
                kind == "udp"
                and endpoint is right
                and endpoint["error_kind"] in {"timeout", "drain-bound"}
            )
            for endpoint in (left, right)
        ):
            corrupt += 1
    goodput = active_received * 8 / seconds / 1_000_000
    sent_rate = active_sent * 8 / seconds / 1_000_000
    data_valid = (
        len(rows) == flows
        and active_available
        and all(row.get("source_verified") is True for row in rows)
        and all(
            isinstance(row.get(end, {}).get("bytes"), int)
            and isinstance(row.get(end, {}).get("packets"), int)
            and isinstance(row.get(end, {}).get("bytes_per_second"), list)
            for row in rows
            for end in ("sent", "received")
        )
        and corrupt == 0
    )
    reached = data_valid and math.isfinite(goodput) and goodput >= mbps * 0.99
    result = {
        "transport": transport,
        "status": "FAIL_DATA"
        if not data_valid
        else "PASS"
        if reached
        else "LOAD_NOT_REACHED",
        "load_reached": reached,
        "data_valid": data_valid,
        "active_counters_available": active_available,
        "driver_complete": all(branch.get("complete") is True for branch in traffic),
        "flows": len(rows),
        "actual_seconds": duration,
        "load_seconds": seconds,
        "offered_mbps": mbps,
        "sent_mbps": sent_rate,
        "goodput_mbps": goodput,
        "sent_bytes": sent,
        "received_bytes": received,
        "active_sent_bytes": active_sent,
        "active_received_bytes": active_received,
        "loss_packets": loss,
        "dropped_bytes": max(0, sent - received),
        "errors": {
            "flow_count": sum(bool(row.get("error")) for row in rows),
            "corruption_count": corrupt,
            "kinds": dict(errors),
        },
    }
    if dns_qps:
        dns_result = summarize_dns(dns, qps=dns_qps, seconds=seconds)
        result["dns"] = dns_result
        result["throughput_load_reached"] = result["load_reached"]
        result["data_valid"] &= dns_result["data_valid"]
        result["load_reached"] &= dns_result["load_reached"]
        result["driver_complete"] &= dns_result.get("succeeded") == dns_qps * seconds
        result["status"] = (
            "FAIL_DATA"
            if not result["data_valid"]
            else "PASS"
            if result["load_reached"]
            else "LOAD_NOT_REACHED"
        )
    return result


DNS_COUNTERS = (
    "scheduled",
    "sent",
    "active_sent",
    "succeeded",
    "active_succeeded",
    "tail_succeeded",
    "timed_out",
    "send_errors",
    "invalid_responses",
    "duplicates",
    "late_responses",
    "skipped",
    "inflight_peak",
)


def summarize_dns(report, *, qps, seconds):
    """DNS counters use the same active-window 99% gate as payload pressure."""
    raw = report.get("dns_summary", {}) if isinstance(report, dict) else {}
    result = {
        "available": False,
        "status": "FAIL_DATA",
        "data_valid": False,
        "load_reached": False,
        "offered_qps": qps,
        "load_seconds": seconds,
    }
    exit_code = report.get("driver_exit_code") if isinstance(report, dict) else None
    if type(exit_code) is int:
        result["driver_exit_code"] = exit_code
    if not isinstance(raw, dict):
        return result
    if not all(
        type(raw.get(key)) is int and 0 <= raw[key] <= 2**64 - 1 for key in DNS_COUNTERS
    ):
        return result
    elapsed = raw.get("elapsed_seconds")
    if (
        type(elapsed) not in (int, float)
        or not math.isfinite(elapsed)
        or not 0 <= elapsed <= seconds + 15
    ):
        return result
    valid = (
        type(exit_code) is int
        and exit_code == 0
        and raw.get("offered_qps") == qps
        and raw.get("load_seconds") == seconds
        and raw["scheduled"] == qps * seconds
        and raw["sent"] + raw["skipped"] + raw["send_errors"] == raw["scheduled"]
        and raw["succeeded"] + raw["timed_out"] == raw["sent"]
        and raw["active_sent"] <= raw["sent"]
        and raw["active_succeeded"] + raw["tail_succeeded"] == raw["succeeded"]
        and raw["active_succeeded"] <= raw["active_sent"]
        and raw["inflight_peak"] <= 4096
        and not raw["invalid_responses"]
        and not raw["duplicates"]
        and not raw["send_errors"]
    )
    sent_qps = raw["active_sent"] / seconds
    successful_qps = raw["active_succeeded"] / seconds
    reached = valid and min(sent_qps, successful_qps) >= qps * 0.99
    result.update(
        available=True,
        data_valid=valid,
        load_reached=reached,
        status="FAIL_DATA" if not valid else "PASS" if reached else "LOAD_NOT_REACHED",
        sent_qps=sent_qps,
        successful_qps=successful_qps,
        success_ratio=raw["succeeded"] / raw["sent"] if raw["sent"] else 0,
        elapsed_seconds=elapsed,
        **{key: raw[key] for key in DNS_COUNTERS},
    )
    return result


def directional_packets(traffic: list) -> dict:
    """Aggregate UDP flow delivery without individual endpoint identities."""
    counts = {
        direction: {
            "flows": 0,
            "sent_packets": 0,
            "received_packets": 0,
            "loss_packets": 0,
            "sender_error_kinds": {},
            "receiver_error_kinds": {},
        }
        for direction in ("up", "down")
    }
    for branch in traffic:
        for row in branch.get("flows", []):
            direction = row.get("direction")
            if row.get("transport") != "udp" or direction not in counts:
                continue
            values = counts[direction]
            for endpoint, field in (
                ("sent", "sender_error_kinds"),
                ("received", "receiver_error_kinds"),
            ):
                outcome = row.get(endpoint)
                if not isinstance(outcome, dict):
                    continue
                kind = outcome.get("error_kind")
                if kind in (None, "") and not outcome.get("error"):
                    continue
                classified = (
                    kind
                    if isinstance(kind, str) and kind in ENDPOINT_ERROR_KINDS
                    else "unclassified"
                )
                values[field][classified] = values[field].get(classified, 0) + 1
            sent = row.get("sent", {}).get("packets")
            received = row.get("received", {}).get("packets")
            if (
                type(sent) is not int
                or type(received) is not int
                or min(sent, received) < 0
            ):
                continue
            values["flows"] += 1
            values["sent_packets"] += sent
            values["received_packets"] += received
            values["loss_packets"] += max(0, sent - received)
    return counts


def _traffic_argv(root, args, transport, tun, witness, origin, source, *, probe=False):
    """Control TCP bypasses TUN; named data first uses controlled DNS through TUN."""
    return [
        "ip",
        "netns",
        "exec",
        tun.name,
        str(root / "artifacts/traffic-linux"),
        "-peer",
        endpoint(origin.ipv4, 24003),
        "-transport",
        "tcp" if probe else transport,
        "-direction",
        "both",
        "-seconds",
        "1" if probe else str(args.seconds),
        "-flows",
        "1" if probe else str(args.flows // 2),
        "-mbps",
        str(args.mbps),
        "-target",
        witness,
        "-expect-source",
        source,
        *(
            ["-udp-destinations", str(args.udp_destinations)]
            if not probe and transport in ("udp", "mixed")
            else []
        ),
        *(["-probe", "-probe-rounds", "1"] if probe else []),
    ]


def _dns_argv(root, args, tun):
    return [
        "ip",
        "netns",
        "exec",
        tun.name,
        str(root / "artifacts/traffic-linux"),
        "-mode",
        "dns",
        "-dns-qps",
        str(args.dns_qps),
        "-dns-server",
        "198.18.0.1:53",
        "-dns-answer",
        dns_pressure_address(args),
        "-seconds",
        str(args.seconds),
    ]


@contextlib.contextmanager
def _paired_readiness_errors(processes):
    """After owned readers join, retain only a role and known fixture error."""
    try:
        yield
    except RuntimeError as error:
        for _, _, log, record in processes:
            if "unexpected_exit" not in record:
                continue
            with log.open("rb") as stream:
                text = stream.read(256).decode(errors="replace").strip()
            code = (
                text
                if text
                in (
                    "dns-start-barrier",
                    "dns-start-barrier-timeout",
                    "dns-start-barrier-ready-io",
                    "dns-start-barrier-read-io",
                    "dns-start-barrier-invalid",
                    "start barrier timed out",
                    "start barrier ready_io",
                    "start barrier read_io",
                    "invalid start barrier",
                    "dns-connect-io",
                    "invalid-dns-workload",
                    "invalid workload",
                )
                else "unclassified"
            )
            raise RuntimeError(
                f"paired readiness: {log.stem}; exit={record['unexpected_exit']}; "
                f"reason={code}"
            ) from error
        raise


def run(
    root,
    directory,
    args,
    transport,
    tun,
    witnesses,
    origins,
    source,
    *,
    probe=False,
):
    from .processes import OwnedProcess

    directory.mkdir()
    release = directory / "start"
    processes = []
    # Start the common preparation budget before any inner readiness timer.
    deadline = time.monotonic() + 15
    with _paired_readiness_errors(processes), contextlib.ExitStack() as stack:
        for index, origin in enumerate(origins):
            label = "hit" if index == 0 else "miss"
            ready, log = (
                directory / (label + "-ready.json"),
                directory / (label + ".log"),
            )
            branch = SimpleNamespace(**vars(args))
            branch.mbps = args.mbps // 2 if index == 0 else args.mbps - args.mbps // 2
            argv = _traffic_argv(
                root,
                branch,
                transport,
                tun,
                witnesses["domain_positive" if index == 0 else "domain_negative"],
                origin,
                source,
                probe=probe,
            ) + ["-ready-file", str(ready), "-start-file", str(release)]
            record = {}
            owner = stack.enter_context(
                OwnedProcess(
                    argv,
                    log,
                    record,
                    limit=max(2 * 1024 * 1024, args.flows * (args.seconds + 3) * 16),
                )
            )
            processes.append((owner, ready, log, record))
        if args.dns_qps and not probe:
            ready, log, record = directory / "dns-ready.json", directory / "dns.log", {}
            owner = stack.enter_context(
                OwnedProcess(
                    _dns_argv(root, args, tun)
                    + ["-ready-file", str(ready), "-start-file", str(release)],
                    log,
                    record,
                    limit=64 * 1024,
                )
            )
            processes.append((owner, ready, log, record))
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("paired Linux traffic readiness timed out")
            if all(ready.is_file() for _, ready, _, _ in processes):
                break
            for owner, _, _, _ in processes:
                owner.ensure_alive()
            time.sleep(0.01)
        release.write_text("start\n")
        deadline = time.monotonic() + (1 if probe else args.seconds) + 15
        while any(owner.process.poll() is None for owner, _, _, _ in processes):
            if any(owner.overflow.is_set() for owner, _, _, _ in processes):
                raise RuntimeError("paired Linux traffic output exceeded bound")
            if time.monotonic() >= deadline:
                raise TimeoutError("paired Linux traffic did not join")
            time.sleep(0.02)
    if not all(record.get("joined") for _, _, _, record in processes):
        raise RuntimeError("paired Linux traffic cleanup incomplete")
    rows = [json.loads(log.read_text().splitlines()[0]) for _, _, log, _ in processes]
    dns = None
    if len(rows) == 3:
        dns = rows[2]
        # Use the process owner's result, not a self-reported JSON exit code.
        dns["driver_exit_code"] = processes[2][3].get("exit_code")
    return rows[:2], dns


def endpoint(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def dns_pressure_address(args=None):
    return "198.51.100.53"


def fixed_args(rate, seconds=60, transport="all", dns_qps=1000):
    return SimpleNamespace(
        transport=transport,
        mbps=rate,
        seconds=seconds,
        flows=64,
        dns_qps=dns_qps,
        udp_destinations=64,
        family=4,
        profile="direct",
    )


def probe(root, directory, args, tun, witnesses, origins, source):
    return run(
        root, directory, args, "tcp", tun, witnesses, origins, source, probe=True
    )[0]


@contextlib.contextmanager
def origins(root, args, witnesses, image):
    """Two stock Ubuntu LTS origin guests, separate from the tested kernel."""
    from .inputs import save
    from .linux_builder import LinuxGuest, install_tools
    from .paths import FIXTURE_ROOT

    record = {}
    with contextlib.ExitStack() as stack:
        guests = []
        for role in ("origin-hit", "origin-miss"):
            guest = stack.enter_context(LinuxGuest(root, image, sources={}, role=role))
            install_tools(guest, toolchain=False)
            guests.append(guest)
        positive, negative = guests
        directory = Path(root) / "origins"
        directory.mkdir()
        shutil.copy2(FIXTURE_ROOT / "workload/dns_origin.py", directory / "dns.py")
        save(
            directory / "dns.json",
            {
                "names": {
                    witnesses["domain_positive"]: positive.ipv4,
                    witnesses["domain_negative"]: negative.ipv4,
                },
                "pressure_address": dns_pressure_address(),
            },
        )
        for index, guest in enumerate(guests):
            commands = [
                "nohup /run/benchmark/artifacts/traffic-linux "
                "-mode origin >/run/benchmark/origins/"
                + str(index)
                + "-traffic.log 2>&1 </dev/null &"
            ]
            if index == 1:
                commands.insert(
                    0,
                    "cd /run/benchmark/origins; "
                    "nohup python3 -B dns.py /run/benchmark/origins/dns.json "
                    ">dns.log 2>&1 </dev/null &",
                )
            guest.execute(
                ["/bin/sh", "-ec", "\n".join(commands)],
                directory / (str(index) + "-launch.log"),
                timeout=15,
            )
            guest.peer.wait_tcp(24003)
            record["hit" if index == 0 else "miss"] = guest.record
        yield guests, negative, record
