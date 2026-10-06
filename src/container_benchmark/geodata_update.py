"""Read-only evidence for real GeoData updates during the opt-in TUN workload."""

from __future__ import annotations

import json
from pathlib import Path

from .inputs import sha256


def _complete_rows(path):
    if not path.is_file():
        return []
    # A concurrently flushed observation may end in a partial row. Exclude
    # only that unterminated suffix, never ignore malformed completed data.
    return [
        json.loads(line)
        for line in path.read_text().splitlines(keepends=True)
        if line.endswith("\n")
    ]


def summarize(root, assets, *, load_end_ns):
    root, assets = Path(root), Path(assets)
    start = root / "mixed/start"
    load_start_ns = start.stat().st_mtime_ns
    event_path = root.parent / "origins/geodata-events.jsonl"
    events = [row for row in _complete_rows(event_path) if row.get("job") == root.name]
    state_path = root / "geodata-state.jsonl"
    states = _complete_rows(state_path)
    successful = [
        row for row in states if row.get("response", {}).get("success") is True
    ]
    last = successful[-1]["response"]["data"] if successful else {}
    result = {
        "status": "INCOMPLETE",
        "scope": "real HTTP download + commit/reload during mixed TUN pressure",
        "https_trust_chain_verified": False,
        "load_start_ns": load_start_ns,
        "load_end_ns": load_end_ns,
        "public_state_samples": len(successful),
        "resources": {},
    }
    for kind in ("geosite", "geoip"):
        asset = assets / (kind + ".dat")
        expected = sha256(asset)
        served = [
            row
            for row in events
            if row.get("kind") == asset.name and row.get("phase") == "served"
        ]
        rows = [row["response"]["data"].get(kind, {}) for row in successful]
        final = last.get(kind, {})
        transferred = len(served) == 1 and all(
            row.get("status") == 200
            and row.get("bytes") == asset.stat().st_size
            and row.get("sha256") == expected
            and load_start_ns < row.get("time_ns", 0) < load_end_ns
            for row in served
        )

        def is_restored(row, expected=expected):
            return (
                row.get("required") is True
                and row.get("available") is True
                and row.get("updating") is False
                and row.get("hash") == expected
                and isinstance(row.get("lastSuccess"), int)
                and row.get("lastError") is None
            )

        restored = is_restored(final)
        completion = next(
            (
                row["time_ns"]
                for row in successful
                if load_start_ns < row.get("time_ns", 0) < load_end_ns
                and is_restored(row["response"]["data"].get(kind, {}))
            ),
            None,
        )
        result["resources"][kind] = {
            "downloaded_during_load": transferred,
            "available_after_update": restored,
            "restored_during_load": completion is not None,
            "first_restored_time_ns": completion,
            "updating_observed": any(row.get("updating") is True for row in rows),
            "unavailable_observed": any(row.get("available") is False for row in rows),
            "http_events": served,
            "final_state": final,
        }
    if all(
        row["downloaded_during_load"]
        and row["available_after_update"]
        and row["restored_during_load"]
        for row in result["resources"].values()
    ):
        result["status"] = "PASS"
    return result
