"""Shared enhanced CN GeoSite/GeoIP inputs, witnesses and exact rule counts."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

from .download_cache import daily
from .inputs import protobuf_fields, save

ASSET_BASE = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"


class _Redirects(urllib.request.HTTPRedirectHandler):
    release = None

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if url.scheme != "https":
            raise ValueError("GeoData asset redirect left HTTPS")
        prefix = "/Loyalsoldier/v2ray-rules-dat/releases/download/"
        if url.hostname == "github.com" and url.path.startswith(prefix):
            tag = url.path[len(prefix) :].split("/", 1)[0]
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", tag):
                raise ValueError("invalid GeoData release identity")
            self.release = tag
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def _download(name, destination):
    redirects = _Redirects()
    opener = urllib.request.build_opener(redirects)
    request = urllib.request.Request(
        f"{ASSET_BASE}/{name}", headers={"User-Agent": "container-benchmark"}
    )
    size, digest, deadline = 0, hashlib.sha256(), time.monotonic() + 180
    with opener.open(request, timeout=30) as response, destination.open("xb") as output:
        while chunk := response.read1(65536):
            if time.monotonic() > deadline:
                raise TimeoutError("GeoData download timed out")
            size += len(chunk)
            if size > 256 * 1024**2:
                raise ValueError("GeoData download exceeded its bound")
            digest.update(chunk)
            output.write(chunk)
    if not size or not redirects.release:
        raise ValueError("GeoData release identity or contents unavailable")
    return {
        "url": request.full_url,
        "release": redirects.release,
        "bytes": size,
        "sha256": digest.hexdigest(),
    }


def acquire(root):
    """Freeze both complete upstream files, selecting CN only in each adapter."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)

    def prepare(staging):
        assets = {
            name: _download(name, staging / name)
            for name in (
                "geosite.dat",
                "geosite.dat.sha256sum",
                "geoip.dat",
                "geoip.dat.sha256sum",
            )
        }
        if len({asset["release"] for asset in assets.values()}) != 1:
            raise ValueError("latest GeoData release changed during download")
        for name in ("geosite.dat", "geoip.dat"):
            checksum = (staging / (name + ".sha256sum")).read_text().split()
            if checksum != [assets[name]["sha256"], name]:
                raise ValueError("official GeoData checksum mismatch")
            if not category_entries(staging / name):
                raise ValueError("GeoData CN category is empty")
        return {"assets": assets}

    record = daily(
        "geodata:enhanced-cn:" + ASSET_BASE, prepare, directory=root / "download-1"
    )
    record["directory"] = "download-1"
    save(root / "identity.json", record)
    return record


def category_entries(path, code="cn"):
    """Decode exactly the shared CN category; preserve all four domain types."""
    if code != "cn":
        raise ValueError("cross-core benchmarks select only CN")
    path, selected, seen = Path(path), None, set()
    for field, wire, message in protobuf_fields(memoryview(path.read_bytes())):
        if (field, wire) != (1, 2):
            continue
        codes = [
            bytes(value).lower()
            for field, wire, value in protobuf_fields(message)
            if (field, wire) == (1, 2)
        ]
        if len(codes) != 1 or codes[0] in seen:
            raise ValueError("invalid or duplicate GeoData category")
        seen.add(codes[0])
        if codes[0] == b"cn":
            selected = message
    if selected is None:
        raise ValueError("GeoData CN category unavailable")
    result = []
    for field, wire, entry in protobuf_fields(selected):
        if path.name == "geoip.dat" and (field, wire) == (3, 0) and entry:
            raise ValueError("reverse CN GeoIP category unsupported")
        if (field, wire) == (2, 2):
            result.append({field: value for field, _, value in protobuf_fields(entry)})
    return result


def networks(entries):
    return [
        ipaddress.ip_network(
            (ipaddress.ip_address(bytes(entry[1])), entry.get(2, 0)), strict=True
        )
        for entry in entries
    ]


def contains_ip(assets, address):
    address = ipaddress.ip_address(address)
    return any(
        address in network
        for network in networks(category_entries(Path(assets) / "geoip.dat"))
    )


def selection_statistics(assets, *, codes=None):
    result = {}
    for kind in ("geosite", "geoip"):
        selected_codes = codes[kind + "_codes"] if codes is not None else ["cn"]
        categories = _category_messages(Path(assets) / f"{kind}.dat")
        entries = [
            {field: value for field, _, value in protobuf_fields(record)}
            for code in selected_codes
            for record in _records(categories[code])
        ]
        kinds, unique, value_bytes = Counter(), set(), 0
        for entry in entries:
            if kind == "geosite":
                match_type, value = entry.get(1, 0), bytes(entry[2])
                if match_type not in (0, 1, 2, 3):
                    raise ValueError("unknown GeoSite match type")
                kinds[str(match_type)] += 1
                value_bytes += len(value)
                unique.add((match_type, value))
            else:
                address, prefix = bytes(entry[1]), entry.get(2, 0)
                if len(address) not in (4, 16) or not 0 <= prefix <= len(address) * 8:
                    raise ValueError("invalid GeoIP prefix")
                kinds[str(len(address) * 8)] += 1
                unique.add((address, prefix))
        result[kind] = {
            "entries": len(entries),
            "unique_entries": len(unique),
            "categories": [
                {
                    "code": code,
                    "entries": sum(1 for _ in _records(categories[code])),
                }
                for code in selected_codes
            ],
            "value_bytes": value_bytes,
            "types": dict(kinds),
        }
    return result


def _category_messages(path):
    categories = {}
    for field, wire, message in protobuf_fields(Path(path).read_bytes()):
        if (field, wire) != (1, 2):
            raise ValueError("invalid GeoData list framing")
        codes = [
            bytes(value).decode("ascii").lower()
            for number, kind, value in protobuf_fields(message)
            if (number, kind) == (1, 2)
        ]
        if len(codes) != 1 or codes[0] in categories:
            raise ValueError("invalid or duplicate GeoData category")
        categories[codes[0]] = message
    return categories


def _records(message):
    for field, wire, value in protobuf_fields(message):
        if (field, wire) == (2, 2):
            yield value


def _varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


def _field_bytes(field, value):
    result = _varint(field * 8 + 2)
    result.extend(_varint(len(value)))
    result.extend(value)
    return result


def prepare_stress_assets(upstream, destination, target):
    """Keep an exact real-record workload, with GeoIP priority, outside comparison.

    Linux deliberately has no mobile cap: make the retained fixture explicit
    instead of changing the production build or inventing duplicate records.
    Preserve record payloads from the frozen upstream DATs, trimming only the
    final selected category prefix. Cache/download originals remain untouched.
    """
    upstream, destination = Path(upstream), Path(destination)
    site = _category_messages(upstream / "geosite.dat")
    ip = _category_messages(upstream / "geoip.dat")
    counts = {code: sum(1 for _ in _records(message)) for code, message in site.items()}
    ip_total = sum(sum(1 for _ in _records(message)) for message in ip.values())
    site_budget = target - ip_total
    if site_budget <= 0 or not counts["cn"]:
        raise ValueError("real GeoData cannot fill target while retaining GeoSite CN")
    selected_sites = ["cn"]
    preceding_records = 0
    total = ip_total + counts["cn"]
    for code in sorted(counts, key=lambda code: (-counts[code], code)):
        if total >= target:
            break
        if code != "cn":
            # Select a workload that retains a CN witness under the same
            # sorted-prefix policy; do not move CN ahead of earlier codes.
            if code < "cn" and preceding_records + counts[code] >= site_budget:
                continue
            selected_sites.append(code)
            if code < "cn":
                preceding_records += counts[code]
            total += counts[code]
    if total < target or ip_total >= target:
        raise ValueError("real GeoData cannot fill target while retaining GeoSite CN")
    destination.mkdir(parents=True, exist_ok=False)
    remaining = target
    result = {
        "target_records": target,
        "original_selected_records": total,
        "synthetic_records": False,
        "codes": {},
        "retained_records": {},
        "fixture_sha256": {},
    }
    for kind, categories, selected in (
        ("geoip", ip, sorted(ip)),
        ("geosite", site, sorted(selected_sites)),
    ):
        output, retained = bytearray(), 0
        for code in selected:
            message = _field_bytes(1, code.encode("ascii"))
            for record in _records(categories[code]):
                if remaining:
                    message.extend(_field_bytes(2, record))
                    remaining -= 1
                    retained += 1
            output.extend(_field_bytes(1, message))
        path = destination / f"{kind}.dat"
        path.write_bytes(output)
        result["codes"][kind + "_codes"] = selected
        result["retained_records"][kind] = retained
        result["fixture_sha256"][kind] = hashlib.sha256(output).hexdigest()
    if remaining or not category_entries(destination / "geosite.dat"):
        raise ValueError(
            "stress fixture did not retain the requested records and CN witness"
        )
    save(destination / "selection.json", result)
    return result


def witnesses(assets):
    entries = category_entries(Path(assets) / "geosite.dat")
    records = [(entry.get(1, 0), bytes(entry[2]).decode()) for entry in entries]
    suffixes = {value.lower().rstrip(".") for kind, value in records if kind == 2}
    full = {value.lower().rstrip(".") for kind, value in records if kind == 3}
    keywords = [value.lower() for kind, value in records if kind == 0]
    patterns = [re.compile(value) for kind, value in records if kind == 1]

    def matches(name):
        labels = name.lower().rstrip(".").split(".")
        return (
            name in full
            or any(".".join(labels[index:]) in suffixes for index in range(len(labels)))
            or any(value in name for value in keywords)
            or any(pattern.search(name) for pattern in patterns)
        )

    positive = next(
        (
            value
            for kind, original in records
            if kind in (2, 3)
            and len(value := original.lower().rstrip(".")) <= 253
            and all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in value.split(".")
            )
            and matches(value)
        ),
        None,
    )
    negative = next(
        (
            name
            for number in range(128)
            for suffix in ("test", "invalid", "example")
            if not matches(name := f"benchmark-negative-{number}.{suffix}")
        ),
        None,
    )
    cidrs = category_entries(Path(assets) / "geoip.dat")
    ip_positive = next(
        (
            str(network.network_address + min(1, network.num_addresses - 1))
            for network in networks(cidrs)
            if network.version == 4
        ),
        None,
    )
    if not positive or not negative or not ip_positive:
        raise ValueError("CN routing witnesses unavailable")
    return {
        "counts": {"geosite": len(entries), "geoip": len(cidrs)},
        "domain_positive": positive,
        "domain_negative": negative,
        "ip_positive": {4: ip_positive},
    }
