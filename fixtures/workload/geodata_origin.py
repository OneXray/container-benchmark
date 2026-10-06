"""Owned HTTP assets and a SOCKS5 relay restricted to this exact HTTP origin."""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import re
import select
import shutil
import socket
import socketserver
import struct
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit


class AssetHandler(http.server.BaseHTTPRequestHandler):
    """HTTP response framing shared by the isolated asset endpoint."""

    protocol_version = "HTTP/1.1"

    def end_headers(self):
        self.send_header("Connection", "close")
        self.close_connection = True
        super().end_headers()


def asset_request(path):
    match = re.fullmatch(r"/([a-z0-9-]+)/((?:geosite|geoip)\.dat)", path)
    if match is None:
        raise ValueError("unknown GeoData fixture request")
    return match.groups()


def read_exact(stream, size):
    output = bytearray()
    while len(output) < size:
        chunk = stream.recv(size - len(output))
        if not chunk:
            raise ValueError("truncated SOCKS5 fixture request")
        output.extend(chunk)
    return bytes(output)


def socks_target(stream):
    version, count = read_exact(stream, 2)
    if version != 5 or 0 not in read_exact(stream, count):
        raise ValueError("SOCKS5 fixture requires no-auth v5")
    stream.sendall(b"\x05\x00")
    version, command, reserved, kind = read_exact(stream, 4)
    if (version, command, reserved, kind) != (5, 1, 0, 3):
        raise ValueError("SOCKS5 fixture requires domain CONNECT")
    domain = read_exact(stream, read_exact(stream, 1)[0]).decode("ascii")
    port = struct.unpack("!H", read_exact(stream, 2))[0]
    if (domain, port) != ("geodata.update.test", 24006):
        raise ValueError("SOCKS5 fixture refuses other destinations")


def main():
    if os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise SystemExit("requires an owned isolated container")
    config = json.loads(Path(sys.argv[1]).read_text())
    root, assets = Path(config["root"]), Path(config["assets"])
    metadata = {}
    for name in ("geosite.dat", "geoip.dat"):
        with (assets / name).open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        metadata[name] = {"bytes": (assets / name).stat().st_size, "sha256": digest}
    event_lock = threading.Lock()

    def event(job, kind, phase, **values):
        with event_lock, (root / "origins/geodata-events.jsonl").open("a") as output:
            output.write(
                json.dumps(
                    {
                        "job": job,
                        "kind": kind,
                        "phase": phase,
                        "time_ns": time.time_ns(),
                        **values,
                    }
                )
                + "\n"
            )
            output.flush()

    class Assets(AssetHandler):
        def do_GET(self):
            try:
                url = urlsplit(self.path)
                if url.query or url.fragment:
                    raise ValueError("GeoData fixture does not accept query/fragment")
                job, name = asset_request(url.path)
                event(job, name, "requested")
                release = root / job / "mixed/start"
                deadline = time.monotonic() + 75
                while not release.is_file():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("GeoData fixture workload start timed out")
                    time.sleep(0.05)
                # Stream only during active traffic. Normal auto-update starts
                # before readiness; the barrier leaves its old rules intact.
                time.sleep(5)
                self.send_response(200)
                self.send_header("Content-Length", str(metadata[name]["bytes"]))
                self.send_header("ETag", '"' + metadata[name]["sha256"] + '"')
                self.end_headers()
                event(job, name, "streaming", status=200, **metadata[name])
                with (assets / name).open("rb") as source:
                    shutil.copyfileobj(source, self.wfile, length=16 * 1024)
                self.wfile.flush()
                event(job, name, "served", status=200, **metadata[name])
            except (ValueError, TimeoutError, OSError) as error:
                self.log_error("GeoData fixture failed: %s", type(error).__name__)
                self.close_connection = True

        def log_message(self, *_):
            pass

    class Relay(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(90)
            try:
                socks_target(self.request)
                with socket.create_connection(("127.0.0.1", 24006), timeout=90) as peer:
                    self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                    deadline = time.monotonic() + 90
                    while time.monotonic() < deadline:
                        readable, _, _ = select.select([self.request, peer], [], [], 1)
                        for source in readable:
                            payload = source.recv(16 * 1024)
                            if not payload:
                                return
                            (peer if source is self.request else self.request).sendall(
                                payload
                            )
            except (ValueError, OSError, UnicodeError):
                return

    class SocksServer(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    with (
        http.server.ThreadingHTTPServer(("0.0.0.0", 24006), Assets) as http_server,
        SocksServer(("0.0.0.0", 24005), Relay) as socks,
    ):
        threading.Thread(target=http_server.serve_forever, daemon=True).start()
        socks.serve_forever()


if __name__ == "__main__":
    main()
