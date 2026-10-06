"""Frozen download/state evidence; no host servers, containers, or core mocks."""

import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from container_benchmark.geodata_update import summarize
from container_benchmark.inputs import sha256
from container_benchmark.paths import FIXTURE_ROOT

SPEC = importlib.util.spec_from_file_location(
    "geodata_fixture", FIXTURE_ROOT / "workload/geodata_origin.py"
)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class UpdateEvidenceTest(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.root, self.assets = root / "vcore-2000", root / "rules"
        (self.root / "mixed").mkdir(parents=True)
        (root / "origins").mkdir()
        self.assets.mkdir()
        self.start = self.root / "mixed/start"
        self.start.write_text("start\n")
        os.utime(self.start, ns=(1_000_000_000, 1_000_000_000))
        self.states, self.events = {}, []
        for kind in ("geosite", "geoip"):
            asset = self.assets / (kind + ".dat")
            asset.write_bytes(kind.encode())
            self.states[kind] = {
                "required": True,
                "available": True,
                "updating": False,
                "hash": sha256(asset),
                "lastSuccess": 2,
                "lastError": None,
            }
            self.events.append(
                {
                    "job": "vcore-2000",
                    "kind": asset.name,
                    "phase": "served",
                    "status": 200,
                    "time_ns": 2_000_000_000,
                    "bytes": asset.stat().st_size,
                    "sha256": sha256(asset),
                }
            )

    def report(self):
        (self.root.parent / "origins/geodata-events.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in self.events)
        )
        (self.root / "geodata-state.jsonl").write_text(
            json.dumps(
                {
                    "time_ns": 3_000_000_000,
                    "response": {"success": True, "data": self.states},
                }
            )
            + "\n"
        )
        return summarize(self.root, self.assets, load_end_ns=5_000_000_000)

    def test_complete_downloads_and_restored_state_are_independent_from_memory(self):
        result = self.report()
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["resources"]["geosite"]["available_after_update"])
        self.assertFalse(result["resources"]["geoip"]["updating_observed"])
        self.assertNotIn("memory_target_met", result)

    def test_wrong_hash_outside_window_and_unavailable_state_cannot_pass(self):
        self.events[0]["time_ns"] = 6_000_000_000
        self.states["geoip"]["hash"] = "0" * 64
        result = self.report()
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertFalse(result["resources"]["geosite"]["downloaded_during_load"])
        self.assertFalse(result["resources"]["geoip"]["available_after_update"])

    def test_download_during_load_but_completion_in_drain_is_not_load_acceptance(self):
        self.events[0]["time_ns"] = 1_500_000_000
        self.events[1]["time_ns"] = 1_500_000_000
        result = self.report()
        self.assertEqual(result["status"], "PASS")
        result = summarize(self.root, self.assets, load_end_ns=2_000_000_000)
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_fixture_only_exposes_controlled_dat_paths(self):
        self.assertEqual(
            fixture.asset_request("/vcore-2000/geosite.dat"),
            ("vcore-2000", "geosite.dat"),
        )
        for path in ("/../geosite.dat", "/job/state.json", "/a/b/geoip.dat"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                fixture.asset_request(path)

    def test_asset_response_is_http11_and_closes_after_its_framed_body(self):
        class MemoryConnection:
            def __init__(self):
                self.output = io.BytesIO()

            def makefile(self, *_):
                return io.BytesIO(
                    b"GET / HTTP/1.1\r\nHost: geodata.update.test\r\n\r\n"
                )

            def sendall(self, payload):
                self.output.write(payload)

        class Response(fixture.AssetHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "3")
                self.end_headers()
                self.wfile.write(b"DAT")

            def log_message(self, *_):
                pass

        connection = MemoryConnection()
        Response(connection, ("192.0.2.1", 1234), SimpleNamespace())
        wire = connection.output.getvalue()
        self.assertTrue(wire.startswith(b"HTTP/1.1 200 OK\r\n"), wire)
        self.assertIn(b"Connection: close\r\n", wire)
        self.assertTrue(wire.endswith(b"\r\n\r\nDAT"), wire)

    def test_socks_relay_refuses_nonfixture_destinations(self):
        class Request:
            def __init__(self, domain, port):
                encoded = domain.encode()
                self.input = bytearray(b"\x05\x01\x00\x05\x01\x00\x03")
                self.input += bytes([len(encoded)]) + encoded + port.to_bytes(2)

            def recv(self, size):
                payload = bytes(self.input[:size])
                del self.input[:size]
                return payload

            def sendall(self, _):
                pass

        fixture.socks_target(Request("geodata.update.test", 24006))
        with self.assertRaises(ValueError):
            fixture.socks_target(Request("public.example", 443))
