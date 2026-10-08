"""Core-neutral input and matched-environment regression checks."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from container_benchmark import core_comparison as comparison
from container_benchmark import native_process, workload


def readiness_rows():
    return json.loads((Path(__file__).parent / "fixtures/readiness.json").read_text())


class ComparisonTests(unittest.TestCase):
    def _guest_report(self, core, after_queue_length=4096):
        events = []
        tun = MagicMock()
        tun.__enter__.return_value = tun
        tun.__exit__.return_value = False
        tun.configure_queue_lengths.side_effect = lambda length: events.append(
            ("queues", length)
        )
        tun.record = {"tx_queue_len": 4096, "eth0_tx_queue_len": after_queue_length}
        states = [
            {"tx_queue_len": 4096, "eth0_tx_queue_len": 4096},
            dict(tun.record),
        ]

        def observe():
            events.append("observe")
            return states.pop(0)

        tun.record_host_state.side_effect = observe

        def configure(*args, **kwargs):
            events.append("configure")
            return {"argv": ["core"]}

        process = Mock()
        process.record = {"status": "PASS", "peak_bytes": 12345}
        boundaries = iter(
            [
                {"user_ns": 0, "system_ns": 0},
                {"user_ns": 1_000_000, "system_ns": 0},
            ]
        )

        def boundary(stage):
            events.append(stage)
            return next(boundaries)

        process.boundary.side_effect = boundary
        process.close.side_effect = lambda: events.append("close")

        def start(*args, **kwargs):
            events.append("process")
            return process

        def run(*args, **kwargs):
            events.append("readiness" if kwargs.get("probe") else "load")
            return readiness_rows(), {}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "request.json").write_text(
                json.dumps(
                    {
                        "args": {
                            "transport": "mixed",
                            "mbps": 1000,
                            "seconds": 60,
                            "flows": 64,
                            "dns_qps": 1000,
                        },
                        "witnesses": {"ip_positive": {"4": "192.0.2.1"}},
                        "origins": [],
                        "dns": {},
                        "source": "source",
                        "assets_directory": "frozen",
                    }
                )
            )
            (root / "mixed").mkdir()
            (root / "mixed/start").touch()
            with (
                patch.object(
                    comparison.importlib.util,
                    "spec_from_file_location",
                    return_value=SimpleNamespace(loader=Mock()),
                ),
                patch.object(
                    comparison.importlib.util,
                    "module_from_spec",
                    return_value=SimpleNamespace(RealTun=Mock(return_value=tun)),
                ),
                patch.object(comparison, "_configure", side_effect=configure),
                patch.object(native_process, "NativeProcess", side_effect=start),
                patch.object(comparison.time, "sleep"),
                patch.object(workload, "run", side_effect=run),
                patch.object(workload, "summarize", return_value={}),
                patch.object(workload, "directional_packets", return_value={}),
            ):
                if after_queue_length == 4096:
                    comparison._guest_run(root, core)
                else:
                    with self.assertRaisesRegex(RuntimeError, "host-owned TUN/eth0"):
                        comparison._guest_run(root, core)
            return json.loads((root / "report.json").read_text()), events, tun

    def test_both_cores_share_verified_queue_setup_before_configuration_and_start(self):
        for core in comparison.CORES:
            with self.subTest(core=core):
                report, events, tun = self._guest_report(core)
                tun.configure_queue_lengths.assert_called_once_with(4096)
                self.assertEqual(
                    events[:4], [("queues", 4096), "configure", "observe", "process"]
                )
                self.assertEqual(events[-2:], ["close", "observe"])
                self.assertEqual(report["status"], "MEASURED")
                self.assertTrue(report["host_tun_preserved"])
                self.assertEqual(
                    report["readiness"],
                    {
                        "kind": "native-tun-traffic",
                        "attempts": 1,
                        "retries": [],
                        "status": "READY",
                    },
                )
                self.assertLess(events.index("readiness"), events.index("mixed:start"))
                self.assertLess(events.index("mixed:start"), events.index("load"))

    def test_readiness_retries_real_traffic_and_checks_the_observed_pid(self):
        process = Mock()
        probe = Mock(
            side_effect=[
                workload.ReadinessPending("preparation-timeout"),
                (readiness_rows(), None),
            ]
        )
        with patch.object(comparison.time, "sleep"):
            result = comparison._wait_ready(process, probe)
        self.assertEqual(result["attempts"], 2)
        first, second = (call.args for call in probe.call_args_list)
        self.assertEqual((first[0], second[0]), (1, 2))
        self.assertEqual(first[1], second[1])
        self.assertEqual(
            result["retries"], [{"attempt": 1, "reason": "preparation-timeout"}]
        )
        self.assertEqual(process.sample.call_count, 3)

    def test_readiness_failure_is_bounded_and_pid_failure_is_not_retried(self):
        process = Mock()
        probe = Mock(side_effect=workload.ReadinessPending("preparation-timeout"))
        record = {}
        with (
            patch.object(comparison.time, "monotonic", side_effect=[0, 0, 0, 2]),
            patch.object(comparison.time, "sleep"),
            self.assertRaisesRegex(TimeoutError, "native TUN traffic readiness"),
        ):
            comparison._wait_ready(process, probe, timeout=1, record=record)
        probe.assert_called_once_with(1, 1)
        self.assertEqual(record["status"], "ERROR")
        self.assertEqual(len(record["retries"]), 1)
        process.sample.side_effect = RuntimeError("PID changed")
        probe.reset_mock()
        with self.assertRaisesRegex(RuntimeError, "PID changed"):
            comparison._wait_ready(process, probe)
        probe.assert_not_called()

    def test_late_success_cannot_pass_the_total_deadline(self):
        process, probe = Mock(), Mock(return_value=(readiness_rows(), None))
        record = {}
        with (
            patch.object(comparison.time, "monotonic", side_effect=[0, 0, 2]),
            self.assertRaisesRegex(TimeoutError, "total deadline"),
        ):
            comparison._wait_ready(process, probe, timeout=1, record=record)
        probe.assert_called_once_with(1, 1)
        self.assertEqual(record["status"], "ERROR")

    def test_unclassified_cleanup_output_and_os_errors_fail_without_retry(self):
        for error in (
            RuntimeError("cleanup incomplete"),
            RuntimeError("output bound"),
            OSError("unexpected I/O"),
            TimeoutError("payload completion"),
        ):
            with self.subTest(error=error):
                probe, record = Mock(side_effect=error), {}
                with self.assertRaises(type(error)):
                    comparison._wait_ready(Mock(), probe, record=record)
                self.assertEqual(probe.call_count, 1)
                self.assertEqual(record["retries"], [])
                self.assertIn(str(error), record["failure"])

    def test_both_cores_fail_when_actual_queue_changes_after_start(self):
        for core in comparison.CORES:
            with self.subTest(core=core):
                report, events, _ = self._guest_report(core, after_queue_length=1024)
                self.assertEqual(events[-2:], ["close", "observe"])
                self.assertEqual(report["status"], "ERROR")
                self.assertFalse(report["host_tun_preserved"])

    def test_fixed_workload_and_generic_source_interface(self):
        args = comparison.parse_args(["--core", "mihomo"])
        self.assertEqual(args.rates, [1000, 1500, 2000])
        self.assertEqual(
            (args.seconds, args.transport, args.dns_qps), (60, "mixed", 1000)
        )
        self.assertEqual(args.sources, {})

    def test_retired_private_flags_fail_before_resources(self):
        for flag in ("--vcore", "--workers", "--backend", "--profile", "--tun-ring"):
            with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    comparison.parse_args(["--core", "mihomo", flag, "unused"])
                self.assertEqual(caught.exception.code, 2)

    def test_no_source_built_core_silently_uses_a_sibling(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            comparison.parse_args(["--core", "vcore"])

    def test_default_comparison_is_only_vcore_and_mihomo(self):
        with tempfile.TemporaryDirectory() as source:
            args = comparison.parse_args(["--source", "vcore=" + source])
            self.assertEqual(args.core, ["vcore", "mihomo"])
            self.assertEqual(list(args.sources), ["vcore"])

    def test_other_source_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as source:
            for name in ("mihomo", "other", "1core", "UPPER", "内核", "a" * 33):
                with (
                    self.subTest(name=name),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args(
                        ["--core", "mihomo", "--source", name + "=" + source]
                    )

    def test_other_core_choices_are_rejected(self):
        for core in ("other", "unknown"):
            with (
                self.subTest(core=core),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                comparison.parse_args(["--core", core])

    def test_stress_is_explicit_vcore_mixed_load_without_changing_comparison(self):
        with tempfile.TemporaryDirectory() as source:
            args = comparison.parse_args(["--source", "vcore=" + source], stress=True)
            self.assertEqual(args.core, ["vcore"])
            self.assertEqual(args.rates, [2000])
            self.assertEqual(
                (args.seconds, args.dns_qps, args.transport), (60, 1000, "mixed")
            )

    def test_geodata_scope_is_fixed_cn_for_comparison_and_pressure(self):
        with tempfile.TemporaryDirectory() as source:
            for stress in (False, True):
                with self.subTest(stress=stress):
                    args = comparison.parse_args(
                        ["--source", "vcore=" + source],
                        stress=stress,
                    )
                    self.assertEqual(
                        args.geodata_codes,
                        {
                            "geosite_codes": ["cn"],
                            "geoip_codes": ["cn"],
                        },
                    )

    def test_geodata_record_derivation_is_no_longer_exposed(self):
        with (
            tempfile.TemporaryDirectory() as source,
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            comparison.parse_args(
                ["--source", "vcore=" + source, "--geodata-records", "1280000"],
                stress=True,
            )

    def test_stress_memory_gate_uses_final_process_peak_and_valid_observation(self):
        for status, peak, expected in (
            ("PASS", 51_000_000, False),
            ("PASS", 49_000_000, True),
            ("PASS", 0, False),
            ("ERROR", 40_000_000, False),
        ):
            with self.subTest(status=status, peak=peak):
                report = {
                    "measurement": {"status": status, "peak_bytes": peak},
                    "cases": [{"peak_bytes": 30_000_000}],
                }
                comparison._annotate_stress_memory(report)
                self.assertEqual(report["cases"][0]["peak_bytes"], peak)
                self.assertEqual(report["cases"][0]["memory_target_met"], expected)

    def test_geodata_update_is_rejected_before_resources_without_live_observation(self):
        with tempfile.TemporaryDirectory() as source:
            diagnostics = io.StringIO()
            with contextlib.redirect_stderr(diagnostics), self.assertRaises(SystemExit):
                comparison.parse_args(
                    ["--source", "vcore=" + source, "--geodata-update"], stress=True
                )
            self.assertIn("unavailable", diagnostics.getvalue())
            self.assertIn("live state observer", diagnostics.getvalue())
            for values, stress in (
                (["--core", "mihomo", "--geodata-update"], False),
                (
                    [
                        "--source",
                        "vcore=" + source,
                        "--geodata-update",
                        "--seconds",
                        "3",
                    ],
                    True,
                ),
            ):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args(values, stress=stress)


if __name__ == "__main__":
    unittest.main()
