"""Core-neutral input and default-environment regression checks."""

import contextlib
import io
import tempfile
import unittest

from container_benchmark import core_comparison as comparison


class ComparisonTests(unittest.TestCase):
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

    def test_geodata_update_is_explicit_stress_only_and_needs_overlap_window(self):
        with tempfile.TemporaryDirectory() as source:
            args = comparison.parse_args(
                ["--source", "vcore=" + source, "--geodata-update"], stress=True
            )
            self.assertTrue(args.geodata_update)
            self.assertEqual((args.rates, args.seconds), ([2000], 60))
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
