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


if __name__ == "__main__":
    unittest.main()
