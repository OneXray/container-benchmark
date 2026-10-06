import unittest
from pathlib import Path
from types import SimpleNamespace

from container_benchmark import workload


def traffic(kind="udp"):
    endpoint = {
        "bytes": 1_250_000,
        "packets": 1000,
        "bytes_per_second": [1_250_000, 0, 0, 0],
        "sha256": "fixture",
    }
    return [
        {
            "complete": True,
            "elapsed_seconds": 1,
            "flows": [
                {
                    "transport": kind,
                    "direction": "up",
                    "source_verified": True,
                    "sent": dict(endpoint),
                    "received": dict(endpoint),
                }
            ],
        }
    ]


class WorkloadTest(unittest.TestCase):
    def result(self, rows, transport="udp"):
        return workload.summarize(
            rows, transport=transport, mbps=10, seconds=1, flows=1
        )

    def test_active_bandwidth_does_not_include_drain(self):
        rows = traffic()
        rows[0]["flows"][0]["received"].update(
            bytes=2_500_000, bytes_per_second=[1_250_000, 1_250_000, 0, 0]
        )
        result = self.result(rows)
        self.assertEqual(result["goodput_mbps"], 10)
        self.assertEqual(result["active_received_bytes"], 1_250_000)
        self.assertEqual(result["received_bytes"], 2_500_000)

    def test_udp_missing_packets_are_separate_from_integrity_and_generation(self):
        rows = traffic()
        rows[0]["complete"] = False
        rows[0]["flows"][0]["received"]["packets"] = 990
        result = self.result(rows)
        self.assertEqual(result["loss_packets"], 10)
        self.assertTrue(result["data_valid"])
        self.assertFalse(result["driver_complete"])
        self.assertNotIn("udp_driver_metrics", result)
        self.assertEqual(workload.directional_packets(rows)["up"]["loss_packets"], 10)

    def test_tcp_corruption_and_missing_histograms_are_not_valid_metrics(self):
        rows = traffic("tcp")
        rows[0]["flows"][0]["received"]["sha256"] = "corrupt"
        self.assertFalse(self.result(rows, "tcp")["data_valid"])
        rows = traffic()
        rows[0]["flows"][0]["received"]["bytes_per_second"] = None
        self.assertFalse(self.result(rows)["active_counters_available"])

    def test_fixed_shared_parameters_and_namespace_entry(self):
        args = workload.fixed_args(1500)
        self.assertEqual(
            (args.flows, args.udp_destinations, args.dns_qps), (64, 64, 1000)
        )
        command = workload._traffic_argv(
            Path("/run/benchmark"),
            args,
            "udp",
            SimpleNamespace(name="benchmark-client"),
            "example.cn",
            SimpleNamespace(ipv4="192.0.2.2"),
            "192.0.2.1",
        )
        self.assertEqual(command[:4], ["ip", "netns", "exec", "benchmark-client"])
        self.assertEqual(command[command.index("-udp-destinations") + 1], "64")
        self.assertNotIn("-kernel-tun", command)
        self.assertNotIn("-proxy", command)

    def test_dns_missing_results_remain_unavailable(self):
        result = workload.summarize_dns(None, qps=1000, seconds=60)
        self.assertFalse(result["available"])
        self.assertFalse(result["data_valid"])

    def test_dns_completion_does_not_require_retired_diagnostics(self):
        raw = dict.fromkeys(workload.DNS_COUNTERS, 0)
        raw.update(
            scheduled=10,
            sent=10,
            active_sent=10,
            succeeded=10,
            active_succeeded=10,
            offered_qps=10,
            load_seconds=1,
            elapsed_seconds=1,
        )
        result = workload.summarize_dns(
            {"dns_summary": raw, "driver_exit_code": 0}, qps=10, seconds=1
        )
        self.assertTrue(result["data_valid"])
        self.assertTrue(result["load_reached"])
        self.assertEqual(result["successful_qps"], 10)
        self.assertNotIn("latency", result)
        self.assertNotIn("max_pacing_lag_ns", result)
