"""Bound output and keep post-exec core RSS separate from launcher rusage."""

import contextlib
import io
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.native_process import NativeProcess


class NativeProcessTests(unittest.TestCase):
    @contextlib.contextmanager
    def observed_process(self, *, hwm_kib, rss_kib, wait4_kib):
        """Exercise the public process lifecycle with deterministic OS counters."""
        pid = 43210
        image = Path(sys.executable).stat()
        counters = {"hwm": hwm_kib, "rss": rss_kib}
        original_read, original_stat = Path.read_text, Path.stat
        thread_type = threading.Thread

        def read_text(path, *args, **kwargs):
            if str(path) == f"/proc/{pid}/stat":
                fields = ["0"] * 22
                fields[0], fields[11], fields[12], fields[19] = "S", "5", "3", "10"
                return f"{pid} (selected core) " + " ".join(fields)
            if str(path) == f"/proc/{pid}/status":
                return f"VmRSS:\t{counters['rss']} kB\nVmHWM:\t{counters['hwm']} kB\n"
            return original_read(path, *args, **kwargs)

        def stat(path, *args, **kwargs):
            if str(path) == f"/proc/{pid}/exe":
                return image
            return original_stat(path, *args, **kwargs)

        def manual_thread(**kwargs):
            thread = Mock(spec=thread_type)
            thread.ident = None
            thread.is_alive.return_value = False
            return thread

        child = SimpleNamespace(pid=pid, returncode=None, stdout=io.BytesIO())
        usage = SimpleNamespace(ru_maxrss=wait4_kib, ru_utime=0.1, ru_stime=0.2)
        with (
            tempfile.TemporaryDirectory() as work,
            patch("container_benchmark.native_process.sys.platform", "linux"),
            patch.dict(os.environ, {"BENCHMARK_ISOLATED": "1"}),
            patch.object(Path, "read_text", read_text),
            patch.object(Path, "stat", stat),
            patch("container_benchmark.native_process.os.sysconf", return_value=100),
            patch(
                "container_benchmark.native_process.subprocess.Popen",
                return_value=child,
            ),
            patch("container_benchmark.native_process.threading.Thread", manual_thread),
            patch(
                "container_benchmark.native_process.os.wait4",
                return_value=(pid, 0, usage),
            ),
        ):
            process = NativeProcess([sys.executable], work)
            try:
                yield process, counters
            finally:
                process.close()

    def test_earlier_post_exec_hwm_survives_a_smaller_last_observation(self):
        with self.observed_process(hwm_kib=65536, rss_kib=32768, wait4_kib=16384) as (
            process,
            counters,
        ):
            counters.update(hwm=32768, rss=16384)
            process.sample()
            result = process.close()
            self.assertEqual(result["last_sample"]["peak"], 33554432)
            self.assertEqual(result["proc_vm_hwm_peak_bytes"], 67108864)
            self.assertEqual(result["peak_bytes"], 67108864)

    def test_launcher_inclusive_wait4_does_not_replace_core_observed_peak(self):
        with self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=262144) as (
            process,
            _,
        ):
            result = process.close()
            self.assertEqual(result["wait4_max_rss_bytes"], 268435456)
            self.assertEqual(result["peak_bytes"], 33554432)
            self.assertEqual(result["peak_sources"], ["proc_vm_hwm", "proc_vm_rss"])
            self.assertEqual(
                result["observation_window"], "post_exec_through_workload_drain"
            )
            self.assertFalse(result["shutdown_observed"])

    def test_log_bound_keeps_draining_without_stopping_the_core(self):
        process = NativeProcess.__new__(NativeProcess)
        process.lock = threading.RLock()
        output = b"error output\n" * 200_000
        process.child = SimpleNamespace(stdout=io.BytesIO(output))
        process.log = io.BytesIO()
        process.record = {"sampling_errors": [], "log_bytes": 0}
        process._signal = Mock()
        process._drain_log()
        process._signal.assert_not_called()
        self.assertEqual(process.log.getvalue(), output[: 1024 * 1024])
        self.assertEqual(process.record["log_bytes"], len(output))
        self.assertTrue(process.record["log_truncated"])
        self.assertEqual(process.record["sampling_errors"], [])


if __name__ == "__main__":
    unittest.main()
