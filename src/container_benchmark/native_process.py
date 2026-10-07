"""One post-exec CLI PID observation, with separate Linux wait4 diagnostics."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


def sample_pid(pid: int) -> dict:
    """Read kernel PID identity, RSS/HWM and accumulated process CPU."""
    root = Path("/proc") / str(pid)
    stat = (root / "stat").read_text()
    _, separator, tail = stat.rpartition(") ")
    fields = tail.split()
    if not separator or len(fields) < 22:
        raise ValueError("incomplete Linux process stat")
    memory = {}
    for line in (root / "status").read_text().splitlines():
        name, _, value = line.partition(":")
        if name in ("VmRSS", "VmHWM"):
            amount, unit = value.split()
            if unit != "kB":
                raise ValueError("unexpected Linux RSS unit")
            memory[name] = int(amount) * 1024
    if set(memory) != {"VmRSS", "VmHWM"}:
        raise OSError("Linux process memory counters unavailable")
    ticks = os.sysconf("SC_CLK_TCK")
    image = (root / "exe").stat()
    return {
        "pid": pid,
        "start": int(fields[19]),
        "rss": memory["VmRSS"],
        "peak": memory["VmHWM"],
        "user_ns": int(fields[11]) * 1_000_000_000 // ticks,
        "system_ns": int(fields[12]) * 1_000_000_000 // ticks,
        "executable_device_inode": f"{image.st_dev}:{image.st_ino}",
    }


class NativeProcess:
    """Launch a core normally and keep a single owner of its resource reap.

    Callers own TUN/configuration and use sample()/boundary() for scene deltas.
    Never call child.poll()/wait(), which would discard wait4's resource usage.
    Procfs observations cover post-exec startup, workload and graceful shutdown.
    The close owner samples during reap after joining the background sampler.
    RSS is a metric, not an acceptance gate; brief exit races remain unobservable.
    """

    def __init__(self, argv, work, *, pass_fds=(), env=None):
        if sys.platform != "linux" or os.environ.get("BENCHMARK_ISOLATED") != "1":
            raise RuntimeError("core measurement requires the owned Linux guest")
        self.work = Path(work)
        self.work.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.finished = threading.Event()
        self.closed = False
        self.stage = "spawn"
        self.identity = None
        self.record = {
            "status": "OBSERVING",
            "measurement_kind": "linux_rss",
            "metric": "rss",
            "unit": "bytes",
            "cpu_unit": "nanoseconds",
            "sampling_interval_seconds": 0.02,
            "sampling_errors": [],
            "samples": 0,
            "peak_bytes": 0,
            "peak_sources": ["proc_vm_hwm", "proc_vm_rss"],
            "proc_vm_hwm_peak_bytes": 0,
            "observation_window": "post_exec_through_shutdown_reap",
            "shutdown_observed": False,
            "cleanup": False,
            "forced_signals": [],
            "log_bytes": 0,
            "log_truncated": False,
        }
        executable = Path(argv[0]).stat()
        self.expected_image = f"{executable.st_dev}:{executable.st_ino}"
        self.log = (self.work / "core.log").open("wb")
        self.timeline = (self.work / "timeline.jsonl").open("w")
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.log_thread = threading.Thread(target=self._drain_log, daemon=True)
        try:
            self.child = subprocess.Popen(
                [str(item) for item in argv],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                pass_fds=pass_fds,
                env=os.environ.copy() if env is None else env,
            )
        except BaseException:
            self.log.close()
            self.timeline.close()
            raise
        self.record["pid"] = self.child.pid
        try:
            self.log_thread.start()
            deadline = time.monotonic() + 1
            while True:
                try:
                    self.sample()
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.01)
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def sample(self):
        with self.lock:
            row = sample_pid(self.child.pid)
            identity = (row["start"], row["executable_device_inode"])
            if identity[1] != self.expected_image:
                raise RuntimeError("measured PID is not the selected executable")
            if self.identity is None:
                self.identity = identity
                self.record["identity"] = {
                    "start": identity[0],
                    "executable_device_inode": identity[1],
                }
            if identity != self.identity:
                raise RuntimeError("measured core PID identity changed")
            self.record["samples"] += 1
            self.record["proc_vm_hwm_peak_bytes"] = max(
                self.record["proc_vm_hwm_peak_bytes"], row["peak"]
            )
            self.record["peak_bytes"] = max(
                self.record["peak_bytes"], row["peak"], row["rss"]
            )
            self.record["sampled_current_max_bytes"] = max(
                self.record.get("sampled_current_max_bytes", 0), row["rss"]
            )
            self.record["last_sample"] = row
            self.timeline.write(
                json.dumps(
                    {"monotonic_ns": time.monotonic_ns(), "stage": self.stage, **row}
                )
                + "\n"
            )
            self.timeline.flush()
            return row

    def boundary(self, stage):
        self.stage = stage
        if self.record["sampling_errors"]:
            raise RuntimeError("core process observation failed")
        return self.sample()

    def _monitor(self):
        while not self.finished.is_set():
            try:
                self.sample()
            except (OSError, ValueError, RuntimeError) as error:
                with self.lock:
                    self.record["sampling_errors"].append(
                        f"{type(error).__name__}: {error}"
                    )
                return
            self.finished.wait(0.02)

    def _drain_log(self):
        """Keep a bounded prefix, but always drain the common output pipe."""
        retained = 0
        try:
            while chunk := self.child.stdout.read1(64 * 1024):
                self.record["log_bytes"] += len(chunk)
                remaining = max(0, 1024 * 1024 - retained)
                if remaining:
                    prefix = chunk[:remaining]
                    self.log.write(prefix)
                    self.log.flush()
                    retained += len(prefix)
                self.record["log_truncated"] = self.record["log_bytes"] > retained
        except OSError as error:
            with self.lock:
                self.record["sampling_errors"].append(f"log drain: {error}")
            self._signal(signal.SIGKILL)

    def _signal(self, number):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.child.pid, number)

    def _reap_once(self):
        if self.child.returncode is not None:
            return True
        pid, status, usage = os.wait4(self.child.pid, os.WNOHANG)
        if not pid:
            return False
        self.child.returncode = os.waitstatus_to_exitcode(status)
        rss = usage.ru_maxrss * 1024
        self.record.update(
            exit_code=self.child.returncode,
            wait4_max_rss_bytes=rss,
            user_seconds=usage.ru_utime,
            system_seconds=usage.ru_stime,
        )
        # Linux retains an old pre-exec image's HWM in task rusage. Keep wait4
        # as a separate diagnostic, never as the selected core's observed RSS.
        return True

    def _reap_for(self, seconds):
        deadline = time.monotonic() + seconds
        while True:
            if self._reap_once():
                return True
            try:
                self.sample()
                self.record["shutdown_observed"] = True
            except (OSError, ValueError, RuntimeError) as error:
                # Exit between wait4 and procfs is expected. Other sampling
                # failures remain visible and cannot pass the observer gate.
                if self._reap_once():
                    return True
                self.record["sampling_errors"].append(
                    f"shutdown sample: {type(error).__name__}: {error}"
                )
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def close(self):
        if self.closed:
            return self.record
        self.finished.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=2)
        try:
            if self.thread.is_alive():
                self.record["sampling_errors"].append(
                    "core process sampler failed to join"
                )
            if self._reap_once():
                self.record["exited_before_close"] = True
            else:
                self.stage = "shutdown"
                self._signal(signal.SIGINT)
                self.record["sigint_requested"] = True
                if not self._reap_for(5):
                    for number, duration in ((signal.SIGTERM, 2), (signal.SIGKILL, 2)):
                        self.record["forced_signals"].append(
                            signal.Signals(number).name
                        )
                        self._signal(number)
                        if self._reap_for(duration):
                            break
                    else:
                        raise TimeoutError("core process did not join after SIGKILL")
            self.log_thread.join(timeout=2)
            if self.log_thread.is_alive():
                self.record["sampling_errors"].append(
                    "core output drain failed to join"
                )
            self.record["cleanup"] = (
                self.child.returncode is not None
                and not self.thread.is_alive()
                and not self.log_thread.is_alive()
            )
            self.record["status"] = (
                "PASS"
                if self.record["cleanup"]
                and self.record["samples"]
                and not self.record["sampling_errors"]
                and not self.record["forced_signals"]
                and self.child.returncode in (0, -signal.SIGINT)
                else "ERROR"
            )
            return self.record
        finally:
            self.closed = self.child.returncode is not None
            self.child.stdout.close()
            self.log.close()
            self.timeline.close()
            (self.work / "measurement.json").write_text(
                json.dumps(self.record, indent=2) + "\n"
            )
