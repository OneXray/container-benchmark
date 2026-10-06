import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from container_benchmark.processes import run_command


class ProcessesTest(unittest.TestCase):
    def run_python(self, source, **options):
        with (
            tempfile.TemporaryDirectory() as root,
            patch.dict(os.environ, {"BENCHMARK_WORK_DIR": root}),
        ):
            return run_command([sys.executable, "-c", source], **options)

    def test_capture_and_join_use_only_the_explicit_work_directory(self):
        result = self.run_python("print('ready')", timeout=3)
        self.assertEqual((result.returncode, result.stdout), (0, b"ready\n"))
        self.assertTrue(result.cleanup)

    def test_timeout_and_output_limit_join_owned_children(self):
        timeout = self.run_python("import time; time.sleep(30)", timeout=0.05)
        self.assertEqual((timeout.returncode, timeout.reason), (124, "timeout"))
        self.assertTrue(timeout.cleanup)
        overflow = self.run_python("print('x' * 10000)", timeout=3, limit=64)
        self.assertEqual((overflow.returncode, overflow.reason), (125, "output-limit"))
        self.assertEqual(len(overflow.stdout), 64)
        self.assertTrue(overflow.cleanup)
