"""An explicit dirty checkout identity includes untracked production sources."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from container_benchmark.core_comparison import _check_sources
from container_benchmark.inputs import sha256, source_identity


class SourceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.git("init", "--quiet")
        (self.root / ".gitignore").write_text("target/\n")
        (self.root / "Cargo.lock").write_text("frozen lock")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Offline Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        )

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root)

    def test_untracked_code_changes_identity_but_ignored_builds_do_not(self):
        code = self.root / "new-cli.rs"
        code.write_text("first implementation")
        before = source_identity(self.root)
        self.assertEqual(before["untracked_files"], {"new-cli.rs": sha256(code)})
        self.assertEqual(before["lockfile_sha256"], sha256(self.root / "Cargo.lock"))
        (self.root / "target").mkdir()
        (self.root / "target/vole").write_text("ignored executable")
        self.assertEqual(source_identity(self.root), before)
        code.write_text("different implementation")
        after = source_identity(self.root)
        self.assertEqual(before["commit"], after["commit"])
        self.assertEqual(before["working_diff_sha256"], after["working_diff_sha256"])
        self.assertNotEqual(before["untracked_files"], after["untracked_files"])

    def test_freeze_check_rejects_source_change(self):
        before = source_identity(self.root)
        _check_sources({"vole": self.root}, {"vole": before})
        (self.root / "Cargo.lock").write_text("changed lock")
        with self.assertRaisesRegex(RuntimeError, "selected source changed"):
            _check_sources({"vole": self.root}, {"vole": before})
