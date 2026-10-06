"""Offline checks for the small cache and exact-resource cleanup contract."""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import download_cache, ownership, session


class StorageTests(unittest.TestCase):
    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temporary)
        self.enterContext(
            patch.object(download_cache, "CACHE_ROOT", self.root / "cache")
        )
        self.enterContext(
            patch.dict(
                os.environ,
                {"BENCHMARK_SESSION_ACTIVE": "0", "BENCHMARK_CACHE_FREEZE": "0"},
            )
        )
        self.prepared = []

    def prepare(self, staging):
        version = len(self.prepared) + 1
        self.prepared.append(version)
        (staging / "binary").write_text(f"version-{version}")
        return {"version": version}

    def owned_work(self):
        work = self.root / "owned"
        work.mkdir()
        (work / ".owned-session").write_text("test")
        ownership.initialize(work)
        os.environ.update(BENCHMARK_WORK_DIR=str(work), BENCHMARK_SESSION_ACTIVE="1")
        return work

    def test_daily_hit_keeps_shared_payload_separate_from_consumer(self):
        with patch.object(download_cache, "today", return_value="2026-10-05"):
            first = download_cache.daily(
                "release", self.prepare, directory=self.root / "first"
            )
            (self.root / "first/binary").write_text("consumer changed it")
            second = download_cache.daily(
                "release", self.prepare, directory=self.root / "second"
            )
        self.assertEqual(self.prepared, [1])
        self.assertFalse(first["cache"]["hit"])
        self.assertTrue(second["cache"]["hit"])
        self.assertEqual((self.root / "second/binary").read_text(), "version-1")

    def test_next_local_day_refreshes_dependency(self):
        with patch.object(download_cache, "today", return_value="2026-10-05"):
            download_cache.daily("release", self.prepare)
        with patch.object(download_cache, "today", return_value="2026-10-06"):
            result = download_cache.daily(
                "release", self.prepare, directory=self.root / "consumer"
            )
        self.assertEqual(self.prepared, [1, 2])
        self.assertEqual(result["cache"], {"checked_on": "2026-10-06", "hit": False})
        self.assertEqual((self.root / "consumer/binary").read_text(), "version-2")

    def test_same_day_damaged_shared_payload_is_rechecked(self):
        with patch.object(download_cache, "today", return_value="2026-10-05"):
            download_cache.daily("release", self.prepare)
            payload = next((self.root / "cache").glob("*/payload-*/binary"))
            payload.write_text("damaged")
            result = download_cache.daily(
                "release", self.prepare, directory=self.root / "consumer"
            )
        self.assertEqual(self.prepared, [1, 2])
        self.assertFalse(result["cache"]["hit"])
        self.assertEqual((self.root / "consumer/binary").read_text(), "version-2")

    def test_session_snapshot_stays_frozen_and_rejects_corruption(self):
        work = self.owned_work()
        os.environ["BENCHMARK_CACHE_FREEZE"] = "1"
        with patch.object(download_cache, "today", return_value="2026-10-05"):
            download_cache.daily("release", self.prepare)
        with patch.object(download_cache, "today", return_value="2026-10-06"):
            frozen = download_cache.daily("release", self.prepare)
            self.assertEqual(frozen["version"], 1)
            self.assertEqual(frozen["cache"]["checked_on"], "2026-10-05")
            payload = next((work / "dependency-snapshots").glob("*/payload-*/binary"))
            payload.write_text("damaged")
            with self.assertRaisesRegex(RuntimeError, "snapshot integrity changed"):
                download_cache.daily("release", self.prepare)
        self.assertEqual(self.prepared, [1])

    def test_session_saves_text_before_cleanup_and_restores_environment(self):
        previous = {
            name: os.environ.get(name)
            for name in (
                "BENCHMARK_WORK_DIR",
                "BENCHMARK_SESSION_ACTIVE",
                "BENCHMARK_CACHE_FREEZE",
                "GOCACHE",
                "PYTHONDONTWRITEBYTECODE",
            )
        }
        previous_bytecode = sys.dont_write_bytecode
        real_rmtree = shutil.rmtree
        saved = []

        def remove_after_save(path):
            reports = list((self.root / "conclusions").glob("*.md"))
            self.assertEqual(len(reports), 1)
            saved.append(reports[0].read_text())
            self.assertIn("matched workload complete", saved[-1])
            self.assertIn("scratch cleanup pending", saved[-1])
            real_rmtree(path)

        with (
            patch.object(session, "BENCHMARK_ROOT", self.root),
            patch.object(session.ownership, "cleanup", return_value=[]) as cleanup,
            patch.object(session.shutil, "rmtree", side_effect=remove_after_save),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with session.Session(["compare", "--core", "mihomo"]) as run:
                (run.work / "summary.md").write_text("matched workload complete")
                run.status = "COMPLETED"
                self.assertTrue(sys.dont_write_bytecode)
                self.assertEqual(os.environ["BENCHMARK_WORK_DIR"], str(run.work))
            cleanup.assert_called_once_with(run.work)
        self.assertEqual(len(saved), 1)
        self.assertFalse(run.work.exists())
        self.assertIn("Cleanup: complete", run.report.read_text())
        self.assertEqual(sys.dont_write_bytecode, previous_bytecode)
        self.assertEqual({name: os.environ.get(name) for name in previous}, previous)

    def test_cleanup_changes_only_registered_matching_container(self):
        work = self.owned_work()
        run_id = "0123456789ab"
        owned = f"benchmark-{run_id}-core"
        unregistered = f"benchmark-{run_id}-unregistered"
        labels = {"purpose": ownership.PURPOSE, "benchmark-run": run_id}
        rows = {
            name: {
                "id": name,
                "configuration": {"labels": labels},
                "status": {"state": "running"},
            }
            for name in (owned, unregistered, "unrelated-service")
        }
        before = json.dumps(rows, sort_keys=True)
        ownership.register_container(owned, run_id=run_id)
        mutations = []

        def container_cli(*arguments, **kwargs):
            if arguments == ("list", "--all", "--format", "json"):
                return json.dumps(list(rows.values()))
            mutations.append(arguments)
            self.assertEqual(arguments[-1], owned)
            if arguments[0] == "delete":
                del rows[owned]
            elif arguments[0] != "stop":
                self.fail(f"unexpected CLI mutation: {arguments}")
            return ""

        with patch.object(ownership, "_run", side_effect=container_cli):
            self.assertEqual(ownership.cleanup(work), [])
        self.assertEqual(
            mutations,
            [("stop", "--time", "5", owned), ("delete", "--force", owned)],
        )
        self.assertEqual(
            rows,
            {name: row for name, row in json.loads(before).items() if name != owned},
        )


if __name__ == "__main__":
    unittest.main()
