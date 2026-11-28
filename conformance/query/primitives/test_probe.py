# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Run with: python -m unittest discover -s conformance/query/primitives -p 'test_*.py'."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("primitive_probe", Path(__file__).with_name("probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeBehaviorTests(unittest.TestCase):
    # Catch silently dropping cases, comparing a result with itself, or treating
    # diagnostic wording/normalization presentation as observable match behavior.
    def test_comparison_keeps_real_mismatches_and_ignores_only_normalization(self):
        reference = [{"id": "newline", "observation": {"match": True}, "normalized": "wrapper"}]
        own = [{"id": "newline", "observation": {"match": False}, "normalized": ""}]
        self.assertEqual(probe.compare(["newline"], reference, own), [
            {"id": "newline", "reference": {"match": True}, "own": {"match": False}}])
        own[0]["observation"]["match"] = True
        self.assertEqual(probe.compare(["newline"], reference, own), [])

    def test_missing_duplicate_or_unrequested_case_is_not_a_success(self):
        row = {"id": "a", "observation": {"match": True}}
        for rows in ([], [row, row], [row, {"id": "other", "observation": {}}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                probe.compare(["a"], [row], rows)

    def test_existing_tampered_artifact_is_rejected_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact.zip"
            artifact.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                probe.acquire("https://invalid.invalid/never-contacted", artifact,
                              hashlib.sha256(b"approved").hexdigest())
            self.assertEqual(artifact.read_bytes(), b"changed")

    def test_archive_path_cannot_escape_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("../escape", "/absolute", "C:/outside", "safe/../../escape", "safe\\escape"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    probe.archive_destination(Path(directory), name)
            self.assertEqual(probe.archive_destination(Path(directory), "go/bin/go"),
                             Path(directory).resolve() / "go/bin/go")

    def test_runtime_identity_must_be_actual_pinned_compiler(self):
        good = {"compiler": "go1.23.4", "unicode": "15.0.0", "goos": "windows", "goarch": "amd64",
                "module": "v0.0.0-20240518133315-a468a5bfb3bc"}
        probe.check_identity(good, "go1.23.4", good["module"], "windows", "amd64")
        for field, value in (("compiler", "go1.23.5"), ("module", "latest"), ("unicode", "17.0.0")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                probe.check_identity(dict(good, **{field: value}), "go1.23.4", good["module"], "windows", "amd64")


if __name__ == "__main__":
    unittest.main()
