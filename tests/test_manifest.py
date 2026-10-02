from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import sqlite3
from contextlib import closing
import tempfile
import unittest
from unittest.mock import patch

from home_net_recovery.manifest import (
    RecoveryError, create_manifest, decode_document, verify_manifest,
    write_manifest,
)


class ManifestTests(unittest.TestCase):
    def test_round_trip_and_sqlite_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "snapshot").mkdir()
            database = root / "snapshot" / "site.sqlite3"
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY)")
                connection.execute("INSERT INTO sample VALUES (1)")
            (root / "snapshot" / "note.txt").write_bytes(b"ok")
            expected = create_manifest(root)
            self.assertEqual(expected["file_count"], 2)
            write_manifest(root)
            result = verify_manifest(root, sqlite_names=("snapshot/site.sqlite3",))
            self.assertTrue(result["verified"])
            self.assertEqual(result["sqlite_checked"], 1)
            with self.assertRaises(FileExistsError):
                write_manifest(root)

    def test_tamper_and_unlisted_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").write_bytes(b"before")
            write_manifest(root)
            (root / "data").write_bytes(b"after")
            with self.assertRaisesRegex(RecoveryError, "artifact_mismatch"):
                verify_manifest(root)
            (root / "data").write_bytes(b"before")
            (root / "extra").write_bytes(b"not listed")
            with self.assertRaisesRegex(RecoveryError, "unlisted_artifact"):
                verify_manifest(root)
            self.assertTrue(verify_manifest(root, strict=False)["verified"])

    def test_symlink_and_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").write_bytes(b"x")
            (root / "linked").symlink_to("data")
            with self.assertRaisesRegex(RecoveryError, "artifact_not_regular"):
                create_manifest(root)
            (root / "linked").unlink()
            os.link(root / "data", root / "linked")
            with self.assertRaisesRegex(RecoveryError, "artifact_not_regular"):
                create_manifest(root)

    def test_duplicate_json_key_rejected(self):
        with self.assertRaisesRegex(RecoveryError, "duplicate_json_key"):
            decode_document(b'{"a":1,"a":2}\n')

    def test_trusted_pin_rejects_consistently_rewritten_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").write_bytes(b"original")
            write_manifest(root)
            pin = hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()
            result = verify_manifest(root, manifest_sha256=pin)
            self.assertTrue(result["manifest_pin_verified"])
            self.assertEqual(result["manifest_sha256"], pin)
            (root / "data").write_bytes(b"replacement")
            (root / "manifest.json").unlink()
            write_manifest(root)
            # Self-consistency alone accepts a complete replacement of both files.
            self.assertFalse(verify_manifest(root)["manifest_pin_verified"])
            with self.assertRaisesRegex(RecoveryError, "manifest_pin_mismatch"):
                verify_manifest(root, manifest_sha256=pin)

    def test_bad_pin_is_rejected_before_artifact_access(self):
        for pin in (True, "", "g" * 64, "A" * 64, "a" * 63):
            with self.subTest(pin=pin):
                with self.assertRaisesRegex(RecoveryError, "manifest_pin_shape"):
                    verify_manifest(Path("/does/not/exist"), manifest_sha256=pin)

    def test_replaced_manifest_inode_is_rejected_even_with_identical_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifest(root)
            path = root / "manifest.json"
            original_open = os.open
            def replace_after_open(target, *args, **kwargs):
                descriptor = original_open(target, *args, **kwargs)
                if target == path:
                    replacement = root / "replacement"
                    replacement.write_bytes(path.read_bytes())
                    os.replace(replacement, path)
                return descriptor
            with patch("home_net_recovery.manifest.os.open", side_effect=replace_after_open):
                with self.assertRaisesRegex(RecoveryError, "manifest_changed"):
                    verify_manifest(root)


if __name__ == "__main__":
    unittest.main()
