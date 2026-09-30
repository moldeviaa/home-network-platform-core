from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

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
            with sqlite3.connect(database) as connection:
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


if __name__ == "__main__":
    unittest.main()
