from __future__ import annotations

import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from home_net_recovery.manifest import RecoveryError
from home_net_recovery.tar_audit import audit_tar


def make_tar(path: Path, rows: list[tuple[str, bytes | None, bytes | None]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content, kind in rows:
            info = tarfile.TarInfo(name)
            if kind == tarfile.SYMTYPE:
                info.type = kind
                info.linkname = "outside"
                archive.addfile(info)
            elif content is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))


class TarAuditTests(unittest.TestCase):
    def test_valid_archive_is_not_extracted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup.tar.gz"
            make_tar(path, [("snapshot", None, None),
                            ("snapshot/file", b"abc", None)])
            result = audit_tar(path)
            self.assertEqual(result["files"], 1)
            self.assertEqual(result["unpacked_bytes"], 3)
            self.assertFalse(result["extracted"])
            self.assertEqual(sorted(item.name for item in Path(directory).iterdir()),
                             ["backup.tar.gz"])

    def test_path_and_link_attacks_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.tar.gz"
            for name, content, kind, code in [
                ("../outside", b"x", None, "unsafe_path"),
                ("/outside", b"x", None, "unsafe_path"),
                ("link", None, tarfile.SYMTYPE, "unsupported_member_type"),
            ]:
                make_tar(path, [(name, content, kind)])
                with self.assertRaisesRegex(RecoveryError, code):
                    audit_tar(path)

    def test_duplicates_and_limits_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.tar.gz"
            make_tar(path, [("same", b"a", None), ("same", b"b", None)])
            with self.assertRaisesRegex(RecoveryError, "duplicate_member"):
                audit_tar(path)
            make_tar(path, [("large", b"abcd", None)])
            with self.assertRaisesRegex(RecoveryError, "unpacked_limit"):
                audit_tar(path, max_unpacked_bytes=3)


if __name__ == "__main__":
    unittest.main()
