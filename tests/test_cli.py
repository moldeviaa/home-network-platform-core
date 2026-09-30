from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest

from home_net_recovery.__main__ import main


class CliTests(unittest.TestCase):
    def test_created_pin_can_be_verified_without_emitting_artifact_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "private-artifact-name").write_bytes(b"private bytes")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["manifest-create", str(root)]), 0)
            created = json.loads(output.getvalue())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["manifest-verify", str(root), "--manifest-sha256",
                                       created["manifest_sha256"]]), 0)
            self.assertTrue(json.loads(output.getvalue())["manifest_pin_verified"])
            self.assertNotIn("private-artifact-name", output.getvalue())
            self.assertNotIn("private bytes", output.getvalue())
            error = io.StringIO()
            with redirect_stderr(error):
                self.assertEqual(main(["manifest-verify", str(root), "--manifest-sha256", "0" * 64]), 2)
            self.assertEqual(json.loads(error.getvalue()), {"ok": False, "error": "manifest_pin_mismatch"})
