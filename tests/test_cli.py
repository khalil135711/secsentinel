import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from secsentinel.cli import main

ROOT = Path(__file__).resolve().parent.parent


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in argv])
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_logs_exit_code_and_output(self):
        code, out, _ = run("logs", ROOT / "samples" / "auth.log", "--year", 2026)
        self.assertEqual(code, 1)
        self.assertIn("203.0.113.45", out)
        self.assertIn("CRITICAL", out)

    def test_logs_missing_file(self):
        code, _, err = run("logs", ROOT / "does-not-exist.log")
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_integrity_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "d"
            data.mkdir()
            (data / "f.txt").write_text("x")
            base = Path(tmp) / "b.json"
            self.assertEqual(run("integrity", "init", data, "--baseline", base)[0], 0)
            self.assertEqual(run("integrity", "check", data, "--baseline", base)[0], 0)
            (data / "f.txt").write_text("y")
            code, out, _ = run("integrity", "check", data, "--baseline", base)
            self.assertEqual(code, 1)
            self.assertIn("MODIFIED", out)

    def test_passwords_file(self):
        code, out, _ = run("passwords", "--file", ROOT / "samples" / "passwords.txt")
        self.assertEqual(code, 1)
        self.assertNotIn("password123", out)

    def test_json_output_is_valid(self):
        import json
        _, out, _ = run("logs", ROOT / "samples" / "auth.log", "--year", 2026, "--json")
        self.assertEqual(json.loads(out)["findings"][0]["ip"], "203.0.113.45")


if __name__ == "__main__":
    unittest.main()
