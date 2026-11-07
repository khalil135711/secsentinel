import tempfile
import unittest
from pathlib import Path

from secsentinel import integrity


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "data"
        (self.root / "sub").mkdir(parents=True)
        (self.root / "a.txt").write_text("alpha")
        (self.root / "sub" / "b.txt").write_text("beta")
        (self.root / "skip.log").write_text("noise")
        self.baseline = Path(self._tmp.name) / "baseline.json"

    def test_clean_after_init(self):
        count = integrity.save_baseline(self.root, self.baseline, ["*.log"])
        self.assertEqual(count, 2)
        self.assertTrue(integrity.check(self.root, self.baseline).clean)

    def test_detects_modified_added_removed(self):
        integrity.save_baseline(self.root, self.baseline, ["*.log"])
        (self.root / "a.txt").write_text("tampered")
        (self.root / "sub" / "b.txt").unlink()
        (self.root / "new.txt").write_text("new")
        diff = integrity.check(self.root, self.baseline)
        self.assertEqual(diff.modified, ["a.txt"])
        self.assertEqual(diff.removed, ["sub/b.txt"])
        self.assertEqual(diff.added, ["new.txt"])

    def test_excluded_files_ignored(self):
        integrity.save_baseline(self.root, self.baseline, ["*.log"])
        (self.root / "skip.log").write_text("changed but excluded")
        self.assertTrue(integrity.check(self.root, self.baseline).clean)

    def test_baseline_inside_root_is_skipped(self):
        inside = self.root / "baseline.json"
        integrity.save_baseline(self.root, inside)
        self.assertNotIn("baseline.json", integrity.load_baseline(inside)["files"])
        self.assertTrue(integrity.check(self.root, inside).clean)

    def test_corrupt_baseline_rejected(self):
        self.baseline.write_text('{"version": 99}')
        with self.assertRaises(ValueError):
            integrity.check(self.root, self.baseline)

    def test_not_a_directory(self):
        with self.assertRaises(NotADirectoryError):
            integrity.save_baseline(self.root / "a.txt", self.baseline)


if __name__ == "__main__":
    unittest.main()
