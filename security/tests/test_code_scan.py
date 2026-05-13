import tempfile
import unittest
from pathlib import Path

from scanner import trivy_code_scan as code_scan


class CodeScanTests(unittest.TestCase):
    def test_default_excludes_legacy_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = root / "_sem-uso" / "site_old" / "index.php"
            legacy.parent.mkdir(parents=True)
            legacy.write_text("<?php include $_GET['p'];", encoding="utf-8")
            active = root / "public" / "index.php"
            active.parent.mkdir(parents=True)
            active.write_text("<?php echo 'ok';", encoding="utf-8")
            self.assertTrue(code_scan.is_ignored_source_path(legacy, root))
            self.assertFalse(code_scan.is_ignored_source_path(active, root))

    def test_load_code_scan_config_from_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / "code_scan.toml").write_text('[scan]\nexclude_dirs = ["legacy", "tmp"]\n', encoding="utf-8")
            self.assertEqual(code_scan.load_code_scan_config(root)["exclude_dirs"], ["legacy", "tmp"])

    def test_tar_exclude_args_contains_nested_pattern(self):
        args = code_scan.tar_exclude_args(["_sem-uso"])
        self.assertIn("--exclude='_sem-uso'", args)
        self.assertIn("--exclude='*/_sem-uso'", args)


if __name__ == "__main__":
    unittest.main()
