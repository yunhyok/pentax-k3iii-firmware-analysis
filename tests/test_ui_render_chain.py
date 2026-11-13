"""Keep the recorded-evidence checker fail closed without proprietary fixtures."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/check_ui_render_chain.py"


class RecordedInputTests(unittest.TestCase):
    def run_check(self, *args, optimized=False):
        return subprocess.run(
            [sys.executable, "-I", "-S", "-B", *(["-O"] if optimized else []),
             str(TOOL), "missing-package.bin", "missing-analysis.elf", *map(str, args)],
            capture_output=True, text=True, timeout=15,
        )

    def test_optimized_execution_is_rejected(self):
        result = self.run_check(optimized=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verification requires assertions", result.stderr)

    def test_changed_records_are_rejected_before_firmware_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            for flag, filename in (("--report", "ui-render-chain.json"),
                                   ("--boundary", "ui-render-chain-boundary.json")):
                with self.subTest(flag=flag):
                    path = Path(temporary) / filename
                    original = (ROOT / "analysis" / filename).read_bytes()
                    changed = original + b" "
                    path.write_bytes(changed)
                    result = self.run_check(flag, path)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"{filename}: SHA-256 mismatch", result.stderr)
                    self.assertEqual(path.read_bytes(), changed)

    def test_missing_firmware_does_not_report_success(self):
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS", result.stdout)
        self.assertIn("missing-package.bin", result.stderr)


if __name__ == "__main__":
    unittest.main()
