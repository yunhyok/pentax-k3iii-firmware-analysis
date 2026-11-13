from pathlib import Path
import os
import runpy
import subprocess
import sys
import tempfile
import unittest


CLI = Path(__file__).resolve().parents[1] / "tools/verify_ui_surface_producers.py"
API = runpy.run_path(str(CLI))


class SurfaceGuards(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)

    def test_output_hardlink_guard_survives_optimization(self):
        source = self.folder / "source"
        source.write_bytes(b"keep")
        alias = self.folder / "alias"
        os.link(source, alias)
        run = subprocess.run([sys.executable, "-B", "-S", "-O", str(CLI), "missing",
                              "--output", str(alias)], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertIn(b"output must be new", run.stderr)
        self.assertEqual(source.read_bytes(), b"keep")

    def test_capture_bounds_and_line_endings(self):
        path = self.folder / "sample"
        data = b"x\ny\n"
        pin = API["digest"](data)
        path.write_bytes(b"x\r\ny\r\n")
        self.assertEqual(API["capture"](path, 4, pin, normalize_lf=True), data)
        with self.assertRaisesRegex(ValueError, "type or size"):
            API["capture"](path, 4, pin)
        path.write_bytes(b"x\nz\n")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            API["capture"](path, 4, pin)

    def test_complete_original_gate_precedes_projection(self):
        # Incomplete or incorrectly typed input must fail before the projection
        # could attempt to read missing instruction data.
        with self.assertRaisesRegex(ValueError, "complete original evidence"):
            API["project"]({"schema": 1.0}, {})

    def test_wrong_input_rejected_before_optional_import(self):
        source = self.folder / "wrong"
        source.write_bytes(b"no")
        output = self.folder / "receipt"
        run = subprocess.run([sys.executable, "-B", "-S", str(CLI), str(source),
                              "--output", str(output)], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertIn(b"size or SHA-256 mismatch", run.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
