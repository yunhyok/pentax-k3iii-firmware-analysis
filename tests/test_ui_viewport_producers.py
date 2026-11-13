from pathlib import Path
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools/verify_ui_viewport_producers.py"
API = runpy.run_path(str(CLI))


class ViewportGuards(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def test_optimized_mode_checks_existing_output_before_input(self):
        source = self.folder / "input"
        source.write_bytes(b"keep")
        target = self.folder / "alias"
        os.link(source, target)
        run = subprocess.run([sys.executable, "-B", "-S", "-O", str(CLI), "missing",
                              "--output", str(target)], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertIn(b"fresh output", run.stderr)
        self.assertEqual(source.read_bytes(), b"keep")

    def test_dangling_output_rejected(self):
        target = self.folder / "missing"
        link = self.folder / "dangling"
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlink unavailable: {error}")
        with self.assertRaisesRegex(ValueError, "fresh output"):
            API["exclusive_write"](link, b"rejected")
        self.assertFalse(target.exists())

    def test_capture_pins_lf_and_rejects_oversized_file(self):
        sample = self.folder / "sample"
        data = b"x\ny\n"
        digest = API["sha"](data)
        sample.write_bytes(b"x\r\ny\r\n")
        self.assertEqual(API["capture"](sample, len(data), digest, normalize_lf=True), data)
        with self.assertRaisesRegex(ValueError, "size/type"):
            API["capture"](sample, len(data), digest)
        sample.write_bytes(b"x\nz\n")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            API["capture"](sample, len(data), digest)

    def test_original_complete_typed_observation_and_archive(self):
        archive = json.loads((ROOT / "analysis/ui-viewport-producers.json").read_bytes())
        observation = archive["original_observation"]
        self.assertEqual(API["exact_observation"](observation), observation)
        for key, value in (("checked_instruction_contract_count", 73.0),
                           ("new_original_CPU_execution", 0), ("limits", [])):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "complete original observation"):
                API["exact_observation"]({**observation, key: value})
        with self.assertRaisesRegex(ValueError, "complete public witness"):
            API["exact_archive"]({**archive, "additional_static_review": {}})

    def test_geometry_and_independent_integer_halves(self):
        self.assertEqual(API["geometry"]([100, 10, 580, 40], [0, 0, 580, 40],
                                         [10, 12, 180, 60], [50, 20, 100, 30]),
                         ([110, 22, 580, 40], [110, 22, 40, 28]))
        self.assertEqual(API["aligned_text"]([10, 20, 100, 80], [75, 39], 1, 1), [23, 41, 75, 39])
        with self.assertRaisesRegex(ValueError, "illustration domain"):
            API["geometry"]([10001, 0, 1, 1], [0, 0, 1, 1], [0, 0, 1, 1], [0, 0, 1, 1])

    def test_wrong_original_size_rejected_without_capstone(self):
        fixture = self.folder / "fixture"
        output = self.folder / "receipt"
        fixture.write_bytes(b"x")
        run = subprocess.run([sys.executable, "-B", "-S", str(CLI), str(fixture), "--output", str(output)],
                             capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertIn(b"input length or SHA-256 mismatch", run.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
