"""Portable and fail-closed boundary checks for the Color Space text verifier."""

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools/verify_colorspace_text.py"
SPEC = importlib.util.spec_from_file_location("verify_colorspace_text", SCRIPT)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ReplayGuards(unittest.TestCase):
    def test_surface_dimensions_remain_distinct_from_bitmap(self):
        record = json.loads((SCRIPT.parents[1] / "analysis/colorspace-text.json").read_text(encoding="utf-8"))
        self.assertEqual(record["fixture"]["surface_size"], [256, 144])
        for case in record["cases"]:
            self.assertEqual(case["surface_size"], record["fixture"]["surface_size"])
            self.assertEqual(case["draw_bitmap"]["bitmap_layout"], [76, 40])

    def test_optimized_mode_exits_before_helper_loading(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", "-O", str(SCRIPT)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Run without -O", result.stderr)

    def test_existing_output_preserves_input_or_hardlink(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            decoded = root / "input.bin"
            decoded.write_bytes(b"original")
            alias = root / "alias.json"
            alias.hardlink_to(decoded)
            existing = root / "existing.json"
            existing.write_bytes(b"record")
            with patch.object(verifier, "capture_sources") as capture:
                for output in (decoded, alias, existing):
                    with self.subTest(output=output.name):
                        with self.assertRaises(SystemExit), patch("sys.stderr") as stderr:
                            verifier.main([str(decoded), "--output", str(output)])
                        self.assertIn("Output already exists", str(stderr.write.call_args_list))
                capture.assert_not_called()
            self.assertEqual(decoded.read_bytes(), b"original")
            self.assertEqual(alias.read_bytes(), b"original")
            self.assertEqual(existing.read_bytes(), b"record")

    def test_dangling_output_preserves_link(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "missing.json"
            output = root / "dangling.json"
            try:
                output.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"Symlink unavailable: {exc}")
            with patch.object(verifier, "capture_sources") as capture:
                with self.assertRaises(SystemExit), patch("sys.stderr") as stderr:
                    verifier.main([str(root / "input.bin"), "--output", str(output)])
                self.assertIn("Output already exists", str(stderr.write.call_args_list))
                capture.assert_not_called()
            self.assertTrue(output.is_symlink())
            self.assertFalse(target.exists())

    def test_late_tamper_rejected_before_early_helper_can_run(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name in verifier.HELPERS:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(verifier.ROOT / name, destination)
            marker = root / "early-helper-ran"
            sentinel = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n".encode()
            (root / verifier.MEASURE).write_bytes(sentinel)
            (root / verifier.TEXT).write_bytes(b"unexpected text helper")
            with patch.object(verifier, "ROOT", root), patch.object(
                verifier, "HELPERS", {**verifier.HELPERS, verifier.MEASURE: sha256(sentinel).hexdigest()}
            ):
                output = root / "new.json"
                with self.assertRaises(SystemExit), patch("sys.stderr") as stderr:
                    verifier.main([str(root / "input.bin"), "--output", str(output)])
                self.assertIn(f"Dependency SHA-256 mismatch: {verifier.TEXT}", str(stderr.write.call_args_list))
                self.assertFalse(output.exists())
                self.assertFalse(marker.exists())

    def test_relocated_cwd_and_bad_input_fail_before_output(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "relocated source"
            for name in (*verifier.HELPERS, "tools/verify_colorspace_text.py"):
                destination = checkout / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                raw = (verifier.ROOT / name).read_bytes().replace(b"\r\n", b"\n")
                destination.write_bytes(raw.replace(b"\n", b"\r\n"))
            decoded = root / "decoded.bin"
            decoded.write_bytes(b"wrong size")
            output = root / "new.json"
            args = [sys.executable, "-I", "-S", "-B", str(checkout / "tools/verify_colorspace_text.py"),
                    str(decoded), "--output", str(output)]
            result = subprocess.run(args, cwd=root, capture_output=True, text=True)
            self.assertIn("Decoded input size/type mismatch", result.stderr)
            self.assertNotEqual(result.returncode, 0)
            with decoded.open("wb") as stream:
                stream.truncate(78_683_892)
            result = subprocess.run(args, cwd=root, capture_output=True, text=True)
            self.assertIn("Decoded input SHA-256 mismatch", result.stderr)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

    def test_canonical_comparison_rejects_numeric_substitution(self):
        verifier.equal({"value": True, "count": 1}, {"count": 1, "value": True}, "same witness")
        with self.assertRaisesRegex(ValueError, "Typed comparison failed"):
            verifier.equal({"value": True}, {"value": 1}, "boolean type")
        with self.assertRaisesRegex(ValueError, "Typed comparison failed"):
            verifier.equal({"value": 1}, {"value": 1.0}, "integer type")


if __name__ == "__main__":
    unittest.main()
