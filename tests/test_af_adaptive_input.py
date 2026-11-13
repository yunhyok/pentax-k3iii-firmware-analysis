"""Guards for the static adaptive AF verifier. No firmware fixture is required."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "verify_af_adaptive_input.py"
ARCHIVE = ROOT / "analysis/af-adaptive-input-checks.json"
SPEC = importlib.util.spec_from_file_location("af_adaptive_verifier", CLI)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class AdaptiveInputGuards(TestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name)
        self.output = self.work / "result.json"
        self.carrier = self.work / "raw.bin"

    def run_cli(self, *flags):
        return subprocess.run([sys.executable, "-B", "-S", *flags, str(CLI),
                               str(self.carrier), "--output", str(self.output)], capture_output=True)

    def test_wrong_size_rejected_before_optional_import_even_optimized(self):
        self.carrier.write_bytes(b"short")
        for flags in ((), ("-O",)):
            result = self.run_cli(*flags)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"RTOS length/type", result.stderr)
            self.assertFalse(self.output.exists())

    def test_same_size_wrong_hash(self):
        self.carrier.write_bytes(b"bad!")
        with patch.object(verifier, "SIZE", 4):
            with self.assertRaisesRegex(ValueError, "RTOS identity"):
                verifier.capture(self.carrier)

    def test_existing_output_alias_is_preserved(self):
        self.carrier.write_bytes(b"untouched")
        os.link(self.carrier, self.output)
        result = self.run_cli()
        self.assertIn(b"new output path required", result.stderr)
        self.assertEqual(self.carrier.read_bytes(), b"untouched")
        self.assertEqual(self.output.read_bytes(), b"untouched")

    def test_dangling_output_rejected(self):
        target = self.work / "absent"
        try:
            self.output.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symbolic links unavailable: {error}")
        result = self.run_cli()
        self.assertIn(b"new output path required", result.stderr)
        self.assertTrue(self.output.is_symlink())
        self.assertFalse(target.exists())

    def test_dangling_output_inserted_after_preflight(self):
        target = self.work / "late-target"
        record = json.loads(ARCHIVE.read_bytes())["observations"]

        def scan_and_insert(_):
            try:
                self.output.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            return record

        with patch.object(verifier, "capture", return_value=b"fixture"):
            with patch.object(verifier, "scan", side_effect=scan_and_insert):
                with self.assertRaisesRegex(ValueError, "output already exists"):
                    verifier.main([str(self.carrier), "--output", str(self.output)])
        self.assertTrue(self.output.is_symlink())
        self.assertFalse(target.exists())

    def test_entire_record_checked_before_output(self):
        archived = json.loads(ARCHIVE.read_bytes())["observations"]
        for kind in ("type", "missing", "extra", "order"):
            mutated = json.loads(verifier.json_bytes(archived))
            row = mutated["host_arithmetic_controls"][0]
            if kind == "type":
                row["now"] = True
            elif kind == "missing":
                del row["now"]
            elif kind == "extra":
                row["guessed_unit"] = "us"
            else:
                mutated = dict(reversed(list(mutated.items())))
            expected = "serialized witness" if kind == "order" else "typed witness"
            with self.subTest(kind=kind):
                with patch.object(verifier, "capture", return_value=b"fixture"):
                    with patch.object(verifier, "scan", return_value=mutated):
                        with self.assertRaisesRegex(ValueError, expected):
                            verifier.main([str(self.carrier), "--output", str(self.output)])
                self.assertFalse(self.output.exists())

    def test_compare_mismatch_leaves_output_uncreated(self):
        record = json.loads(ARCHIVE.read_bytes())["observations"]
        comparison = self.work / "compare.json"
        comparison.write_bytes(b"{}\n")
        with patch.object(verifier, "capture", return_value=b"fixture"):
            with patch.object(verifier, "scan", return_value=record):
                with self.assertRaisesRegex(ValueError, "differs from --compare"):
                    verifier.main([str(self.carrier), "--output", str(self.output), "--compare", str(comparison)])
        self.assertFalse(self.output.exists())
        comparison.write_bytes(ARCHIVE.read_bytes().replace(b"\n", b"\r\n"))
        verifier.check_compare(comparison, ARCHIVE.read_bytes())

    def test_wrap_and_strict_threshold_contrasts(self):
        divide = verifier.shift_model
        bound = 0xffffffff
        self.assertEqual(divide(1, bound, bound, 0), (1, 0))
        self.assertEqual(divide(123, 123, bound, 0), (bound, 159072862))
        for threshold in (2000, 4000, 8000):
            self.assertEqual(divide(threshold * 27 + 27, 1, bound, 0)[1], threshold)
            self.assertEqual(divide(threshold * 27 + 28, 1, bound, 0)[1], threshold + 1)
