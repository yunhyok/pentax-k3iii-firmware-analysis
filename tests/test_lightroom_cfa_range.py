"""Exercise fixed CFA result and file trust boundaries without camera assets."""
from hashlib import sha256
import json
from pathlib import Path
import runpy
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools/check_lightroom_cfa_range.py"
REFERENCE = ROOT / "analysis/lightroom-cfa-range.json"
METHOD = runpy.run_path(str(CHECKER))


class CfaRangeTests(unittest.TestCase):
    def test_crop_phase_and_fixed_point_controls(self):
        METHOD["self_test"]()

    def test_complete_witness_rejects_same_length_count_mutation(self):
        frozen = REFERENCE.read_bytes()
        result = json.loads(frozen)
        self.assertEqual(METHOD["verify_payload"](result), frozen)
        result["regions"]["default_crop"]["CFA"]["R"]["above_dng_white"] += 1
        tampered = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        self.assertEqual(len(tampered), len(frozen))
        with self.assertRaisesRegex(ValueError, "complete CFA range witness mismatch"):
            METHOD["verify_payload"](result)

    def test_input_capture_rejects_wrong_type_size_and_digest(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "input"
            fixture = b"abc"
            pin = (len(fixture), sha256(fixture).hexdigest())
            with self.assertRaisesRegex(ValueError, "input size or type mismatch"):
                METHOD["capture"](root, pin)
            path.write_bytes(fixture)
            self.assertEqual(METHOD["capture"](path, pin), fixture)
            path.write_bytes(b"ab")
            with self.assertRaisesRegex(ValueError, "input size or type mismatch"):
                METHOD["capture"](path, pin)
            path.write_bytes(b"abd")
            with self.assertRaisesRegex(ValueError, "input SHA mismatch"):
                METHOD["capture"](path, pin)

    def test_existing_output_is_rejected_before_input(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            sentinel = root / "input"
            sentinel.write_bytes(b"preserve")
            alias = root / "output"
            alias.hardlink_to(sentinel)
            for output in (sentinel, alias):
                call = subprocess.run(
                    [sys.executable, "-B", "-I", "-S", str(CHECKER), "--dng", str(sentinel),
                     "--pef", "absent", "--sdk", "absent", "--output", str(output)],
                    capture_output=True, text=True, timeout=20,
                )
                self.assertNotEqual(call.returncode, 0)
                self.assertIn("new output path required", call.stderr)
                self.assertEqual(output.read_bytes(), b"preserve")

    def test_optimized_run_refuses_to_skip_controls(self):
        call = subprocess.run(
            [sys.executable, "-B", "-O", "-I", "-S", str(CHECKER), "--self-test"],
            capture_output=True, text=True, timeout=20,
        )
        self.assertNotEqual(call.returncode, 0)
        self.assertIn("optimized Python unsupported", call.stderr)


if __name__ == "__main__":
    unittest.main()
