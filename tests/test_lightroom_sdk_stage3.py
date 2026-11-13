from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools/check_lightroom_sdk_stage3.py"
API = runpy.run_path(str(CLI))


class Stage3Guards(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name)

    def test_existing_work_rejected_before_other_inputs_under_optimization(self):
        existing = self.work / "protected"
        existing.write_bytes(b"protected")
        run = subprocess.run([sys.executable, "-B", "-O", str(CLI), "--work", str(existing),
                              "--sdk", str(existing), "--dng", "missing", "--zig", "missing"],
                             capture_output=True, check=False, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertIn(b"work directory must be a new path", run.stderr)
        self.assertEqual(existing.read_bytes(), b"protected")

    def test_helper_bytes_are_checked_before_exec(self):
        tools = self.work / "tools"
        tools.mkdir()
        (tools / "check_lightroom_sdk_stage2.py").write_bytes(b"raise RuntimeError('ran unchecked helper')\n")
        with self.assertRaisesRegex(ValueError, "helper SHA-256"):
            API["load_stage2_helper"](self.work)

    def test_existing_and_dangling_log_paths_rejected_before_command(self):
        log = self.work / "compile.log"
        log.write_bytes(b"keep")
        with patch.object(API["subprocess"], "run") as execute:
            with self.assertRaisesRegex(ValueError, "log path must be new"):
                API["run_command"]([], log, self.work, {}, 1)
            execute.assert_not_called()
        self.assertEqual(log.read_bytes(), b"keep")
        link = self.work / "link.log"
        target = self.work / "absent"
        try:
            link.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symbolic links unavailable: {exc}")
        with patch.object(API["subprocess"], "run") as execute:
            with self.assertRaisesRegex(ValueError, "log path must be new"):
                API["run_command"]([], link, self.work, {}, 1)
            execute.assert_not_called()
        self.assertFalse(target.exists())

    def test_lf_pin_accepts_crlf_checkout(self):
        tools = self.work / "tools"
        tools.mkdir()
        name = "check_lightroom_sdk_stage2.py"
        data = (ROOT / "tools" / name).read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        (tools / name).write_bytes(data)
        self.assertTrue(callable(API["load_stage2_helper"](self.work).build))

    def test_full_witness_compares_keys_and_types(self):
        valid = {"groups": [{"mismatches": 0, "values_equal": True}], "samples": 8}
        API["verify_witness"](valid, valid, "Test")
        for change in ({"samples": 8}, {**valid, "samples": 8.0}, {**valid, "extra": True},
                       {**valid, "groups": [{"mismatches": False, "values_equal": 1}]}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "canonical witness"):
                API["verify_witness"](change, valid, "Test")

    def test_historical_object_mutation_rejected(self):
        helper = API["load_stage2_helper"](ROOT)
        name = "object.o"
        data = b"original"
        (self.work / name).write_bytes(b"modified")
        source = ["original.cpp", "a" * 64]
        recipe = {"compile_units_in_link_order": [[name, 0, *source]]}
        record = {"object": name, "original_flag_group": 0, "source": source[0], "source_sha256": source[1],
                  "object_bytes": len(data), "object_sha256": helper.digest(data)}
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            list(API["object_records"](helper, recipe, self.work, [record]))

    def test_numeric_corner_keeps_bayer_phase_and_rounds_ties_up(self):
        import numpy as np

        src = np.array([[101, 5, 103, 7], [9, 901, 10, 903],
                        [105, 11, 107, 13], [12, 905, 14, 907]], dtype=np.uint16)
        actual = API["interpolate_plane"](src, 0, 0, API["CROSS"], np)
        # Corner taps G=9,5,5,9; lower-left taps G=9,11,11,12.
        self.assertEqual(actual.tolist(), [[7, 8], [11, 12]])
        half = API["interpolate_plane"](src, 1, 0, API["HORIZONTAL"], np)
        self.assertEqual(half.tolist(), [[901, 902], [905, 906]])


if __name__ == "__main__":
    unittest.main()
