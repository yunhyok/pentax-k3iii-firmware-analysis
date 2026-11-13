"""Asset-free checks for the AF driver/PWM verifier."""

import contextlib
import hashlib
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "verify_af_driver_pwm.py"


class DriverPwmGuards(unittest.TestCase):
    def test_optimized_mode_rejects_before_imports(self):
        result = subprocess.run([sys.executable, "-O", "-I", "-S", str(CLI), "--help"],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Run without -O", result.stderr)

    def test_existing_output_aliases_reject_before_helpers(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source"
            alias = Path(folder) / "hardlink"
            source.write_bytes(b"original")
            os.link(source, alias)
            api = runpy.run_path(str(CLI))["main"]
            with patch.dict(api.__globals__, {"ROOT": Path(folder)}):
                for output in (source, alias, Path(folder)):
                    with self.subTest(output=output), contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit) as error:
                        api([str(source), "--output", str(output)])
                    self.assertEqual(error.exception.code, 2)
                    self.assertIn("output already exists", stderr.getvalue())
            self.assertEqual(source.read_bytes(), b"original")

    def test_dangling_output_does_not_create_target(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "absent"
            link = Path(folder) / "link"
            try:
                link.symlink_to(target)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"symlinks unavailable: {error}")
            api = runpy.run_path(str(CLI))["main"]
            with patch.dict(api.__globals__, {"ROOT": Path(folder)}):
                with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit) as error:
                    api(["unavailable", "--output", str(link)])
            self.assertEqual(error.exception.code, 2)
            self.assertIn("output already exists", stderr.getvalue())
            self.assertFalse(target.exists())

    def test_both_helpers_are_checked_before_first_execution(self):
        api = runpy.run_path(str(CLI))["main"]
        first, second = api.__globals__["HELPERS"]
        first_code = b"raise RuntimeError('first helper executed before second check')\n"
        second_code = b"raise RuntimeError('tampered second helper executed')\n"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / first).write_bytes(first_code)
            (root / second).write_bytes(second_code)
            output = root / "out.json"
            with patch.dict(api.__globals__, {"ROOT": root,
                                             "HELPERS": {first: hashlib.sha256(first_code).hexdigest(), second: "0" * 64}}):
                with self.assertRaisesRegex(ValueError, f"{second} SHA-256 mismatch"):
                    api(["unavailable", "--output", str(output)])
            self.assertFalse(output.exists())

    def test_hidden_observation_mutation_rejects_before_projection(self):
        verify = runpy.run_path(str(CLI))["verify_and_project"]
        serialize = verify.__globals__["json_bytes"]
        alias = {"only_in_full_witness": False}
        service = {"source_spans": {"one": {"a32_disassembly": ["expected"]}}}
        pins = {"ALIAS_WITNESS": hashlib.sha256(serialize(alias)).hexdigest(),
                "SERVICE_WITNESS": hashlib.sha256(serialize(service)).hexdigest()}
        with patch.dict(verify.__globals__, pins):
            with self.assertRaisesRegex(ValueError, "Motor alias complete witness"):
                verify({"only_in_full_witness": 0}, service)
            changed = {"source_spans": {"one": {"a32_disassembly": ["different"]}}}
            with self.assertRaisesRegex(ValueError, "Driver/Pwm complete witness"):
                verify(alias, changed)


if __name__ == "__main__":
    unittest.main()
