"""AF PWM CLI guards without firmware or Unicorn."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "verify_af_pwm_parameters.py"
ARCHIVE = ROOT / "analysis/af-pwm-parameter-checks.json"


class PwmGuards(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.api = runpy.run_path(str(CLI))
        self.main = self.api["main"]

    def test_optimized_mode_is_rejected_before_imports(self):
        result = subprocess.run([sys.executable, "-O", "-I", "-S", str(CLI), "--help"],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Run without -O", result.stderr)

    def check_rejected_output(self, output):
        with patch.dict(self.main.__globals__, {"ROOT": self.folder}), \
                contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit) as error:
            self.main(["unavailable.bin", "--output", str(output)])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("output already exists", stderr.getvalue())

    def test_existing_input_and_hardlink_are_rejected(self):
        source = self.folder / "original"
        source.write_bytes(b"keep")
        alias = self.folder / "alias"
        os.link(source, alias)
        for output in (source, alias, self.folder):
            self.check_rejected_output(output)
        self.assertEqual(source.read_bytes(), b"keep")

    def test_dangling_output_does_not_create_target(self):
        target = self.folder / "absent"
        link = self.folder / "link"
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symlinks unavailable: {error}")
        self.check_rejected_output(link)
        self.assertFalse(target.exists())

    def test_second_helper_is_checked_before_first_execution(self):
        first, second = self.api["HELPERS"]
        source = b"raise RuntimeError('unexpected first helper execution')\n"
        (self.folder / first).write_bytes(source)
        (self.folder / second).write_bytes(b"tampered")
        pins = {first: hashlib.sha256(source).hexdigest(), second: "0" * 64}
        output = self.folder / "out.json"
        with patch.dict(self.main.__globals__, {"ROOT": self.folder, "HELPERS": pins}):
            with self.assertRaisesRegex(ValueError, f"{second} SHA-256 mismatch"):
                self.main(["unavailable.bin", "--output", str(output)])
        self.assertFalse(output.exists())

    def test_whole_witness_gate_rejects_value_type_and_order_mutations(self):
        public = json.loads(ARCHIVE.read_bytes())
        record = public["observations"]
        package = self.api["verify_and_package"]
        verifier_pin = hashlib.sha256(CLI.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        self.assertEqual(self.api["json_bytes"](package(record, verifier_pin)),
                         ARCHIVE.read_bytes().replace(b"\r\n", b"\n"))

        record["runs"][0]["poison"] = 0
        with self.assertRaisesRegex(ValueError, "typed witness"):
            package(record, verifier_pin)
        record["runs"][0]["poison"] = False
        reordered = dict(reversed(tuple(record.items())))
        with self.assertRaisesRegex(ValueError, "serialized witness"):
            package(reordered, verifier_pin)

    def test_compare_regular_file_size_and_no_output_on_mismatch(self):
        compare = self.folder / "reference.json"
        output = self.folder / "out.json"
        payload = self.api["json_bytes"]({"expected": False})
        check_compare = self.api["check_compare"]
        compare.write_bytes(payload.replace(b"\n", b"\r\n"))
        check_compare(compare, payload)

        with patch.dict(self.main.__globals__, {
            "load_helpers": lambda: (self, self),
            "replay_all": lambda *_: None,
            "verify_and_package": lambda *_: {"expected": False},
        }):
            self.__version__ = "2.1.4"
            self.read_image = lambda _: b""
            args = ["unused.bin", "--output", str(output), "--compare"]
            with self.assertRaisesRegex(ValueError, "regular file"):
                self.main([*args, str(self.folder)])
            compare.write_bytes(payload + b" " * 20)
            with self.assertRaisesRegex(ValueError, "exceeds"):
                self.main([*args, str(compare)])
            compare.write_bytes(payload.replace(b"false", b"true "))
            with self.assertRaisesRegex(ValueError, "differs"):
                self.main([*args, str(compare)])
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
