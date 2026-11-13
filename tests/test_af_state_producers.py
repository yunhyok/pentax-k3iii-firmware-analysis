"""Asset-free checks for the PafMotor static verifier."""
from copy import deepcopy
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
CLI = ROOT / "verify_af_state_producers.py"
PUBLIC = ROOT / "analysis/af-state-producer-checks.json"
spec = importlib.util.spec_from_file_location("af_state_verifier", CLI)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class StateProducerGuards(TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.output = self.work / "output.json"

    def run_cli(self, carrier, output, *flags):
        return subprocess.run(
            [sys.executable, "-B", "-S", *flags, str(CLI), str(carrier), "--output", str(output)],
            capture_output=True,
        )

    def test_bad_carrier_rejected_before_optional_import(self):
        carrier = self.work / "short.bin"
        carrier.write_bytes(b"not a firmware")
        result = self.run_cli(carrier, self.output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"unexpected carrier size or file type", result.stderr)
        self.assertNotIn(b"capstone", result.stderr)
        self.assertFalse(self.output.exists())

    def test_same_size_wrong_digest(self):
        carrier = self.work / "candidate.bin"
        carrier.write_bytes(b"\x00\x00\x00\x00")
        with patch.object(verifier, "RTOS_SIZE", 4):
            with self.assertRaisesRegex(ValueError, "wrong original carrier SHA"):
                verifier.load(carrier)

    def test_existing_output_hardlink_is_preserved(self):
        source = self.work / "sentinel"
        source.write_bytes(b"keep")
        os.link(source, self.output)
        result = self.run_cli(self.work / "missing.bin", self.output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"expected a new output", result.stderr)
        self.assertEqual(source.read_bytes(), b"keep")
        self.assertEqual(self.output.read_bytes(), b"keep")

    def test_dangling_output_link_rejected_without_creating_target(self):
        target = self.work / "absent"
        try:
            self.output.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symbolic links unavailable: {exc}")
        result = self.run_cli(self.work / "missing.bin", self.output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"expected a new output", result.stderr)
        self.assertTrue(self.output.is_symlink())
        self.assertFalse(target.exists())

    def test_optimized_mode_fails_before_work(self):
        result = self.run_cli(self.work / "missing.bin", self.output, "-O")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Run without -O", result.stderr)
        self.assertFalse(self.output.exists())

    def test_full_witness_type_and_byte_guards(self):
        published = json.loads(PUBLIC.read_bytes())
        original = published["observations"]
        self.assertEqual(verifier.verify_and_package(original, published["public_verifier_lf_sha256"]), published)
        for key, value in (("schema", True), ("schema", 1.0)):
            altered = deepcopy(original)
            altered[key] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "typed witness"):
                verifier.verify_and_package(altered, published["public_verifier_lf_sha256"])
        reversed_keys = dict(reversed(tuple(original.items())))
        with self.assertRaisesRegex(ValueError, "serialized witness"):
            verifier.verify_and_package(reversed_keys, published["public_verifier_lf_sha256"])

    def test_crlf_compare_and_mismatch(self):
        expected = verifier.json_bytes({"schema": 1})
        self.output.write_bytes(expected.replace(b"\n", b"\r\n"))
        verifier.check_compare(self.output, expected)
        self.output.write_bytes(verifier.json_bytes({"schema": True}))
        with self.assertRaisesRegex(ValueError, "differs from --compare"):
            verifier.check_compare(self.output, expected)
