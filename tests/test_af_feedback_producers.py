"""Public evidence and executable trust checks without the firmware inputs."""
from importlib.util import find_spec
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = "verify_af_feedback_producers.py"
CHAIN = ("verify_af_request3_feedback.py", "verify_af_mode1_parameters.py",
         "verify_af_udc_binding.py", "verify_af_service_binding.py", "verify_af_packet_8902.py")


def run_cli(path, *args, flags=()):
    return subprocess.run([sys.executable, "-B", *flags, str(path), *map(str, args)],
                          capture_output=True, text=True, timeout=30)


class FeedbackProducerGuards(unittest.TestCase):
    def test_optimized_mode_is_rejected_before_imports(self):
        result = run_cli(ROOT / CLI, "--help", flags=("-O", "-I", "-S"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("Run without -O", result.stderr)

    def test_each_dependency_is_checked_before_its_source_executes(self):
        for dependency in CHAIN:
            with self.subTest(dependency=dependency), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                for name in (CLI, *CHAIN):
                    shutil.copyfile(ROOT / name, folder / name)
                (folder / dependency).write_text("raise RuntimeError('untrusted helper executed')\n", encoding="utf-8")
                result = run_cli(folder / CLI, "--help", flags=("-I", "-S"))
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"Dependency SHA-256 mismatch: {dependency}", result.stderr)
                self.assertNotIn("untrusted helper executed", result.stderr)

    @unittest.skipUnless(find_spec("unicorn"), "Unicorn is required to start the verifier")
    def test_protected_output_aliases_and_bad_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            source = folder / "input.bin"
            source.write_bytes(b"original")
            hardlink = folder / "hardlink.json"
            os.link(source, hardlink)
            for output in (source, hardlink):
                with self.subTest(output=output.name):
                    self.reject_output(source, output)
            output = folder / "fresh.json"
            invalid = run_cli(ROOT / CLI, source, "--output", output)
            self.assertEqual(invalid.returncode, 1)
            self.assertIn("unexpected RTOS or decoded carrier size", invalid.stderr)
            self.assertFalse(output.exists())
            self.assertEqual(source.read_bytes(), b"original")
            self.assertEqual(hardlink.read_bytes(), b"original")

    @unittest.skipUnless(find_spec("unicorn"), "Unicorn is required to start the verifier")
    def test_live_and_dangling_symlinks_are_rejected_at_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            source, missing = folder / "input.bin", folder / "missing.json"
            source.write_bytes(b"original")
            for target in (source, missing):
                link = target.with_suffix(".link")
                try:
                    link.symlink_to(target)
                except (NotImplementedError, OSError) as exc:
                    self.skipTest(f"Symlink creation unavailable: {exc}")
                self.reject_output(source, link)
            self.assertFalse(missing.exists())
            self.assertEqual(source.read_bytes(), b"original")

    def reject_output(self, source, output):
        denied = run_cli(ROOT / CLI, source, "--output", output)
        self.assertEqual(denied.returncode, 2)
        self.assertIn("--output must be a new file", denied.stderr)


class FeedbackProducerEvidence(unittest.TestCase):
    def test_canonical_observations_keep_the_numeric_seam_and_negative_control(self):
        record = json.loads((ROOT / "analysis/af-feedback-producer-checks.json").read_bytes())
        expected = (
            ("0x52cb2c64", 737, 337, -56, "0x52f0ca70"),
            ("0x52cb2c64", 0xFFFFFFF3, 65423, 18, "0x52f0c78c"),
            ("0x52cb2e28", 65, 81, 41, "0x52f0c78c"),
            ("0x52cb2e28", 0xFFFFFFC7, 65299, 87, "0x52f0c78c"),
        )
        for row, (pc, baseline, delta, remainder, stop) in zip(record["cases"], expected, strict=True):
            with self.subTest(case=row["fixtures"]):
                self.assertEqual(row["writes"][4], ["pulse_a88", pc, 0, 4, baseline])
                self.assertEqual(row["fields"]["pulse_5a"], delta)
                self.assertEqual(row["consumer_signed_remainder"], remainder)
                self.assertEqual(row["consumer_stop_pc"], stop)
                self.assertEqual(row["stages"][-1][1:], [0x52F0C9F0, int(stop, 16)])
                self.assertEqual(row["mapped_rtos_sha256"], record["rtos_sha256"])
                if remainder < 0:
                    self.assertIsNone(row["request3_arguments"])
                else:
                    self.assertEqual(row["request3_arguments"][1:], [remainder, 0, 3])


if __name__ == "__main__":
    unittest.main()
