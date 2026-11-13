"""Guard and evidence-contract checks for the mode-1 replays without firmware."""

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
TAIL = "verify_af_reset_tail.py"
PARAMETERS = "verify_af_mode1_parameters.py"
FEEDBACK = "verify_af_request3_feedback.py"
UDC = "verify_af_udc_binding.py"
SERVICE = "verify_af_service_binding.py"
PACKET = "verify_af_packet_8902.py"
CHAIN = (FEEDBACK, PARAMETERS, UDC, SERVICE, PACKET)


def run_cli(tool, *args, flags=()):
    return subprocess.run(
        [sys.executable, "-B", *flags, str(tool), *map(str, args)],
        capture_output=True, text=True, timeout=30,
    )


class TrustGuards(unittest.TestCase):
    def test_all_clis_reject_optimized_mode_before_imports(self):
        for tool in (TAIL, PARAMETERS, FEEDBACK):
            with self.subTest(tool=tool):
                result = run_cli(ROOT / tool, "--help", flags=("-O", "-I", "-S"))
                self.assertEqual(result.returncode, 1)
                self.assertIn("Run without -O", result.stderr)

    def test_feedback_rejects_each_untrusted_source_before_its_execution(self):
        for dependency in CHAIN[1:]:
            with self.subTest(dependency=dependency), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                for name in CHAIN:
                    shutil.copyfile(ROOT / name, folder / name)
                (folder / dependency).write_text("raise RuntimeError('unverified body executed')\n", encoding="utf-8")
                result = run_cli(folder / FEEDBACK, "--help", flags=("-I", "-S"))
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"Dependency SHA-256 mismatch: {dependency}", result.stderr)
                self.assertNotIn("unverified body executed", result.stderr)

    @unittest.skipUnless(find_spec("unicorn"), "Unicorn is required to start the verifiers")
    def test_input_alias_is_preserved_and_invalid_input_creates_no_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            source, alias, output = (folder / name for name in ("input.bin", "alias", "result.json"))
            source.write_bytes(b"original")
            os.link(source, alias)
            for tool in (TAIL, PARAMETERS, FEEDBACK):
                with self.subTest(tool=tool):
                    denied = run_cli(ROOT / tool, folder / "missing", "--output", alias)
                    self.assertEqual(denied.returncode, 2)
                    self.assertIn("--output must be a new path", denied.stderr)
                    invalid = run_cli(ROOT / tool, source, "--output", output)
                    self.assertEqual(invalid.returncode, 1)
                    self.assertIn("unexpected RTOS or decoded carrier size", invalid.stderr)
                    self.assertFalse(output.exists())
            self.assertEqual(source.read_bytes(), b"original")
            self.assertEqual(alias.read_bytes(), b"original")


class EvidenceContracts(unittest.TestCase):
    def test_feedback_uses_separate_numeric_input_after_first_read_stop(self):
        data = json.loads((ROOT / "analysis/af-request3-feedback-checks.json").read_bytes())
        for row in data["cases"]:
            with self.subTest(case=row["case"]):
                stages = row["stages_name_entry_stop"]
                first, numeric = stages[-2:]
                self.assertEqual(first[2], 0x5326D5E8)
                self.assertIn(numeric[1], (0x52F0C7D8, 0x52F0C9F0))
                self.assertIn("input_u16", row["numeric_fixtures"])
                self.assertEqual(numeric[2], row["boundary_pc"])
                self.assertEqual(row["mapped_rtos_sha256"], data["rtos_sha256"])

    def test_same_numeric_result_does_not_hide_a_different_rom_branch(self):
        data = json.loads((ROOT / "analysis/af-request3-feedback-checks.json").read_bytes())
        rows = {row["case"]: row["measured_or_validated"] for row in data["cases"]}
        last, fallback = rows["bucket_last_2900"], rows["bucket_overflow_2901"]
        self.assertEqual(last["output_5a_u16"], fallback["output_5a_u16"])
        self.assertEqual(len(last["table_reads_pc_address_u16"]), 2)
        self.assertEqual(len(fallback["table_reads_pc_address_u16"]), 1)
        self.assertEqual(rows["override_bypasses_lut"]["output_5a_u16"], 5)
        self.assertEqual(rows["override_bypasses_lut"]["output_5c_u16"], 300)
