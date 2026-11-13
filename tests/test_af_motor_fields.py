"""Focused CLI and frozen observation checks without the original firmware."""

from copy import deepcopy
from hashlib import sha256
from importlib.util import find_spec
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "verify_af_motor_fields.py"
HELPER = ROOT / "verify_af_packet_8902.py"
ARCHIVE = ROOT / "analysis/af-motor-field-checks.json"


def cli(script, *args, flags=()):
    return subprocess.run([sys.executable, "-B", *flags, str(script), *map(str, args)],
                          capture_output=True, text=True, timeout=20)


class MotorFieldChecks(unittest.TestCase):
    def test_optimized_mode_is_rejected_before_imports(self):
        result = cli(CLI, "--help", flags=("-O", "-I", "-S"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("Run without -O", result.stderr)

    def test_public_archive_retains_both_complete_witnesses(self):
        record = json.loads(ARCHIVE.read_bytes())
        flags = record.pop("lens_info_flag_control")
        native_pin = record.pop("native_witness_sha256")
        flags_pin = record.pop("lens_info_flag_witness_sha256")
        def digest(data):
            return sha256((json.dumps(data, indent=2, allow_nan=False) + "\n").encode("utf-8")).hexdigest()
        self.assertEqual(digest(record), native_pin)
        self.assertEqual(digest(flags), flags_pin)
        self.assertEqual(len(record["cases"]), 10)
        self.assertEqual(len(flags["pairs"]), 12)
        for row in flags["pairs"]:
            zero, one = row["pair"]
            self.assertEqual((zero["flag"], one["flag"]), (0, 1))
            self.assertEqual(zero["ratio"], one["ratio"])
            self.assertEqual(zero["reads"][-1][0], "0x52f06744")
            self.assertEqual(one["reads"][-1][0], "0x52f06748")


@unittest.skipUnless(find_spec("unicorn"), "Unicorn is required to start the verifier")
class MotorFieldRuntimeGuards(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.source = self.folder / "input.bin"
        self.source.write_bytes(b"original")

    def test_existing_input_and_hardlink_aliases(self):
        hardlink = self.folder / "alias"
        os.link(self.source, hardlink)
        for target in (self.source, hardlink, self.folder):
            self.check_rejected_output(target)
        self.assertEqual(self.source.read_bytes(), b"original")

    def test_dangling_output_does_not_create_target(self):
        link, target = self.folder / "link", self.folder / "absent"
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symlinks unavailable: {error}")
        self.check_rejected_output(link)
        self.assertFalse(target.exists())

    def check_rejected_output(self, output):
        result = cli(CLI, self.source, "--output", output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("output already exists", result.stderr)

    def test_wrong_input_length_and_full_size_wrong_hash(self):
        output = self.folder / "new.json"
        for size, error in ((3, "carrier size"), (25_483_200, "carrier SHA-256")):
            with self.subTest(size=size), self.source.open("wb") as source:
                source.truncate(size)
            result = cli(CLI, self.source, "--output", output)
            self.assertEqual(result.returncode, 1)
            self.assertIn(error, result.stderr)
            self.assertFalse(output.exists())
            self.assertEqual(self.source.stat().st_size, size)

    def test_changed_helper_is_refused_before_execution(self):
        script = self.folder / CLI.name
        shutil.copyfile(CLI, script)
        (self.folder / HELPER.name).write_text("raise RuntimeError('unchecked helper executed')\n",
                                                encoding="utf-8")
        output = self.folder / "new.json"
        result = cli(script, self.source, "--output", output)
        self.assertEqual(result.returncode, 1)
        self.assertIn("verify_af_packet_8902.py SHA-256 mismatch", result.stderr)
        self.assertNotIn("unchecked helper executed", result.stderr)
        self.assertFalse(output.exists())

    def test_type_change_in_unprojected_observation_is_rejected(self):
        api = runpy.run_path(str(CLI))
        witness = json.loads(ARCHIVE.read_bytes())
        witness.pop("lens_info_flag_control")
        pin = witness.pop("native_witness_sha256")
        witness.pop("lens_info_flag_witness_sha256")
        api["verify_witness"](witness, pin, "native")
        changed = deepcopy(witness)
        changed["motor_56_68_nonzero_writer_identified"] = 0
        self.assertEqual(changed, witness)
        with self.assertRaisesRegex(ValueError, "native SHA-256 mismatch"):
            api["verify_witness"](changed, pin, "native")


if __name__ == "__main__":
    unittest.main()
