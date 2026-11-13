"""Asset-free guards for the K-3 III text clip verifier."""
import contextlib
from copy import deepcopy
from hashlib import sha256
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
CLI = ROOT / "tools/verify_colorspace_clip.py"


class TextClipGuards(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.api = runpy.run_path(str(CLI))
        self.main = self.api["main"]
        self.archive = self.api["ARCHIVE"]

    def test_optimized_mode_fails_before_imports(self):
        result = subprocess.run([sys.executable, "-O", "-I", "-S", str(CLI), "--help"],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Run without -O", result.stderr)

    def test_existing_output_and_hardlink_precede_archive_reads(self):
        source = self.folder / "original"
        source.write_bytes(b"keep")
        alias = self.folder / "hardlink"
        os.link(source, alias)
        for output in (source, alias, self.folder):
            self.assert_output_refused(output)
        self.assertEqual(source.read_bytes(), b"keep")

    def test_dangling_output_does_not_create_target(self):
        target = self.folder / "absent"
        link = self.folder / "link"
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symlinks unavailable: {error}")
        self.assert_output_refused(link)
        self.assertFalse(target.exists())

    def assert_output_refused(self, output):
        with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit) as error:
            self.main(["unused", "--compare", str(self.folder / "missing"), "--output", str(output)])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("Output already exists", stderr.getvalue())

    def test_compare_regular_file_bound_and_full_record_pin(self):
        reference = self.api["load_archive"](self.archive)
        output = self.folder / "output.json"
        compare = self.folder / "compare.json"
        args = ["unused", "--output", str(output), "--compare"]
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.main([*args, str(self.folder)])
        compare.write_bytes(bytes(self.api["ARCHIVE_LIMIT"] + 1))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            self.main([*args, str(compare)])
        compare.write_bytes(self.archive.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        self.assertEqual(self.api["load_archive"](compare), reference)
        changed = self.api["package"](reference, "one case: forged")
        compare.write_bytes(self.api["json_bytes"](changed))
        with self.assertRaisesRegex(ValueError, "metadata or serialization"):
            self.main([*args, str(compare)])
        reference["cases"][0]["unchanged_source_bitmap"] = 1
        compare.write_bytes(self.api["json_bytes"](self.api["package"](reference, "all seven cases")))
        with self.assertRaisesRegex(ValueError, "complete original observation"):
            self.main([*args, str(compare)])
        self.assertFalse(output.exists())

    def test_one_case_checks_full_digest_and_metadata(self):
        reference = self.api["load_archive"](self.archive)
        selected = {**reference, "cases": [reference["cases"][3]]}
        package = self.api["check_replay"](selected, reference, "upper_left")
        self.assertEqual(package["execution_scope"], "one case: upper_left")
        self.assertEqual(len(package["observations"]["cases"]), 1)
        mutations = [
            ("cases", [{**reference["cases"][3], "full_witness_sha256": "0" * 64}]),
            ("surface", {**reference["surface"], "size": [256, 145]}),
        ]
        for key, value in mutations:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "metadata or case witness"):
                self.api["check_replay"]({**selected, key: value}, reference, "upper_left")
        altered = deepcopy(reference)
        altered["cases"].pop()
        with self.assertRaisesRegex(ValueError, "complete replay observation"):
            self.api["check_replay"](altered, reference, None)

    def test_later_helper_drift_fails_before_first_helper_exec(self):
        namespace = self.main.__globals__
        first = self.api["TEXT_CLI"]
        later = "tools/_colorspace_text_replay.py"
        (self.folder / "tools").mkdir()
        (self.folder / "analysis").mkdir()
        marker = b"raise RuntimeError('first helper executed')\n"
        (self.folder / first).write_bytes(marker)
        (self.folder / later).write_bytes(b"wrong")
        for key in ("BASELINE", "CROSS"):
            (self.folder / self.api[key]).write_bytes((ROOT / self.api[key]).read_bytes())
        pins = {first: sha256(marker).hexdigest(), later: "0" * 64}
        output = self.folder / "out.json"
        with patch.dict(namespace, {"ROOT": self.folder, "PINS": pins}):
            with self.assertRaisesRegex(ValueError, f"SHA-256 mismatch: {later}"):
                self.main(["unused", "--output", str(output)])
        self.assertFalse(output.exists())

    def test_oversized_helper_is_refused_before_exec(self):
        name = self.api["TEXT_CLI"]
        helper = self.folder / name
        helper.parent.mkdir()
        data = b"raise RuntimeError('oversized helper executed')\n"
        limit = self.api["SOURCE_LIMIT"]
        data += b" " * (limit + 1 - len(data))
        helper.write_bytes(data)
        output = self.folder / "out.json"
        with patch.dict(self.main.__globals__, {"ROOT": self.folder, "PINS": {name: sha256(data).hexdigest()}}):
            with self.assertRaisesRegex(ValueError, f"{name} exceeds {limit} bytes"):
                self.main(["unused", "--output", str(output)])
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
