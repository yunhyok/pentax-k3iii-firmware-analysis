from hashlib import sha256
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import check_lightroom_sdk_stage2 as check


class Stage2Guards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_input_size_hash_and_regular_file(self):
        sample = self.root / "sample"
        sample.write_bytes(b"abcd")
        with self.assertRaisesRegex(ValueError, "type or size"):
            check.capture(sample, 3)
        with self.assertRaisesRegex(ValueError, "input size"):
            check.capture(sample, 4, size=3)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            check.capture(sample, 4, pin=sha256(b"abce").hexdigest())
        with self.assertRaisesRegex(ValueError, "regular file"):
            check.capture(self.root, 100)

    def test_lf_and_crlf_authored_fixture(self):
        path = self.root / "probe.cpp"
        expected = b"a\nb\n"
        path.write_bytes(b"a\r\nb\r\n")
        self.assertEqual(check.capture(path, 20, pin=sha256(expected).hexdigest(), normalize_lf=True), expected)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            check.capture(path, 20, pin=sha256(expected).hexdigest())

    def test_existing_work_path_rejected_before_inputs_under_optimization(self):
        saved = self.root / "saved"
        saved.write_bytes(b"existing input and output alias")
        run = subprocess.run(
            [sys.executable, "-B", "-O", check.__file__,
             "--work", str(saved), "--sdk", str(saved), "--zig", "missing", "--dng", "missing"],
            capture_output=True, check=False,
        )
        self.assertEqual(run.returncode, 1)
        self.assertIn(b"work directory must be a new path", run.stderr)
        self.assertEqual(saved.read_bytes(), b"existing input and output alias")

    def test_two_guards_preserve_surrounding_bytes(self):
        original = (b"start\n\t\t// XMP.\n\t\tEncode();\n\t\t// IPTC.\n"
                    b"void dng_jxl_decoder::ProcessXMPBox()\n{\n\tif (fInfo)\n\t{\n\t\tParse();\n\t}\n}\nend\n")
        expected = (b"start\n#if qDNGUseXMP\n\t\t// XMP.\n\t\tEncode();\n#endif\n\t\t// IPTC.\n"
                    b"void dng_jxl_decoder::ProcessXMPBox()\n{\n#if qDNGUseXMP\n\tif (fInfo)\n"
                    b"\t{\n\t\tParse();\n#endif\n\n\t}\n}\nend\n")
        self.assertEqual(check.with_xmp_guards(original), expected)

    def test_canonical_fields_reject_type_changes(self):
        fields = {"matches": True, "mismatches": 0, "stage2": {"samples": 25891840}}
        historical = {"stage2": {"samples": 25891840}, "mismatches": 0, "matches": True, "other": None}
        check.require_canonical_fields(fields, historical)
        for changes in ({"matches": 1}, {"mismatches": False}, {"stage2": {"samples": 25891840.0}}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "witness mismatch"):
                check.require_canonical_fields(fields, dict(historical, **changes))

    def test_dangling_output_symlink(self):
        target = self.root / "absent"
        link = self.root / "result.json"
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symbolic links unavailable: {error}")
        with self.assertRaises(FileExistsError):
            check.exclusive_bytes(link, b"one")
        self.assertTrue(link.is_symlink())
        self.assertFalse(target.exists())

    def test_new_output_and_exclusive_write(self):
        work = self.root / "work"
        self.assertEqual(check.new_work_path(work), work)
        work.mkdir()
        with self.assertRaisesRegex(ValueError, "new path"):
            check.new_work_path(work)
        result = work / "result.json"
        check.exclusive_bytes(result, b"one")
        with self.assertRaises(FileExistsError):
            check.exclusive_bytes(result, b"two")
        self.assertEqual(result.read_bytes(), b"one")


if __name__ == "__main__":
    unittest.main()
