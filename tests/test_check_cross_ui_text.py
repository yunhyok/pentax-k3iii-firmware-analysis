"""Arithmetic and fail-closed tests for the public cross-UI text checker."""
import importlib.util
from hashlib import sha256
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools/check_cross_ui_text.py"
SPEC = importlib.util.spec_from_file_location("check_cross_ui_text", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class Arithmetic(unittest.TestCase):
    def test_q16_center_quantization_and_widths(self):
        width, step, columns = checker.q7_columns(24)
        self.assertEqual((width,step,columns[:4]),(18,87381,[0,1,3,4]))
        self.assertEqual((3*24)//(2*18),2)
        self.assertEqual((2*24)//18,2)
        self.assertEqual([checker.q7_columns(n)[0] for n in (24,29,34,29)],[18,21,25,21])
        with self.assertRaises(ValueError):
            checker.q7_columns(1)

    def test_source_encoding_and_iii_word(self):
        self.assertEqual(checker.q7_codes(0x1b),[0,1,2,3])
        self.assertEqual(checker.blend_word(0xffffffff,0x31425364,0.4,0.6),0x838d97a2)
        with self.assertRaises(ValueError):
            checker.q7_codes(256)

    def test_geometry_overlap_and_touching_edge(self):
        self.assertEqual(checker.overlap([110,22,76,40],[110,22,80,40]),[110,22,76,40])
        self.assertEqual(checker.overlap([3,4,9,8],[6,7,10,5]),[6,7,6,5])
        self.assertEqual(checker.overlap([3,4,9,8],[12,7,10,5]),[12,7,0,5])


class GuardTests(unittest.TestCase):
    def test_optimized_mode_exits_before_argument_parsing(self):
        result = subprocess.run([sys.executable,"-I","-S","-B","-O",str(SCRIPT)],
                                capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("Run without -O",result.stderr)

    def test_crlf_source_and_changed_input(self):
        with TemporaryDirectory() as folder:
            path = Path(folder)/"record.json"
            canonical = b'{"x":1}\n'
            expected = sha256(canonical).hexdigest()
            path.write_bytes(canonical.replace(b"\n",b"\r\n"))
            self.assertEqual(checker.capture_record(path,expected),canonical)
            path.write_bytes(b'{"x":2}\n')
            with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
                checker.capture_record(path,expected)
            with path.open("wb") as source:
                source.truncate(checker.MAX_RECORD_BYTES+1)
            with self.assertRaisesRegex(ValueError,"size mismatch"):
                checker.capture_record(path,expected)

    def test_existing_and_hardlinked_outputs_are_preserved(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            original = root/"source.json"
            original.write_bytes(b"pinned source")
            alias = root/"hardlink.json"
            alias.hardlink_to(original)
            with patch.object(checker,"capture_record") as read:
                for output in (original,alias):
                    with self.subTest(output=output.name), self.assertRaises(SystemExit):
                        checker.main(["--q7-root",str(root),"--output",str(output)])
                read.assert_not_called()
            self.assertEqual(original.read_bytes(),b"pinned source")
            self.assertEqual(alias.read_bytes(),b"pinned source")

    def test_dangling_output_is_preserved(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            missing = root/"missing.json"
            link = root/"link.json"
            try:
                link.symlink_to(missing)
            except OSError as error:
                self.skipTest(f"Symlink unavailable: {error}")
            with patch.object(checker,"capture_record") as read, self.assertRaises(SystemExit):
                checker.main(["--q7-root",str(root),"--output",str(link)])
            read.assert_not_called()
            self.assertTrue(link.is_symlink())
            self.assertFalse(missing.exists())

    def test_all_records_pin_before_parsing_or_output(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            good = b'{"tested":true}\n'
            pin = sha256(good).hexdigest()
            (root/"first.json").write_bytes(good)
            (root/"last.json").write_bytes(b'{"tested":false}\n')
            sources = {"iii":{"first.json":pin},"q7":{"last.json":pin}}
            output = root/"new.json"
            with patch.object(checker,"SOURCES",sources), patch.object(checker.json,"loads") as parse:
                with self.assertRaises(SystemExit):
                    checker.main(["--iii-root",str(root),"--q7-root",str(root),"--output",str(output)])
                parse.assert_not_called()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
