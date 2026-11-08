"""Regression checks for destructive report paths, optimized execution, and metadata preservation."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tracemalloc
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from verify_package_roundtrip import compare_outer
from inspect_firmware import decode


class VerifierGuards(unittest.TestCase):
    def test_empty_blocks_reject_before_metadata_growth(self):
        for block in (b'\x80\x00', b'\x00\x02\x00\x00'):
            stream = block * 50000 + b'\0\0'
            tracemalloc.start()
            try:
                with self.assertRaisesRegex(ValueError, 'empty nonterminal block at 0x0'):
                    decode(stream, 0)
                self.assertLess(tracemalloc.get_traced_memory()[1], 1024*1024)
            finally:
                tracemalloc.stop()

    def test_outer_invariants_and_allowed_length_checksum_changes(self):
        original = bytearray(512)
        edited = bytearray(original)
        info = {'version_start': 232, 'footer_start': 488}
        edited[500:504] = b'len!'
        edited[508:512] = b'sum!'
        compare_outer(original, edited, info, info)
        for offset, message in [(100, 'header'), (240, 'Version'), (488, 'footer'), (504, 'footer')]:
            with self.subTest(offset=offset):
                bad = bytearray(edited);bad[offset] ^= 1
                with self.assertRaisesRegex(ValueError, message):
                    compare_outer(original, bad, info, info)

    def test_existing_output_and_hardlink_fail_before_input_validation(self):
        if importlib.util.find_spec('unicorn') is None:
            self.skipTest('Unicorn is required to import the ICON/AF verification CLIs')
        tools = [('verify_package_roundtrip.py', 4), ('verify_icon_resources.py', 1),
                 ('verify_af_commands.py', 1), ('verify_af_drive_selection.py', 1),
                 ('verify_af_capability.py', 1), ('verify_af_request_consumer.py', 1),
                 ('verify_colorspace_ui.py', 1), ('verify_colorspace_ui_input.py', 1),
                 ('verify_update_file_loader.py', 1), ('verify_update_allocator.py', 1)]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'source.bin';source.write_bytes(b'input sentinel')
            alias = Path(directory)/'hardlink.bin';os.link(source, alias)
            for tool, nargs in tools:
                for output in (source, alias):
                    with self.subTest(tool=tool, output=output.name):
                        result = subprocess.run([sys.executable, str(ROOT/tool), *([str(source)]*nargs),
                                                 '--output', str(output)], capture_output=True, text=True)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertRegex(result.stderr, '(?i)report.*exists')
                        self.assertEqual(source.read_bytes(), b'input sentinel')
                        self.assertEqual(alias.read_bytes(), b'input sentinel')

    def test_optimized_interpreter_is_rejected_before_loading_unicorn(self):
        for tool in ('verify_icon_resources.py', 'verify_af_commands.py', 'verify_af_drive_selection.py',
                     'verify_af_capability.py', 'verify_af_request_consumer.py', 'verify_colorspace_ui.py',
                     'verify_colorspace_ui_input.py', 'verify_update_file_loader.py',
                     'verify_update_allocator.py', 'tools/verify_qflag_scope.py'):
            with self.subTest(tool=tool):
                result = subprocess.run([sys.executable, '-O', str(ROOT/tool), '--help'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Verification requires assertions', result.stderr)


if __name__ == '__main__':
    unittest.main()
