"""CLI guard checks for the Stubby ROMFS verifier using synthetic files."""
import errno
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOL = Path(__file__).resolve().parents[1] / 'verify_stubby_romfs.py'


def run_cli(*args, python_flags=()):
    return subprocess.run(
        [sys.executable, '-B', *python_flags, str(TOOL), *map(str, args)],
        capture_output=True, text=True, timeout=30,
    )


@unittest.skipUnless(importlib.util.find_spec('unicorn'), 'Unicorn is required by the verifier')
class StubbyRomfsGuards(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = self.directory / 'source.bin'
        self.output = self.directory / 'report.json'

    def assert_cli_rejects(self, output, error):
        result = run_cli(self.source, '--output', output)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertRegex(result.stderr, error)

    def test_existing_output_and_input_aliases_are_preserved(self):
        self.source.write_bytes(b'input sentinel')
        self.output.write_bytes(b'report sentinel')
        alias = self.directory / 'hardlink.bin'
        os.link(self.source, alias)

        for output in (self.output, self.source, alias):
            with self.subTest(output=output.name):
                self.assert_cli_rejects(output, r'(?i)(?:report|output).*exists')
                self.assertEqual(self.source.read_bytes(), b'input sentinel')
                self.assertEqual(alias.read_bytes(), b'input sentinel')
                self.assertEqual(self.output.read_bytes(), b'report sentinel')

    def test_dangling_output_symlink_is_preserved(self):
        self.source.write_bytes(b'input sentinel')
        target = self.directory / 'missing.json'
        try:
            self.output.symlink_to(target.name)
        except NotImplementedError as exc:
            self.skipTest(str(exc))
        except OSError as exc:
            unavailable = exc.errno in {errno.EPERM, errno.EACCES, errno.ENOSYS, errno.ENOTSUP}
            if not unavailable and getattr(exc, 'winerror', None) != 1314:
                raise
            self.skipTest(f'File symlinks are unavailable: {exc}')

        self.assert_cli_rejects(self.output, r'(?i)(?:report|output).*exists')
        self.assertEqual(self.output.readlink(), Path(target.name))
        self.assertFalse(target.exists())
        self.assertEqual(self.source.read_bytes(), b'input sentinel')

    def test_correct_size_wrong_hash_is_rejected(self):
        data = bytes(3062784)
        self.source.write_bytes(data)

        self.assert_cli_rejects(self.output, r'Unknown input SHA256')
        self.assertFalse(os.path.lexists(self.output))
        self.assertEqual(self.source.read_bytes(), data)


class StubbyRomfsOptimizationGuard(unittest.TestCase):
    def test_optimized_mode_is_rejected_without_dependency_imports(self):
        result = run_cli('--help', python_flags=('-O', '-I', '-S'))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertRegex(result.stderr, r'(?i)(?:requires assertions|assertions required)')
