"""Guards for the public selector/header replay; no firmware required."""
import errno
import importlib.util
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).resolve().parents[1] / 'verify_selector_policy.py'


class SelectorPolicyGuards(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = self.directory / 'decoded.bin'
        self.source.write_bytes(b'input sentinel')
        with self.source.open('r+b') as f:
            f.truncate(78683892)
        self.output = self.directory / 'report.json'

    def cli(self, output=None, flags=()):
        return subprocess.run([sys.executable, '-B', *flags, str(TOOL), str(self.source),
                               '--output', str(output or self.output)], capture_output=True, text=True, timeout=30)

    def helper_fixture(self):
        tool = Path(shutil.copyfile(TOOL, self.directory / TOOL.name))
        helper = self.directory / 'verify_update_bank_selection.py'
        shutil.copyfile(TOOL.parent / helper.name, helper)
        return tool, helper

    def helper_load(self, tool, flags=()):
        code = "import runpy,sys; m,e=runpy.run_path(sys.argv[1])['load_helper'](); assert m['DECODED_SHA']; print(e['executed_LF_sha256'])"
        return subprocess.run([sys.executable, '-B', *flags, '-c', code, str(tool)],
                              capture_output=True, text=True, timeout=30)

    def reject(self, result, text):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(text, result.stderr)

    def test_optimized_mode_rejected_before_optional_imports(self):
        self.reject(self.cli(flags=('-O', '-I', '-S')), 'Assertions required')
        self.assertFalse(os.path.lexists(self.output))

    def test_existing_output_input_hardlink_and_helper_preserved(self):
        self.output.write_bytes(b'report sentinel')
        _, helper = self.helper_fixture()
        helper_bytes = helper.read_bytes()
        alias = self.directory / 'alias.bin'
        os.link(self.source, alias)
        for path in (self.output, self.source, alias, helper, self.directory):
            with self.subTest(output=path.name):
                self.reject(self.cli(output=path, flags=('-I', '-S')), 'FileExistsError')
        self.assertEqual(self.output.read_bytes(), b'report sentinel')
        self.assertEqual(helper.read_bytes(), helper_bytes)
        for path in (self.source, alias):
            self.assertEqual(path.stat().st_size, 78683892)
            with path.open('rb') as f:
                self.assertEqual(f.read(14), b'input sentinel')

    def test_wrong_hash_rejected_before_optional_imports(self):
        self.reject(self.cli(flags=('-I', '-S')), 'Original decoded input hash mismatch')
        self.assertFalse(os.path.lexists(self.output))
        self.assertEqual(self.source.stat().st_size, 78683892)

    def test_modified_helper_never_executes(self):
        tool, helper = self.helper_fixture()
        helper.write_bytes(b"raise RuntimeError('UNVERIFIED_HELPER_EXECUTED')\n" + helper.read_bytes())
        result = self.helper_load(tool, flags=('-I', '-S'))
        self.reject(result, 'Helper source hash mismatch')
        self.assertNotIn('UNVERIFIED_HELPER_EXECUTED', result.stderr)

    def test_crlf_helper_uses_checked_LF_buffer(self):
        tool, helper = self.helper_fixture()
        helper.write_bytes(helper.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
        result = self.helper_load(tool)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('0618f4a8160f66f93c5ab385739a6f149a5cf9eda71c982f0502ca538a37650d', result.stdout)

    def test_unchecked_pyc_is_bypassed(self):
        tool, helper = self.helper_fixture()
        original = helper.read_bytes()
        helper.write_bytes(b"raise RuntimeError('UNCHECKED_PYC_EXECUTED')\n")
        py_compile.compile(str(helper), cfile=importlib.util.cache_from_source(str(helper)),
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        helper.write_bytes(original)
        normal = subprocess.run([sys.executable, '-B', '-c',
                                 "import sys; sys.path.insert(0,sys.argv[1]); import verify_update_bank_selection",
                                 str(self.directory)], capture_output=True, text=True, timeout=30)
        self.reject(normal, 'UNCHECKED_PYC_EXECUTED')
        checked = self.helper_load(tool)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertNotIn('UNCHECKED_PYC_EXECUTED', checked.stderr)

    def test_dangling_output_link_preserved(self):
        missing = self.directory / 'missing.json'
        try:
            self.output.symlink_to(missing.name)
        except NotImplementedError as exc:
            self.skipTest(str(exc))
        except OSError as exc:
            if exc.errno not in {errno.EPERM, errno.EACCES, errno.ENOSYS, errno.ENOTSUP} and getattr(exc, 'winerror', None) != 1314:
                raise
            self.skipTest(f'Symlink creation unavailable: {exc}')
        self.reject(self.cli(flags=('-I', '-S')), 'FileExistsError')
        self.assertEqual(self.output.readlink(), Path(missing.name))
        self.assertFalse(missing.exists())


if __name__ == '__main__':
    unittest.main()
