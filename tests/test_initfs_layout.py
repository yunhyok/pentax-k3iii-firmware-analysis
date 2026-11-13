"""Dependency, input and output guards for the INITFS layout replay."""
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


TOOL = Path(__file__).resolve().parents[1] / "verify_initfs_layout.py"


class InitfsLayoutGuards(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = self.directory / "decoded.bin"
        self.source.write_bytes(b"input sentinel")
        with self.source.open("r+b") as stream:
            stream.truncate(78683892)
        self.output = self.directory / "report.json"

    def run_cli(self, *, tool=TOOL, output=None, python_flags=()):
        return subprocess.run(
            [sys.executable, "-B", *python_flags, str(tool), str(self.source),
             "--output", str(output if output is not None else self.output)],
            capture_output=True, text=True, timeout=30,
        )

    def assert_rejected(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)

    def test_dependency_drift_prevents_import_and_crlf_is_accepted(self):
        tool = Path(shutil.copyfile(TOOL, self.directory / TOOL.name))
        name = "verify_update_bank_selection.py"
        dependency = self.directory / name
        original = (TOOL.parent / name).read_bytes().replace(b"\r\n", b"\n")
        crlf = original.replace(b"\n", b"\r\n")
        dependency.write_bytes(crlf)
        self.assert_rejected(self.run_cli(tool=tool), "Unknown decoded input SHA-256")
        dependency.write_bytes(b"raise RuntimeError('executed unverified dependency')\r\n" + crlf)
        result = self.run_cli(tool=tool, python_flags=("-S",))
        self.assert_rejected(result, f"Dependency SHA-256 mismatch: {name}")
        self.assertNotIn("executed unverified dependency", result.stderr)
        self.assertFalse(os.path.lexists(self.output))

    def test_unchecked_bytecode_cannot_replace_pinned_dependency(self):
        tool = Path(shutil.copyfile(TOOL, self.directory / TOOL.name))
        dependency = self.directory / "verify_update_bank_selection.py"
        dependency.write_bytes(b"raise RuntimeError('unchecked dependency cache')\n")
        py_compile.compile(str(dependency), cfile=importlib.util.cache_from_source(str(dependency)),
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        shutil.copyfile(TOOL.parent / dependency.name, dependency)
        result = self.run_cli(tool=tool)
        self.assert_rejected(result, "Unknown decoded input SHA-256")
        self.assertNotIn("unchecked dependency cache", result.stderr)
        self.assertFalse(os.path.lexists(self.output))

    def test_existing_output_and_source_aliases_are_preserved(self):
        self.output.write_bytes(b"report sentinel")
        alias = self.directory / "alias.bin"
        os.link(self.source, alias)
        for path in (self.output, self.source, alias, self.directory):
            with self.subTest(output=path.name):
                self.assert_rejected(self.run_cli(output=path, python_flags=("-I", "-S")), "FileExistsError")
        self.assertEqual(self.output.read_bytes(), b"report sentinel")
        for path in (self.source, alias):
            self.assertEqual(path.stat().st_size, 78683892)
            with path.open("rb") as stream:
                self.assertEqual(stream.read(14), b"input sentinel")

    def test_dangling_output_link_is_preserved(self):
        missing = self.directory / "missing.json"
        try:
            self.output.symlink_to(missing.name)
        except NotImplementedError as exc:
            self.skipTest(str(exc))
        except OSError as exc:
            unavailable = exc.errno in {errno.EPERM, errno.EACCES, errno.ENOSYS, errno.ENOTSUP}
            if not unavailable and getattr(exc, "winerror", None) != 1314:
                raise
            self.skipTest(f"File symlinks are unavailable: {exc}")
        self.assert_rejected(self.run_cli(python_flags=("-I", "-S")), "FileExistsError")
        self.assertEqual(self.output.readlink(), Path(missing.name))
        self.assertFalse(missing.exists())

    def test_correct_decoded_size_with_wrong_hash_is_rejected(self):
        self.assert_rejected(self.run_cli(), "Unknown decoded input SHA-256")
        self.assertEqual(self.source.stat().st_size, 78683892)
        with self.source.open("rb") as stream:
            self.assertEqual(stream.read(14), b"input sentinel")
        self.assertFalse(os.path.lexists(self.output))

    def test_split_sized_input_is_rejected_before_imports(self):
        with self.source.open("r+b") as stream:
            stream.truncate(25483200)
        result = self.run_cli(python_flags=("-I", "-S"))
        self.assert_rejected(result, "Original decoded carrier")
        self.assertFalse(os.path.lexists(self.output))

    def test_optimized_mode_is_rejected_before_imports(self):
        self.assert_rejected(self.run_cli(python_flags=("-O", "-I", "-S")), "Assertions required")
        self.assertFalse(os.path.lexists(self.output))


if __name__ == "__main__":
    unittest.main()
