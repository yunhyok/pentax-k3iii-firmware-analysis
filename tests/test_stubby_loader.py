"""Dependency, input and output guards for the Stubby loader replay."""
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


TOOL = Path(__file__).resolve().parents[1] / "verify_stubby_loader.py"


class StubbyLoaderGuards(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = self.directory / "decoded.bin"
        self.source.write_bytes(b"input sentinel")
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
        dependencies = ("verify_stubby_romfs.py", "verify_stubby_load_auth.py")
        for name in dependencies:
            original = (TOOL.parent / name).read_bytes().replace(b"\r\n", b"\n")
            (self.directory / name).write_bytes(original.replace(b"\n", b"\r\n"))
        self.assert_rejected(self.run_cli(tool=tool), "Unknown input size")
        for name in dependencies:
            with self.subTest(dependency=name):
                dependency = self.directory / name
                original = dependency.read_bytes()
                dependency.write_bytes(b"raise RuntimeError('executed unverified dependency')\r\n" + original)
                result = self.run_cli(tool=tool, python_flags=("-S",))
                self.assert_rejected(result, f"Dependency SHA-256 mismatch: {name}")
                self.assertNotIn("executed unverified dependency", result.stderr)
                self.assertFalse(os.path.lexists(self.output))
                dependency.write_bytes(original)

    def test_unchecked_bytecode_cannot_replace_a_pinned_dependency(self):
        tool = Path(shutil.copyfile(TOOL, self.directory / TOOL.name))
        auth = self.directory / "verify_stubby_load_auth.py"
        auth.write_bytes(b"raise RuntimeError('unchecked dependency cache')\n")
        py_compile.compile(str(auth), cfile=importlib.util.cache_from_source(str(auth)),
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        for name in (auth.name, "verify_stubby_romfs.py"):
            shutil.copyfile(TOOL.parent / name, self.directory / name)
        result = self.run_cli(tool=tool)
        self.assert_rejected(result, "Unknown input size")
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
        self.assertEqual(self.source.read_bytes(), b"input sentinel")
        self.assertEqual(alias.read_bytes(), b"input sentinel")

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
        with self.source.open("r+b") as stream:
            stream.truncate(78683892)
        self.assert_rejected(self.run_cli(), "Unknown input SHA256")
        self.assertEqual(self.source.stat().st_size, 78683892)
        with self.source.open("rb") as stream:
            self.assertEqual(stream.read(14), b"input sentinel")
        self.assertFalse(os.path.lexists(self.output))

    def test_optimized_mode_is_rejected_before_imports(self):
        self.assert_rejected(self.run_cli(python_flags=("-O", "-I", "-S")), "Assertions required")
        self.assertFalse(os.path.lexists(self.output))


if __name__ == "__main__":
    unittest.main()
