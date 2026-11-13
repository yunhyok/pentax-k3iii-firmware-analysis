"""Check public AF binding verifier trust boundaries without firmware."""

import errno
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SERVICE = "verify_af_service_binding.py"
UDC = "verify_af_udc_binding.py"
PACKET = "verify_af_packet_8902.py"


def run_cli(tool, *args, flags=()):
    return subprocess.run(
        [sys.executable, "-B", *flags, str(tool), *map(str, args)],
        capture_output=True, text=True, timeout=30,
    )


class DependencyGuardTests(unittest.TestCase):
    def test_optimized_mode_stops_before_imports(self):
        for name in (SERVICE, UDC):
            with self.subTest(tool=name):
                result = run_cli(ROOT / name, "--help", flags=("-O", "-I", "-S"))
                self.assertEqual(result.returncode, 1)
                self.assertIn("Replay requires assertions", result.stderr)

    def test_each_dependency_is_verified_before_execution(self):
        for name, dependency in ((SERVICE, PACKET), (UDC, SERVICE), (UDC, PACKET)):
            with self.subTest(tool=name, dependency=dependency), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                for module in {name, SERVICE, dependency}:
                    shutil.copyfile(ROOT / module, folder / module)
                (folder / dependency).write_text("raise RuntimeError('unchecked code ran')\n", encoding="utf-8")
                result = run_cli(folder / name, "--help", flags=("-I", "-S"))
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"Dependency SHA-256 mismatch: {dependency}", result.stderr)
                self.assertNotIn("unchecked code ran", result.stderr)

    @unittest.skipUnless(importlib.util.find_spec("unicorn"), "Unicorn is required by the verifiers")
    def test_lf_pins_accept_crlf_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            for module in (UDC, SERVICE, PACKET):
                source = (ROOT / module).read_bytes().replace(b"\r\n", b"\n")
                (folder / module).write_bytes(source.replace(b"\n", b"\r\n"))
            result = run_cli(folder / UDC, "--help")
            self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(importlib.util.find_spec("unicorn"), "Unicorn is required by the verifiers")
class FileGuardTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = self.folder / "input.bin"
        self.output = self.folder / "result.json"

    def test_wrong_size_and_wrong_digest_leave_no_output(self):
        for size, error in (
            (32, "unexpected RTOS or decoded carrier size"),
            (25_483_200, "unrecognized RTOS or decoded carrier SHA-256"),
        ):
            with self.source.open("wb") as stream:
                stream.truncate(size)
            for name in (SERVICE, UDC):
                with self.subTest(size=size, tool=name):
                    result = run_cli(ROOT / name, self.source, "--output", self.output)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(error, result.stderr)
                    self.assertEqual(self.source.stat().st_size, size)
                    self.assertFalse(os.path.lexists(self.output))

    def test_existing_output_and_input_hardlink_are_preserved(self):
        self.source.write_bytes(b"original")
        self.output.write_bytes(b"existing")
        alias = self.folder / "alias.bin"
        os.link(self.source, alias)
        for name in (SERVICE, UDC):
            for source, output in ((self.folder / "missing.bin", self.output),
                                   (self.source, self.source), (self.source, alias)):
                with self.subTest(tool=name, output=output.name):
                    result = run_cli(ROOT / name, source, "--output", output)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("--output must be a new path", result.stderr)
        self.assertEqual(self.source.read_bytes(), b"original")
        self.assertEqual(alias.read_bytes(), b"original")
        self.assertEqual(self.output.read_bytes(), b"existing")

    def test_dangling_output_symlink_is_preserved(self):
        target = self.folder / "missing.json"
        try:
            self.output.symlink_to(target.name)
        except NotImplementedError as error:
            self.skipTest(str(error))
        except OSError as error:
            if (error.errno not in {errno.EPERM, errno.EACCES, errno.ENOSYS, errno.ENOTSUP}
                    and getattr(error, "winerror", None) != 1314):
                raise
            self.skipTest(f"File symlinks are unavailable: {error}")
        for name in (SERVICE, UDC):
            with self.subTest(tool=name):
                result = run_cli(ROOT / name, self.source, "--output", self.output)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--output must be a new path", result.stderr)
                self.assertEqual(self.output.readlink(), Path(target.name))
                self.assertFalse(target.exists())
