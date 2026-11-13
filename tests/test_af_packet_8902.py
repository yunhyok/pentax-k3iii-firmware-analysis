"""Exercise the public AF packet verifier's input and output guards."""

import errno
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOL = Path(__file__).resolve().parents[1] / "verify_af_packet_8902.py"


def run_cli(*args, flags=()):
    return subprocess.run(
        [sys.executable, "-B", *flags, str(TOOL), *map(str, args)],
        capture_output=True, text=True, timeout=30,
    )


class OptimizedModeTests(unittest.TestCase):
    def test_optimized_mode_is_rejected_before_importing_unicorn(self):
        result = run_cli("--help", flags=("-O", "-I", "-S"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("Replay requires assertions", result.stderr)


@unittest.skipUnless(importlib.util.find_spec("unicorn"), "Unicorn is required by the verifier")
class FileGuardTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = self.folder / "source.bin"
        self.output = self.folder / "result.json"

    def assert_rejected(self, source, output, error):
        result = run_cli(source, "--output", output)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(error, result.stderr)

    def test_wrong_size_and_wrong_digest_leave_no_output(self):
        for size, error in (
            (32, "unexpected RTOS or decoded carrier size"),
            (25_483_200, "unrecognized RTOS or decoded carrier SHA-256"),
        ):
            with self.subTest(size=size):
                with self.source.open("wb") as source:
                    source.truncate(size)
                self.assert_rejected(self.source, self.output, error)
                self.assertEqual(self.source.stat().st_size, size)
                self.assertFalse(os.path.lexists(self.output))

    def test_existing_output_and_input_aliases_are_preserved(self):
        self.source.write_bytes(b"source sentinel")
        self.output.write_bytes(b"report sentinel")
        alias = self.folder / "alias.bin"
        os.link(self.source, alias)
        self.assert_rejected(self.folder / "missing.bin", self.output, "FileExistsError")
        for output in (self.source, alias):
            with self.subTest(output=output.name):
                self.assert_rejected(self.source, output, "FileExistsError")
                self.assertEqual(output.read_bytes(), b"source sentinel")
        self.assertEqual(self.output.read_bytes(), b"report sentinel")

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
        self.assert_rejected(self.source, self.output, "FileExistsError")
        self.assertEqual(self.output.readlink(), Path(target.name))
        self.assertFalse(target.exists())
