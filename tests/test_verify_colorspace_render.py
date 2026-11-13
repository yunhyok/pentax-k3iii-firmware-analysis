from copy import deepcopy
from hashlib import sha256
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools/verify_colorspace_render.py"
SPEC = importlib.util.spec_from_file_location("verify_colorspace_render", SCRIPT)
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)


class ReplayGuards(unittest.TestCase):
    def test_optimized_mode_exits_before_argument_or_helper_loading(self):
        process = subprocess.run(
            [sys.executable, "-I", "-S", "-O", str(SCRIPT)],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("Run without -O", process.stderr)

    def test_late_helper_tamper_prevents_any_helper_execution(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for name in replay.HELPERS:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((replay.ROOT / name).read_bytes())

            marker = root / "executed"
            sentinel = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n".encode()
            (root / replay.PARSER).write_bytes(sentinel)
            with (root / replay.FONT).open("ab") as stream:
                stream.write(b"\n# tamper\n")
            pins = {**replay.HELPERS, replay.PARSER: sha256(sentinel).hexdigest()}
            output = root / "new.json"
            with (patch.object(replay, "ROOT", root), patch.object(replay, "HELPERS", pins),
                  patch.object(replay, "read_decoded", return_value=b"source")):
                with self.assertRaises(SystemExit), patch("sys.stderr") as stderr:
                    replay.main([str(root / "missing-input"), "--output", str(output)])
            self.assertIn(f"Dependency SHA-256 mismatch: {replay.FONT}",
                          "".join(str(call.args[0]) for call in stderr.write.call_args_list))
            self.assertFalse(marker.exists())
            self.assertFalse(output.exists())

    def test_existing_output_same_input_and_hardlink_are_unchanged(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            decoded = root / "input.bin"
            decoded.write_bytes(b"source")
            existing = root / "existing.json"
            existing.write_bytes(b"existing")
            hardlink = root / "alias.json"
            os.link(decoded, hardlink)
            with patch.object(replay, "capture_sources") as capture:
                for path in (decoded, existing, hardlink):
                    with self.subTest(path=path.name):
                        with self.assertRaises(SystemExit), patch("sys.stderr") as stderr:
                            replay.main([str(decoded), "--output", str(path)])
                        self.assertIn("Output already exists", str(stderr.write.call_args_list))
                capture.assert_not_called()
            self.assertEqual(decoded.read_bytes(), b"source")
            self.assertEqual(hardlink.read_bytes(), b"source")
            self.assertEqual(existing.read_bytes(), b"existing")

    def test_dangling_output_link_does_not_create_its_target(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "missing.json"
            link = root / "dangling.json"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"Symlink unavailable: {exc}")
            with self.assertRaises(SystemExit), patch("sys.stderr") as stderr:
                replay.main([str(root / "input.bin"), "--output", str(link)])
            self.assertIn("Output already exists", str(stderr.write.call_args_list))
            self.assertTrue(link.is_symlink())
            self.assertFalse(target.exists())

    def test_wrong_size_and_same_size_wrong_bytes_fail_before_replay(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            decoded = root / "input.bin"
            output = root / "new.json"
            with patch.object(replay, "DECODED_SIZE", 3), patch.object(replay, "replay") as run:
                for data, expected in [(b"ab", "size/type mismatch"), (b"abc", "SHA-256 mismatch")]:
                    with self.subTest(data=data):
                        decoded.write_bytes(data)
                        with self.assertRaises(SystemExit), patch("sys.stderr") as stderr:
                            replay.main([str(decoded), "--output", str(output)])
                        self.assertIn(expected, str(stderr.write.call_args_list))
                run.assert_not_called()
            self.assertFalse(output.exists())


class FillComparison(unittest.TestCase):
    def test_fill_normalization_keeps_other_observations(self):
        def row(fill):
            result = {"rounded_extent": [76, 40], "measure_scratch_host_fill": fill,
                      "image1_host_fills": [
                          ["0x10100000", 128, fill, "0x528c38a4"] for _ in range(12)
                      ]}
            return {"initial_byte": f"{fill:02x}", "case": {
                "text_resolution": [{"measurement": result}],
            }}

        base = row(0)
        alternate = row(0xA5)
        before = deepcopy(alternate)
        self.assertEqual(replay.normalized_measurement(base), replay.normalized_measurement(alternate))
        self.assertEqual(alternate, before)
        measurement = alternate["case"]["text_resolution"][0]["measurement"]
        measurement["rounded_extent"][0] = 75
        self.assertNotEqual(replay.normalized_measurement(base), replay.normalized_measurement(alternate))
        measurement["image1_host_fills"][0][2] = 0
        with self.assertRaises(AssertionError):
            replay.normalized_measurement(alternate)


if __name__ == "__main__":
    unittest.main()
