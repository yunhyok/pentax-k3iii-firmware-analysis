from hashlib import sha256
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools/check_lightroom_tone_coordinates.py"
sys.path.insert(0, str(CLI.parent))
import check_lightroom_tone_coordinates as tool


class ToneCoordinatesTests(unittest.TestCase):
    def test_only_checked_source_bytes_execute(self):
        name = "_tone_coordinates_test_helper"
        marker = "executed"
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            good = f"VALUE = '{marker}'\n".encode()
            second = "raise RuntimeError('must never execute')\n".encode()
            (folder / "first.py").write_bytes(good.replace(b"\n", b"\r\n"))
            (folder / "second.py").write_bytes(second)
            first = (name, "first.py", sha256(good).hexdigest())
            with self.assertRaisesRegex(ValueError, "second.py"):
                tool.load_checked_sources((first, (name+"2", "second.py", "0"*64)), folder)
            self.assertNotIn(name, sys.modules)
            try:
                tool.load_checked_sources((first,), folder)
                self.assertEqual(sys.modules[name].VALUE, marker)
                with self.assertRaisesRegex(ValueError, "already loaded"):
                    tool.load_checked_sources((first,), folder)
            finally:
                sys.modules.pop(name, None)

    def test_fresh_allows_container_but_pins_baseline_pixels_and_controls(self):
        expected = {
            "file_sha256":"archived","pixel_sha256_le_uint16_rgb":"fixed","icc_sha256":"ICC",
            "shape_yxc":[4,5,3],"storage":"u16","software":"Lightroom",
            "crs_attributes":{"CameraProfile":"Role","CameraProfileDigest":"Digest"},
            "crs_nested":{},
        }
        new = {**expected, "file_sha256":"fresh"}

        def reader(path, shape, profile, name, pin):
            self.assertEqual((profile["profile"],profile["xmp_profile_digest"]), ("Role","Digest"))
            if pin is not None:
                self.assertEqual(pin,expected["file_sha256"])
                if pin != new["file_sha256"]:
                    raise ValueError("TIFF SHA-256 mismatch")
            return None,None,new

        path = Path("test.tif")
        with self.assertRaisesRegex(ValueError,"TIFF SHA"):
            tool.replay_export(reader,path,expected,"ICC")
        self.assertEqual(tool.replay_export(reader,path,expected,"ICC",True,True)[2],new)
        new["pixel_sha256_le_uint16_rgb"] = "changed"
        with self.assertRaisesRegex(ValueError,"archived ProPhoto pixels"):
            tool.replay_export(reader,path,expected,"ICC",True,True)
        self.assertEqual(tool.replay_export(reader,path,expected,"ICC",True,False)[2],new)
        new["crs_nested"] = {"bad":"value"}
        with self.assertRaisesRegex(ValueError,"crs_nested"):
            tool.replay_export(reader,path,expected,"ICC",True,False)

    def test_counterexample_and_typed_comparison(self):
        first,second = tool.basis_counterexample()
        self.assertEqual(first["tone_rgb_low_to_high"][0],"1157/14400")
        self.assertEqual(second["tone_rgb_low_to_high"][0],"291247/7200000")
        self.assertEqual(tool.first_difference({"x":[1]}, {"x":[True]}, "result"), "result.x[0]")
        self.assertIsNone(tool.first_difference({"x":[1]}, {"x":[1]}, "result"))

    def test_overwrite_and_optimized_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.json"
            output.write_bytes(b"unchanged")
            args = [item for role in ("raw","dcps","tiffs","sdk","adobe-icc","tificc")
                    for item in ("--"+role,"missing")]
            args.extend(("--output",str(output)))
            existing = subprocess.run([sys.executable,"-B",str(CLI),*args],capture_output=True,text=True)
            self.assertEqual(existing.returncode,2)
            self.assertIn("output must be a new file",existing.stderr)
            self.assertEqual(output.read_bytes(),b"unchanged")
            optimized = subprocess.run([sys.executable,"-B","-O",str(CLI),"--help"],capture_output=True,text=True)
            self.assertNotEqual(optimized.returncode,0)
            self.assertIn("Run without -O",optimized.stderr)

    def test_converter_path_is_bound_before_measurement(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            converter = folder / "tificc.exe"
            converter.write_bytes(b"path resolution fixture; never executed")
            try:
                os.chdir(folder)
                for index, relative in enumerate(("tificc.exe", "./tificc.exe")):
                    args = [item for role in ("raw", "dcps", "tiffs", "sdk", "adobe-icc")
                            for item in ("--"+role, "unused")]
                    args += ["--tificc", relative, "--output", f"result{index}.json"]
                    with patch.object(tool, "run", return_value={"measured":{}}) as measurement:
                        self.assertEqual(tool.main(args), 0)
                    self.assertEqual(measurement.call_args.args[0].tificc, converter.resolve())
                    self.assertTrue(measurement.call_args.args[0].tificc.is_absolute())
            finally:
                os.chdir(original)


if __name__ == "__main__":
    unittest.main()
