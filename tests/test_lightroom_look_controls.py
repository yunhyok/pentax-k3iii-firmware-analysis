"""Focused checks for LookTable controls and replay input guards."""
from hashlib import md5, sha256
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from tools import check_lightroom_look_controls as look
from tools.profile_bridge import build_dcp
from inspect_adobe_profiles import describe


class LightroomLookTests(unittest.TestCase):
    def test_looktable_diffs_and_fingerprint_bytes(self):
        matrix = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
        recipe = {
            "provenance": "Synthetic test", "ProfileName": "Base", "UniqueCameraModel": "Synthetic model",
            "CalibrationIlluminant1": 17, "CalibrationIlluminant2": 21,
            "ColorMatrix1": matrix, "ColorMatrix2": matrix,
        }
        base_dcp = build_dcp(recipe)
        base = describe(base_dcp)["tags"]
        segments, _ = look.stream_segments(base_dcp)
        full, render = look.look_fingerprints(segments, "Sat control", 0.8)
        color_bytes = b"".join(list(segments.values())[:4])
        # Hand-encoded [1,2,1] and two {0, binary32(0.8), 1} rows.
        look_bytes = bytes.fromhex(
            "010000000200000001000000" "00000000cdcc4c3f0000803f" "00000000cdcc4c3f0000803f"
        )
        self.assertEqual(full, md5(color_bytes + b"Sat control" + b"\0" * 4 + look_bytes).hexdigest().upper())
        self.assertEqual(render, md5(color_bytes + look_bytes).hexdigest().upper())
        self.assertNotEqual(render, look.look_fingerprints(segments, "Sat control", 1.0)[1])
        data = build_dcp(look.control_spec(recipe, "Sat control", 0.8))
        tags = describe(data)["tags"]
        self.assertEqual(set(tags) - set(base), {"ProfileLookTableDims", "ProfileLookTableData"})
        self.assertEqual({key for key in base if base[key] != tags[key]}, {"ProfileName"})
        self.assertEqual(tags["ProfileLookTableDims"]["dimensions"], [1, 2, 1])
        self.assertEqual(tags["ProfileLookTableData"], {
            "type": 11, "count": 6, "sha256": sha256(look_bytes[12:]).hexdigest(),
        })

    def test_recipe_pin_normalizes_only_crlf(self):
        recipe = look.RECIPE.read_bytes().replace(b"\r\n", b"\n")
        self.assertEqual(look.load_recipe(recipe), look.load_recipe(recipe.replace(b"\n", b"\r\n")))
        with self.assertRaisesRegex(AssertionError, "Baseline recipe SHA-256 mismatch"):
            look.load_recipe(recipe + b"\n")
        base = look.load_recipe(recipe)
        for pin in look.PROFILES.values():
            dcp = build_dcp(look.control_spec(base, pin["name"], pin["sat_scale"]))
            self.assertEqual(sha256(dcp).hexdigest(), pin["dcp_sha256"])

    def test_develop_allows_only_expected_profile_fields_to_change(self):
        attrs = {**look.tone.REQUIRED, "CameraProfile": "Base", "CameraProfileDigest": "A" * 32}
        attrs.update({f"fixture_{i}": "0" for i in range(114 - len(attrs))})
        nested = {f"Nested{i}": str(i) for i in range(6)}
        look_attrs = {**attrs, "CameraProfile": "Look", "CameraProfileDigest": "B" * 32}
        args = (attrs, nested, "Look", "B" * 32, True)
        self.assertEqual(look.check_develop(look_attrs, nested, *args), ["CameraProfile", "CameraProfileDigest"])
        for candidate, tree, expected in (
            ({**look_attrs, "fixture_0": "1"}, nested, "Unexpected develop field differences"),
            ({**look_attrs, "CameraProfileDigest": "C" * 32}, nested, "CameraProfileDigest mismatch"),
            (look_attrs, {**nested, "Nested0": "changed"}, "Nested develop metadata differs"),
        ):
            with self.subTest(expected=expected), self.assertRaisesRegex(AssertionError, expected):
                look.check_develop(candidate, tree, *args)

    def test_cli_rejects_existing_targets_before_input_and_optimized_before_imports(self):
        script = Path(look.__file__).resolve()
        with TemporaryDirectory() as temp:
            root = Path(temp)
            original = root / "original"
            original.write_bytes(b"keep")
            output = root / "hardlink.json"
            os.link(original, output)
            missing = str(root / "missing")
            arguments = [
                arg for flag in ("raw", "omitted-tiff", "omitted-current-tiff", "identity-dcp", "identity-tiff",
                                 "identity-repeat-tiff", "sat80-dcp", "sat80-tiff")
                for arg in (f"--{flag}", missing)
            ] + ["--scratch", temp]
            occupied = subprocess.run([sys.executable, "-B", str(script), *arguments, "--output", str(output)],
                                      capture_output=True, text=True)
            self.assertNotEqual(occupied.returncode, 0)
            self.assertIn("output path already exists", occupied.stderr)
            self.assertEqual(original.read_bytes(), b"keep")
            opt = subprocess.run([sys.executable, "-B", "-S", "-O", str(script)],
                                 capture_output=True, text=True)
            self.assertNotEqual(opt.returncode, 0)
            self.assertIn("Run without -O", opt.stderr)


if __name__ == "__main__":
    unittest.main()
