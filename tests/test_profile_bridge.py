import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from inspect_adobe_profiles import describe
from tools.profile_bridge import build_dcp


def fixture():
    # Synthetic values; no relation to any PENTAX camera or Adobe profile.
    return {
        "provenance": "Synthetic serialization test only",
        "UniqueCameraModel": "TEST camera, not a real model",
        "ProfileName": "테스트 A",
        "CalibrationIlluminant1": 17,
        "ColorMatrix1": [[0.85, -0.125, 0.0625], [0, 1, 0], [0, 0, 1]],
    }


class ProfileBridgeTests(unittest.TestCase):
    def test_dual_illuminant_roundtrip(self):
        spec = fixture()
        forward = [[0.9643, 0, 0], [0, 1, 0], [0, 0, 0.8251]]
        spec.update(CalibrationIlluminant2=21, ColorMatrix2=[[1, 0, 0], [0, 1, 0], [0.125, 0, 1]],
                    ForwardMatrix1=forward, ForwardMatrix2=forward,
                    ProfileHueSatMapDims=[1, 2, 1], ProfileHueSatMapData1=[[0, 1, 1], [10, 1.25, 1]],
                    ProfileHueSatMapData2=[[0, 1, 1], [-20, 0.75, 1]],
                    ProfileLookTableDims=[1, 2, 2], ProfileLookTableEncoding=1,
                    ProfileLookTableData=[[0, 1, 1], [90, 0.75, 1], [0, 1, 1], [-90, 1.25, 0.5]],
                    ProfileToneCurve=[[0, 0], [0.5, 0.625], [1, 1]])
        data = build_dcp(spec)
        tags = describe(data)["tags"]
        self.assertEqual(tags["ProfileName"]["text"], "테스트 A")
        self.assertEqual(tags["UniqueCameraModel"]["text"], spec["UniqueCameraModel"])
        self.assertEqual(tags["CalibrationIlluminant2"]["value"], 21)
        self.assertEqual(tags["ForwardMatrix2"]["type"], 10)
        self.assertEqual(tags["ProfileHueSatMapDims"]["dimensions"], [1, 2, 1])
        self.assertEqual(tags["ProfileLookTableDims"]["dimensions"], [1, 2, 2])
        self.assertEqual(tags["ProfileLookTableEncoding"]["value"], 1)
        self.assertEqual(tags["ProfileToneCurve"]["count"], 6)

        entries = {tag: (kind, count, offset) for tag, kind, count, offset in
                   struct.iter_unpack("<HHII", data[10:10 + 12 * len(tags)])}
        _, _, offset = entries[50721]
        self.assertEqual(struct.unpack_from("<ii", data, offset + 8), (-125000, 1000000))
        _, count, offset = entries[50982]
        self.assertEqual(struct.unpack_from(f"<{count}f", data, offset),
                         (0, 1, 1, 90, 0.75, 1, 0, 1, 1, -90, 1.25, 0.5))

    def test_rejects_unsafe_or_ambiguous_inputs(self):
        invalid = [
            ({"provenance": ""}, "provenance"),
            ({"ColorMatrix1": [[1, 0, 0], [1, 0, 0], [0, 0, 1]]}, "invertible"),
            ({"ColorMatrix1": [[float("nan"), 0, 0], [0, 1, 0], [0, 0, 1]]}, "finite"),
            ({"ForwardMatrix1": [[1, 0, 0], [0, 1, 0], [0, 0, 1]]}, "XYZ D50"),
            ({"CalibrationIlluminant2": 21}, "Dual illuminants"),
            ({"ProfileLookTableDims": [1, 2, 2]}, "explicitly specify"),
            ({"ProfileLookTableDims": [1, 2, 1], "ProfileLookTableData": [[0, 1, 1]]}, "exactly 2"),
            ({"ProfileLookTableDims": [1, 2, 1], "ProfileLookTableData": [[0, 1, 0.75], [0, 1, 1]]},
             "zero-saturation"),
            ({"ProfileToneCurve": [[0, 0], [0.5, 0.5], [0.500000001, 0.75], [1, 1]]}, "increasing x"),
            ({"ProfileToneCurve": [[0, 0], [0.5, 0.5], [1, 0.9]]}, "\\(1,1\\)"),
            ({"ProfileLooktableData": []}, "unknown fields"),
        ]
        for fields, message in invalid:
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, message):
                build_dcp({**fixture(), **fields})

    def test_dng_sdk_matrix_validation_preserves_serialized_coefficients(self):
        spec = fixture()
        # SDK 1e-4 rounding keeps these ties invertible. The file still carries 1e-6 SRATIONALs.
        for diagonal in (0.00005, -0.00005):
            with self.subTest(diagonal=diagonal):
                spec["ColorMatrix1"] = [[1, 0, 0], [0, 1, 0], [0, 0, diagonal]]
                data = build_dcp(spec)
                tag_count, = struct.unpack_from("<H", data, 8)
                entries = struct.iter_unpack("<HHII", data[10:10 + 12 * tag_count])
                _, _, _, offset = next(entry for entry in entries if entry[0] == 50721)
                self.assertEqual(struct.unpack_from("<ii", data, offset + 8 * 8),
                                 (int(diagonal * 1_000_000), 1_000_000))

        # The same positive tie becomes zero after normalizing the D50 response by 2.
        spec["ColorMatrix1"] = [[2, 0, 0], [0, 2, 0], [0, 0, 0.00005]]
        with self.assertRaisesRegex(ValueError, "not invertible after DNG SDK normalization"):
            build_dcp(spec)
        spec["ColorMatrix1"] = [[1, 0, 0], [0, 1, 0], [0, 0, 0.000001]]
        with self.assertRaisesRegex(ValueError, "not invertible after DNG SDK normalization"):
            build_dcp(spec)

        spec = fixture()
        spec["ForwardMatrix1"] = [[0.31804, 0.31804, 0.31822], [0, 1, 0], [0, 0, 0.825105]]
        with self.assertRaisesRegex(ValueError, "XYZ D50 after DNG SDK rounding"):
            build_dcp(spec)

    def test_dng_sdk_tone_curve_limit(self):
        spec = fixture()
        spec["ProfileToneCurve"] = [[i / 8191, i / 8191] for i in range(8192)]
        self.assertEqual(describe(build_dcp(spec))["tags"]["ProfileToneCurve"]["count"], 16384)
        spec["ProfileToneCurve"] = [[i / 8192, i / 8192] for i in range(8193)]
        with self.assertRaisesRegex(ValueError, "at most 8192"):
            build_dcp(spec)

    def test_cli_preserves_existing_output_and_rejects_duplicate_fields(self):
        script = Path(__file__).resolve().parents[1] / "tools" / "profile_bridge.py"
        with tempfile.TemporaryDirectory() as temp:
            source, target = (Path(temp) / name for name in ("input.json", "profile.dcp"))
            source.write_text(json.dumps(fixture()), encoding="utf-8")
            command = [sys.executable, str(script), str(source), str(target)]
            good = subprocess.run(command, capture_output=True, check=True)
            original = target.read_bytes()
            self.assertEqual(json.loads(good.stdout)["output_sha256"], describe(original)["sha256"])
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(target.read_bytes(), original)
            target.unlink()
            source.write_text(source.read_text(encoding="utf-8")[:-1] + ', "ProfileName": "Again"}',
                              encoding="utf-8")
            failed = subprocess.run(command, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn(b"Duplicate JSON fields", failed.stderr)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
