import unittest
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

import cv2
import numpy as np

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import check_color_scene_transfer as scene


class SceneTransferTests(unittest.TestCase):
    def test_gradient_registration_recovers_known_translation(self):
        spec = scene.read_plan()["registration"].copy()
        spec.update(x=[150, 340, 530, 720], y=[150, 340, 530, 720])
        rng = np.random.default_rng(1363)
        rgb = rng.integers(0, 256, (880, 880, 3), dtype=np.uint8)
        dx, dy = 4, -3
        moved = cv2.warpAffine(rgb, np.float32([[1, 0, dx], [0, 1, dy]]), (880, 880))
        rows = scene.match_sites(scene.gradient(rgb), scene.gradient(moved), spec)
        affine = scene.fit_affine(rows, spec)
        np.testing.assert_allclose(np.array([450, 450, 1]) @ affine, [454, 447], atol=0.02)
        self.assertEqual(len(rows), 16)
        self.assertLess(max(row["residual_px"] for row in rows), 0.02)
        centers = [(350, 350), (600, 600)]
        np.testing.assert_array_equal(scene.roi_samples(rgb, centers, 32),
                                      scene.roi_samples(moved, centers, 32, affine))

    def test_changes_beyond_profile_fields_are_rejected(self):
        base = {"crs_attributes": {"CameraProfile": "Matrix", "Temperature": "5200", "Exposure2012": "0.00"},
                "crs_nested": {"ToneCurve": "linear"}}
        second = {"crs_attributes": {**base["crs_attributes"], "CameraProfile": "Natural", "Temperature": "5300"},
                  "crs_nested": base["crs_nested"]}
        self.assertEqual(set(scene.require_same_controls(base, second, scene.PROFILE_FIELDS)),
                         {"CameraProfile", "Temperature"})
        second["crs_attributes"]["Exposure2012"] = "0.10"
        with self.assertRaisesRegex(AssertionError, "unexpected develop differences"):
            scene.require_same_controls(base, second, scene.PROFILE_FIELDS)

    def test_paired_mask_controls_region_weighting(self):
        truth = np.full((3, 4, 4, 3), [50, 0, 0], dtype=np.float64)
        matrix = truth.copy()
        matrix[..., 0] += 10
        adjusted = truth.copy()
        adjusted[1, ..., 0] += 20
        keep = np.ones(truth.shape[:-1], dtype=bool)
        keep[2] = False
        result = scene.compare_regions(truth, {"matrix1376": matrix, "matrix1376_fixed_chart_tone": adjusted}, keep, 8)
        self.assertEqual(result["included_regions"], [0, 1])
        self.assertEqual((result["improved_regions"], result["worsened_regions"]), (1, 1))
        self.assertEqual(result["methods"]["matrix1376"]["pixels"], 32)

    def test_cli_refuses_existing_input_alias_and_optimized_mode(self):
        with TemporaryDirectory() as directory:
            raw = Path(directory) / "source.dng"
            raw.write_bytes(b"source sentinel")
            alias = raw.with_name("hardlink.dng")
            alias.hardlink_to(raw)
            command = [sys.executable, "-B", str(TOOLS / "check_color_scene_transfer.py"),
                       "--raw", str(raw), "--preview", "missing.jpg", "--exports", "missing",
                       "--bridge", "missing.tif", "--exiftool", "missing",
                       "--scratch", directory, "--registration-only", "--output", str(alias)]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("output path already exists", result.stderr)
            self.assertEqual(alias.read_bytes(), b"source sentinel")
            result = subprocess.run([*command[:2], "-O", "-I", "-S", command[2], "--help"],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Run without -O", result.stderr)


if __name__ == "__main__":
    unittest.main()
