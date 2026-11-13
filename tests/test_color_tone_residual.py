import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

import numpy as np
from skimage.color import rgb2hsv

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/check_color_tone_residual.py"
sys.path.insert(0, str(ROOT / "tools"))

import check_color_tone_residual as residual


class ColorToneResidualTests(unittest.TestCase):
    def test_rgb_tone_preserves_hue_and_maps_neutral(self):
        rgb = np.array([[0.2, 0.7, 0.4], [0.7, 0.2, 0.4], [0.4, 0.4, 0.4],
                        [0.2, 0.4, 0.7], [0.0, 0.0, 1.0]])
        output = residual.rgb_tone(rgb, np.square)
        np.testing.assert_allclose(output.min(axis=1), rgb.min(axis=1) ** 2)
        np.testing.assert_allclose(output.max(axis=1), rgb.max(axis=1) ** 2)
        np.testing.assert_allclose(rgb2hsv(output)[:, 0], rgb2hsv(rgb)[:, 0], atol=1e-14)

    def test_fit_uses_only_neutrals_and_keeps_endpoints(self):
        lightness = np.linspace(15, 90, 24)
        base = np.column_stack((lightness, np.zeros((24, 2))))
        first_target = base.copy()
        first_target[18:, 0] += 5
        second_target = first_target.copy()
        second_target[:18] = [-50, 100, -100]
        for kind in ("linear", "pchip"):
            x, y, curve = residual.xy_fit(base, first_target, residual.NEUTRAL, kind)
            other_x, other_y, other_curve = residual.xy_fit(base, second_target, residual.NEUTRAL, kind)
            grid = np.linspace(0, 1, 100)
            np.testing.assert_array_equal(x, other_x)
            np.testing.assert_array_equal(y, other_y)
            np.testing.assert_allclose(curve(grid), other_curve(grid), atol=1e-14)
            np.testing.assert_allclose(curve([0, 1]), [0, 1], atol=1e-14)
            self.assertTrue(np.all(np.diff(curve(grid)) > 0))

    def test_source_record_hashes_accept_line_endings_but_reject_changed_data(self):
        from unittest.mock import patch
        name = "lightroom-tone-comparison"
        original = (ROOT / f"analysis/{name}.json").read_bytes().replace(b"\r\n", b"\n")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "analysis").mkdir()
            record = root / f"analysis/{name}.json"
            with patch.object(residual.render, "ROOT", root):
                record.write_bytes(original.replace(b"\n", b"\r\n"))
                self.assertEqual(residual.load(name), json.loads(original))
                record.write_bytes(original + b" ")
                with self.assertRaisesRegex(AssertionError, "source record SHA-256 mismatch"):
                    residual.load(name)

    def test_existing_output_precedes_input_and_optimized_mode_fails(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "keep.json"
            output.write_bytes(b"sentinel")
            args = ["--samples", directory, "--exports", directory,
                    "--scratch", directory, "--output", str(output)]
            result = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("output path already exists", result.stderr)
            self.assertEqual(output.read_bytes(), b"sentinel")
            optimized = subprocess.run([sys.executable, "-B", "-O", str(SCRIPT), *args], capture_output=True, text=True)
            self.assertNotEqual(optimized.returncode, 0)
            self.assertIn("Run without -O", optimized.stderr)
