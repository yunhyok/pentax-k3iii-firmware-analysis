"""Checks of the firmware colour model and the profile math that need no firmware.

The camera parameters here are synthetic (a made-up matrix and an sRGB-shaped
curve).  One optional test runs the real firmware when the environment variable
PENTAX_K3III_DECODED names a decoded firmware 2.20 image.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import compare_camera_jpeg as compare      # noqa: E402
import firmware_color_model as model       # noqa: E402
from profile_bridge import build_dcp       # noqa: E402


def synthetic_camera(space="srgb", chroma_fixed=False):
    cc0 = np.array([[330.0, -90.0, 16.0], [-40.0, 340.0, -44.0], [10.0, -110.0, 356.0]])
    assert all(cc0.sum(axis=1) == 256)
    x = np.arange(256) / 256.0
    # A plausible camera curve: sRGB encoding of a mildly S-shaped tone curve, stored like the firmware does.
    tone = x ** 0.85 / (x ** 0.85 + 0.35 * (1 - x) ** 1.2 + 1e-12)
    tone = np.where(x > 0, tone, 0.0)
    curve = np.round(model.srgb_encode(tone) * 16384.0)
    curves = np.stack([curve, curve, curve])
    yc = np.array([[77.0, 150.0, 29.0], [-43.0, -85.0, 128.0], [128.0, -107.0, -21.0]])
    return model.CameraColour(cc0=cc0, cc0_unit=256.0, curves=curves, curve_max=16384.0, yc=yc,
                              chroma_fixed=chroma_fixed, space=space, name="synthetic")


def random_colours(count, seed=3):
    rng = np.random.default_rng(seed)
    base = rng.random((count, 3))
    base /= base.max(axis=1, keepdims=True)
    return base * (rng.random(count) ** 2.0)[:, None]


class ColourModel(unittest.TestCase):
    def test_hsv_round_trip(self):
        rgb = random_colours(5000)
        back = model.hsv_to_rgb(model.rgb_to_hsv(rgb))
        self.assertLess(np.abs(back - rgb).max(), 1e-12)
        self.assertTrue(np.array_equal(model.rgb_to_hsv(np.array([0.3, 0.3, 0.3])), [0.0, 0.0, 0.3]))

    def test_tone_inverse_and_sorting_cases(self):
        x = np.linspace(0, 1, 257)
        y = model.srgb_decode(model.srgb_encode(x) ** 0.8)
        rgb = random_colours(5000)
        toned = model.rgb_tone(rgb, x, y)
        self.assertLess(np.abs(model.rgb_tone_inverse(toned, x, y) - rgb).max(), 1e-6)
        # RefBaselineRGBTone keeps the hue order and the relative position of the middle channel.
        sample = np.array([[0.6, 0.3, 0.1], [0.1, 0.6, 0.3], [0.3, 0.1, 0.6], [0.5, 0.5, 0.2]])
        out = model.rgb_tone(sample, x, y)
        self.assertTrue(np.array_equal(np.argsort(sample, axis=1), np.argsort(out, axis=1)))
        ratio_in = (np.median(sample, axis=1) - sample.min(axis=1)) / (sample.max(axis=1) - sample.min(axis=1))
        ratio_out = (np.median(out, axis=1) - out.min(axis=1)) / (out.max(axis=1) - out.min(axis=1))
        self.assertLess(np.abs(ratio_in - ratio_out).max(), 1e-12)

    def test_exposure_tone_matches_sdk_shape(self):
        x = np.linspace(0, 1, 101)
        self.assertTrue(np.array_equal(model.exposure_tone(x, 0.25), x))
        y = model.exposure_tone(x, -0.5)
        self.assertAlmostEqual(float(y[-1]), 1.0, places=12)
        self.assertAlmostEqual(float(y[20]), 0.2 * 2 ** -0.5, places=12)      # below 0.25: plain scale
        self.assertTrue(np.all(np.diff(y) > 0))
        at_join = model.exposure_tone(np.array([0.25, 0.25 + 1e-9]), -0.5)
        self.assertLess(abs(at_join[1] - at_join[0]), 1e-6)                   # continuous at 0.25

    def test_chroma_gain_follows_register_semantics(self):
        camera = synthetic_camera()
        gain = camera.chroma_gain(np.array([0.0, 28 / 1023, 56 / 1023, 0.5, 768 / 1023, 856 / 1023, 1.0]))
        self.assertAlmostEqual(float(gain[0]), 0.0)
        self.assertAlmostEqual(float(gain[1]), 73 * 28 / 8 / 512)
        for value in gain[2:5]:
            self.assertAlmostEqual(float(value), 1.0, places=2)
        self.assertAlmostEqual(float(gain[5]), 432 / 512, places=2)
        self.assertLess(float(gain[6]), 0.3)

    def test_neutral_stays_neutral_and_matrix_is_white_preserving(self):
        camera = synthetic_camera()
        grey = np.linspace(0, 1, 33)[:, None] * np.ones(3)
        out = camera.render(grey)
        self.assertLess(np.abs(out - out[:, :1]).max(), 1e-3)                # JFIF coefficients are rounded to 8 bits
        self.assertLess(np.abs(camera.forward_matrix().sum(axis=1) - model.SRGB_TO_PCS.sum(axis=1)).max(), 1e-12)

    def test_profile_reproduces_camera_model(self):
        for space in ("srgb", "adobergb"):
            with self.subTest(space=space):
                camera = synthetic_camera(space)
                x, y = camera.tone_curve(257)
                self.assertEqual((x[0], y[0], x[-1], y[-1]), (0.0, 0.0, 1.0, 1.0))
                self.assertTrue(np.all(np.diff(y) >= 0))
                table = model.build_look_table(camera, x, y, 90, 30, 30)
                self.assertTrue(np.all(table.data[:, :, 0, 2] == 1.0))       # DNG rule for zero saturation
                linear = random_colours(20000)                                # linear RGB of the output space
                camera_rgb = linear @ np.linalg.inv(camera.matrix).T
                keep = np.all((camera_rgb >= 0) & (camera_rgb <= 1), axis=1)
                camera_rgb = camera_rgb[keep]
                expected = camera.decode(camera.render(camera_rgb))
                got = model.dng_render(camera_rgb, camera.forward_matrix(), table, x, y, output=space)
                error = np.abs(model.RGB_SPACES[space][1](got) - model.RGB_SPACES[space][1](expected)) * 255
                self.assertLess(error.mean(), 0.8)
                self.assertLess(np.percentile(error, 95), 5.0)
                without = model.dng_render(camera_rgb, camera.forward_matrix(), None, x, y, output=space)
                worse = np.abs(model.RGB_SPACES[space][1](without) - model.RGB_SPACES[space][1](expected)) * 255
                self.assertGreater(worse.mean(), 3 * error.mean())           # the table is doing real work

    def test_monochrome_uses_base_matrix_and_zero_saturation(self):
        camera = synthetic_camera(chroma_fixed=True)
        camera.cc0 = np.array([[86.0, 156.0, 14.0]] * 3)
        base = np.array([[1.4, -0.5, 0.1], [-0.2, 1.4, -0.2], [0.05, -0.45, 1.4]])
        x, y = camera.tone_curve(257)
        table = model.build_look_table(camera, x, y, 36, 9, 9, forward_base=base)
        self.assertEqual(float(np.abs(table.data[..., 1]).max()), 0.0)       # every colour loses its saturation
        camera_rgb = random_colours(2000) * 0.8
        got = model.dng_render(camera_rgb, camera.forward_matrix(base), table, x, y)
        self.assertLess(np.abs(got - got[:, :1]).max(), 2e-3)

    def test_dcp_round_trip_and_new_tags(self):
        camera = synthetic_camera()
        x, y = camera.tone_curve(65)
        table = model.build_look_table(camera, x, y, 12, 5, 5)
        spec = {
            "provenance": "unit test", "UniqueCameraModel": "PENTAX K-3 Mark III", "ProfileName": "test",
            "CalibrationIlluminant1": 21, "ColorMatrix1": [[0.7, -0.16, -0.09], [-0.46, 1.27, 0.21], [-0.06, 0.14, 0.57]],
            "ForwardMatrix1": camera.forward_matrix().tolist(),
            "ProfileToneCurve": [[float(a), float(b)] for a, b in zip(x, y)],
            "ProfileLookTableDims": [12, 5, 5], "ProfileLookTableEncoding": 1,
            "ProfileLookTableData": [[float(v) for v in row] for row in table.rows()],
            "BaselineExposureOffset": 0.5, "DefaultBlackRender": 1, "ProfileEmbedPolicy": 0, "ProfileCopyright": "test",
        }
        profile = model.read_dcp(build_dcp(spec))
        self.assertEqual(profile["BaselineExposureOffset"], 0.5)
        self.assertEqual(profile["DefaultBlackRender"], 1)
        self.assertLess(np.abs(profile["ForwardMatrix1"] - camera.forward_matrix()).max(), 1e-6)
        self.assertLess(np.abs(profile["LookTable"].data - table.data).max(), 1e-6)
        for key, bad in (("BaselineExposureOffset", 11), ("DefaultBlackRender", 2), ("ProfileEmbedPolicy", 4)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                build_dcp({**spec, key: bad})

    def test_colour_difference_and_baseline_exposure_formula(self):
        # Sharma, Wu, Dalal (2005), CIEDE2000 test data pairs 1 and 17.
        a = np.array([[50.0, 2.6772, -79.7751], [50.0, 2.5, 0.0]])
        b = np.array([[50.0, 0.0, -82.7485], [61.0, -5.0, 29.0]])
        result = compare.delta_e_2000(a, b)
        self.assertAlmostEqual(float(result[0]), 2.0425, places=4)
        self.assertAlmostEqual(float(result[1]), 22.8977, places=4)
        # The public sample raw.pixls.us #4678 carries BaselineExposure -54871/65536 and maker-note value 2576.
        value = compare.firmware_baseline_exposure(4 * 2576, 16379, 64)
        self.assertLess(abs(value - (-54871 / 65536)), 2e-4)

    def test_published_record_is_consistent(self):
        record = json.loads((ROOT / "analysis" / "firmware-color-pipeline.json").read_text(encoding="utf-8"))
        checks = record["reference_checks"]
        self.assertLess(checks["colour_space_matrix"]["max_abs_difference"], 0.001)
        self.assertTrue(all(item["equal"] for item in checks["baseline_exposure_constants"].values()))
        self.assertEqual(len(record["modes"]), 19)
        for mode in record["modes"]:
            self.assertEqual(mode["cc0_row_sums"], [256, 256, 256], mode["name"])
            self.assertEqual(mode["assertions"], 0)
            self.assertTrue(mode["yc_is_bt601"] and mode["tone_table_is_identity"] and not mode["cc1_enabled"])
        per_channel = sorted(m["name"] for m in record["modes"] if m["per_channel_gamma_curves"])
        self.assertEqual(per_channel, ["cross-processing", "gold"])


@unittest.skipUnless(importlib.util.find_spec("unicorn") and os.environ.get("PENTAX_K3III_DECODED"),
                     "set PENTAX_K3III_DECODED to a decoded firmware 2.20 image to run the firmware test")
class WithFirmware(unittest.TestCase):
    def test_survey_matches_published_record(self):
        import check_firmware_color

        fresh = check_firmware_color.survey(Path(os.environ["PENTAX_K3III_DECODED"]))
        published = json.loads((ROOT / "analysis" / "firmware-color-pipeline.json").read_text(encoding="utf-8"))
        self.assertEqual(json.loads(json.dumps(fresh)), published)


if __name__ == "__main__":
    unittest.main()
