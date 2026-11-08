"""Focused synthetic tests for TIFF storage and profile/crop rejection."""
from fractions import Fraction
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import numpy as np
import tifffile

from tools import check_lightroom_model_exports as exports


class LightroomModelExportTests(unittest.TestCase):
    def test_source_pin_has_the_same_meaning_for_lf_and_crlf_checkouts(self):
        lf = exports.SOURCE.read_bytes().replace(b"\r\n", b"\n")
        crlf = lf.replace(b"\n", b"\r\n")
        self.assertNotEqual(lf, crlf)
        self.assertEqual(exports.load_source(lf), exports.load_source(crlf))
        with self.assertRaisesRegex(AssertionError, "Source fixture SHA-256 mismatch"):
            exports.load_source(lf + b"\n")

    def test_signed_tiff_fails_before_reading_profile_metadata(self):
        with TemporaryDirectory() as work:
            path = Path(work) / "signed.tif"
            tifffile.imwrite(path, np.ones((4, 5, 3), dtype=np.int16), photometric="rgb")
            geometry = {"expected_unresized_tiff_size_xy": [5, 4]}
            pins = {"tiff_sha256": exports.digest(path)}
            with self.assertRaisesRegex(AssertionError, "uint16"):
                exports.read_tiff(path, geometry, "Synthetic", pins, None, "not-used")

    def test_requires_profile_digest_and_exact_default_crop(self):
        pins = {"profile_digest": "A" * 32, "temperature": 4100, "tint": 3}
        fields = {
            **exports.EXPECTED_XMP, "CameraProfile": "Synthetic", "CameraProfileDigest": "A" * 32,
            "Temperature": "4100", "Tint": "+3", "HasCrop": "True", "CropAngle": "0",
            "CropLeft": "0", "CropTop": "0.25", "CropRight": "1", "CropBottom": "0.75",
        }
        crop = (0, Fraction(1, 4), 1, Fraction(3, 4))
        exports.check_develop(fields, "Synthetic", pins, crop)
        uncropped = {**fields, "HasCrop": "False", "CropTop": "0", "CropBottom": "1"}
        exports.check_develop(uncropped, "Synthetic", pins, None)
        for key, wrong, label in (
            ("CameraProfile", "Wrong name", "CameraProfile name mismatch"),
            ("CameraProfileDigest", "B" * 32, "CameraProfileDigest mismatch"),
            ("CropBottom", "0.750001", "Crop bounds mismatch"),
            ("HasCrop", "False", "HasCrop mismatch"),
            ("CropAngle", "1", "Crop angle mismatch"),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(AssertionError, label):
                exports.check_develop({**fields, key: wrong}, "Synthetic", pins, crop)


if __name__ == "__main__":
    unittest.main()
