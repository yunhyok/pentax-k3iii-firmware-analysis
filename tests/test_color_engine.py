"""Tests of the firmware-free colour engine, the published tables and the generated profile files.

None of them needs a firmware image: the published records carry the hashes
that were produced with one.
"""

import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build_profile_pages                      # noqa: E402
import check_color_engine                       # noqa: E402
import compare_camera_jpeg                      # noqa: E402
import firmware_color_model as model            # noqa: E402
from k3iii_color_engine import SLIDERS, Engine  # noqa: E402
from make_k3iii_profile import LABELS, make_profile  # noqa: E402


def digest(values, dtype):
    return hashlib.sha256(np.asarray(values).astype(dtype).tobytes()).hexdigest()


class EngineAgainstPublishedRecords(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = Engine.load()
        cls.pipeline = {m["name"]: m for m in json.loads((ROOT / "analysis" / "firmware-color-pipeline.json").read_text(encoding="utf-8"))["modes"]}

    def test_engine_hashes_equal_the_record_made_with_the_firmware(self):
        published = json.loads((ROOT / "analysis" / "k3iii-color-engine-checks.json").read_text(encoding="utf-8"))
        self.assertEqual(published["emulator_comparison"]["mismatches"], 0)
        self.assertTrue(published["emulator_comparison"]["all_tone_settings_included"])
        result = check_color_engine.survey(None)
        self.assertEqual(result["modes"], published["modes"])
        self.assertEqual(result["all_tone_settings_natural"], published["all_tone_settings_natural"])

    def test_engine_registers_equal_the_firmware_pipeline_record(self):
        # analysis/firmware-color-pipeline.json was written by tools/check_firmware_color.py from the emulator alone.
        for mode in LABELS:
            record = self.pipeline[mode]["sha256"]
            self.assertEqual(digest(self.engine.cc0(mode), "<i2"), record["cc0"], mode)
            self.assertEqual(digest(self.engine.yc(mode), "<i2"), record["yc"], mode)
            self.assertEqual(digest(self.engine.gamma(mode), "<u2"), record["gamma_curve"], mode)

    def test_tables_record_the_registers_of_every_mode(self):
        for mode, entry in self.engine.modes.items():
            if mode == "auto":                       # picks another Custom Image's matrix per scene
                continue
            self.assertEqual(self.engine.cc0(mode), entry["default_registers"]["cc0"], mode)
            self.assertEqual(self.engine.yc(mode), entry["default_registers"]["yc"], mode)

    def test_rows_of_every_colour_matrix_sum_to_one(self):
        for mode in LABELS:
            for saturation in range(-4, 5):
                rows = np.array(self.engine.cc0(mode, saturation)).reshape(3, 3).sum(axis=1)
                self.assertEqual(rows.tolist(), [256, 256, 256], (mode, saturation))

    def test_settings_a_mode_does_not_have_are_ignored(self):
        self.assertEqual(self.engine.gamma("reversal-film", key=3, contrast=-4), self.engine.gamma("reversal-film"))
        self.assertEqual(self.engine.cc0("monochrome", saturation=4), self.engine.cc0("monochrome"))
        self.assertEqual(self.engine.yc("muted", hue=3), self.engine.yc("muted"))
        self.assertNotEqual(self.engine.gamma("natural", contrast=1), self.engine.gamma("natural"))

    def test_factory_settings(self):
        for mode in LABELS:
            factory = self.engine.factory_settings(mode)
            self.assertEqual(set(factory), set(SLIDERS))
            for name, value in factory.items():
                self.assertTrue(-4 <= value <= 4)
                if self.engine.modes[mode]["sliders"][name] != "slider":       # a setting the mode lacks has no factory value
                    self.assertIsNone(self.engine.modes[mode]["factory_settings"][name], (mode, name))
        self.assertEqual(self.engine.factory_settings("natural"), dict.fromkeys(SLIDERS, 0))
        self.assertEqual(self.engine.factory_settings("bright")["contrast"], 1)
        self.assertEqual(self.engine.factory_settings("flat")["contrast"], -4)
        self.assertEqual({m: self.engine.factory_toning(m) for m in LABELS if self.engine.factory_toning(m)},
                         {"bleach-bypass": 1, "harubeni": 4})

    def test_toning_tints_grey_and_only_where_the_mode_has_it(self):
        grey = np.full((1, 3), 0.125)
        plain = self.engine.camera("bleach-bypass").encode(grey)
        green = self.engine.camera("bleach-bypass", toning=1).encode(grey)
        self.assertLess(np.ptp(plain), 1e-3)
        self.assertGreater(green[0, 1] - green[0, 0], 0.02)                    # green above red
        self.assertEqual(self.engine.chroma_offset("natural", 1), (0, 0))
        self.assertEqual(self.engine.chroma_offset("muted", 0), (0, 0))
        self.assertNotEqual(self.engine.chroma_offset("muted", 1, "srgb"), self.engine.chroma_offset("muted", 1, "adobergb"))


class GeneratedFiles(unittest.TestCase):
    def test_profiles_pages_and_data_are_up_to_date(self):
        stale = [path for path, content in build_profile_pages.build().items()
                 if not (ROOT / path).is_file() or (ROOT / path).read_bytes() != content]
        self.assertEqual(stale, [], "run python tools/build_profile_pages.py")

    def test_default_profile_uses_the_factory_settings(self):
        engine = Engine.load()
        default, report = make_profile(engine, "bright", table_dims=(6, 3, 3))
        explicit, _ = make_profile(engine, "bright", {"contrast": 1}, table_dims=(6, 3, 3))
        neutral, neutral_report = make_profile(engine, "bright", dict.fromkeys(SLIDERS, 0), table_dims=(6, 3, 3))
        self.assertEqual(default, explicit)
        self.assertNotEqual(default, neutral)
        self.assertEqual(report["profile_name"], "K-3 III Firmware Bright")
        self.assertEqual(neutral_report["profile_name"], "K-3 III Firmware Bright con+0")
        profile = model.read_dcp(default)
        self.assertEqual(profile["ProfileName"], "K-3 III Firmware Bright")

    def test_published_profile_is_a_readable_dcp(self):
        data = (ROOT / "profiles" / "k3iii" / "k3iii-firmware-natural.dcp").read_bytes()
        profile = model.read_dcp(data)
        self.assertEqual(profile["ProfileName"], "K-3 III Firmware Natural")
        self.assertEqual((profile["LookTable"].hue, profile["LookTable"].sat, profile["LookTable"].val), (90, 30, 30))
        engine = Engine.load()
        expected = model.SRGB_TO_PCS @ (np.array(engine.cc0("natural")).reshape(3, 3) / 256.0)
        self.assertLess(np.abs(profile["ForwardMatrix1"] - expected).max(), 1e-4)


def raw_with_settings(order: str, tone: int, values: tuple) -> bytes:
    """A minimal TIFF with a PENTAX maker note that holds ImageTone, ColorSpace and the setting record."""
    mark = "II" if order == "<" else "MM"
    payload = struct.pack(f"<{len(values)}h", *values)                 # the camera stores the record little-endian
    note_start = 8 + 2 + 12 + 4 + 2 + 12 + 4                           # header, IFD0 (1 entry), Exif IFD (1 entry)
    entries = [(0x37, 3, 1, struct.pack(order + "HH", 1, 0)), (0x4F, 3, 1, struct.pack(order + "HH", tone, 0)),
               (0x247, 7, len(payload), None)]
    note_ifd = 6 + 2 + 12 * len(entries) + 4
    note = b"AOC\0" + mark.encode() + struct.pack(order + "H", len(entries))
    for tag, kind, count, inline in entries:
        note += struct.pack(order + "HHI", tag, kind, count) + (inline or struct.pack(order + "I", note_ifd))
    note += struct.pack(order + "I", 0) + payload
    data = mark.encode() + struct.pack(order + "HI", 42, 8)
    data += struct.pack(order + "HHHII", 1, 0x8769, 4, 1, 8 + 2 + 12 + 4) + struct.pack(order + "I", 0)
    data += struct.pack(order + "HHHII", 1, 0x927C, 7, len(note), note_start) + struct.pack(order + "I", 0)
    assert len(data) == note_start
    return data + note


class SettingRecordInRawFiles(unittest.TestCase):
    def test_settings_and_toning_are_read_from_the_maker_note(self):
        record = (0, 0, -4, 4, 0, 0, -1, -32768, -32768, -32768, 0, -1, 1, -1, -1, -1, -1, 8, 0, 8, 0, -1, -1, 1)
        for order in "<>":
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "sample.pef"
                path.write_bytes(raw_with_settings(order, 8, record))
                info = compare_camera_jpeg.capture_info(path)
            self.assertEqual(compare_camera_jpeg.IMAGE_TONE[info["image_tone"]], "bleach-bypass")
            self.assertEqual(info["color_space"], 1)
            self.assertEqual(info["settings"], {"saturation": 0, "hue": 0, "key": -4, "contrast": 4, "highlight": 0, "shadow": 0})
            self.assertEqual(info["toning"], 1)

    def test_a_setting_that_does_not_apply_reads_as_zero(self):
        record = (-32768, -32768, -32768, -32768, -32768, -32768, 0) + (-1,) * 17
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.pef"
            path.write_bytes(raw_with_settings("<", 7, record))
            info = compare_camera_jpeg.capture_info(path)
        self.assertEqual(info["settings"], dict.fromkeys(SLIDERS, 0))
        self.assertEqual(info["toning"], 0)


if __name__ == "__main__":
    unittest.main()
