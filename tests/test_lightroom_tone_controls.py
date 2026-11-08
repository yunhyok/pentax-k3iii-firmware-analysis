from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from inspect_adobe_profiles import describe
from tools import build_lightroom_tone_controls as tone
from tools.profile_bridge import build_dcp


def synthetic_source():
    # These are generated dyadic values and do not come from the SDK.
    ordinates = [i / 1024 for i in range(1025)]
    ordinates[512] = 0.50048828125
    table = ",\n".join(f"{value:.11f}f" for value in ordinates)
    source = (
        "real64 dng_tone_curve_acr3_default::Evaluate (real64 x) const\n"
        f"{{ const real32 kTable [] = {{ {table}, }}; }}\n"
        "real64 dng_tone_curve_acr3_default::EvaluateInverse (real64 x) const\n"
        "{ const real32 kTable [] = { 0.8f, 0.3f }; }\n"
    )
    return source.encode("ascii"), [[i / 1024, value] for i, value in enumerate(ordinates)]


class ForwardTableTests(unittest.TestCase):
    def test_public_recipe_rebuilds_the_pinned_baseline(self):
        recipe = Path(__file__).resolve().parents[1] / 'analysis/lightroom-matrix-1376.json'
        source = recipe.read_bytes()
        self.assertEqual(sha256(source).hexdigest(), tone.BASE_JSON_SHA)
        self.assertEqual(sha256(build_dcp(json.loads(source))).hexdigest(), tone.BASE_DCP_SHA)

    def test_selects_forward_table_and_uses_binary32_points(self):
        source, points = synthetic_source()
        self.assertEqual(tone.parse_forward_table(source), points)
        self.assertEqual(points[512], [0.5, 0.50048828125])

    def test_rejects_wrong_boundary_count_tokens_and_duplicate_ordinate(self):
        source, _ = synthetic_source()
        for changed, message in (
            (source.replace(b"::EvaluateInverse", b"::Other"), "boundary"),
            (source.replace(b"0.50048828125f,\n", b""), "1025"),
            (source.replace(b"0.50048828125f", b"0.5"), "1025"),
            (source.replace(b"0.50048828125f", b"0.49902343750f"), "strictly increasing"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                tone.parse_forward_table(changed)


class ToneBuildTests(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temp)
        self.spec = self.root / "baseline.json"
        self.dcp = self.root / "baseline.dcp"
        self.sdk = self.root / "sdk.zip"
        self.output = self.root / "output"
        # Deliberately synthetic camera and illuminant matrices.
        matrix_spec = {
            "provenance": "Synthetic tone-control unit test",
            "UniqueCameraModel": "Synthetic camera",
            "ProfileName": "Baseline",
            "CalibrationIlluminant1": 17,
            "CalibrationIlluminant2": 21,
            "ColorMatrix1": [[1, 0, 0], [0, 1, 0], [0, 0, 1]],
            "ColorMatrix2": [[1, 0, 0], [0.125, 1, 0], [0, 0, 1]],
        }
        self.spec.write_text(json.dumps(matrix_spec), encoding="utf-8")
        self.dcp.write_bytes(build_dcp(matrix_spec))
        source, points = synthetic_source()
        with ZipFile(self.sdk, "x") as archive:
            archive.writestr(tone.SDK_MEMBER, source)
            archive.writestr("unrelated.txt", b"unrelated")
        self.expected = {
            key: build_dcp({**matrix_spec, "ProfileName": name, "ProfileToneCurve": curve})
            for key, name, curve in (
                ("identity", "PENTAX 1376 Tone Identity v1", [[0, 0], [1, 1]]),
                ("lift", "PENTAX 1376 Tone Lift v1", [[0, 0], [0.5, 0.53125], [1, 1]]),
                ("acr3", "PENTAX 1376 ACR3 Control v1", points),
            )
        }
        xy = [coord for point in points for coord in point]
        self.enterContext(patch.multiple(
            tone, BASE_JSON_SHA=sha256(self.spec.read_bytes()).hexdigest(),
            BASE_DCP_SHA=sha256(self.dcp.read_bytes()).hexdigest(),
            SDK_ZIP_SHA=sha256(self.sdk.read_bytes()).hexdigest(), SDK_MEMBER_SHA=sha256(source).hexdigest(),
            ACR3_PAYLOAD_SHA=sha256(struct.pack("<2050f", *xy)).hexdigest(),
            OUTPUT_SHA={key: sha256(data).hexdigest() for key, data in self.expected.items()},
        ))

    def generate(self):
        return tone.generate(self.spec, self.dcp, self.sdk, self.output)

    def test_rebuilds_all_controls_and_preserves_common_payloads(self):
        audit = self.generate()
        names = {
            "identity": "pentax-k3ii-1376-tone-identity-v1.dcp",
            "lift": "pentax-k3ii-1376-tone-lift-v1.dcp",
            "acr3": "pentax-k3ii-1376-acr3-control-v1.dcp",
        }
        self.assertEqual(set(self.output.iterdir()), {self.output / name for name in names.values()})
        baseline = describe(self.dcp.read_bytes())["tags"]
        self.assertNotIn("ProfileToneCurve", baseline)
        for key, name in names.items():
            data = (self.output / name).read_bytes()
            self.assertEqual(data, self.expected[key])
            tags = describe(data)["tags"]
            self.assertEqual(set(tags), set(baseline) | {"ProfileToneCurve"})
            self.assertEqual({tag for tag in baseline if tags[tag] != baseline[tag]}, {"ProfileName"})
            self.assertEqual(audit[name]["curve"], tags["ProfileToneCurve"])

    def test_every_pin_mismatch_is_rejected_before_creating_output(self):
        for field, message in (
            ("BASE_JSON_SHA", "Baseline JSON SHA-256"),
            ("BASE_DCP_SHA", "Baseline DCP SHA-256"),
            ("SDK_ZIP_SHA", "Adobe SDK ZIP SHA-256"),
            ("SDK_MEMBER_SHA", "source member SHA-256"),
            ("ACR3_PAYLOAD_SHA", "forward FLOAT payload SHA-256"),
            ("OUTPUT_SHA", "generated DCP SHA-256"),
        ):
            bad = {**tone.OUTPUT_SHA, "acr3": "0" * 64} if field == "OUTPUT_SHA" else "0" * 64
            with self.subTest(field=field), patch.object(tone, field, bad):
                with self.assertRaisesRegex(ValueError, message):
                    self.generate()
                self.assertFalse(os.path.lexists(self.output))

    def test_pinned_baseline_spec_must_rebuild_exact_dcp(self):
        spec = json.loads(self.spec.read_bytes())
        spec["ProfileName"] = "Mismatch"
        changed = json.dumps(spec).encode("utf-8")
        self.spec.write_bytes(changed)
        with patch.object(tone, "BASE_JSON_SHA", sha256(changed).hexdigest()):
            with self.assertRaisesRegex(ValueError, "does not rebuild the exact baseline DCP"):
                self.generate()
        self.assertFalse(os.path.lexists(self.output))

    def test_existing_destinations_are_untouched_even_with_missing_inputs(self):
        directory = self.root / "existing"
        directory.mkdir()
        marker = directory / "marker"
        marker.write_bytes(b"untouched")
        alias = self.root / "existing-hardlink"
        os.link(marker, alias)
        destinations = [directory, marker, alias]
        link = self.root / "existing-dangling-link"
        try:
            link.symlink_to(self.root / "missing")
        except OSError:
            # Some Windows accounts cannot create symlinks.
            pass
        else:
            self.assertFalse(link.exists())
            destinations.append(link)
        missing = self.root / "missing-input"
        for destination in destinations:
            with self.subTest(destination=destination), self.assertRaisesRegex(FileExistsError, "must be new"):
                tone.generate(missing, missing, missing, destination)
        self.assertEqual(marker.read_bytes(), b"untouched")
        self.assertEqual(alias.read_bytes(), b"untouched")
        self.assertEqual(list(directory.iterdir()), [marker])
        if link in destinations:
            self.assertTrue(link.is_symlink())

    def test_rolls_back_created_output_on_second_file_open_failure(self):
        open_file = Path.open

        def fail_lift(path, *args, **kwargs):
            if path.parent == self.output and path.name.endswith("tone-lift-v1.dcp"):
                raise OSError("synthetic output failure")
            return open_file(path, *args, **kwargs)

        with patch.object(Path, "open", fail_lift), self.assertRaisesRegex(OSError, "synthetic output failure"):
            self.generate()
        self.assertFalse(os.path.lexists(self.output))


if __name__ == "__main__":
    unittest.main()
