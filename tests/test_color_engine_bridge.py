from pathlib import Path
import subprocess
import sys
import unittest
from tempfile import TemporaryDirectory

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import check_color_engine_bridge as compare


class MatrixExportTests(unittest.TestCase):
    def test_pixel_and_channel_difference_counts(self):
        before = np.zeros((129, 2, 3), dtype="uint16")
        after = before.copy()
        before[0, 0] = [0, 4, 65535]
        after[0, 0] = [65535, 4, 0]
        after[128, 1] = [0, 2, 0]
        result = compare.rgb_difference(before, after)
        self.assertEqual(result["changed_pixels"], 2)
        self.assertEqual(result["changed_samples_rgb"], [1, 1, 1])
        self.assertEqual(result["positive_delta_samples_rgb"], [1, 1, 0])
        self.assertEqual(result["negative_delta_samples_rgb"], [0, 0, 1])
        self.assertEqual(result["maximum_absolute_delta_rgb"], [65535, 2, 65535])
        self.assertEqual(result["maximum_absolute_delta"], 65535)
        self.assertEqual(result["mean_absolute_delta_rgb"], [65535 / 258, 2 / 258, 65535 / 258])
        self.assertTrue(compare.rgb_difference(before, before)["identical_pixel_arrays"])

    def test_nested_xmp_diff_includes_child_values(self):
        xmp = compare.render.ET.fromstring('''
            <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
                     xmlns:crs="http://ns.adobe.com/camera-raw-settings/1.0/">
              <rdf:Description crs:Version="18.7" crs:ProcessVersion="15.4">
                <crs:Curve><rdf:Seq><rdf:li>0, 0</rdf:li></rdf:Seq></crs:Curve>
              </rdf:Description>
            </rdf:RDF>''')
        attrs, nested = compare.develop_fields(xmp)
        xmp.find(".//{http://www.w3.org/1999/02/22-rdf-syntax-ns#}li").text = "1, 1"
        _, changed = compare.develop_fields(xmp)
        self.assertEqual(attrs["ProcessVersion"], ["15.4"])
        self.assertEqual(set(compare.field_diff(nested, changed)["changed"]), {"Curve"})

    def test_output_guard_and_optimized_mode(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "existing.json"
            output.write_bytes(b"sentinel")
            command = [sys.executable, "-B", compare.__file__, "--raw", "missing.dng",
                       "--old-tiff", "missing-old.tif", "--new-tiff", "missing-new.tif", "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("output must be a new file", result.stderr)
            self.assertEqual(output.read_bytes(), b"sentinel")
            command.insert(2, "-O")
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Run without -O", result.stderr)

    def test_fresh_export_relaxes_only_container_metadata(self):
        frozen = compare.load_record()["new_tiff"]
        fresh = {**frozen, "bytes": frozen["bytes"] + 10, "file_sha256": "new", "xmp_sha256": "new"}
        compare.require_export(fresh, frozen)
        fresh["pixels_le_rgb16_sha256"] = "changed"
        with self.assertRaisesRegex(AssertionError, "Chart export"):
            compare.require_export(fresh, frozen)


if __name__ == "__main__":
    unittest.main()
