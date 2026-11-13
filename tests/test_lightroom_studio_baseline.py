from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT/"tools/check_lightroom_studio_baseline.py"
sys.path.insert(0,str(CLI.parent))
import check_lightroom_studio_baseline as tool


class StudioBaselineTests(unittest.TestCase):
    def test_all_sources_are_captured_before_any_execution(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            (root/"tools").mkdir()
            first,second = (root/"tools"/(n+".py") for n in ("first","second"))
            first.write_bytes(b"raise RuntimeError('would execute before second pin')\r\n")
            second.write_bytes(b"value = 2\n")
            first_pin = sha256(first.read_bytes().replace(b"\r\n",b"\n")).hexdigest()
            with self.assertRaisesRegex(ValueError,"second.py"):
                tool.load_sources({"first":first_pin,"second":"0"*64},root)
            first.write_bytes(b"value = 1\r\n")
            module = tool.load_sources({"first":sha256(b"value = 1\n").hexdigest()},root)["first"]
            self.assertEqual(module.value,1)

    def test_malformed_tiff_rejected_by_hash_before_parse(self):
        with tempfile.TemporaryDirectory() as path:
            fixture = Path(path)/"unrelated.tif"
            fixture.write_bytes(b"malformed TIFF")
            with self.assertRaisesRegex(ValueError,"TIFF SHA"):
                tool.read_tiff(fixture,{"file_sha256":"0"*64})

    def test_mask_drift_rejected_even_when_count_matches(self):
        spec = {"preselected_geometry":{"sites":[{"id":1,"xy":[1,1],"fit":True,"jpeg_template_gradient_std":3.0}]}}
        plan = {"registration":{"local_verification":{"minimum_scored_regions_per_scene":1}}}
        region = {"site_id":1,"used":True,"mask_sha256_c_order_uint8":sha256(b"\x01\x00").hexdigest()}
        actual = {"id":1,"xy":[1,1],"fit":True,"texture":3.0}
        helper = SimpleNamespace(geometry=lambda *_: ({},[actual],[actual],None),
                                 gather=lambda *_: ([],[],[np.array([False,True])],[region]))
        history = {"global_registration":{},"registration_sites":[actual],"regions":[region],
                   "local_passed_regions":1,"qualified_regions":1,"qualified_pixels":1,
                   "minimum_qualified_regions":1,"geometry_and_mask_gate_passed":True,
                   "geometry_model":"independent_local_translation"}
        with self.assertRaises(AssertionError):
            tool.replay_geometry(plan,spec,history,helper,None,None)

    def test_bins_and_pooled_vs_equal_region(self):
        jpeg = np.array([[[[0,0,0],[25,3,4],[50,0,20],[100,0,40]]],
                         [[[75,0,40],[99,0,0],[99,0,0],[99,0,0]]]],dtype=float)
        tiff = jpeg.copy()
        tiff[...,0] += np.array([1,5])[:,None,None]
        mask = np.array([[[True]*4],[[True,False,False,False]]])
        opts = {"jpeg_L_edges":[0,25,50,75,100],"jpeg_C_edges":[0,5,20,40,None]}
        result = tool.compare(jpeg,tiff,mask,[{"site_id":1},{"site_id":2}],opts,lambda a,b: np.abs(a[...,0]-b[...,0]))
        self.assertEqual(result["overall"]["pixel_weighted"]["median_delta_Lstar"],1)
        self.assertEqual(result["overall"]["equal_region"]["median_delta_Lstar"],3)
        self.assertEqual([row["pixels"] for row in result["jpeg_L_bins"]],[1,1,1,2])
        self.assertEqual([row["pixels"] for row in result["jpeg_C_bins"]],[1,1,1,2])
        self.assertFalse(tool.same_record({"x":True},{"x":1}))

    def test_exclusive_output_and_optimized_mode(self):
        with tempfile.TemporaryDirectory() as path:
            output = Path(path)/"existing.json"
            output.write_bytes(b"preserved")
            existing = subprocess.run([sys.executable,"-B",str(CLI),"--inputs","missing","--exiftool","missing",
                                       "--tificc","missing","--output",str(output)],capture_output=True,text=True)
            self.assertEqual(existing.returncode,2)
            self.assertIn("output must be a new file",existing.stderr)
            self.assertEqual(output.read_bytes(),b"preserved")
        optimized = subprocess.run([sys.executable,"-B","-O",str(CLI),"--help"],capture_output=True,text=True)
        self.assertNotEqual(optimized.returncode,0)
        self.assertIn("Run without -O",optimized.stderr)


if __name__=="__main__":
    unittest.main()
