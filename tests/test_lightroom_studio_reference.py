"""Focused replay trust and paired-statistic controls."""
from hashlib import sha256
from pathlib import Path
import runpy
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT/"tools/check_lightroom_studio_reference.py"
METHOD = runpy.run_path(str(CHECKER))


class ReferenceTests(unittest.TestCase):
    def test_capture_before_any_source_execution(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools = root/"tools"
            tools.mkdir()
            first = b"raise RuntimeError('must not run if the second pin fails')\n"
            second = b"y = 2\n"
            (tools/"first.py").write_bytes(first)
            (tools/"second.py").write_bytes(second)
            pins = {"first":sha256(first).hexdigest(),"second":"0"*64}
            with self.assertRaisesRegex(ValueError,"second.py"):
                METHOD["load_sources"](root,pins)
            first = b"x = 1\n"
            (tools/"first.py").write_bytes(first.replace(b"\n",b"\r\n"))
            pins = {"first":sha256(first).hexdigest(),"second":sha256(second).hexdigest()}
            self.assertEqual(METHOD["load_sources"](root,pins)["first"].x,1)

    def test_size_and_input_boundary(self):
        with TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            root = parent/"fixtures"
            root.mkdir()
            (root/"one").write_bytes(b"one")
            (parent/"outside").write_bytes(b"outside")
            self.assertEqual(METHOD["bound_path"](root,"one",3),root/"one")
            with self.assertRaises(ValueError):
                METHOD["bound_path"](root,"one",2)
            with self.assertRaises(ValueError):
                METHOD["bound_path"](root,"../outside",7)

    def test_reference_reconstruction_keeps_all_other_metadata(self):
        class Base:
            @staticmethod
            def read_tiff(path,expected):
                return expected

        attrs = {"CameraProfile":"matrix","CameraProfileDigest":"matrix-digest","Temperature":"5400","Tint":"-7",
                 "Exposure2012":"0.00","WhiteBalance":"As Shot","LensProfileEnable":"0"}
        base = {"crs_attributes":attrs,"crs_nested":{"ToneCurve":"frozen"}}
        spec = {"sha256":"tiff-hash","tiff":{"bytes":99},"crs_attribute_count":len(attrs),"crs_nested_count":1,
                "crs_changes":{"CameraProfile":["matrix","Camera Bright"],"CameraProfileDigest":["matrix-digest","new-digest"],
                               "Temperature":["5400","5350"],"Tint":["-7","-6"]}}
        result = METHOD["reference_tiff"](Base,None,base,spec)
        self.assertEqual(result["crs_attributes"]["CameraProfile"],"Camera Bright")
        self.assertEqual(result["crs_attributes"]["LensProfileEnable"],"0")
        self.assertEqual(result["crs_nested"],base["crs_nested"])
        spec["crs_changes"]["LensProfileEnable"] = ["0","1"]
        with self.assertRaises(AssertionError):
            METHOD["reference_tiff"](Base,None,base,spec)

    def test_common_mask_and_paired_change(self):
        image = np.zeros((1,3,3))
        mask1,mask2 = np.array([[1,1,0]],bool),np.array([[0,1,1]],bool)
        members = {"matrix":{1:(image,image,mask1)},"reference":{1:(image,image,mask2)}}
        rows,kept = METHOD["intersect"](members,2)
        self.assertEqual(rows[0]["pixels"],1)
        self.assertEqual(kept,{})
        rgb = image[None]
        matrix,ref = rgb.copy(),rgb.copy()
        matrix[0,0,:,0] = [0,10,20]
        ref[0,0,:,0] = [7,11,12]
        delta = lambda first,second: np.abs(first[...,0]-second[...,0])
        record = METHOD["paired_change"](rgb,matrix,ref,np.ones(rgb.shape[:-1],bool),[1],delta)
        self.assertEqual(record["pixel_median"],1)
        self.assertNotEqual(record["pixel_median"],np.median(ref)-np.median(matrix))
        self.assertEqual(record["pixels_closer"],1)

    def test_existing_output_and_optimized_mode(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp)/"existing"
            output.write_bytes(b"preserve")
            proc = subprocess.run([sys.executable,"-B",str(CHECKER),"--inputs","missing","--exiftool","missing",
                                   "--tificc","missing","--output",str(output)],capture_output=True,text=True)
            self.assertNotEqual(proc.returncode,0)
            self.assertIn("output must be a new file",proc.stderr)
            self.assertEqual(output.read_bytes(),b"preserve")
        proc = subprocess.run([sys.executable,"-B","-O",str(CHECKER),"--help"],capture_output=True,text=True)
        self.assertNotEqual(proc.returncode,0)
        self.assertIn("Run without -O",proc.stderr)


if __name__=="__main__":
    unittest.main()
