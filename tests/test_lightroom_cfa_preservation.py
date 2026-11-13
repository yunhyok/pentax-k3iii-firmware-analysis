"""Test signed differences and file/output trust boundaries without rawpy."""
from hashlib import sha256
import json
from pathlib import Path
import runpy
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT/"tools/check_lightroom_cfa_preservation.py"
METHOD = runpy.run_path(str(CHECKER))


class CfaTests(unittest.TestCase):
    def test_unsigned_extremes_and_mismatched_shape(self):
        left = np.array([[0,65535]],dtype=np.uint16)
        right = np.array([[65535,0]],dtype=np.uint16)
        result = METHOD["delta_record"](left,right)
        self.assertEqual((result["min_delta"],result["max_delta"],result["equal_samples"]),(-65535,65535,0))
        self.assertEqual(METHOD["delta_record"](left,right.T),{"same_shape":False})

    def test_capture_rejects_wrong_size_digest_and_file_type(self):
        with TemporaryDirectory() as tmp:
            f = Path(tmp)/"input"
            with patch.dict(METHOD["INPUTS"],{"pef":(3,sha256(b"abc").hexdigest())}):
                f.write_bytes(b"abc")
                self.assertEqual(METHOD["capture"](f,"pef"),b"abc")
                f.write_bytes(b"abd")
                with self.assertRaisesRegex(ValueError,"digest mismatch"):
                    METHOD["capture"](f,"pef")
                f.write_bytes(b"ab")
                with self.assertRaisesRegex(ValueError,"size mismatch"):
                    METHOD["capture"](f,"pef")
                with self.assertRaisesRegex(ValueError,"regular input"):
                    METHOD["capture"](Path(tmp),"pef")

    def test_complete_payload_pin(self):
        data = json.loads((ROOT/"analysis/lightroom-cfa-preservation.json").read_bytes())["comparison"]
        self.assertEqual(sha256(METHOD["verify_payload"](data)).hexdigest(),METHOD["REFERENCE_SHA"])
        data["pef_libraw"]["white_level"] -= 1
        with self.assertRaisesRegex(ValueError,"Complete CFA replay differs"):
            METHOD["verify_payload"](data)

    def test_existing_output_alias_before_decoder_import(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root/"input"
            f.write_bytes(b"preserve")
            alias = root/"alias"
            alias.hardlink_to(f)
            for output in (f,alias):
                proc = subprocess.run([sys.executable,"-B",str(CHECKER),"--pef",str(f),"--dng",str(f),
                                       "--output",str(output)],capture_output=True,text=True)
                self.assertNotEqual(proc.returncode,0)
                self.assertIn("output must be a new file",proc.stderr)
                self.assertEqual(f.read_bytes(),b"preserve")
            missing = root/"not-written"
            proc = subprocess.run([sys.executable,"-B",str(CHECKER),"--pef",str(f),"--dng",str(f),
                                   "--output",str(missing)],capture_output=True,text=True)
            self.assertNotEqual(proc.returncode,0)
            self.assertIn("pef: size mismatch",proc.stderr)
            self.assertFalse(missing.exists())


if __name__=="__main__":
    unittest.main()
