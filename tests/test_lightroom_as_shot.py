"""Trust-boundary and math tests without the SDK or proprietary fixtures."""
from hashlib import sha256
from pathlib import Path
import runpy
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

import numpy as np

CHECKER = Path(__file__).resolve().parents[1]/"tools/check_lightroom_as_shot.py"
METHOD = runpy.run_path(str(CHECKER))


class AsShotTests(unittest.TestCase):
    def test_complete_typed_result_and_exclusive_output(self):
        expected = {"samples": [1.0, 0.0], "passes": 6, "flag": False, "label": "Q7"}
        reference = METHOD["result_bytes"](expected)
        archive = {"reference_calculation": expected,
                   "q7": {"reference_calculation_sha256": sha256(reference).hexdigest()}}
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root/"result.json"
            for changed, message in (
                (dict(expected, samples=[1.0, 1.01e-10]), "absolute tolerance"),
                (dict(expected, samples=[1.0, float("nan")]), "Out of range"),
                (dict(expected, samples=[1.0, float("inf")]), "Out of range"),
                (dict(expected, samples=[1.0]), "list length"),
                (dict(expected, samples=[1, 0.0]), "type mismatch"),
                (dict(expected, passes=6.0), "type mismatch"),
                (dict(expected, flag=0), "type mismatch"),
                (dict(expected, label="other"), "value mismatch"),
                (dict(expected, extra=1), "keys mismatch"),
                ({k:v for k,v in expected.items() if k!="label"}, "keys mismatch"),
            ):
                with self.subTest(changed=changed):
                    with self.assertRaisesRegex(ValueError,message):
                        METHOD["write_result"](output,changed,archive)
                    self.assertFalse(output.exists())
            bad_archive = dict(archive,q7={"reference_calculation_sha256":"0"*64})
            with self.assertRaisesRegex(ValueError,"reference calculation SHA-256"):
                METHOD["write_result"](output,expected,bad_archive)
            self.assertFalse(output.exists())
            actual = dict(expected,samples=(1.0,1e-10))
            got = METHOD["write_result"](output,actual,archive)
            self.assertEqual(got["match"],"numeric")
            self.assertEqual(output.read_bytes(),METHOD["result_bytes"](actual))
            self.assertEqual(got["sha256"],sha256(output.read_bytes()).hexdigest())
            self.assertEqual(got["reference_sha256"],sha256(reference).hexdigest())
            with self.assertRaises(FileExistsError):
                METHOD["write_result"](output,expected,archive)
            self.assertEqual(output.read_bytes(),METHOD["result_bytes"](actual))
            exact = root/"exact.json"
            got = METHOD["write_result"](exact,expected,archive)
            self.assertEqual(got["match"],"exact")
            self.assertEqual(exact.read_bytes(),reference)

    def test_float_comparison_has_no_relative_tolerance(self):
        with self.assertRaisesRegex(ValueError,"absolute tolerance"):
            METHOD["compare_result"](1e10 + 1e-5, 1e10)
        for bad in (float("nan"),float("inf"),float("-inf")):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError,"absolute tolerance"):
                METHOD["compare_result"](bad,bad)

    def test_bounded_input_size_and_content(self):
        with TemporaryDirectory() as tmp:
            f = Path(tmp)/"input"
            pin = {"bytes":3,"sha256":sha256(b"abc").hexdigest()}
            f.write_bytes(b"abc")
            self.assertEqual(METHOD["read_input"](f,pin),b"abc")
            f.write_bytes(b"abd")
            with self.assertRaisesRegex(ValueError,"SHA-256"):
                METHOD["read_input"](f,pin)
            f.write_bytes(b"abcd")
            with self.assertRaisesRegex(ValueError,"input size"):
                METHOD["read_input"](f,pin)
            with self.assertRaisesRegex(ValueError,"regular"):
                METHOD["read_input"](Path(tmp),pin)

    def test_captured_code_lf_pin(self):
        with TemporaryDirectory() as tmp:
            f = Path(tmp)/"helper.py"
            data = b"example = 1\n"
            f.write_bytes(data.replace(b"\n",b"\r\n"))
            pin = sha256(data).hexdigest()
            self.assertEqual(METHOD["checked"](f,pin,True),data)
            f.write_bytes(b"example = 2\n")
            with self.assertRaisesRegex(ValueError,"SHA-256"):
                METHOD["checked"](f,pin,True)

    def test_independent_diagonal_neutral_and_forward_mapping(self):
        # The artificial isotherm changes interpolation weights only. Each
        # profile has equal endpoint matrices, so its solved xy is analytical.
        table = [(20.*i, .18+.003*i, .25+.006*i, -1.) for i in range(31)]
        raw = np.array([.75,1.,.5])
        first = np.eye(3)
        second = np.diag([1.25,1.,.8])
        for color,solved_xyz in ((first,(.75,1.,.5)),(second,(.6,1.,.625))):
            forward = np.diag(METHOD["xyz"](METHOD["D50"]))  # Exact fixture PCS white.
            record = METHOD["model"](raw,(color,color),(forward,forward),table)
            total = sum(solved_xyz)
            np.testing.assert_allclose(record["xy"],[solved_xyz[0]/total,1/total],rtol=0,atol=1e-15)
            np.testing.assert_allclose(record["camera_white_rgb"],raw,rtol=0,atol=1e-15)
            np.testing.assert_allclose(record["reciprocal_neutral_ratios_green_1"],[4/3,1,2],rtol=0,atol=1e-15)
            self.assertLess(record["pcs_white_mapping_max_abs_error"],1e-14)
        self.assertEqual([METHOD["fraction"](x) for x in (2000,2850,6500,9000)],[1.,1.,0.,0.])

    def test_output_alias_and_optimized_mode(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root/"input"
            source.write_bytes(b"original")
            args = [flag for name in ("sdk","raw","pef","matrix","adobe-standard") for flag in ("--"+name,str(source))]
            alias = root/"hardlink"
            alias.hardlink_to(source)
            for output in (source,alias,root/"missing-parent/out"):
                command = [sys.executable,"-B",str(CHECKER),*args,"--output",str(output)]
                got = subprocess.run(command,capture_output=True,text=True)
                self.assertNotEqual(got.returncode,0)
                self.assertIn("output must be a new file",got.stderr)
            self.assertEqual(source.read_bytes(),b"original")
        got = subprocess.run([sys.executable,"-B","-O",str(CHECKER),"--help"],capture_output=True,text=True)
        self.assertNotEqual(got.returncode,0)
        self.assertIn("Run without -O",got.stderr)


if __name__=="__main__":
    unittest.main()
