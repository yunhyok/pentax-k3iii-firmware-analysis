"""Focused trust-boundary and DCP tag handling tests without source assets."""
from hashlib import sha256
from pathlib import Path
import runpy
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

CHECKER = Path(__file__).resolve().parents[1]/"tools/check_lightroom_pef_neutral.py"
M = runpy.run_path(str(CHECKER))


def synthetic_profile(forward):
    fields = {
        50708:(2,4,b"ABC\0"), 50936:(2,4,b"DCP\0"),
        50721:(10,9,struct.pack("<ii",1,1)*9), 50722:(10,9,struct.pack("<ii",1,1)*9),
        50778:(3,1,struct.pack("<H",17)), 50779:(3,1,struct.pack("<H",21)),
    }
    if forward:
        fields[50964]=fields[50965]=(10,9,struct.pack("<ii",1,1)*9)
        for index in range(9):
            fields[64000+index]=(4,1,b"\0"*4)
    header = bytearray(b"IIRC\x08\0\0\0"+struct.pack("<H",len(fields)))
    payload = bytearray()
    tail = 10+len(fields)*12+4
    for code,(kind,count,data) in sorted(fields.items()):
        header.extend(struct.pack("<HHI",code,kind,count))
        if len(data)<=4:
            header.extend(data.ljust(4,b"\0"))
        else:
            header.extend(struct.pack("<I",tail+len(payload)))
            payload.extend(data)
    return bytes(header+b"\0"*4+payload)


class PefNeutralTests(unittest.TestCase):
    def test_profile_tag_counts_and_forward_tags(self):
        matrix,bright = synthetic_profile(False),synthetic_profile(True)
        self.assertEqual(set(M["model_tags"](matrix,6)),{50721,50722,50778,50779})
        self.assertEqual(set(M["model_tags"](bright,17)),{50721,50722,50778,50779,50964,50965})
        with self.assertRaises(AssertionError):
            M["model_tags"](bright,16)
        with self.assertRaises(AssertionError):
            M["model_tags"](bright[:-1],17)

    def test_capture_all_sources_before_execution(self):
        with TemporaryDirectory() as temp:
            root=Path(temp)
            t=root/"tools"
            t.mkdir()
            one=b"raise RuntimeError('must not execute')\n"
            two=b"value=2\n"
            (t/"one.py").write_bytes(one)
            (t/"two.py").write_bytes(two)
            pins={"one":("one.py",sha256(one).hexdigest()),"two":("two.py","0"*64)}
            with self.assertRaisesRegex(ValueError,"two.py"):
                M["sources"](root,pins)
            one=b"value=1\n"
            (t/"one.py").write_bytes(one.replace(b"\n",b"\r\n"))
            pins={"one":("one.py",sha256(one).hexdigest()),"two":("two.py",sha256(two).hexdigest())}
            self.assertEqual(M["sources"](root,pins)["one"].value,1)

    def test_output_alias_and_optimized_mode(self):
        with TemporaryDirectory() as temp:
            root=Path(temp)
            source=root/"input"
            source.write_bytes(b"preserve")
            alias=root/"alias"
            alias.hardlink_to(source)
            args=[word for name in ("sdk","dng","matrix","adobe-standard","camera-bright") for word in ("--"+name,str(source))]
            for target in (source,alias):
                out=subprocess.run([sys.executable,"-B",str(CHECKER),*args,"--output",str(target)],
                                   capture_output=True,text=True)
                self.assertNotEqual(out.returncode,0)
                self.assertIn("output must be a new file",out.stderr)
            self.assertEqual(source.read_bytes(),b"preserve")
        out=subprocess.run([sys.executable,"-B","-O",str(CHECKER),"--help"],capture_output=True,text=True)
        self.assertNotEqual(out.returncode,0)
        self.assertIn("Run without -O",out.stderr)


if __name__=="__main__":
    unittest.main()
