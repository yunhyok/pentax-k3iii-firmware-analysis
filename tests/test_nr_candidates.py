import copy
import hashlib
import struct
import unittest

from verify_nr_candidates import inspect


class NrAnchorTests(unittest.TestCase):
    def setUp(self):
        self.data = struct.pack("<I", 0xeb000000) + b"NR\0\0" + b"\0" * 4
        self.profile = {"size": len(self.data), "sha256": hashlib.sha256(self.data).hexdigest(),
                        "version": "synthetic", "offset": 0, "length": len(self.data), "base": 0,
                        "strings": {"nr": (4, b"NR")}, "words": {0: 0xeb000000},
                        "calls": {0: 8}, "ranges": {"test": (0, 12)}}

    def test_static_record_and_call(self):
        result = inspect(self.data, self.profile)
        self.assertEqual(result["calls"], [{"site": "0x0", "target": "0x8"}])
        self.assertEqual(result["ranges"]["test"]["sha256"], self.profile["sha256"])

    def test_wrong_firmware_and_truncation_rejected(self):
        for data in (self.data[:-1], b"X" + self.data[1:]):
            with self.subTest(data=data), self.assertRaises(ValueError):
                inspect(data, self.profile)

    def test_wrong_anchors_rejected(self):
        for key, value in [("strings", {"nr": (4, b"NX")}), ("words", {0: 0xea000000}),
                           ("calls", {0: 12}), ("ranges", {"test": (0, 13)}),
                           ("offset", 4)]:
            profile = copy.deepcopy(self.profile)
            profile[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                inspect(self.data, profile)


if __name__ == "__main__":
    unittest.main()
