"""Describe DCP structure without exporting matrices, curves or lookup-table values."""

import argparse
import hashlib
import json
from pathlib import Path
import struct


TAGS = {
    50708: "UniqueCameraModel", 50721: "ColorMatrix1", 50722: "ColorMatrix2",
    50778: "CalibrationIlluminant1", 50779: "CalibrationIlluminant2",
    50936: "ProfileName", 50937: "ProfileHueSatMapDims",
    50938: "ProfileHueSatMapData1", 50939: "ProfileHueSatMapData2",
    50940: "ProfileToneCurve", 50964: "ForwardMatrix1", 50965: "ForwardMatrix2",
    50981: "ProfileLookTableDims", 50982: "ProfileLookTableData",
    51107: "ProfileHueSatMapEncoding", 51108: "ProfileLookTableEncoding",
}
TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2,
              9: 4, 10: 8, 11: 4, 12: 8}


def describe(data):
    if len(data) < 8 or data[:4] not in (b"IIRC", b"MMCR"):
        raise ValueError("Expected a DNG camera profile header.")
    endian = "<" if data[:2] == b"II" else ">"
    offset = struct.unpack_from(endian + "I", data, 4)[0]
    if not 8 <= offset <= len(data) - 2:
        raise ValueError("Invalid profile IFD offset.")
    count = struct.unpack_from(endian + "H", data, offset)[0]
    end = offset + 2 + count * 12
    if end + 4 > len(data):
        raise ValueError("Truncated profile IFD.")
    if struct.unpack_from(endian + "I", data, end)[0]:
        raise ValueError("Only a single camera-profile IFD is supported.")
    tags = {}
    seen = set()
    for index in range(count):
        entry = offset + 2 + 12 * index
        tag, kind, items, value = struct.unpack_from(endian + "HHII", data, entry)
        if tag in seen or kind not in TYPE_SIZES:
            raise ValueError("Duplicate tag or unsupported TIFF type.")
        seen.add(tag)
        size = TYPE_SIZES[kind] * items
        start = entry + 8 if size <= 4 else value
        if start + size > len(data):
            raise ValueError(f"Tag {tag} extends beyond the file.")
        if tag not in TAGS:
            continue
        payload = data[start:start + size]
        item = {"type": kind, "count": items,
                "sha256": hashlib.sha256(payload).hexdigest()}
        if tag in (50708, 50936):
            if kind != 2 or not payload.endswith(b"\0"):
                raise ValueError("Invalid profile name or camera-model string.")
            item["text"] = payload.rstrip(b"\0").decode("utf-8")
        if tag in (50937, 50981):
            if kind != 4 or items != 3:
                raise ValueError("Expected three LONG table dimensions.")
            item["dimensions"] = list(struct.unpack(endian + "III", payload))
        if tag in (50778, 50779, 51107, 51108):
            if kind not in (3, 4) or items != 1:
                raise ValueError("Expected one integer illuminant or encoding.")
            item["value"] = struct.unpack(endian + {3: "H", 4: "I"}[kind], payload)[0]
        tags[TAGS[tag]] = item
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "tags": tags}


def self_test():
    for endian, header in (("<", b"IIRC"), (">", b"MMCR")):
        sample = (header + struct.pack(endian + "IH", 8, 1)
                  + struct.pack(endian + "HHII", 50981, 4, 3, 26)
                  + struct.pack(endian + "IIII", 0, 36, 8, 16))
        assert describe(sample)["tags"]["ProfileLookTableDims"]["dimensions"] == [36, 8, 16]
        for broken in (sample[:6], sample[:-1], sample[:4] + b"\xff" * 4 + sample[8:]):
            try:
                describe(broken)
            except ValueError:
                continue
            raise AssertionError("Malformed DCP was accepted.")
    print("DCP metadata self-test passed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profiles", nargs="*", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.profiles:
        parser.error("Supply one or more .dcp paths.")
    try:
        output = [{"file": path.name, **describe(path.read_bytes())} for path in args.profiles]
        print(json.dumps(output, indent=2))
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"Profile inspection failed: {error}\n")


if __name__ == "__main__":
    main()
