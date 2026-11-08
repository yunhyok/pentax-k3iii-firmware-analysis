"""Reproduce six hash-pinned Adobe profile fingerprints from DCP/TIFF pairs."""
import argparse
from hashlib import file_digest, md5, sha256
import json
import math
import os
from pathlib import Path
import struct
import sys
import xml.etree.ElementTree as ET
from zipfile import BadZipFile, ZipFile

if not __debug__:
    raise RuntimeError("Run without -O so all evidence checks remain enabled.")
sys.dont_write_bytecode = True
import tifffile

RECORD = Path(__file__).resolve().parents[1] / "analysis/lightroom-profile-fingerprints.json"
RECORD_SHA256 = "609d686102c52a44d314b46c0220f86e21af6b85b754b07ec35fa80af8110ce3"
SIX_TAGS = {50708, 50721, 50722, 50778, 50779, 50936}
TYPE_SIZES = {2: 1, 3: 2, 10: 8, 11: 4}
SDK_MAX_TONE_POINTS = 8192  # Adobe dng_sdk_limits.h:72.
CRS = "{http://ns.adobe.com/camera-raw-settings/1.0/}"


def digest(data):
    return sha256(data).hexdigest()


def digest_file(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def read_ifd(data):
    endian = {b"IIRC": "<", b"MMCR": ">"}.get(data[:4])
    assert endian and struct.unpack_from(endian + "I", data, 4) == (8,)
    count, = struct.unpack_from(endian + "H", data, 8)
    assert count in (6, 7)
    end = 10 + 12 * count
    assert data[end:end + 4] == b"\0" * 4
    tags = {}
    for entry in range(10, end, 12):
        code, kind, length, offset = struct.unpack_from(endian + "HHII", data, entry)
        assert kind in TYPE_SIZES, f"Unsupported TIFF field type {kind}"
        size = TYPE_SIZES[kind] * length
        start = entry + 8 if size <= 4 else offset
        assert size and start + size <= len(data) and code not in tags
        if size > 4:
            assert start >= end + 4 and start % 2 == 0
        tags[code] = (kind, length, data[start:start + size])
    assert set(tags) in (SIX_TAGS, SIX_TAGS | {50940}), "Unsupported profile IFD tag set"
    for code in (50708, 50936):
        kind, length, payload = tags[code]
        assert kind == 2 and payload.endswith(b"\0") and b"\0" not in payload[:-1] and length > 1
        payload[:-1].decode("ascii")  # All six named fixtures have ASCII strings.
    return endian, tags


def round_int(value):
    return int(value + 0.5 if value > 0 else value - 0.5)


def normalize_matrix(payload, endian):
    pairs = tuple(struct.iter_unpack(endian + "ii", payload))
    assert len(pairs) == 9 and all(d > 0 for _, d in pairs)
    matrix = [n / d for n, d in pairs]
    x, y = 0.3457, 0.3585
    pcs = (x / y, 1.0, (1.0 - x - y) / y)
    maximum = max((matrix[row] * pcs[0] + matrix[row + 1]) + matrix[row + 2] * pcs[2]
                  for row in (0, 3, 6))
    scale = 1.0 / maximum if maximum > 0 and (maximum < 0.99 or maximum > 1.01) else 1.0
    matrix = [round_int(value * scale * 10000) * 0.0001 for value in matrix]
    return [(round_int(value * 10000), 10000 if value else 1) for value in matrix]


def stream_segments(data):
    endian, tags = read_ifd(data)
    segments = {}
    zeroes = []
    for i, (illuminant, matrix) in enumerate(((50778, 50721), (50779, 50722)), 1):
        kind, count, payload = tags[illuminant]
        assert (kind, count) == (3, 1)
        value, = struct.unpack(endian + "H", payload)
        assert value in (17, 20, 21)
        segments[f"illuminant_{i}"] = struct.pack("<H", value)
        kind, count, payload = tags[matrix]
        assert (kind, count) == (10, 9)
        rationals = normalize_matrix(payload, endian)
        segments[f"color_matrix_{i}"] = b"".join(struct.pack("<ii", n, d) for n, d in rationals)
        zeroes.append(sum(n == 0 for n, _ in rationals))
    segments["profile_name"] = tags[50936][2][:-1]
    segments["embed_policy"] = struct.pack("<I", 0)
    if 50940 in tags:
        kind, count, payload = tags[50940]
        assert kind == 11 and 4 <= count <= 2 * SDK_MAX_TONE_POINTS and count % 2 == 0
        points = tuple(struct.iter_unpack(endian + "ff", payload))
        assert all(math.isfinite(v) and 0 <= v <= 1 for pair in points for v in pair)
        assert all(a[0] < b[0] for a, b in zip(points, points[1:]))
        segments["tone_curve"] = b"".join(struct.pack("<ff", x, y) for x, y in points)
    return segments, zeroes


def fingerprints(segments):
    full = b"".join(segments.values())
    render = b"".join(value for name, value in segments.items() if name not in ("profile_name", "embed_policy"))
    return md5(full).hexdigest().upper(), md5(render).hexdigest().upper()



def load_record(data):
    record = json.loads(data)
    assert isinstance(record, dict), "Expected a JSON fixture object"
    canonical = json.dumps(record, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    assert record["schema_version"] == 1 and digest(canonical.encode("utf-8")) == RECORD_SHA256, "Fixture SHA-256 mismatch"
    return record


def verify_sdk(path, sdk):
    with path.open("rb") as stream:
        assert file_digest(stream, "sha256").hexdigest() == sdk["archive_sha256"], "Adobe SDK ZIP SHA-256 mismatch"
        stream.seek(0)
        with ZipFile(stream) as archive:
            for name, entry in sdk["members"].items():
                assert digest(archive.read(sdk["source_prefix"] + name)) == entry["sha256"], name


def inspect_tiff(path, expected_sha):
    assert digest_file(path) == expected_sha, f"{path.name}: TIFF SHA-256 mismatch"
    with tifffile.TiffFile(path) as tif:
        root = ET.fromstring(tif.pages[0].tags[700].value)
    wanted = {CRS + "CameraProfile", CRS + "CameraProfileDigest"}
    fields = [(key, value) for node in root.iter() for key, value in node.attrib.items() if key in wanted]
    assert len(fields) == 2 and {key for key, _ in fields} == wanted
    return dict(fields)


def verify_cases(args, record):
    verified = {}
    for key, files in record["input_layout"].items():
        expected = record["profiles"][key]
        dcp_sha, tiff_sha = expected["dcp_sha256"], expected["tiff_sha256"]
        data = (args.dcps / files["dcp"]).read_bytes()
        assert digest(data) == dcp_sha, f"{key}: DCP SHA-256 mismatch"
        xmp = inspect_tiff(args.exports / files["tiff"], tiff_sha)
        segments, zeroes = stream_segments(data)
        profile = segments["profile_name"].decode("ascii")
        assert xmp[CRS + "CameraProfile"] == profile
        full, render = fingerprints(segments)
        assert full == xmp[CRS + "CameraProfileDigest"] == expected["xmp_camera_profile_digest"] and render != full
        assert zeroes == [0, 0]
        file_md5 = md5(data).hexdigest().upper()
        assert file_md5 != full
        verified[key] = {
            "dcp_sha256": dcp_sha, "tiff_sha256": tiff_sha, "profile": profile,
            "xmp_camera_profile_digest": xmp[CRS + "CameraProfileDigest"],
            "computed_full_md5": full, "computed_render_data_md5": render,
            "dcp_file_md5": file_md5,
            "stream_bytes": sum(map(len, segments.values())),
            "stream_sha256": digest(b"".join(segments.values())),
            "stream_segments_in_order": {name: {"bytes": len(chunk), "sha256": digest(chunk)}
                                         for name, chunk in segments.items()},
            "normalized_zero_entries_per_matrix": zeroes,
        }
    return verified



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True, help="exact Adobe DNG SDK ZIP")
    parser.add_argument("--dcps", type=Path, required=True, help="directory containing the six DCPs")
    parser.add_argument("--exports", type=Path, required=True, help="root containing the six TIFF subdirectories")
    parser.add_argument("--output", type=Path, required=True, help="new replay JSON file")
    args = parser.parse_args()
    if os.path.lexists(args.output) or not args.output.parent.is_dir():
        parser.error("output must be a new file in an existing directory, including links")
    try:
        record = load_record(RECORD.read_bytes())
        verify_sdk(args.sdk, record["sdk"])
        profiles = verify_cases(args, record)
        assert profiles == record["profiles"], "Replay differs from the published fixture"
        text = json.dumps({**record, "profiles": profiles}, ensure_ascii=False, indent=2, allow_nan=False)
        with args.output.open("x", encoding="utf-8", newline="\n") as out:
            out.write(text + "\n")
    except (AssertionError, OSError, KeyError, ValueError, struct.error, BadZipFile) as error:
        parser.exit(1, f"Profile fingerprint check failed: {error or 'invalid profile or TIFF metadata'}\n")
    print("Six calculated full profile fingerprints match the TIFF CameraProfileDigest values.")


if __name__ == "__main__":
    main()
