"""Rebuild the three exact K-3 II #1376 Lightroom tone-control DCPs."""
import argparse
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import re
import struct
import sys
from zipfile import BadZipFile, ZipFile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inspect_adobe_profiles import describe
from tools.profile_bridge import build_dcp, unique_fields

BASE_JSON_SHA = "dcdeca66bcc3f2ea0ebdb2a91856aea3c794244ada89994eed67f3914013a04d"
BASE_DCP_SHA = "6aa402a77f6b41f9fa37e99f1bd6911447e74c112eb7f7601c8c3bb116570ee4"
SDK_ZIP_SHA = "c1d3a545ed45b150e59af2e6aa0695c1551f0e2bed34ad87436898a05194d2b1"
SDK_MEMBER_SHA = "e8920b456e46b9b11a4bb775694aa516c9b5afe2998926acb0c4086eca71529c"
SDK_MEMBER = "dng_sdk_1_7_1/dng_sdk/source/dng_render.cpp"
ACR3_PAYLOAD_SHA = "51dac135a83970b08279dcdcc59839b851c66c7069501aabbbd014ba57715b01"
OUTPUT_SHA = {
    "identity": "7fde7d8708ef93324ff5c76e893fa1ecbb2fc4c49ba1269a5d4c3418b65d92f4",
    "lift": "f106554b266df62c4d4a0ba4a86e87143fe872e53963c8e8aa37775466065fbf",
    "acr3": "d9bd4d7bfecfcddbbdb3fd88c87bb487bf53af06221fb66b5ada8adb0345cd9f",
}
COMMON_TAGS = {
    "UniqueCameraModel", "ColorMatrix1", "ColorMatrix2", "CalibrationIlluminant1", "CalibrationIlluminant2",
}


def parse_forward_table(source):
    text = source.decode("utf-8")
    function = "real64 dng_tone_curve_acr3_default::Evaluate"
    start = text.find(function + " (real64 x) const")
    end = text.find(function + "Inverse", start + 1)
    if not 0 <= start < end:
        raise ValueError("SDK ACR3 forward/inverse boundary not found")
    tables = re.findall(r"\bkTable\s*\[\]\s*=\s*\{([^}]+)\}", text[start:end])
    if len(tables) != 1:
        raise ValueError("Expected one SDK ACR3 forward table")
    values = [token.strip() for token in tables[0].strip().removesuffix(",").split(",")]
    if len(values) != 1025 or any(not re.fullmatch(r"[01]\.\d+f", token) for token in values):
        raise ValueError("Expected 1025 decimal FLOAT ordinates in the SDK ACR3 forward table")
    ordinates = [struct.unpack("<f", struct.pack("<f", float(token[:-1])))[0] for token in values]
    if ordinates[0] != 0 or ordinates[-1] != 1 or any(a >= b for a, b in zip(ordinates, ordinates[1:])):
        raise ValueError("Expected strictly increasing SDK ACR3 ordinates from zero to one")
    return [[index / 1024, value] for index, value in enumerate(ordinates)]


def curve_tag(points):
    payload = b"".join(struct.pack("<ff", x, y) for x, y in points)
    return {"type": 11, "count": len(points) * 2, "sha256": sha256(payload).hexdigest()}


def read_acr3(sdk_zip):
    # Hash and read the same archive handle. No SDK member is extracted to disk.
    with sdk_zip.open("rb") as stream:
        if file_digest(stream, "sha256").hexdigest() != SDK_ZIP_SHA:
            raise ValueError("Adobe SDK ZIP SHA-256 mismatch")
        stream.seek(0)
        with ZipFile(stream) as archive:
            try:
                source = archive.read(SDK_MEMBER)
            except KeyError as error:
                raise ValueError("Pinned Adobe SDK source member missing") from error
    if sha256(source).hexdigest() != SDK_MEMBER_SHA:
        raise ValueError("Adobe SDK source member SHA-256 mismatch")
    points = parse_forward_table(source)
    if curve_tag(points)["sha256"] != ACR3_PAYLOAD_SHA:
        raise ValueError("ACR3 forward FLOAT payload SHA-256 mismatch")
    return points


def generate(baseline_json, baseline_dcp, sdk_zip, output_dir):
    if os.path.lexists(output_dir):
        raise FileExistsError("Output directory must be new, including links")
    source, baseline = baseline_json.read_bytes(), baseline_dcp.read_bytes()
    if sha256(source).hexdigest() != BASE_JSON_SHA:
        raise ValueError("Baseline JSON SHA-256 mismatch")
    if sha256(baseline).hexdigest() != BASE_DCP_SHA:
        raise ValueError("Baseline DCP SHA-256 mismatch")
    spec = json.loads(source.decode("utf-8-sig"), object_pairs_hook=unique_fields)
    if build_dcp(spec) != baseline:
        raise ValueError("Baseline JSON does not rebuild the exact baseline DCP")
    baseline_tags = describe(baseline)["tags"]
    if set(baseline_tags) != COMMON_TAGS | {"ProfileName"}:
        raise ValueError("Unexpected baseline DCP tags")

    identity = [[0, 0], [1, 1]]
    definitions = (
        ("identity", "tone-identity-v1", "PENTAX 1376 Tone Identity v1", identity),
        ("lift", "tone-lift-v1", "PENTAX 1376 Tone Lift v1", [[0, 0], [0.5, 0.53125], [1, 1]]),
        ("acr3", "acr3-control-v1", "PENTAX 1376 ACR3 Control v1", read_acr3(sdk_zip)),
    )
    outputs, audit = {}, {}
    for key, suffix, name, points in definitions:
        data = build_dcp({**spec, "ProfileName": name, "ProfileToneCurve": points})
        result = describe(data)
        tags, curve = result["tags"], curve_tag(points)
        if (set(tags) != set(baseline_tags) | {"ProfileToneCurve"}
                or any(tags[tag] != baseline_tags[tag] for tag in COMMON_TAGS)
                or tags["ProfileName"]["text"] != name or tags["ProfileName"] == baseline_tags["ProfileName"]
                or tags["ProfileToneCurve"] != curve):
            raise ValueError(f"{key}: unexpected IFD tag changes")
        if result["sha256"] != OUTPUT_SHA[key]:
            raise ValueError(f"{key}: generated DCP SHA-256 mismatch")
        filename = f"pentax-k3ii-1376-{suffix}.dcp"
        outputs[filename] = data
        audit[filename] = {"sha256": result["sha256"], "bytes": len(data), "curve": curve}

    # All inputs and generated bytes have been checked before any output is created.
    output_dir.mkdir()
    created = []
    try:
        for filename, data in outputs.items():
            path = output_dir / filename
            with path.open("xb") as stream:
                created.append(path)
                stream.write(data)
    except OSError as error:
        try:
            for path in reversed(created):
                path.unlink(missing_ok=True)
            output_dir.rmdir()
        except OSError as cleanup:
            raise OSError(f"{error}; output cleanup also failed: {cleanup}") from error
        raise
    return audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-json", type=Path, required=True, help="exact original #1376 matrix profile spec")
    parser.add_argument("--baseline-dcp", type=Path, required=True, help="exact omitted-curve #1376 DCP")
    parser.add_argument("--sdk-zip", type=Path, required=True, help="pinned Adobe DNG SDK 1.7.1 archive")
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory for the three DCPs")
    args = parser.parse_args()
    try:
        audit = generate(args.baseline_json, args.baseline_dcp, args.sdk_zip, args.output_dir)
    except (OSError, ValueError, OverflowError, struct.error, BadZipFile) as error:
        parser.exit(1, f"Tone control build failed: {error}\n")
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
