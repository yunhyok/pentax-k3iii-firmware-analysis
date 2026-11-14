"""Write an SDR DNG camera profile from independently sourced calibration JSON."""

import argparse
from hashlib import sha256
import json
from math import isfinite, prod
from pathlib import Path
import struct


# DNG 1.7.1.0, Camera Profile IFD tags; see analysis/lightroom-bridge.html.
TAGS = {
    "UniqueCameraModel": 50708, "ColorMatrix1": 50721, "ColorMatrix2": 50722,
    "CalibrationIlluminant1": 50778, "CalibrationIlluminant2": 50779,
    "ProfileName": 50936, "ProfileHueSatMapDims": 50937,
    "ProfileHueSatMapData1": 50938, "ProfileHueSatMapData2": 50939,
    "ProfileToneCurve": 50940, "ForwardMatrix1": 50964, "ForwardMatrix2": 50965,
    "ProfileLookTableDims": 50981, "ProfileLookTableData": 50982,
    "ProfileHueSatMapEncoding": 51107, "ProfileLookTableEncoding": 51108,
    "ProfileEmbedPolicy": 50941, "ProfileCopyright": 50942,
    "BaselineExposureOffset": 51109, "DefaultBlackRender": 51110,
}
REQUIRED = {"provenance", "UniqueCameraModel", "ProfileName", "ColorMatrix1", "CalibrationIlluminant1"}
# shortcut: named standard illuminants only; add IlluminantData for measured custom lights.
ILLUMINANTS = {17, 20, 21, 22, 23}  # A, D55, D65, D75, D50
D50 = (0.3457 / 0.3585, 1.0, (1 - 0.3457 - 0.3585) / 0.3585)
MATRIX_DENOMINATOR = 1_000_000
SDK_MATRIX_PRECISION = 10_000
SDK_MAX_TONE_CURVE_POINTS = 8192


def string(value, key):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise ValueError(f"{key}: expected a non-empty string without control characters")
    return value


def number(value, key):
    if type(value) not in (int, float) or not isfinite(value):
        raise ValueError(f"{key}: expected a finite number")
    return value


def determinant3(values):
    a, b, c, d, e, f, g, h, i = values
    return a * (e * i - f * h) + b * (g * f - d * i) + c * (d * h - e * g)


def sdk_read_matrix(scaled, key):
    coefficients = [value / MATRIX_DENOMINATOR for value in scaled]
    # Adobe DNG SDK 1.7.1: NormalizeColorMatrix scales the largest D50
    # response to 1 outside [0.99, 1.01], but only if the response is positive.
    if key.startswith("ColorMatrix"):
        white_max = max(coefficients[i] * D50[0] + coefficients[i + 1] + coefficients[i + 2] * D50[2]
                        for i in (0, 3, 6))
        if white_max > 0 and not 0.99 <= white_max <= 1.01:
            factor = 1.0 / white_max
            coefficients = [value * factor for value in coefficients]
    # dng_matrix::Round uses Round_int32 (ties away from zero).
    units = [value * SDK_MATRIX_PRECISION for value in coefficients]
    rounded = [int(value + (0.5 if value > 0 else -0.5)) for value in units]
    if any(not -(2**31) <= value < 2**31 for value in rounded):
        raise ValueError(f"{key}: coefficient overflows DNG SDK rounding")
    return [value * (1.0 / SDK_MATRIX_PRECISION) for value in rounded]


def matrix(rows, key):
    if not isinstance(rows, list) or len(rows) != 3 or any(
            not isinstance(row, list) or len(row) != 3 for row in rows):
        raise ValueError(f"{key}: expected three rows of three coefficients")
    scaled = [round(number(n, key) * MATRIX_DENOMINATOR) for row in rows for n in row]
    if any(not -(2**31) <= n < 2**31 for n in scaled):
        raise ValueError(f"{key}: coefficient exceeds the supported SRATIONAL range")
    sdk_coefficients = sdk_read_matrix(scaled, key)
    if key.startswith("ColorMatrix"):
        # Adobe DNG SDK Invert3by3 rejects determinants below 1e-10.
        if abs(determinant3(scaled)) < MATRIX_DENOMINATOR**3 // 10**10:
            raise ValueError(f"{key}: matrix is not invertible at export precision")
        if abs(determinant3(sdk_coefficients)) < 1e-10:
            raise ValueError(f"{key}: matrix is not invertible after DNG SDK normalization and rounding")
    elif any(abs(sum(scaled[i:i+3]) / MATRIX_DENOMINATOR - white) > 0.01
             for i, white in zip((0, 3, 6), D50)):
        raise ValueError(f"{key}: equal camera values must map to XYZ D50")
    elif any(abs(sdk_coefficients[i] + sdk_coefficients[i + 1] + sdk_coefficients[i + 2] - white) > 0.01
             for i, white in zip((0, 3, 6), D50)):
        raise ValueError(f"{key}: equal camera values must map to XYZ D50 after DNG SDK rounding")
    return 10, 9, b"".join(struct.pack("<ii", n, MATRIX_DENOMINATOR) for n in scaled)


def float_rows(rows, width, key):
    if not isinstance(rows, list) or any(not isinstance(row, list) or len(row) != width for row in rows):
        raise ValueError(f"{key}: expected rows of {width} numbers")
    packed = b"".join(struct.pack(f"<{width}f", *(number(n, key) for n in row)) for row in rows)
    return (11, len(rows) * width, packed), struct.iter_unpack(f"<{width}f", packed)


def add_table(spec, tags, prefix, data_keys):
    dims_key, encoding_key = prefix + "Dims", prefix + "Encoding"
    if not any(key in spec for key in (dims_key, encoding_key, *data_keys)):
        return
    dims = spec.get(dims_key)
    if not isinstance(dims, list) or len(dims) != 3 or any(
            type(n) is not int or not minimum <= n < 2**32 for n, minimum in zip(dims, (1, 2, 1))):
        raise ValueError(f"{dims_key}: expected integer [H, S, V] with H,V >= 1 and S >= 2")
    size = prod(dims)
    if size * 12 >= 2**32:
        raise ValueError(f"{dims_key}: table exceeds classic TIFF limits")
    tags[dims_key] = 4, 3, struct.pack("<III", *dims)
    if dims[2] > 1:
        encoding = spec.get(encoding_key)
        if type(encoding) is not int or encoding not in (0, 1):
            raise ValueError(f"{encoding_key}: explicitly specify 0 (linear) or 1 (sRGB value encoding)")
        tags[encoding_key] = 4, 1, struct.pack("<I", encoding)
    elif encoding_key in spec:
        raise ValueError(f"{encoding_key}: only applies when V > 1")
    for key in data_keys:
        rows = spec.get(key)
        if not isinstance(rows, list) or len(rows) != size:
            raise ValueError(f"{key}: expected exactly {size} HSV triplets")
        tags[key], values = float_rows(rows, 3, key)
        for index, (_, sat_scale, value_scale) in enumerate(values):
            if sat_scale < 0 or value_scale < 0 or (index % dims[1] == 0 and value_scale != 1):
                raise ValueError(f"{key}: scales must be nonnegative and zero-saturation V scale must be 1")


def build_dcp(spec):
    if not isinstance(spec, dict):
        raise ValueError("Expected a profile JSON object")
    missing, extra = REQUIRED - spec.keys(), spec.keys() - REQUIRED - TAGS.keys()
    if missing or extra:
        raise ValueError(f"Missing fields: {sorted(missing)}; unknown fields: {sorted(extra)}")
    string(spec["provenance"], "provenance")
    dual = "ColorMatrix2" in spec
    if ("CalibrationIlluminant2" in spec) != dual or (
            "ForwardMatrix2" in spec and not dual) or (
            dual and (("ForwardMatrix1" in spec) != ("ForwardMatrix2" in spec))):
        raise ValueError("Dual illuminants require two ColorMatrices and zero or two ForwardMatrices")
    if "ProfileHueSatMapData2" in spec and not dual:
        raise ValueError("ProfileHueSatMapData2 requires dual illuminants")

    tags = {}
    for key, encoding in (("UniqueCameraModel", "ascii"), ("ProfileName", "utf-8")):
        payload = string(spec[key], key).encode(encoding) + b"\0"
        tags[key] = 2, len(payload), payload
    for index in range(1, 3 if dual else 2):
        key = f"CalibrationIlluminant{index}"
        illuminant = spec[key]
        if type(illuminant) is not int or illuminant not in ILLUMINANTS:
            raise ValueError(f"{key}: use a standard illuminant from {sorted(ILLUMINANTS)}")
        if index == 2 and illuminant == spec["CalibrationIlluminant1"]:
            raise ValueError("Dual illuminants must be different")
        tags[key] = 3, 1, struct.pack("<H", illuminant)
        for key in (f"ColorMatrix{index}", f"ForwardMatrix{index}"):
            if key in spec:
                tags[key] = matrix(spec[key], key)

    maps = ("ProfileHueSatMapData1",)
    if "ProfileHueSatMapData2" in spec:
        maps += ("ProfileHueSatMapData2",)
    add_table(spec, tags, "ProfileHueSatMap", maps)
    add_table(spec, tags, "ProfileLookTable", ("ProfileLookTableData",))
    key = "ProfileToneCurve"
    if key in spec:
        curve = spec[key]
        if isinstance(curve, list) and len(curve) > SDK_MAX_TONE_CURVE_POINTS:
            raise ValueError(f"{key}: DNG SDK supports at most {SDK_MAX_TONE_CURVE_POINTS} points")
        tags[key], values = float_rows(curve, 2, key)
        points = list(values)
        if (len(points) < 2 or points[0] != (0, 0) or points[-1] != (1, 1)
                or any(not 0 <= y <= 1 for _, y in points)
                or any(left[0] >= right[0] for left, right in zip(points, points[1:]))):
            raise ValueError(f"{key}: expected (0,0) to (1,1), increasing x and y within [0,1]")

    if "ProfileCopyright" in spec:
        payload = string(spec["ProfileCopyright"], "ProfileCopyright").encode("utf-8") + b"\0"
        tags["ProfileCopyright"] = 2, len(payload), payload
    for key, allowed in (("ProfileEmbedPolicy", (0, 1, 2, 3)), ("DefaultBlackRender", (0, 1))):
        if key in spec:
            if type(spec[key]) is not int or spec[key] not in allowed:
                raise ValueError(f"{key}: expected one of {allowed}")
            tags[key] = 4, 1, struct.pack("<I", spec[key])
    if "BaselineExposureOffset" in spec:
        offset_ev = number(spec["BaselineExposureOffset"], "BaselineExposureOffset")
        if not -10 <= offset_ev <= 10:
            raise ValueError("BaselineExposureOffset: expected a value within -10..10 EV")
        tags["BaselineExposureOffset"] = 10, 1, struct.pack("<ii", round(offset_ev * MATRIX_DENOMINATOR), MATRIX_DENOMINATOR)

    directory = bytearray(struct.pack("<2sHIH", b"II", 0x4352, 8, len(tags)))
    offset = len(directory) + 12 * len(tags) + 4
    data = bytearray()
    for key in sorted(tags, key=TAGS.get):
        kind, count, payload = tags[key]
        directory.extend(struct.pack("<HHI", TAGS[key], kind, count))
        if len(payload) <= 4:
            directory.extend(payload.ljust(4, b"\0"))
        else:
            directory.extend(struct.pack("<I", offset + len(data)))
            data.extend(payload)
            if len(data) % 2:
                data.append(0)  # TIFF requires even offsets for out-of-line values.
    return bytes(directory + b"\0" * 4 + data)


def unique_fields(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON fields")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.output.suffix.lower() != ".dcp":
            raise ValueError("Output path must end in .dcp")
        raw = args.input.read_bytes()
        spec = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_fields)
        data = build_dcp(spec)
        with args.output.open("xb") as output:
            output.write(data)
        print(json.dumps({"input_sha256": sha256(raw).hexdigest(), "output_sha256": sha256(data).hexdigest(),
                          "camera_model": spec["UniqueCameraModel"], "profile_name": spec["ProfileName"],
                          "provenance": spec["provenance"]}))
    except (OSError, ValueError, OverflowError, struct.error) as error:
        parser.exit(1, f"Profile export failed: {error}\n")


if __name__ == "__main__":
    main()
