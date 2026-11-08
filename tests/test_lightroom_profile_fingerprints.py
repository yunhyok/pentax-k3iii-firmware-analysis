"""Synthetic profile fingerprint and fixture validation controls."""
import json
import struct
import unittest

from tools.check_lightroom_profile_fingerprints import (
    RECORD, TYPE_SIZES, fingerprints, load_record, read_ifd, stream_segments,
)
from tools.profile_bridge import build_dcp


def transpose_byte_order(data):
    """Independently synthesize a big-endian copy of a known little-endian control."""
    endian, _ = read_ifd(data)
    assert endian == "<"
    swapped = bytearray(data)
    swapped[:4] = b"MMCR"
    count, = struct.unpack_from("<H", data, 8)
    struct.pack_into(">IH", swapped, 4, 8, count)
    for entry in range(10, 10 + 12 * count, 12):
        code, kind, length, offset = struct.unpack_from("<HHII", data, entry)
        struct.pack_into(">HHII", swapped, entry, code, kind, length, offset)
        size = TYPE_SIZES[kind] * length
        position = entry + 8 if size <= 4 else offset
        code_format, width = {2: ("B", 1), 3: ("H", 2), 10: ("I", 4), 11: ("I", 4)}[kind]
        fmt = str(size // width) + code_format
        struct.pack_into(">" + fmt, swapped, position, *struct.unpack_from("<" + fmt, data, position))
    return bytes(swapped)


def synthetic_controls():
    identity = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
    spec = {"provenance": "Synthetic fingerprint test", "ProfileName": "Control A",
            "UniqueCameraModel": "Synthetic model", "CalibrationIlluminant1": 17, "CalibrationIlluminant2": 21,
            "ColorMatrix1": identity, "ColorMatrix2": identity, "ProfileToneCurve": [[0, 0], [0.5, 0.55], [1, 1]]}
    base = build_dcp(spec)
    base_segments, zeroes = stream_segments(base)
    baseline = fingerprints(base_segments)
    assert zeroes == [6, 6]
    assert all((n == 0 and d == 1) or (n != 0 and d == 10000) for n, d in
               struct.iter_unpack("<ii", base_segments["color_matrix_1"]))
    checks = {}
    for name, mutation, changed in (
        ("name", {"ProfileName": "Control B"}, (True, False)),
        ("model_restriction", {"UniqueCameraModel": "Synthetic alternate model"}, (False, False)),
        ("quantized_away_matrix", {"ColorMatrix1": [[1, 0.000001, 0], *identity[1:]]}, (False, False)),
        ("matrix_uniform_scale", {"ColorMatrix1": [[2 * value for value in row] for row in identity]}, (False, False)),
        ("matrix", {"ColorMatrix1": [[1, 0.01, 0], *identity[1:]]}, (True, True)),
        ("illuminant", {"CalibrationIlluminant1": 20}, (True, True)),
        ("tone", {"ProfileToneCurve": [[0, 0], [0.5, 0.56], [1, 1]]}, (True, True)),
        ("tone_removed", {"ProfileToneCurve": None}, (True, True)),
    ):
        variant = {**spec, **mutation}
        if variant["ProfileToneCurve"] is None:
            variant.pop("ProfileToneCurve")
        dcp = build_dcp(variant)
        assert dcp != base
        actual = tuple(a != b for a, b in zip(fingerprints(stream_segments(dcp)[0]), baseline, strict=True))
        assert actual == changed, (name, actual)
        checks[name] = {"dcp_sha256_changed": True, "full_changed": actual[0], "render_data_changed": actual[1]}

    big = transpose_byte_order(base)
    assert big != base and big[:4] == b"MMCR"
    assert stream_segments(big) == (base_segments, zeroes)
    old_zero = {**base_segments}
    for name in ("color_matrix_1", "color_matrix_2"):
        old_zero[name] = b"".join(struct.pack("<ii", n, 10000) for n, _ in struct.iter_unpack("<ii", old_zero[name]))
    assert all(a != b for a, b in zip(fingerprints(old_zero), baseline, strict=True))
    policy = fingerprints({**base_segments, "embed_policy": struct.pack("<I", 1)})
    assert policy[0] != baseline[0] and policy[1] == baseline[1]
    big_stream = {**base_segments}
    for name, size in (("illuminant_1", 2), ("illuminant_2", 2), ("color_matrix_1", 4),
                       ("color_matrix_2", 4), ("tone_curve", 4)):
        big_stream[name] = b"".join(big_stream[name][i:i + size][::-1] for i in range(0, len(big_stream[name]), size))
    assert all(a != b for a, b in zip(fingerprints(big_stream), baseline, strict=True))
    return {"base_full_md5": baseline[0], "base_render_data_md5": baseline[1],
            "mutations": checks, "big_endian_container_keeps_same_little_endian_stream": True,
            "incorrect_big_endian_stream_changes_both_fingerprints": True,
            "canonical_zero_count_per_matrix": zeroes, "legacy_zero_denominator_changes_both": True,
            "embed_policy_stream_mutation_changes_full_only": True}



class ProfileFingerprintTests(unittest.TestCase):
    def test_synthetic_scope_controls_reproduce_the_frozen_evidence(self):
        record = load_record(RECORD.read_bytes())
        self.assertEqual(synthetic_controls(), record["synthetic_controls"])

    def test_fixture_pin_is_stable_across_checkout_line_endings(self):
        lf = RECORD.read_bytes().replace(b"\r\n", b"\n")
        crlf = lf.replace(b"\n", b"\r\n")
        self.assertNotEqual(lf, crlf)
        self.assertEqual(load_record(lf), load_record(crlf))
        changed = json.loads(lf)
        changed["profiles"]["k3ii-matrix"]["dcp_sha256"] = "0" * 64
        with self.assertRaisesRegex(AssertionError, "Fixture SHA-256 mismatch"):
            load_record(json.dumps(changed).encode("utf-8"))

    def test_rejects_malformed_and_unsupported_profiles(self):
        matrix = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
        data = build_dcp({
            "provenance": "Synthetic fingerprint rejection test", "ProfileName": "Test",
            "UniqueCameraModel": "Synthetic model", "ColorMatrix1": matrix, "ColorMatrix2": matrix,
            "CalibrationIlluminant1": 17, "CalibrationIlluminant2": 21,
        })
        unknown_tag = bytearray(data)
        struct.pack_into("<H", unknown_tag, 10, 50709)
        unknown_type = bytearray(data)
        struct.pack_into("<H", unknown_type, 12, 5)
        for corrupt in (b"bad header", data[:-20], bytes(unknown_tag), bytes(unknown_type)):
            with self.subTest(length=len(corrupt)), self.assertRaises((AssertionError, struct.error)):
                stream_segments(corrupt)


if __name__ == "__main__":
    unittest.main()
