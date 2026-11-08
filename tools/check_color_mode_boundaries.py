"""Replay K-3 III color-mode configuration in original ARM with Unicorn 2.1.4."""

if not __debug__:
    raise RuntimeError("This checker requires assertions. Run without -O or PYTHONOPTIMIZE.")

import argparse
from collections import Counter
from hashlib import sha256
from itertools import product
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
DECODED_SIZE = 78_683_892
DECODED_SHA256 = "7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9"
SOURCE_SHA256 = {
    "analysis/color-resources.json": "7aa1a50ecaead22896462623390811af654eb328d77d0bdf59771ac8d91df475",
    "analysis/color-math-checks.json": "514c2aef004798c1cd7a9a6c910c5cdddd483ac8260a77f5674187197a72d21d",
    "analysis/gamma-tone-checks.json": "2037797ab030723517df7395c44233ae346af431648c8a8e2deb1f0bf0e0b152",
    "analysis/lightroom-bridge.json": "aa2355a06376b589de9295659995c3d046a086e5bb3352f0fae393ec725e8952",
}
MODES = ("Natural", "Portrait", "Bright", "Reversal Film")
SATURATION = (4, 5)
CONTRAST = (4, 6)
GAMMA_RANGES = (
    ("regular_generator", 0x53135DA0, 0x53136518),
    ("reversal_generator", 0x53136518, 0x53136728),
    ("selector", 0x53136728, 0x531368E0),
    ("udiv_nonzero", 0x526A8330, 0x526A8340),
    ("sdiv_nonzero", 0x526A8364, 0x526A8374),
    ("memcpy_short", 0x526AAC80, 0x526AACF4),
)


def digest(data):
    return sha256(data).hexdigest()


def load_sources(root):
    sources = {}
    for path, expected in SOURCE_SHA256.items():
        raw = (root / path).read_bytes().replace(b"\r\n", b"\n")
        if digest(raw) != expected:
            raise ValueError(f"Pinned source SHA-256 mismatch: {path}")
        sources[Path(path).stem] = json.loads(raw)
    return sources


def require_decoded(path):
    from decompile_sample import RTOS_OFFSET, RTOS_SIZE

    with path.open("rb") as stream:
        data = stream.read(DECODED_SIZE + 1)
    if len(data) != DECODED_SIZE or digest(data) != DECODED_SHA256:
        raise ValueError("Expected the full decoded K-3 Mark III v2.20 image (size and SHA-256).")
    return data[RTOS_OFFSET:RTOS_OFFSET + RTOS_SIZE]


def named_modes(check, resources):
    named = {row["display_name"]: row for row in resources["modes"] if row["display_name"] in MODES}
    assert set(named) == set(MODES)
    for row in named.values():
        index = check.raw(0x53A767D8 + row["common_enum"], 1)[0]
        assert index == row["resource_index"]
        descriptor = int(row["descriptor"].split("-")[0], 16)
        assert all(check.word(0x54562694 + 4 * (35 * project + index)) == descriptor for project in range(3))
        for offset, key in enumerate(("common_matrix", "mode_matrix", "filter_pointer_array")):
            address, size = (int(number, 16) for number in row[key].split("-"))
            assert check.word(descriptor + 4 * offset) == address
            assert digest(check.raw(address, size)) == resources["resources"][row[key]]["sha256"]
        row["descriptor_address"] = descriptor
    assert len({row["common_matrix"] for row in named.values()}) == 1
    assert len({row["filter_pointer_array"] for row in named.values()}) == 1
    natural = check.word(named["Natural"]["descriptor_address"] + 4)
    assert struct.unpack("<9h", check.raw(natural, 18)) == (8192, 0, 0, 0, 8192, 0, 0, 0, 8192)
    return named


def matrix_runner(matrix, check, modes):
    matrix.B = check.data
    cpu, map_source, counts = matrix.make_cpu()
    start, end = matrix.CODE[0]

    def check_code(uc, address, size, unused):
        assert start <= address < end or address in (matrix.COPY, matrix.SINGLETON), hex(address)

    cpu.hook_add(matrix.unicorn.UC_HOOK_CODE, check_code)
    for row in modes.values():
        descriptor = row["descriptor_address"]
        map_source(descriptor, 84)
        common, mode, sat, more, extra = matrix.ints(descriptor, 5, "I")
        for address, size in ((common, 18), (mode, 18), (sat, 36), (more, 16), (extra, 12)):
            map_source(address, size)
        for address in matrix.ints(sat, 9, "I"):
            map_source(address, 18)

    def run(descriptor, saturation, contrast):
        params = bytearray(256)
        struct.pack_into("<I", params, 8, descriptor)
        struct.pack_into("<H", params, 0x5A, 256)
        struct.pack_into("<I", params, 0x70, contrast)
        struct.pack_into("<3h", params, 0x80, 2730, 2730, 2730)
        params[0x52] = 1  # Output-color-space parameter held fixed.
        params[0x57] = saturation
        params[0x58] = 8
        params[0x86] = 4
        cpu.mem_write(matrix.BUF, bytes(params))
        out = matrix.BUF + 0x1000
        cpu.mem_write(out, b"\xa5" * 256)
        matrix.run(cpu, 0x5312CE30, [out, matrix.BUF])
        data = bytes(cpu.mem_read(out, 256))
        assert data[0] == 1
        intermediate = struct.unpack_from("<9h", data, 0x48)
        prepared = tuple(matrix.s16(value) for value in struct.unpack_from("<9I", data, 4))
        assert all(-2048 <= value <= 2047 for value in prepared)
        return intermediate, prepared, digest(data)

    return run, counts


def gamma_runner(gamma, check):
    cpu = check.u
    cpu.reg_write(gamma.UC_ARM_REG_C1_C0_2, 0x00F00000)
    cpu.reg_write(gamma.UC_ARM_REG_FPEXC, 0x40000000)
    entries = {0x53135DA0: "regular", 0x53136518: "reversal", 0x526AAC80: "memcpy32"}
    calls = []
    counts = Counter()

    def on_code(uc, address, size, unused):
        assert any(start <= address < end for _, start, end in GAMMA_RANGES), hex(address)
        if address == 0x526AAC80:
            assert uc.reg_read(gamma.UC_ARM_REG_R2) == 32
            assert uc.reg_read(gamma.UC_ARM_REG_R0) == gamma.OBJ + 0x320C
        if address in entries:
            calls.append(entries[address])
            counts[entries[address]] += 1

    def on_write(uc, access, address, size, value, unused):
        assert any(start <= address and address + size <= end for start, end in (
            (gamma.OBJ, gamma.OBJ + 512),
            (gamma.OBJ + 0x3209, gamma.OBJ + 0x3234),
            (gamma.STACK - 0x1000, gamma.STACK),
        )), hex(address)

    cpu.hook_add(gamma.unicorn.UC_HOOK_CODE, on_code)
    cpu.hook_add(gamma.unicorn.UC_HOOK_MEM_WRITE, on_write)

    def run(mode_enum, saturation, contrast):
        reversal = mode_enum == 10
        params = bytearray(256)
        params[0x55] = reversal
        params[0x57] = saturation
        struct.pack_into("<6I", params, 0x64, 8192, 8192, 4, contrast, 4, 4)
        cpu.mem_write(gamma.PARAM, bytes(params))
        cpu.mem_write(gamma.OBJ, bytes(0x3300))
        regs = {gamma.UC_ARM_REG_R0: gamma.OBJ, gamma.UC_ARM_REG_R1: gamma.PARAM}
        calls.clear()
        check.run(0x53136728, regs=regs)
        assert calls == ["reversal" if reversal else "regular", "memcpy32"], calls
        assert cpu.mem_read(gamma.OBJ + 0x3209, 1) == b"\x01"
        assert int.from_bytes(cpu.mem_read(gamma.OBJ + 0x3230, 4), "little") == reversal
        curve = tuple(check.read16(gamma.OBJ, 256))
        assert 0 <= min(curve) < max(curve) <= 16384
        calls.clear()
        check.run(0x53136728, regs=regs)
        assert not calls and cpu.mem_read(gamma.OBJ + 0x3209, 1) == b"\x00"
        assert tuple(check.read16(gamma.OBJ, 256)) == curve
        counts["warm_hits"] += 1
        return curve

    return run, counts


def differences(a, b):
    deltas = [abs(left - right) for left, right in zip(a, b, strict=True)]
    return {"different_entries": sum(delta != 0 for delta in deltas), "max_abs_code_delta": max(deltas)}


def experiment(image, verified_rtos, sources):
    try:
        import unicorn
    except ImportError as exc:
        raise RuntimeError("Replay requires the Python package unicorn==2.1.4.") from exc
    if unicorn.__version__ != "2.1.4":
        raise RuntimeError("Replay requires unicorn==2.1.4 for the recorded emulator results.")
    import verify_color_math as matrix
    import verify_gamma_tone as gamma

    check = gamma.Check(image)
    if check.data != verified_rtos:
        raise ValueError("Loaded RTOS differs from the validated decoded image.")
    resources = sources["color-resources"]
    matrix_baseline = sources["color-math-checks"]
    gamma_baseline = sources["gamma-tone-checks"]
    assert resources["image_sha256"] == matrix_baseline["image_sha256"] == gamma_baseline["image_sha256"] == gamma.EXPECTED
    named = named_modes(check, resources)
    run_matrix, matrix_counts = matrix_runner(matrix, check, named)
    run_gamma, gamma_counts = gamma_runner(gamma, check)
    expected_matrix = {row["case"]: row["result_sha256"] for row in matrix_baseline["prepare_cases"]}

    rows, states = [], {}
    for mode, sat, contrast in product(MODES, SATURATION, CONTRAST):
        enum, descriptor = (named[mode][key] for key in ("common_enum", "descriptor_address"))
        intermediate, prepared, result = run_matrix(descriptor, sat, contrast)
        assert result == expected_matrix[f"profile_{descriptor:x}_sat{sat}_space1"]
        curve = run_gamma(enum, sat, contrast)
        states[mode, sat, contrast] = intermediate, prepared, curve
        rows.append({
            "mode": mode, "mode_enum": enum, "descriptor": hex(descriptor),
            "saturation_index": sat, "contrast_control": contrast,
            "intermediate_q13_sha256": digest(struct.pack("<9h", *intermediate)),
            "prepared_coefficients_sha256": digest(struct.pack("<9h", *prepared)),
            "gamma_u16_sha256": gamma.hash16(curve),
        })
    assert len(rows) == 16
    assert matrix_counts["memcpy_calls"] == matrix_counts["singleton_calls"] == 0
    assert gamma_counts == {"regular": 12, "reversal": 4, "memcpy32": 16, "warm_hits": 16}

    factors = {}
    for mode in MODES:
        base, sat, con = (states[mode, s, c] for s, c in ((4, 4), (5, 4), (4, 6)))
        assert all(states[mode, s, 4][:2] == states[mode, s, 6][:2] for s in SATURATION)
        assert all(states[mode, 4, c][2] == states[mode, 5, c][2] for c in CONTRAST)
        assert sat[0] != base[0] and sat[1] != base[1]
        assert (base[2] == con[2]) == (mode == "Reversal Film")
        factors[mode] = {
            "only_saturation_intermediate_q13": differences(base[0], sat[0]),
            "only_saturation_prepared": differences(base[1], sat[1]),
            "only_contrast_gamma": differences(base[2], con[2]),
        }
    natural = states["Natural", 4, 4]
    deltas = {}
    for other in MODES[1:]:
        state = states[other, 4, 4]
        assert state[0] != natural[0] and state[1] != natural[1]
        assert (state[2] != natural[2]) == (other == "Reversal Film")
        deltas[other] = {key: differences(a, b) for key, a, b in zip(
            ("intermediate_q13", "prepared", "gamma"), natural, state, strict=True
        )}
    direct, = [
        row for row in gamma_baseline["checks"] if row["algorithm"] == "regular"
        and [row[key] for key in ("key", "contrast_control", "high_control", "low_control", "numerator", "denominator")]
        == [0, 0, 0, 0, 8192, 8192]
    ]
    assert direct["passed"] and direct["output_sha256"] == gamma.hash16(natural[2])

    profiles = {
        row["tags"]["ProfileName"]["text"]: row["tags"]
        for row in sources["lightroom-bridge"]["profiles"]
        if row["tags"]["UniqueCameraModel"]["text"] == "PENTAX K-3 Mark III"
    }
    same = ("ColorMatrix1", "ColorMatrix2", "ProfileToneCurve", "ProfileLookTableData")
    different = ("ForwardMatrix1", "ForwardMatrix2")
    assert all(profiles["Camera Natural"][tag] == profiles["Camera Portrait"][tag] for tag in same)
    assert all(profiles["Camera Natural"][tag] != profiles["Camera Portrait"][tag] for tag in different)
    ranges = [("matrix_core", *matrix.CODE[0]), *GAMMA_RANGES]
    return {
        "schema_version": 1,
        "firmware": "K-3 Mark III 2.20",
        "decoded_sha256": DECODED_SHA256,
        "rtos_sha256": gamma.EXPECTED,
        "emulator": {"engine": "Unicorn", "version": unicorn.__version__, "cpu": "Cortex-A7"},
        "source_reports_canonical_lf_sha256": SOURCE_SHA256,
        "original_code_ranges": [
            {"name": name, "start": hex(start), "end_exclusive": hex(end), "sha256": digest(check.raw(start, end - start))}
            for name, start, end in ranges
        ],
        "matrix_stub_scope": {
            "0x526aac80": {"modeled_bytes": 18, "calls": matrix_counts["memcpy_calls"]},
            "0x5313eb50": {"role": "singleton initializer", "calls": matrix_counts["singleton_calls"]},
        },
        "gamma_original_calls": dict(gamma_counts),
        "baseline_matches": {
            "matrix_prepare_cases": len(rows), "gamma_direct_generator_cases": 1,
            "adobe_camera_natural_vs_portrait": {"same_tag_payload": same, "different_tag_payload": different},
        },
        "synthetic_fixed_controls": {
            "color_space_parameter_0x52": 1, "matrix_gain": 256, "matrix_key": 8,
            "manual_and_filter_override": 0, "gamma_numerator": 8192, "gamma_denominator": 8192,
            "gamma_key_and_high_low_fields": 4,
        },
        "cases": rows,
        "within_mode_deltas": factors,
        "mode_deltas_relative_to_natural_at_saturation4_contrast4": deltas,
        "limits": [
            "Mode enum and resource descriptor checked against the RTOS. Upstream UI/parameter producer not executed.",
            "Separate calls use synthetic configuration, not a connected image-processing pipeline.",
            "The matrix runner registers two stubs; neither is reached. No external callbacks are executed.",
            "Gamma executes original 32-byte NEON copy and nonzero division helpers, with no stubs or external callbacks.",
            "Neither call runs pixel processing, camera hardware, or Lightroom. No RAW, DCP, or profile payload is read or exported.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path, help="full decoded K-3 Mark III v2.20 BIN")
    parser.add_argument("--output", type=Path, required=True, help="new JSON path; existing files and links are refused")
    args = parser.parse_args()
    if os.path.lexists(args.output):
        parser.error("output already exists")
    if not args.output.parent.is_dir():
        parser.error("output parent is not a directory")
    try:
        sources = load_sources(ROOT)
        sys.path.insert(0, str(ROOT))
        verified_rtos = require_decoded(args.decoded)
        result = experiment(args.decoded, verified_rtos, sources)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    except (OSError, RuntimeError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")
    print(f"PASS: {len(result['cases'])} control tuples and {result['gamma_original_calls']['warm_hits']} warm gamma hits")


if __name__ == "__main__":
    main()
