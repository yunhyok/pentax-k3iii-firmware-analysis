"""Check the firmware-derived colour pipeline of the K-3 Mark III against the published record.

Runs the camera's still ImageTuning routine in a CPU emulator for every Custom
Image and records hashes and structure (the values themselves are exported by
tools/export_color_tables.py into analysis/k3iii-color-tables.json):

* SHA-256 of each colour register group (colour matrix, gamma curve, YC matrix,
  chroma suppress, multi-axis block) and structural facts (row sums, which
  modes share a curve, per-channel curves, tone table);
* checks against public references: the colour-space matrix against the
  standard linear sRGB -> AdobeRGB matrix, the YC matrix against JFIF/BT.601,
  the AdobeRGB gamma table against "sRGB decode, gamma 2.2 encode" of the sRGB
  table, and the constants of the firmware's BaselineExposure formula.

    python tools/check_firmware_color.py .private/my-decode/decoded.bin --compare analysis/firmware-color-pipeline.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

import firmware_color_model as model          # noqa: E402
import k3iii_tuning_emulator as emulator      # noqa: E402

COLOR_SPACE_MATRIX = 0x53A7BACC       # signed 16-bit 3x3, 1.0 = 8192
COMMON_MATRIX = 0x53A7D2E4
SATURATION_CENTRE = 0x53A7D230        # saturation matrix number 4
BASELINE_CONSTANTS = {0x53127B00: 2048.0, 0x53127B08: 1024.0, 0x53127B10: 1.0 / 8192.0,
                      0x53127B18: 1448.0, 0x53127B20: 65536.0}
BASELINE_DENOMINATOR = 0x53C16C04
DNG_TABLES = {"ColorMatrix1 table": 0x53C16C08, "ColorMatrix2 table": 0x53C16220}
BT601 = [77, 150, 29, -43, -85, 128, 128, -107, -21]
# linear sRGB -> linear Adobe RGB (1998), from the two RGB -> XYZ (D65) matrices
SRGB_XYZ = np.array([[0.4124564, 0.3575761, 0.1804375], [0.2126729, 0.7151522, 0.0721750], [0.0193339, 0.1191920, 0.9503041]])
ADOBE_XYZ = np.array([[0.5767309, 0.1855540, 0.1881852], [0.2973769, 0.6273491, 0.0752741], [0.0270343, 0.0706872, 0.9911085]])


def digest(array, dtype) -> str:
    return hashlib.sha256(np.asarray(array).astype(dtype).tobytes()).hexdigest()


def survey(decoded: Path) -> dict:
    rtos = emulator.load_rtos(decoded)

    def q13(address):
        return np.array(emulator.read_table(rtos, address, 9, "h"), dtype=np.float64).reshape(3, 3) / 8192.0

    space = q13(COLOR_SPACE_MATRIX)
    reference = np.linalg.inv(ADOBE_XYZ) @ SRGB_XYZ
    common = q13(COMMON_MATRIX)
    constants = {}
    for address, expected in BASELINE_CONSTANTS.items():
        value = struct.unpack_from("<d", rtos, address - emulator.BASE)[0]
        constants[f"{address:#x}"] = {"value": value, "expected": expected, "equal": value == expected}
    denominator = emulator.read_table(rtos, BASELINE_DENOMINATOR, 1, "I")[0]

    modes, curves = [], {}
    for name, number in emulator.MODES.items():
        result = emulator.StillTuning(rtos).make(number)
        r = result.registers
        per_channel = any(not np.array_equal(result.channel_curves[c], result.gamma_curve) for c in "rgb")
        curve_hash = digest(result.gamma_curve, "<u2")
        curves.setdefault(curve_hash, name)
        modes.append({
            "name": name, "number": number, "assertions": len(result.asserts),
            "cc0_decimal_point": int(r.cc0_decimal_point),
            "cc0_row_sums": [int(v) for v in r.cc0.sum(axis=1)],
            "cc0_rank_one": bool(np.all(np.abs(r.cc0 - r.cc0[0]) <= 1)),
            "cc1_enabled": bool(r.cc1_control),
            "yc_is_bt601": [int(v) for v in r.yc.reshape(-1)] == BT601,
            "tone_table_is_identity": bool(np.all(r.tone_table == 4096)),
            "gamma_curve_shared_with": curves[curve_hash],
            "per_channel_gamma_curves": bool(per_channel),
            "hardware_table_is_curve_shifted_by_4": all(
                np.array_equal(np.minimum(result.channel_curves[c] >> 4, 1023), r.gamma_full[c]) for c in "rgb"),
            "chroma_suppress_enabled": bool(r.csp_control[0] & 1),
            "chroma_fixed": bool(r.chroma_fixed),
            "sha256": {
                "cc0": digest(r.cc0, "<i2"), "gamma_curve": curve_hash, "yc": digest(r.yc, "<i2"),
                "chroma_suppress": hashlib.sha256(bytes(r.csp_control) + struct.pack("<4H4h3H", *r.csp_offset, *r.csp_gain, *r.csp_border)).hexdigest(),
                "multi_axis_block": hashlib.sha256(r.multi_axis).hexdigest(),
            },
        })

    # AdobeRGB: the hardware gamma table is the sRGB table re-encoded with gamma 2.2.
    srgb = emulator.StillTuning(rtos).make(emulator.MODES["natural"])
    adobe = emulator.StillTuning(rtos).make(emulator.MODES["natural"], adobe_rgb=True)
    predicted = model.adobe_encode(model.srgb_decode(srgb.registers.gamma_full["g"] / 1023.0)) * 1023.0
    adobe_matrix = adobe.registers.cc0 / 256.0
    expected_matrix = space @ (srgb.registers.cc0 / 256.0)

    # Sliders: which register group each one changes (Natural, -4..+4 against 0).
    slider_effect = {}
    base = srgb
    for slider in ("saturation", "hue", "key", "contrast", "highlight", "shadow"):
        changed = emulator.StillTuning(rtos).make(emulator.MODES["natural"], **{slider: 2})
        slider_effect[slider] = {
            "colour_matrix": not np.array_equal(changed.registers.cc0, base.registers.cc0),
            "gamma_curve": not np.array_equal(changed.gamma_curve, base.gamma_curve),
            "yc_matrix": not np.array_equal(changed.registers.yc, base.registers.yc),
        }

    return {
        "scope": "Hashes and structural facts of firmware-derived colour parameters, all settings 0. The values are in analysis/k3iii-color-tables.json.",
        "firmware": {"rtos_sha256": emulator.RTOS_SHA256, "rtos_base": f"{emulator.BASE:#x}"},
        "routines": {
            "ImageTuningStill constructor": f"{emulator.CTOR_STILL:#x}", "Initialize": f"{emulator.INITIALIZE:#x}",
            "Make": f"{emulator.MAKE_STILL:#x}", "DNG colour information": "0x53127888",
            "skipped in emulation": [f"{a:#x}" for a in emulator.SKIPPED],
        },
        "reference_checks": {
            "colour_space_matrix": {
                "address": f"{COLOR_SPACE_MATRIX:#x}", "reference": "linear sRGB to linear Adobe RGB (1998), D65",
                "max_abs_difference": round(float(np.abs(space - reference).max()), 6),
                "sha256": digest(np.round(space * 8192), "<i2"),
            },
            "common_matrix": {
                "address": f"{COMMON_MATRIX:#x}", "row_sums": [round(float(v), 6) for v in common.sum(axis=1)],
                "sha256": digest(np.round(common * 8192), "<i2"),
            },
            "saturation_centre_is_identity": bool(np.array_equal(q13(SATURATION_CENTRE), np.eye(3))),
            "baseline_exposure_constants": constants,
            "baseline_exposure_denominator": {"address": f"{BASELINE_DENOMINATOR:#x}", "value": int(denominator)},
            "dng_matrix_tables_sha256": {name: hashlib.sha256(struct.pack("<18i", *emulator.read_table(rtos, address, 18, "i"))).hexdigest()
                                         for name, address in DNG_TABLES.items()},
            "adobe_rgb": {
                "matrix_is_space_matrix_times_srgb_matrix_max_difference": round(float(np.abs(adobe_matrix - expected_matrix).max()), 4),
                "gamma_table_vs_srgb_decode_then_gamma_2_2_max_difference_10bit": round(float(np.abs(adobe.registers.gamma_full["g"] - predicted).max()), 3),
                "firmware_curve_unchanged": bool(np.array_equal(adobe.gamma_curve, srgb.gamma_curve)),
            },
        },
        "slider_effect_natural": slider_effect,
        "modes": modes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path, help="published JSON to compare with")
    parser.add_argument("--output", type=Path, help="write the fresh result to a new file")
    args = parser.parse_args()
    try:
        result = survey(args.decoded)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Check failed: {error}\n")
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(text)
    status = {"modes": len(result["modes"]), "assertions": sum(m["assertions"] for m in result["modes"])}
    if args.compare:
        published = json.loads(args.compare.read_text(encoding="utf-8"))
        status["matches_published"] = published == json.loads(text)
        print(json.dumps(status))
        if not status["matches_published"]:
            parser.exit(1, "Result differs from the published record.\n")
    else:
        print(json.dumps(status))


if __name__ == "__main__":
    main()
