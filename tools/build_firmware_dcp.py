"""Build Lightroom camera profiles (DCP) for the K-3 Mark III from the user's own firmware copy.

The profile values come from the camera's own tuning code, which this tool
runs in a CPU emulator on the decoded firmware 2.20 image:

* ForwardMatrix      the CC0 colour matrix (white-balanced sensor RGB -> linear sRGB) carried to XYZ D50
* ProfileToneCurve   the gamma curve the firmware computes for the chosen Custom Image
* ProfileLookTable   what is left: the camera applies its curve per channel and suppresses
                     chroma by luminance, Lightroom applies a curve differently
* BaselineExposureOffset +0.5 EV: the firmware's own BaselineExposure formula holds a
                     factor 1448/2048; with the offset Lightroom's linear value equals
                     the input of the camera's gamma stage
* ColorMatrix1/2     the firmware's DNG tables (illuminants A and D65), scaled per channel
                     like the camera does when it writes a DNG

No firmware data is stored in this repository; the output file contains values
derived from your firmware copy.  See analysis/firmware-dcp.html.

Example
    python inspect_firmware.py fwdc233b.bin --output-dir .private/my-decode
    python tools/build_firmware_dcp.py .private/my-decode/decoded.bin --mode natural --output Natural.dcp
    python tools/build_firmware_dcp.py .private/my-decode/decoded.bin --all --output-dir my-profiles
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
from profile_bridge import build_dcp          # noqa: E402

CAMERA_MODEL = "PENTAX K-3 Mark III"
COMMON_MATRIX = 0x53A7D2E4            # signed 16-bit 3x3, 1.0 = 8192: sensor matrix shared by all modes
DNG_MATRIX_A = 0x53C16C08             # nine (numerator, denominator) pairs -> ColorMatrix1
DNG_MATRIX_D65 = 0x53C16220           # nine pairs -> ColorMatrix2
# The camera divides each row of its DNG tables by a per-body gain before it
# writes ColorMatrix1/2.  These ratios (DNG value / table value) are taken from
# the public CC0 sample raw.pixls.us #4678; --color-matrix-from uses your own DNG.
DEFAULT_ROW_SCALE = (0.68926, 1.0, 0.31733)
BASELINE_EXPOSURE_OFFSET = 0.5

LABELS = {
    "natural": "Natural", "bright": "Bright", "portrait": "Portrait", "landscape": "Landscape",
    "vibrant": "Vibrant", "radiant": "Radiant", "muted": "Muted", "flat": "Flat",
    "bleach-bypass": "Bleach Bypass", "reversal-film": "Reversal Film", "monochrome": "Monochrome",
    "satobi": "SATOBI", "harubeni": "HARUBENI", "katen": "KATEN", "kyushu": "KYUSHU", "fuyuno": "FUYUNO",
}
# Not offered: Auto Select picks a mode per scene; Cross Processing and Gold use a
# different curve per channel, which a profile tone curve cannot hold.
UNSUPPORTED = {"auto": "scene dependent", "cross-processing": "per-channel curves", "gold": "per-channel curves"}


def firmware_color_matrices(rtos: bytes, row_scale=DEFAULT_ROW_SCALE):
    out = []
    for address in (DNG_MATRIX_A, DNG_MATRIX_D65):
        pairs = emulator.read_table(rtos, address, 18, "i")
        table = np.array([pairs[2 * i] / pairs[2 * i + 1] for i in range(9)]).reshape(3, 3)
        out.append(table * np.asarray(row_scale)[:, None])
    return out


def color_matrices_from_dng(path: Path):
    """ColorMatrix1/2 and their illuminants from a camera DNG (little- or big-endian TIFF)."""
    data = Path(path).read_bytes()
    order = "<" if data[:2] == b"II" else ">"
    offset = struct.unpack_from(order + "I", data, 4)[0]
    count = struct.unpack_from(order + "H", data, offset)[0]
    found = {}
    for i in range(count):
        tag, kind, n, value = struct.unpack_from(order + "HHII", data, offset + 2 + 12 * i)
        if tag in (50721, 50722) and kind == 10 and n == 9:
            numbers = struct.unpack_from(order + "18i", data, value)
            found[tag] = np.array([numbers[2 * k] / numbers[2 * k + 1] for k in range(9)]).reshape(3, 3)
        elif tag in (50778, 50779):
            found[tag] = struct.unpack_from(order + "H", data, offset + 2 + 12 * i + 8)[0]
    if found.get(50778) != 17 or found.get(50779) != 21 or 50721 not in found or 50722 not in found:
        raise ValueError("expected a DNG with ColorMatrix1/2 for illuminants A (17) and D65 (21)")
    return [found[50721], found[50722]]


def build_profile(rtos: bytes, mode: str, sliders: dict, table_dims=(90, 25, 25), color_matrices=None,
                  name: str | None = None):
    """Return (dcp bytes, report dict) for one Custom Image."""
    if mode in UNSUPPORTED:
        raise ValueError(f"{mode}: not supported ({UNSUPPORTED[mode]})")
    result = emulator.StillTuning(rtos).make(emulator.MODES[mode], **sliders)
    if result.asserts:
        raise RuntimeError(f"firmware assertions fired during Make: {result.asserts}")
    for channel in "rgb":
        if not np.array_equal(result.channel_curves[channel], result.gamma_curve):
            raise ValueError(f"{mode}: per-channel gamma curves; a profile cannot hold them")
    camera = model.CameraColour.from_tuning(result, mode)
    common = np.array(emulator.read_table(rtos, COMMON_MATRIX, 9, "h"), dtype=np.float64).reshape(3, 3) / 8192.0
    singular = abs(np.linalg.det(camera.matrix)) < 1e-3          # Monochrome: all rows equal
    forward_base = common if singular else None
    forward = camera.forward_matrix(forward_base)
    curve_x, curve_y = camera.tone_curve(257)
    table = model.build_look_table(camera, curve_x, curve_y, *table_dims, forward_base=forward_base)
    matrices = color_matrices if color_matrices is not None else firmware_color_matrices(rtos)
    label = LABELS[mode]
    changed = {key: value for key, value in sliders.items() if value}
    suffix = "".join(f" {key[:3]}{value:+d}" for key, value in changed.items())
    spec = {
        "provenance": "Built by tools/build_firmware_dcp.py from a user-supplied K-3 Mark III firmware 2.20 image",
        "UniqueCameraModel": CAMERA_MODEL,
        "ProfileName": name or f"K-3 III Firmware {label}{suffix}",
        "ProfileCopyright": "Generated from the user's firmware copy with pentax-k3iii-firmware-analysis tools",
        "ProfileEmbedPolicy": 0,
        "CalibrationIlluminant1": 17, "CalibrationIlluminant2": 21,
        "ColorMatrix1": matrices[0].tolist(), "ColorMatrix2": matrices[1].tolist(),
        "ForwardMatrix1": forward.tolist(), "ForwardMatrix2": forward.tolist(),
        "ProfileToneCurve": [[float(a), float(b)] for a, b in zip(curve_x, curve_y)],
        "ProfileLookTableDims": list(table_dims), "ProfileLookTableEncoding": 1,
        "ProfileLookTableData": [[float(v) for v in row] for row in table.rows()],
        "BaselineExposureOffset": BASELINE_EXPOSURE_OFFSET,
        "DefaultBlackRender": 1,
    }
    data = build_dcp(spec)
    report = {
        "mode": mode, "profile_name": spec["ProfileName"], "sliders": sliders,
        "forward_matrix_source": "common matrix (colour matrix is singular)" if singular else "CC0 colour matrix",
        "look_table_dims": list(table_dims), "tone_curve_points": len(curve_x),
        "register_sha256": {
            "cc0": hashlib.sha256(result.registers.cc0.astype("<i2").tobytes()).hexdigest(),
            "gamma_curve": hashlib.sha256(result.gamma_curve.astype("<u2").tobytes()).hexdigest(),
            "yc": hashlib.sha256(result.registers.yc.astype("<i2").tobytes()).hexdigest(),
        },
        "dcp_bytes": len(data), "dcp_sha256": hashlib.sha256(data).hexdigest(),
    }
    return data, report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("decoded", type=Path, help="decoded.bin written by inspect_firmware.py (firmware 2.20)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--mode", choices=sorted(LABELS))
    group.add_argument("--all", action="store_true", help="build every supported Custom Image")
    parser.add_argument("--output", type=Path, help="output .dcp (with --mode)")
    parser.add_argument("--output-dir", type=Path, help="output folder (with --all)")
    for slider in ("saturation", "hue", "key", "contrast", "highlight", "shadow"):
        parser.add_argument(f"--{slider}", type=int, default=0, choices=range(-4, 5), metavar="-4..4",
                            help=f"Custom Image {slider} setting baked into the profile (default 0)")
    parser.add_argument("--table", default="90x25x25", help="LookTable size HxSxV (default 90x25x25)")
    parser.add_argument("--color-matrix-from", type=Path, metavar="DNG",
                        help="copy ColorMatrix1/2 from a DNG shot with your own camera")
    parser.add_argument("--name", help="profile name shown in Lightroom (with --mode)")
    args = parser.parse_args()
    try:
        dims = tuple(int(n) for n in args.table.lower().split("x"))
        if len(dims) != 3 or dims[0] < 6 or dims[1] < 2 or dims[2] < 2:
            raise ValueError("--table: expected HxSxV such as 90x25x25")
        rtos = emulator.load_rtos(args.decoded)
        matrices = color_matrices_from_dng(args.color_matrix_from) if args.color_matrix_from else None
        sliders = {name: getattr(args, name) for name in ("saturation", "hue", "key", "contrast", "highlight", "shadow")}
        if args.all:
            if not args.output_dir:
                raise ValueError("--all needs --output-dir")
            args.output_dir.mkdir(parents=True, exist_ok=True)
            jobs = [(mode, args.output_dir / f"PENTAX K-3 Mark III Firmware {LABELS[mode]}.dcp", None) for mode in LABELS]
        else:
            if not args.output or args.output.suffix.lower() != ".dcp":
                raise ValueError("--mode needs --output ending in .dcp")
            jobs = [(args.mode, args.output, args.name)]
        reports = []
        for mode, path, name in jobs:
            data, report = build_profile(rtos, mode, sliders, dims, matrices, name)
            with path.open("xb") as output:
                output.write(data)
            report["file"] = path.name
            reports.append(report)
        print(json.dumps({"firmware_rtos_sha256": emulator.RTOS_SHA256, "profiles": reports}, indent=2))
    except (OSError, ValueError, RuntimeError, struct.error) as error:
        parser.exit(1, f"Profile build failed: {error}\n")


if __name__ == "__main__":
    main()
