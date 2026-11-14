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

This tool reads the values from a firmware image.  tools/make_k3iii_profile.py
builds the same profiles from the published tables without the firmware.
See analysis/firmware-dcp.html.

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


def profile_name(mode: str, sliders: dict, color_space: str, prefix: str = "K-3 III Firmware",
                 factory: dict | None = None) -> str:
    """Name shown in Lightroom: the Custom Image, then every setting that differs from the factory value."""
    factory = factory or {}
    changed = {key: value for key, value in sliders.items() if value != (factory.get(key) or 0)}
    suffix = "".join(f" {key[:3]}{value:+d}" for key, value in changed.items())
    if color_space == "adobergb":
        suffix += " (AdobeRGB)"
    return f"{prefix} {LABELS[mode]}{suffix}"


def assemble_profile(camera, common: np.ndarray, color_matrices, name: str, table_dims=(90, 30, 30),
                     provenance: str = "Built from K-3 Mark III firmware 2.20 colour values"):
    """Turn colour parameters (firmware_color_model.CameraColour) into DCP bytes and a short report.

    `common` is the sensor matrix shared by all Custom Images (white-balanced
    sensor RGB -> linear sRGB).  It alone goes into the ForwardMatrix; the
    Custom Image's own matrix, the per-channel curve and the camera's gamut
    clip go into the LookTable.  A ForwardMatrix that held the Custom Image's
    matrix would push saturated colours out of the pipeline's working space,
    where they are clipped before the LookTable can treat them.
    """
    forward = camera.forward_matrix(common)
    curve_x, curve_y = camera.tone_curve(257)
    table = model.build_look_table(camera, curve_x, curve_y, *table_dims, forward_base=common)
    spec = {
        "provenance": provenance,
        "UniqueCameraModel": CAMERA_MODEL,
        "ProfileName": name,
        "ProfileCopyright": "Derived from PENTAX K-3 Mark III firmware 2.20 colour tables (pentax-k3iii-firmware-analysis)",
        "ProfileEmbedPolicy": 0,
        "CalibrationIlluminant1": 17, "CalibrationIlluminant2": 21,
        "ColorMatrix1": color_matrices[0].tolist(), "ColorMatrix2": color_matrices[1].tolist(),
        "ForwardMatrix1": forward.tolist(), "ForwardMatrix2": forward.tolist(),
        "ProfileToneCurve": [[float(a), float(b)] for a, b in zip(curve_x, curve_y)],
        "ProfileLookTableDims": list(table_dims), "ProfileLookTableEncoding": 1,
        "ProfileLookTableData": [[float(v) for v in row] for row in table.rows()],
        "BaselineExposureOffset": BASELINE_EXPOSURE_OFFSET,
        "DefaultBlackRender": 1,
    }
    data = build_dcp(spec)
    report = {
        "profile_name": name,
        "forward_matrix_source": "sensor matrix shared by all Custom Images",
        "look_table_dims": list(table_dims), "tone_curve_points": len(curve_x),
        "dcp_bytes": len(data), "dcp_sha256": hashlib.sha256(data).hexdigest(),
    }
    return data, report


def build_profile(rtos: bytes, mode: str, sliders: dict, table_dims=(90, 30, 30), color_matrices=None,
                  name: str | None = None, color_space: str = "srgb"):
    """Return (dcp bytes, report dict) for one Custom Image, from the firmware image.

    A setting left out of `sliders` (or None) takes the value the camera ships
    with for that Custom Image.  `color_space` is the camera setting to follow:
    "srgb" or "adobergb".  The camera uses a wider colour matrix and re-encodes
    its curve for AdobeRGB.
    """
    if mode in UNSUPPORTED:
        raise ValueError(f"{mode}: not supported ({UNSUPPORTED[mode]})")
    if color_space not in model.RGB_SPACES:
        raise ValueError("color space must be srgb or adobergb")
    factory = emulator.factory_settings(rtos)[mode]
    sliders = {key: (factory[key] or 0) if sliders.get(key) is None else sliders[key] for key in emulator.SLIDERS}
    # Toning (a constant added to Cb and Cr) tints grey, which a profile cannot do; it stays off.
    result = emulator.StillTuning(rtos).make(emulator.MODES[mode], adobe_rgb=color_space == "adobergb", **sliders)
    if result.asserts:
        raise RuntimeError(f"firmware assertions fired during Make: {result.asserts}")
    for channel in "rgb":
        if not np.array_equal(result.channel_curves[channel], result.gamma_curve):
            raise ValueError(f"{mode}: per-channel gamma curves; a profile cannot hold them")
    camera = model.CameraColour.from_tuning(result, mode, color_space)
    common = np.array(emulator.read_table(rtos, COMMON_MATRIX, 9, "h"), dtype=np.float64).reshape(3, 3) / 8192.0
    matrices = color_matrices if color_matrices is not None else firmware_color_matrices(rtos)
    data, report = assemble_profile(
        camera, common, matrices, name or profile_name(mode, sliders, color_space, factory=factory), table_dims,
        "Built by tools/build_firmware_dcp.py from a user-supplied K-3 Mark III firmware 2.20 image")
    report.update({
        "mode": mode, "sliders": sliders, "color_space": color_space,
        "factory_settings": {key: factory[key] or 0 for key in emulator.SLIDERS},
        "factory_toning_left_out": factory["toning"] or 0,
        "register_sha256": {
            "cc0": hashlib.sha256(result.registers.cc0.astype("<i2").tobytes()).hexdigest(),
            "gamma_curve": hashlib.sha256(result.gamma_curve.astype("<u2").tobytes()).hexdigest(),
            "yc": hashlib.sha256(result.registers.yc.astype("<i2").tobytes()).hexdigest(),
        },
    })
    return data, report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("decoded", type=Path, help="decoded.bin written by inspect_firmware.py (firmware 2.20)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--mode", choices=sorted(LABELS))
    group.add_argument("--all", action="store_true", help="build every supported Custom Image")
    parser.add_argument("--output", type=Path, help="output .dcp (with --mode)")
    parser.add_argument("--output-dir", type=Path, help="output folder (with --all)")
    for slider in emulator.SLIDERS:
        parser.add_argument(f"--{slider}", type=int, choices=range(-4, 5), metavar="-4..4",
                            help=f"Custom Image {slider} setting baked into the profile (default: the camera's factory value)")
    parser.add_argument("--neutral", action="store_true", help="settings not given are 0 instead of the factory value")
    parser.add_argument("--table", default="90x30x30", help="LookTable size HxSxV (default 90x30x30)")
    parser.add_argument("--color-matrix-from", type=Path, metavar="DNG",
                        help="copy ColorMatrix1/2 from a DNG shot with your own camera")
    parser.add_argument("--color-space", choices=("srgb", "adobergb"), default="srgb",
                        help="camera colour-space setting to follow (default srgb)")
    parser.add_argument("--name", help="profile name shown in Lightroom (with --mode)")
    args = parser.parse_args()
    try:
        dims = tuple(int(n) for n in args.table.lower().split("x"))
        if len(dims) != 3 or dims[0] < 6 or dims[1] < 2 or dims[2] < 2:
            raise ValueError("--table: expected HxSxV such as 90x30x30")
        rtos = emulator.load_rtos(args.decoded)
        matrices = color_matrices_from_dng(args.color_matrix_from) if args.color_matrix_from else None
        sliders = {name: (0 if args.neutral and getattr(args, name) is None else getattr(args, name)) for name in emulator.SLIDERS}
        if args.all:
            if not args.output_dir:
                raise ValueError("--all needs --output-dir")
            args.output_dir.mkdir(parents=True, exist_ok=True)
            tail = "-adobergb" if args.color_space == "adobergb" else ""
            jobs = [(mode, args.output_dir / f"k3iii-firmware-{mode}{tail}.dcp", None) for mode in LABELS]
        else:
            if not args.output or args.output.suffix.lower() != ".dcp":
                raise ValueError("--mode needs --output ending in .dcp")
            jobs = [(args.mode, args.output, args.name)]
        reports = []
        for mode, path, name in jobs:
            data, report = build_profile(rtos, mode, sliders, dims, matrices, name, args.color_space)
            with path.open("xb") as output:
                output.write(data)
            report["file"] = path.name
            reports.append(report)
        print(json.dumps({"firmware_rtos_sha256": emulator.RTOS_SHA256, "profiles": reports}, indent=2))
    except (OSError, ValueError, RuntimeError, struct.error) as error:
        parser.exit(1, f"Profile build failed: {error}\n")


if __name__ == "__main__":
    main()
