"""Make Lightroom camera profiles (DCP) for the K-3 Mark III without the firmware.

Uses the published colour tables (analysis/k3iii-color-tables.json) and the
firmware-free colour engine (tools/k3iii_color_engine.py).  For a Custom Image
and its six settings the result is the same profile that
tools/build_firmware_dcp.py builds from a firmware image.  A setting that is
not given takes the value the camera ships with for that Custom Image (Bright
has contrast +1, Flat has contrast -4, ...); --neutral makes them 0 instead.

A look of your own can be described on top of a Custom Image: your own look
matrix (in place of the Custom Image's matrix) and your own settings.

    python tools/make_k3iii_profile.py --mode natural --output Natural.dcp
    python tools/make_k3iii_profile.py --mode bright --saturation 1 --contrast -1 --output "Bright soft.dcp"
    python tools/make_k3iii_profile.py --all --output-dir my-profiles
    python tools/make_k3iii_profile.py --mode natural --look-matrix my-look.json --name "My look" --output MyLook.dcp

The toning colour of Muted, Bleach Bypass and HARUBENI is left out: it tints
grey, which this kind of profile cannot do.

Needs numpy only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

import firmware_color_model as model          # noqa: E402
from k3iii_color_engine import SLIDERS, TABLES, Engine      # noqa: E402

LABELS = {
    "natural": "Natural", "bright": "Bright", "portrait": "Portrait", "landscape": "Landscape",
    "vibrant": "Vibrant", "radiant": "Radiant", "muted": "Muted", "flat": "Flat",
    "bleach-bypass": "Bleach Bypass", "reversal-film": "Reversal Film", "monochrome": "Monochrome",
    "satobi": "SATOBI", "harubeni": "HARUBENI", "katen": "KATEN", "kyushu": "KYUSHU", "fuyuno": "FUYUNO",
}


def look_matrix_from_file(path: Path) -> list:
    """A 3x3 look matrix as real numbers (1.0 = unchanged); rows should sum to 1 to keep grey neutral."""
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    matrix = np.array(rows, dtype=np.float64)
    if matrix.shape != (3, 3) or not np.all(np.isfinite(matrix)):
        raise ValueError("--look-matrix: expected a JSON list of three rows of three numbers")
    if np.abs(matrix.sum(axis=1) - 1.0).max() > 0.02:
        raise ValueError("--look-matrix: each row must sum to 1 (within 0.02) so that grey stays grey")
    scaled = np.round(matrix * 8192.0)
    if np.abs(scaled).max() > 32767:
        raise ValueError("--look-matrix: coefficients must stay within about -4..+4")
    return [int(v) for v in scaled.reshape(-1)]


def make_profile(engine: Engine, mode: str, sliders: dict | None = None, color_space: str = "srgb", table_dims=(90, 30, 30),
                 name: str | None = None, look_matrix=None, color_matrices=None):
    """Return (dcp bytes, report).  A setting missing from `sliders` (or None) takes the camera's factory value."""
    sliders = sliders or {}
    from build_firmware_dcp import assemble_profile, profile_name

    if mode not in LABELS:
        raise ValueError(f"{mode}: not supported")
    factory = engine.factory_settings(mode)
    sliders = {key: factory[key] if sliders.get(key) is None else sliders[key] for key in SLIDERS}
    camera = engine.camera(mode, color_space, mode_matrix=look_matrix, **sliders)
    matrices = color_matrices if color_matrices is not None else engine.dng_color_matrices()
    label = name or profile_name(mode, sliders, color_space, factory=factory)
    data, report = assemble_profile(camera, engine.common_matrix(), matrices, label, table_dims,
                                    "Built by tools/make_k3iii_profile.py from the published K-3 Mark III firmware 2.20 colour tables")
    report.update({"mode": mode, "sliders": sliders, "effective_settings": engine.settings(mode, **sliders),
                   "factory_settings": factory, "factory_toning_left_out": engine.factory_toning(mode),
                   "color_space": color_space, "custom_look_matrix": look_matrix is not None})
    return data, report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--mode", choices=sorted(LABELS))
    group.add_argument("--all", action="store_true", help="every supported Custom Image at its factory settings")
    parser.add_argument("--output", type=Path, help="output .dcp (with --mode)")
    parser.add_argument("--output-dir", type=Path, help="output folder (with --all)")
    for slider in SLIDERS:
        parser.add_argument(f"--{slider}", type=int, choices=range(-4, 5), metavar="-4..4",
                            help=f"Custom Image {slider} setting baked into the profile (default: the camera's factory value)")
    parser.add_argument("--neutral", action="store_true", help="settings not given are 0 instead of the factory value")
    parser.add_argument("--color-space", choices=("srgb", "adobergb"), default="srgb",
                        help="camera colour-space setting to follow (default srgb)")
    parser.add_argument("--look-matrix", type=Path, metavar="JSON",
                        help="3x3 matrix used in place of the Custom Image's own look matrix")
    parser.add_argument("--color-matrix-from", type=Path, metavar="DNG",
                        help="copy ColorMatrix1/2 from a DNG shot with your own camera")
    parser.add_argument("--table", default="90x30x30", help="LookTable size HxSxV (default 90x30x30)")
    parser.add_argument("--name", help="profile name shown in Lightroom (with --mode)")
    parser.add_argument("--tables", type=Path, default=TABLES, help="colour tables JSON (default: the published file)")
    args = parser.parse_args()
    try:
        from build_firmware_dcp import color_matrices_from_dng

        dims = tuple(int(n) for n in args.table.lower().split("x"))
        if len(dims) != 3 or dims[0] < 6 or dims[1] < 2 or dims[2] < 2:
            raise ValueError("--table: expected HxSxV such as 90x30x30")
        engine = Engine.load(args.tables)
        matrices = color_matrices_from_dng(args.color_matrix_from) if args.color_matrix_from else None
        look = look_matrix_from_file(args.look_matrix) if args.look_matrix else None
        sliders = {name: (0 if args.neutral and getattr(args, name) is None else getattr(args, name)) for name in SLIDERS}
        if args.all:
            if not args.output_dir or look is not None:
                raise ValueError("--all needs --output-dir and cannot be combined with --look-matrix")
            args.output_dir.mkdir(parents=True, exist_ok=True)
            tail = "-adobergb" if args.color_space == "adobergb" else ""
            jobs = [(mode, args.output_dir / f"k3iii-firmware-{mode}{tail}.dcp", None) for mode in LABELS]
        else:
            if not args.output or args.output.suffix.lower() != ".dcp":
                raise ValueError("--mode needs --output ending in .dcp")
            if look is not None and not args.name:
                raise ValueError("--look-matrix needs --name so the profile is not mistaken for the camera's own")
            jobs = [(args.mode, args.output, args.name)]
        reports = []
        for mode, path, name in jobs:
            data, report = make_profile(engine, mode, sliders, args.color_space, dims, name, look, matrices)
            with path.open("xb") as output:
                output.write(data)
            report["file"] = path.name
            reports.append(report)
        print(json.dumps({"profiles": reports}, indent=2))
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Profile build failed: {error}\n")


if __name__ == "__main__":
    main()
