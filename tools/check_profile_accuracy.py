"""How closely each published profile follows the camera colour model it was made from.

For every profile in profiles/k3iii the camera colour model (firmware-free
engine, the Custom Image's factory settings, toning off) and the profile
(rendered with the DNG reference pipeline in tools/firmware_color_model.py)
are given the same random scene colours; the difference is CIEDE2000.

This measures the profile format's fit to the model (matrix, one tone curve,
LookTable).  It says nothing about how well the model matches the camera;
that is tools/compare_camera_jpeg.py.

    python tools/check_profile_accuracy.py --output new-accuracy.json
    python tools/check_profile_accuracy.py --compare analysis/k3iii-profile-accuracy.json

Needs numpy only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

import compare_camera_jpeg as compare          # noqa: E402
import firmware_color_model as model           # noqa: E402
from k3iii_color_engine import Engine          # noqa: E402
from make_k3iii_profile import LABELS          # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
COLOURS = 60000
TOLERANCE = 0.01        # allowed drift of a published figure between numpy builds


def scene_classes(rng) -> dict:
    """Random linear sRGB scene colours (1.0 = white at the gamma input scale)."""
    grey = rng.uniform(0.02, 0.9, (COLOURS, 1))
    edge = rng.uniform(0.0, 0.9, (COLOURS, 3))
    edge[np.arange(COLOURS), rng.integers(0, 3, COLOURS)] = rng.uniform(0.0, 0.02, COLOURS)
    return {
        "inside": rng.uniform(0.02, 0.9, (COLOURS, 3)),
        "saturated": edge,                                          # one channel under 2 %
        "near_neutral": np.clip(grey + rng.uniform(-0.01, 0.01, (COLOURS, 3)), 0.0, 1.0),
        "dark": rng.uniform(0.0, 0.02, (COLOURS, 3)),
    }


def lab(code):
    return compare.to_lab(model.srgb_decode(code))


def survey() -> dict:
    engine = Engine.load()
    to_camera = np.linalg.inv(engine.common_matrix()).T
    classes = {name: np.clip(colours @ to_camera, 0.0, 1.0) for name, colours in scene_classes(np.random.default_rng(20261114)).items()}
    profiles = {}
    for mode in LABELS:
        camera = engine.camera(mode, **engine.factory_settings(mode))
        profile = model.read_dcp((ROOT / "profiles" / "k3iii" / f"k3iii-firmware-{mode}.dcp").read_bytes())
        entry = {}
        for name, camera_rgb in classes.items():
            reference = lab(camera.render(camera_rgb))
            for label, table in (("with_look_table", profile["LookTable"]), ("without_look_table", None)):
                if label == "without_look_table" and name != "inside":
                    continue
                rendered = model.srgb_encode(model.dng_render(camera_rgb, profile["ForwardMatrix1"], table,
                                                              profile["curve_x"], profile["curve_y"], 0.0, "srgb"))
                delta = compare.delta_e_2000(lab(rendered), reference)
                figures = {"mean": round(float(delta.mean()), 3), "p99": round(float(np.percentile(delta, 99)), 3),
                           "max": round(float(delta.max()), 3)}
                if label == "without_look_table":
                    entry["inside_without_look_table"] = figures
                else:
                    entry[name] = figures
        profiles[mode] = entry
    return {
        "scope": "CIEDE2000 between each published profile (DNG reference pipeline, total exposure 0 EV, sRGB output) and the "
                 "camera colour model it was built from (factory settings, toning off). Fit of the profile format, not of the model to the camera.",
        "colours_per_class": COLOURS,
        "classes": {"inside": "linear sRGB scene colours, each channel 0.02..0.9", "saturated": "one channel under 0.02, the others 0..0.9",
                    "near_neutral": "grey 0.02..0.9 with +-0.01 per channel", "dark": "each channel under 0.02"},
        "profiles": profiles,
    }


def close(a, b) -> bool:
    if isinstance(a, dict):
        return isinstance(b, dict) and a.keys() == b.keys() and all(close(a[k], b[k]) for k in a)
    if isinstance(a, float):
        return abs(a - b) <= TOLERANCE
    return a == b


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = survey()
    status = {"profiles": len(result["profiles"]),
              "worst_mean_inside": max(p["inside"]["mean"] for p in result["profiles"].values())}
    if args.compare:
        status["matches_published"] = close(json.loads(args.compare.read_text(encoding="utf-8")), result)
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(result, indent=1) + "\n")
    print(json.dumps(status))
    if status.get("matches_published") is False:
        parser.exit(1, "Figures differ from the published record.\n")


if __name__ == "__main__":
    main()
