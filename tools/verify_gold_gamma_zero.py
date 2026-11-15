"""Check Gold's gamma origin against original K-3 III ARM code in both color spaces."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

import numpy as np


UPSTREAM_COMMIT = "aa885bcdaee874d9b9bb18663dd62ed10263eda2"
HARNESS_SHA256 = "bd5db5ce8c8d1bdccc99f8ba1689b2e9eedcf99a52959000cde101b086ff2e52"


def verify(decoded, app_repo, harness):
    harness_code = (harness / "k3iii_tuning_emulator.py").read_text(encoding="utf-8")
    if sha256(harness_code.encode("utf-8")).hexdigest() != HARNESS_SHA256:
        raise ValueError(f"use the tuning harness from research commit {UPSTREAM_COMMIT}")
    sys.path[:0] = [str(harness), str(app_repo / "src")]
    from firmware_color_studio import profiles
    import k3iii_tuning_emulator as emu

    tuning = emu.StillTuning(emu.load_rtos(decoded))
    cases = []
    for space in ("srgb", "adobergb"):
        original = tuning.make(emu.MODES["gold"], adobe_rgb=space == "adobergb")
        if original.asserts:
            raise ValueError(f"unexpected firmware assertions: {original.asserts}")
        recipe = profiles.default_recipe("gold")
        recipe["color_space"] = space
        camera = profiles.camera_for_recipe(recipe)
        physical = np.stack([original.registers.gamma_table(key) for key in ("rgb", "r", "g")])
        model_zero = camera.gamma(np.zeros(3))
        np.testing.assert_array_equal(camera.curves, physical)
        np.testing.assert_array_equal(model_zero, physical[:, 0] / 1023)
        cases.append({
            "space": space,
            "original_physical_rgb_first": physical[:, 0].tolist(),
            "model_gamma_zero": model_zero.tolist(),
            "all_12288_entries_equal": True,
            "original_rgb4096_u16_sha256": sha256(physical.astype("<u2").tobytes()).hexdigest(),
        })
    return {
        "firmware_rtos_sha256": emu.RTOS_SHA256,
        "upstream_commit": UPSTREAM_COMMIT,
        "cases": cases,
        "limit": "Original ARM tuning code in emulator; no camera or ISP pixel execution.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path, help="decoded K-3 Mark III firmware 2.20 image")
    parser.add_argument("--app-repo", required=True, type=Path, help="Firmware Color Studio checkout with the gamma-zero fix")
    parser.add_argument("--harness", type=Path, default=Path(__file__).resolve().parent, help="directory containing the pinned tuning harness")
    parser.add_argument("--output", required=True, type=Path, help="new JSON report path")
    args = parser.parse_args()
    result = verify(args.decoded, args.app_repo.resolve(), args.harness.resolve())
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(f"Gold gamma origin and all physical tables matched in {len(result['cases'])} color spaces.")


if __name__ == "__main__":
    main()
