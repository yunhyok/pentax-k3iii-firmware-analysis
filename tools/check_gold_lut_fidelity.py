"""Compare v1, the gamma-zero correction, and staged v2 using synthetic sensor RGB."""

import argparse
from copy import copy
from hashlib import sha256
import json
from pathlib import Path
import sys
from types import MethodType

import numpy as np


KNOWN = np.array([.7850411286188153, .7747761263451224, .20276238894425247])
KNOWN_SRGB = np.array([.20953687713522073, .8608416551900554, .9950363874156818])
SOURCE_FILES = (
    "src/firmware_color_studio/enhanced.py",
    "src/firmware_color_studio/color_model.py",
    "src/firmware_color_studio/data/k3iii/gold-verification.json",
)


def normalized(matrix):
    # Adobe DNG SDK 1.7.1, dng_color_space.cpp:SetMatrixToPCS.
    white = np.array([.3457 / .3585, 1., (1 - .3457 - .3585) / .3585])
    return np.diag(white / (matrix @ np.ones(3))) @ matrix


def direct(model, camera, raw, ev=0.):
    matrix_output = np.clip(raw, 0, 1) @ camera.matrix.T
    matrix_output = np.clip(matrix_output * 2 ** max(ev, 0), 0, 1)
    if ev < 0:
        # The exposure structure control uses the Adobe tone operation.
        matrix_output = model.dng_tone(matrix_output, [0., 1.], [0., 1.], ev)
    encoded = camera.encode(matrix_output)
    to_srgb = np.linalg.inv(normalized(model.SRGB_TO_PCS)) @ normalized(camera.to_pcs)
    linear = camera.decode(encoded) @ to_srgb.T
    return np.clip(model.srgb_encode(linear), 0, 1)


def old_zero(camera):
    legacy = copy(camera)
    gamma = camera.gamma

    def old_gamma(self, linear, channel=None):
        return np.where(np.asarray(linear) == 0, 0., gamma(linear, channel))

    legacy.gamma = MethodType(old_gamma, legacy)
    return legacy


def legacy_renderer(model, interpolate, camera, forward):
    # Firmware Color Studio v0.1.1, with its sensor-domain LUT extension.
    axis = np.linspace(0., 1., 32)
    grid = np.stack(np.meshgrid(axis, axis, axis, indexing="ij"), -1)
    sensor = np.maximum(model.srgb_decode(grid) @ np.linalg.inv(model.PCS_TO_PROPHOTO @ forward).T, 0.)
    encoded = camera.encode(sensor @ camera.matrix.T)
    output = camera.decode(encoded) @ (model.PCS_TO_PROPHOTO @ camera.to_pcs).T
    table = np.floor(model.srgb_encode(np.clip(output, 0, 1)) * 65535 + .5).astype("<u2")

    def render(raw):
        working = model.dng_working_rgb(raw, forward, 0.)
        code = interpolate(model.srgb_encode(working), table)
        return np.clip(model.srgb_encode(model.srgb_decode(code) @ model.PROPHOTO_TO_SRGB.T), 0, 1)

    return render


def points():
    axis = np.linspace(0., 1., 33)
    cube = np.stack(np.meshgrid(axis, axis, axis, indexing="ij"), -1).reshape(-1, 3)
    rng = np.random.default_rng(864)
    return np.concatenate([cube, rng.random((50000, 3)), rng.random((5000, 3)) * .02, [KNOWN, KNOWN_SRGB]])


def faces(camera):
    # Sample both sides of each CC0 clipping plane.
    rng = np.random.default_rng(129)
    result = []
    for row in camera.matrix:
        solve = int(np.argmax(abs(row)))
        free = [i for i in range(3) if i != solve]
        xy = rng.random((300, 2))
        for edge in (0., 1.):
            for delta in (-1e-5, 0., 1e-5):
                raw = np.empty((len(xy), 3))
                raw[:, free] = xy
                raw[:, solve] = (edge + delta - xy @ row[free]) / row[solve]
                result.append(raw[np.all((raw >= 0) & (raw <= 1), axis=1)])
    return np.concatenate(result)


def cases(profiles):
    recipes = []
    spaces = ("srgb", "adobergb")
    for mode, info in profiles.list_modes().items():
        for space in spaces:
            for tone in range(9) if info["toning"] else (0,):
                recipe = profiles.default_recipe(mode)
                recipe.update(color_space=space, toning=tone)
                recipes.append(("default" if tone == 0 else f"tone{tone}", recipe))
    for mode in ("gold", "muted", "bleach-bypass", "harubeni"):
        controls = profiles.list_modes()[mode]["controls"]
        for space in spaces:
            for slider, enabled in controls.items():
                if enabled:
                    for value in (-4, 4):
                        recipe = profiles.default_recipe(mode)
                        recipe.update(color_space=space, toning=0 if mode == "gold" else 1)
                        recipe["settings"][slider] = value
                        recipes.append((f"{slider}{value:+}", recipe))
            for values in ((-4,) * 6, (4,) * 6, (-4, 4, -4, 4, -4, 4), (4, -4, 4, -4, 4, -4)):
                recipe = profiles.default_recipe(mode)
                recipe.update(color_space=space, toning=0 if mode == "gold" else 8)
                recipe["settings"].update(zip(recipe["settings"], values))
                recipes.append(("mixed:" + ",".join(map(str, values)), recipe))
    return recipes


def stats(actual, expected, raw):
    error = abs(actual - expected) * 255
    point, channel = np.unravel_index(np.argmax(error), error.shape)
    return {
        "mean": float(error.mean()),
        "p95": float(np.percentile(error, 95)),
        "p99": float(np.percentile(error, 99)),
        "max": float(error[point, channel]),
        "worst_rgb": raw[point].tolist(),
        "worst_channel": int(channel),
        "worst_direct": expected[point].tolist(),
        "worst_exported": actual[point].tolist(),
    }


def check(app_repo):
    sys.path.insert(0, str(app_repo / "src"))
    from firmware_color_studio import color_model as model, enhanced, profiles

    if enhanced._FORMAT_VERSION != 2 or enhanced.GRID_SIZE != 32:
        raise ValueError("use the staged v2 app source with a 32³ LUT")
    engine = profiles._pack("pentax-k3iii").engine
    forward = np.round(model.SRGB_TO_PCS @ engine.common_matrix(), 6)
    interpolate = enhanced._tetrahedral
    common = points()
    rows, exposure_rows = [], []
    for label, recipe in cases(profiles):
        camera = profiles.camera_for_recipe(recipe)
        raw = np.concatenate([common, faces(camera)])
        bundle = enhanced.build_enhanced(recipe)
        target = direct(model, camera, raw)
        v1 = legacy_renderer(model, interpolate, old_zero(camera), forward)
        corrected_v1 = legacy_renderer(model, interpolate, camera, forward)
        rows.append({
            "mode": recipe["mode"],
            "space": recipe["color_space"],
            "toning": recipe["toning"],
            "case": label,
            "settings": recipe["settings"],
            "points": len(raw),
            "published_v1": stats(v1(raw), target, raw),
            "zero_fix_only": stats(corrected_v1(raw), target, raw),
            "staged_v2": stats(enhanced.render_enhanced(raw, bundle, -.5), target, raw),
        })
        if label == "default" and recipe["mode"] in ("gold", "muted", "bleach-bypass", "harubeni"):
            for ev in (-2., -1., .5, 1.):
                exposure_rows.append({
                    "mode": recipe["mode"], "space": recipe["color_space"], "total_ev": ev, "points": len(raw),
                    "staged_v2": stats(enhanced.render_enhanced(raw, bundle, ev - .5), direct(model, camera, raw, ev), raw),
                })
    recipe = profiles.default_recipe("gold")
    recipe["color_space"] = "adobergb"
    camera = profiles.camera_for_recipe(recipe)
    bundle = enhanced.build_enhanced(recipe)
    old = old_zero(camera)
    old_linear = old.decode(old.render(KNOWN)) @ (model.PCS_TO_SRGB @ old.to_pcs).T
    regression = {
        "rgb": KNOWN.tolist(),
        "historical_faulty_direct": model.srgb_encode(np.clip(old_linear, 0, 1)).tolist(),
        "published_v1": legacy_renderer(model, interpolate, old, forward)(KNOWN).tolist(),
        "corrected_direct": direct(model, camera, KNOWN).tolist(),
        "zero_fix_only": legacy_renderer(model, interpolate, camera, forward)(KNOWN).tolist(),
        "staged_v2": enhanced.render_enhanced(KNOWN, bundle, -.5).tolist(),
    }
    sources = {}
    for relative in SOURCE_FILES:
        content = (app_repo / relative).read_bytes()
        # Python source is compared with LF endings; the pinned evidence uses its original bytes.
        if relative.endswith(".py"):
            content = content.replace(b"\r\n", b"\n")
        sources[relative] = sha256(content).hexdigest()
    return {
        "method": "deterministic synthetic RGB with SDK-normalized primaries; absolute encoded sRGB channel differences multiplied by 255",
        "net_exposure": 0,
        "common_points": len(common),
        "recipe_cases": len(rows),
        "gamma_zero_regression": regression,
        "cases": rows,
        "exposure_structure_cases": exposure_rows,
        "source_sha256": sources,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-repo", required=True, type=Path, help="staged v2 Firmware Color Studio checkout")
    parser.add_argument("--output", required=True, type=Path, help="new JSON report path")
    args = parser.parse_args()
    result = check(args.app_repo.resolve())
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(f"{result['recipe_cases']} nominal recipes and {len(result['exposure_structure_cases'])} exposure cases")


if __name__ == "__main__":
    main()
