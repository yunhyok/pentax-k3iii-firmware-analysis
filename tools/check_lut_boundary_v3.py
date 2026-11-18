"""Compare exported 32³ enhanced profiles with a direct, synthetic RGB reference."""

import argparse
from hashlib import sha256
from importlib import import_module, util
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from zipfile import ZipFile

# The many narrow N×3 products do not benefit from a BLAS thread pool.
os.environ["OPENBLAS_NUM_THREADS"] = "1"

import numpy as np

from check_gold_lut_fidelity import cases, faces, normalized, points, stats


BASELINE_TAG = "v0.1.2"
BASELINE_COMMIT = "3d50969cebee14ec0e8adff23ab18b493eabb390"
PACKAGE = Path("src/firmware_color_studio")
ORIGINAL = Path(__file__).resolve().parents[1] / "analysis/gold-lut-fidelity.json"
MODES_WITH_EXPOSURE = ("gold", "muted", "bleach-bypass", "harubeni")
EXPOSURE = (-2., -1., .5, 1.)
METRICS = ("mean", "p95", "p99", "max")
SPACES = ("linear_prophoto", "encoded_srgb")
VERSIONS = ("v0.1.2", "candidate")
HELD_OUT_SEED = 917721
GAMUT_MARGIN = 1 / 255
CLIP_EPSILON = 1e-12


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def load_package(repo, name):
    path = repo / PACKAGE / "__init__.py"
    spec = util.spec_from_file_location(name, path)
    module = util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return import_module(f"{name}.enhanced")


def source_hashes(repo):
    package = repo / PACKAGE
    files = [package / f"{name}.py" for name in ("color_model", "dcp", "engine", "enhanced", "gold", "profiles")]
    files += list((package / "data/k3iii").glob("*.json"))
    return {
        path.relative_to(repo).as_posix(): sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        for path in sorted(files)
    }


def direct_prophoto(model, camera, raw, ev, to_prophoto):
    """Exact CC0 and camera stages, without a serialized matrix or any RGB LUT."""
    cc0 = np.clip((raw @ camera.matrix.T) * 2 ** max(ev, 0), 0, 1)
    if ev < 0:
        # The SDK places negative exposure in its sorted-channel tone stage.
        cc0 = model.dng_tone(cc0, (0., 1.), (0., 1.), ev)
    return camera.decode(camera.encode(cc0)) @ to_prophoto.T


def tagged_prophoto(enhanced, raw, bundle, exposure):
    """Read the tagged renderer's linear values just before sRGB conversion."""
    model, profiles = enhanced.color_model, enhanced.profiles
    rgb, exposure = profiles._render_inputs(raw, exposure)
    base = profiles._render_profile(bundle.dcp)
    ev = exposure + base["BaselineExposureOffset"]
    working = np.clip(rgb, 0, 1) @ enhanced._working_matrix(base["ForwardMatrix1"]).T
    working = np.clip(working * 2 ** max(ev, 0), 0, 1)
    if ev < 0:
        working = model.dng_tone(working, base["curve_x"], base["curve_y"], ev)
    code = enhanced._tetrahedral(model.srgb_encode(working), bundle._samples)
    return model.srgb_decode(code)


def held_out_points():
    rng = np.random.default_rng(HELD_OUT_SEED)
    axis = (np.arange(17) + 0.5) / 17
    cube = np.stack(np.meshgrid(axis, axis, axis, indexing="ij"), -1).reshape(-1, 3)
    return np.concatenate([cube, rng.random((8192, 3)), 2 ** rng.uniform(-20, -4, (2048, 3))])


def held_out_faces(camera, ev):
    """Independent samples just inside and outside both active CC0 clipping planes."""
    rng = np.random.default_rng(HELD_OUT_SEED + 1)
    result = []
    for row in camera.matrix:
        solve = int(np.argmax(abs(row)))
        free = [i for i in range(3) if i != solve]
        raw = rng.random((256, 3))
        free_sum = raw[:, free] @ row[free]
        for edge in (0., 2 ** -max(ev, 0)):
            for delta in (-.002, -.0001, .0001, .002):
                raw[:, solve] = (edge + delta - free_sum) / row[solve]
                result.append(raw[np.all((raw >= 0) & (raw <= 1), axis=1)])
    return np.concatenate(result)


def output_clip_faces(camera, model, ev, to_prophoto, to_srgb):
    """Bracket linear sRGB crossings and clipped plateaus on seeded sensor lines."""
    rng = np.random.default_rng(HELD_OUT_SEED + 2)
    result = {"final_srgb_clip_faces": [], "final_srgb_clip_touches": []}
    intervals = np.linspace(0, 1, 9)

    def projected(raw):
        return direct_prophoto(model, camera, raw, ev, to_prophoto) @ to_srgb.T

    for axis in range(3):
        lines = rng.random((64, 3))
        sample = np.repeat(lines[:, None, :], len(intervals), axis=1)
        sample[:, :, axis] = intervals
        values = projected(sample.reshape(-1, 3)).reshape(sample.shape)
        for edge in (0., 1.):
            signed = values - edge
            left, right = signed[:, :-1], signed[:, 1:]
            crosses = ((left < -CLIP_EPSILON) & (right > CLIP_EPSILON)) | (
                (left > CLIP_EPSILON) & (right < -CLIP_EPSILON))
            touches = (abs(left) <= CLIP_EPSILON) != (abs(right) <= CLIP_EPSILON)
            line, segment, channel = np.nonzero(crosses | touches)
            if len(line) == 0:
                continue
            low, high = intervals[segment], intervals[segment + 1]
            touching = touches[line, segment, channel]
            lower_values = signed[line, segment, channel]
            low_side = np.where(touching, abs(lower_values) <= CLIP_EPSILON, lower_values < 0)
            raw = lines[line].copy()
            point = np.arange(len(raw))
            for _ in range(16):
                middle = (low + high) / 2
                raw[:, axis] = middle
                current = projected(raw)[point, channel] - edge
                same_side = np.where(touching, abs(current) <= CLIP_EPSILON, current < 0) == low_side
                low = np.where(same_side, middle, low)
                high = np.where(same_side, high, middle)
            for delta in (-.0002, -.000002, .000002, .0002):
                raw[:, axis] = np.clip((low + high) / 2 + delta, 0, 1)
                result["final_srgb_clip_faces"].append(raw[~touching])
                result["final_srgb_clip_touches"].append(raw[touching])
    return {name: np.concatenate(samples) if samples else np.empty((0, 3)) for name, samples in result.items()}


def srgb_code(model, linear):
    return model.srgb_encode(np.clip(linear, 0, 1))


def gamut_retention(reference, actual):
    low, high = reference < -GAMUT_MARGIN, reference > 1 + GAMUT_MARGIN
    outside = np.any(low | high, axis=1)
    same_side = np.any((low & (actual < -CLIP_EPSILON)) | (high & (actual > 1 + CLIP_EPSILON)), axis=1)
    same_margin = np.any((low & (actual < -GAMUT_MARGIN)) | (high & (actual > 1 + GAMUT_MARGIN)), axis=1)
    return same_side, {
        "reference_outside_points": int(np.count_nonzero(outside)),
        "retained_on_same_side": int(np.count_nonzero(same_side)),
        "retained_with_same_margin": int(np.count_nonzero(same_margin)),
    }


def compare(camera, raw, ev, implementations, bundles, to_prophoto, to_srgb, sections=(), primary_points=None):
    model = implementations[0].color_model
    target = direct_prophoto(model, camera, raw, ev, to_prophoto)
    target_srgb = target @ to_srgb.T
    target_encoded = srgb_code(model, target_srgb)
    primary = slice(None, primary_points)
    result = {"points": len(raw[primary])}
    retained = []
    for label, enhanced, bundle in zip(VERSIONS, implementations, bundles, strict=True):
        if enhanced._FORMAT_VERSION == 2:
            wide = tagged_prophoto(enhanced, raw, bundle, ev - 0.5)
        else:
            wide = enhanced._render_prophoto(raw, bundle, ev - 0.5)
        linear_srgb = wide @ to_srgb.T
        encoded = srgb_code(model, linear_srgb)
        wide_stats = stats(wide[primary], target[primary], raw[primary])
        output_stats = stats(encoded[primary], target_encoded[primary], raw[primary])
        sample = np.vstack([raw[:16], wide_stats["worst_rgb"], output_stats["worst_rgb"]])
        expected = np.vstack([encoded[:16], srgb_code(model, np.array(wide_stats["worst_exported"]) @ to_srgb.T),
                              output_stats["worst_exported"]])
        np.testing.assert_allclose(enhanced.render_enhanced(sample, bundle, ev - 0.5), expected, atol=1e-10, rtol=0)
        result[label] = {"linear_prophoto": wide_stats, "encoded_srgb": output_stats}
        section_stats = {}
        for name, slc in sections:
            if len(raw[slc]):
                section_stats[name] = {"points": len(raw[slc])}
                for space, actual, expected in zip(SPACES, (wide, encoded), (target, target_encoded), strict=True):
                    detailed = stats(actual[slc], expected[slc], raw[slc])
                    section_stats[name][space] = {metric: detailed[metric] for metric in METRICS}
        if section_stats:
            result[label]["sections"] = section_stats
        if camera.space == "adobergb":
            mask, gamut = gamut_retention(target_srgb[primary], linear_srgb[primary])
            retained.append(mask)
            result[label]["adobergb_only"] = gamut
    if retained:
        lost = retained[0] & ~retained[1]
        missing = target_srgb[primary][lost]
        result["candidate"]["adobergb_only"].update(
            lost_vs_baseline=len(missing),
            recovered_vs_baseline=int(np.count_nonzero(retained[1] & ~retained[0])),
            largest_newly_lost_ideal_excursion_x255=float(np.max(np.maximum(-missing, missing - 1), initial=0) * 255),
        )
    return result


def summaries(rows, sample):
    result = {"points": sum(row[sample]["points"] for row in rows)}
    for space in SPACES:
        scores = {version: [row[sample][version][space] for row in rows] for version in VERSIONS}
        result[space] = {
            "largest_per_case": {
                version: {metric: max(value[metric] for value in values) for metric in METRICS}
                for version, values in scores.items()
            },
            "candidate_cases_worse_by_more_than_0.01": {
                metric: sum(b[metric] - a[metric] > .01 for a, b in zip(*scores.values(), strict=True))
                for metric in METRICS
            },
            "largest_regression": {},
            "worst_case": {},
        }
        for metric in METRICS:
            deltas = [b[metric] - a[metric] for a, b in zip(*scores.values(), strict=True)]
            i = int(np.argmax(deltas))
            result[space]["largest_regression"][metric] = {
                "case_id": rows[i]["case_id"], "candidate_minus_baseline": deltas[i],
            }
        for version, values in scores.items():
            i = int(np.argmax([value["max"] for value in values]))
            result[space]["worst_case"][version] = {"case_id": rows[i]["case_id"], **values[i]}
    result["adobergb_only"] = {}
    for version in VERSIONS:
        gamut = [row[sample][version]["adobergb_only"] for row in rows if row["recipe"]["color_space"] == "adobergb"]
        result["adobergb_only"][version] = {
            key: (max if key.startswith("largest") else sum)(row[key] for row in gamut) for key in gamut[0]
        }
    if sample == "held_out":
        result["sections"] = {}
        for section in ("sensor_neutrals", "sensor_cube_corners", "final_srgb_clip_faces", "final_srgb_clip_touches"):
            result["sections"][section] = {}
            for version in VERSIONS:
                scores = [row[sample][version]["sections"][section] for row in rows
                          if section in row[sample][version]["sections"]]
                result["sections"][section][version] = {
                    "points": sum(score["points"] for score in scores),
                    "largest_per_case": {
                        space: {metric: max((score[space][metric] for score in scores), default=None) for metric in METRICS}
                        for space in SPACES
                    },
                }
    return result


def run(baseline, candidate):
    candidate_hashes = source_hashes(candidate)
    implementations = load_package(baseline, "baseline_fcs"), load_package(candidate, "candidate_fcs")
    previous, current = implementations
    if any(enhanced.GRID_SIZE != 32 for enhanced in implementations):
        raise ValueError("both implementations must export at 32 divisions")
    model, profiles = previous.color_model, previous.profiles
    prophoto = normalized(model.PROPHOTO_TO_PCS)
    to_srgb = np.linalg.inv(normalized(model.SRGB_TO_PCS)) @ prophoto
    inverse_prophoto = np.linalg.inv(prophoto)
    original = json.loads(ORIGINAL.read_text(encoding="utf-8"))
    recipes = cases(profiles)
    if len(recipes) != 198:
        raise ValueError("the original recipe manifest has changed")
    common, held_out = points(), held_out_points()
    neutrals = np.repeat(np.linspace(0, 1, 257)[:, None], 3, axis=1)
    corners = np.stack(np.meshgrid([0., 1.], [0., 1.], [0., 1.], indexing="ij"), -1).reshape(-1, 3)
    grid_indices = np.ix_(*([[0, 31]] * 3))
    codes = np.arange(32)
    endpoints = (codes == 0) | (codes == 31)
    wireframe = (endpoints[:, None, None].astype(int) + endpoints[None, :, None] + endpoints[None, None, :]) >= 2
    rows, exposure_rows = [], []
    for index, (label, recipe) in enumerate(recipes):
        published = original["cases"][index]
        if (label, recipe["mode"], recipe["color_space"], recipe["toning"], recipe["settings"]) != (
                published["case"], published["mode"], published["space"], published["toning"], published["settings"]):
            raise ValueError(f"recipe {index} differs from the published sweep")
        camera = profiles.camera_for_recipe(recipe)
        to_prophoto = inverse_prophoto @ normalized(camera.to_pcs)
        raw = np.concatenate([common, faces(camera)])
        bundles = tuple(enhanced.build_enhanced(recipe) for enhanced in implementations)
        if any(bundle._samples.shape != (32, 32, 32, 3) or bundle._samples.dtype != np.dtype("<u2")
               for bundle in bundles):
            raise ValueError(f"recipe {index} did not export a 32³ 16-bit table")
        grid_corners = tuple(bundle._samples[grid_indices].reshape(-1, 3).astype(int) for bundle in bundles)
        grid_difference = abs(bundles[1]._samples.astype(int) - bundles[0]._samples.astype(int))
        if np.any(grid_difference[wireframe]) or np.any(grid_difference[codes, codes, codes]):
            raise ValueError(f"recipe {index} changed an anchored 16-bit LUT sample")
        ev_values = (0., *EXPOSURE) if label == "default" and recipe["mode"] in MODES_WITH_EXPOSURE else (0.,)
        for ev in ev_values:
            face_inputs = output_clip_faces(camera, model, ev, to_prophoto, to_srgb)
            touches = face_inputs.pop("final_srgb_clip_touches")
            sections = {"sensor_neutrals": neutrals, "sensor_cube_corners": corners, **face_inputs}
            ends = np.cumsum([0, *(len(samples) for samples in sections.values())])
            slices = list(zip(sections, map(slice, ends[:-1], ends[1:]), strict=True))
            primary = [*sections.values(), held_out, held_out_faces(camera, ev)]
            primary_points = sum(len(samples) for samples in primary)
            slices.append(("final_srgb_clip_touches", slice(primary_points, None)))
            independent = np.concatenate([*primary, touches])
            row = {
                "case_id": f"{index:03d}/{ev:+g}", "case": label, "recipe": recipe, "total_ev": ev,
                "original": compare(camera, raw, ev, implementations, bundles, to_prophoto, to_srgb),
                "held_out": compare(camera, independent, ev, implementations, bundles, to_prophoto, to_srgb,
                                    slices, primary_points),
            }
            if ev == 0:
                row["lut_corner_codes"] = {label: values.tolist() for label, values in zip(VERSIONS, grid_corners, strict=True)}
                row["lut_corner_max_u16_delta"] = int(grid_difference[grid_indices].max())
                row["lut_neutral_diagonal_max_u16_delta"] = int(grid_difference[codes, codes, codes].max())
                row["lut_wireframe_max_u16_delta"] = int(grid_difference[wireframe].max())
                rows.append(row)
            else:
                published = original["exposure_structure_cases"][len(exposure_rows)]
                if (published["mode"], published["space"], published["total_ev"]) != (
                        recipe["mode"], recipe["color_space"], ev):
                    raise ValueError("the original exposure cases have changed")
                exposure_rows.append(row)
            if row["original"]["points"] != published["points"]:
                raise ValueError("original sample count did not match")
            baseline_score = row["original"][BASELINE_TAG]["encoded_srgb"]
            np.testing.assert_allclose([baseline_score[k] for k in METRICS],
                                       [published["staged_v2"][k] for k in METRICS], atol=5e-7, rtol=0)
        if (index + 1) % 50 == 0:
            print(f"Compared {index + 1}/{len(recipes)} original recipes", file=sys.stderr)
    if len(exposure_rows) != 32:
        raise ValueError("expected 32 original exposure cases")
    if source_hashes(candidate) != candidate_hashes:
        raise ValueError("candidate sources changed during the benchmark")
    return {
        "schema_version": 1,
        "method": {
            "error": "Absolute RGB channel differences multiplied by 255 in both spaces; not a perceptual metric.",
            "reference": "Tagged camera stages at exact CC0, channel order and RGB primaries, without serialized matrix rounding or LUT.",
            "exposure": "Positive gain and negative SDK tone applied in CC0 coordinates before camera gamma; a structure model, not camera exposure gain.",
            "original": "Original 33^3 grid, seeded random and shadow RGB, known test points and CC0 planes (check_gold_lut_fidelity.py).",
            "held_out": "Shifted 17^3 grid, 8192 uniform and 2048 log-dark RGB, CC0 clipping probes, and bracketed 0/1 crossings along new seeded sensor RGB lines. Final sRGB transitions to clipped plateaus are reported separately. Sensor neutrals and eight structural corners are fixed anchors, which can also occur in the original data.",
            "held_out_seeds": [HELD_OUT_SEED, HELD_OUT_SEED + 1, HELD_OUT_SEED + 2],
            "lut_codes": "16-bit table entries at corners (each index 0 or 31), the internal neutral diagonal (all three indices equal) and the wireframe (at least two indices 0 or 31). The grid and sensor cube are distinct domains. Raw code comparison assumes both LUT domains match.",
            "gamut": "Adobe RGB recipes only. An ideal pixel qualifies if at least one linear sRGB channel lies outside [0,1] by over 1/255. The wide-gamut output is tested on the same channel and side, before sRGB clipping.",
            "summary": "Each largest-per-case metric is the maximum of individual-case statistics, not a percentile computed across rows.",
            "validation": "Known v0.1.2 encoded sRGB statistics and sample counts match all 230 published rows. Offline sRGB renderer checked against the wide-gamut output for 16 initial and both worst samples in every row and dataset.",
        },
        "baseline": {"tag": BASELINE_TAG, "commit": BASELINE_COMMIT, "source_sha256_canonical_lf": source_hashes(baseline)},
        "candidate": {"format_version": current._FORMAT_VERSION, "source_sha256_canonical_lf": candidate_hashes},
        "numpy": np.__version__,
        "recipes": len(rows),
        "exposure_cases": len(exposure_rows),
        "lut_anchor_max_u16_deltas": {
            anchor: max(row[f"lut_{anchor}_max_u16_delta"] for row in rows)
            for anchor in ("corner", "neutral_diagonal", "wireframe")
        },
        "summary": {
            sample: {"nominal": summaries(rows, sample), "exposure": summaries(exposure_rows, sample)}
            for sample in ("original", "held_out")
        },
        "cases": rows,
        "exposure_structure_cases": exposure_rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-repo", required=True, type=Path, help="candidate Firmware Color Studio checkout with v0.1.2 tag")
    parser.add_argument("--output", required=True, type=Path, help="new JSON report file")
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        parser.error("output must be a new file in an existing directory")
    repo = args.app_repo.resolve()
    if git(repo, "rev-parse", f"refs/tags/{BASELINE_TAG}^{{commit}}") != BASELINE_COMMIT:
        parser.error(f"expected {BASELINE_TAG} at {BASELINE_COMMIT}")
    with TemporaryDirectory() as directory:
        baseline = Path(directory)
        archive = baseline / "baseline.zip"
        git(repo, "archive", "--format=zip", "-o", str(archive), BASELINE_COMMIT, PACKAGE.as_posix())
        with ZipFile(archive) as source:
            source.extractall(baseline)
        result = run(baseline, repo)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(f"Compared {result['recipes']} recipes and {result['exposure_cases']} exposure cases in both sample sets")


if __name__ == "__main__":
    main()
