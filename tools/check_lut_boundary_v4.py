"""Re-run the published RGB benchmark on two tagged releases and enhanced LUT v4."""

import argparse
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from zipfile import ZipFile

import check_lut_boundary_v3 as study
import numpy as np


TAGS = {
    "v0.1.2": study.BASELINE_COMMIT,
    "v0.1.3": "77cbfc16557f02ae063555bafb28b21d6439070c",
}
CANDIDATE = "v4"
VERSIONS = (*TAGS, CANDIDATE)
PUBLISHED = {
    "gold-lut-fidelity.json": "b3341996655bb7d34ce1670fbdcb990f688d05aca9d5003efb02f4fa88ef3589",
    "lut-boundary-v3.json": "5f21dca9d556df1d069e724f5c42e94af418799575ae10573980d021376d6509",
}
REFERENCE_LABELS = {"v0.1.2": "v0.1.2", "v0.1.3": "candidate"}
CORNER_COORDS = np.array(list(product((0., 1.), repeat=3)))
NEUTRALS = np.repeat(np.linspace(0., 1., 257)[:, None], 3, axis=1)
ANCHOR_INDEX = np.indices((32,) * 3)
ENDPOINT_COUNT = ((ANCHOR_INDEX == 0) | (ANCHOR_INDEX == 31)).sum(axis=0)
ANCHORS = {
    "corner": ENDPOINT_COUNT == 3,
    "wireframe": ENDPOINT_COUNT >= 2,
    "neutral_diagonal": np.all(ANCHOR_INDEX == ANCHOR_INDEX[:1], axis=0),
}
FRESH_SEED = 615087160
REGRESSION_MARGIN = .01


def checked_json(name):
    content = (study.ORIGINAL.parent / name).read_bytes().replace(b"\r\n", b"\n")
    if sha256(content).hexdigest() != PUBLISHED[name]:
        raise ValueError(f"published evidence changed: {name}")
    return json.loads(content)


def archive_tag(repo, directory, tag, commit):
    if study.git(repo, "rev-parse", f"refs/tags/{tag}^{{commit}}") != commit:
        raise ValueError(f"expected {tag} to resolve to {commit}")
    path = directory / tag
    path.mkdir()
    archive = path / "source.zip"
    study.git(repo, "archive", "--format=zip", "-o", str(archive), commit, study.PACKAGE.as_posix())
    with ZipFile(archive) as source:
        source.extractall(path)
    return path


def data_sets(common, held_out, fresh, camera, model, ev, to_prophoto, to_srgb):
    boundaries = study.output_clip_faces(camera, model, ev, to_prophoto, to_srgb)
    primary = [NEUTRALS, CORNER_COORDS, boundaries["final_srgb_clip_faces"], held_out,
               study.held_out_faces(camera, ev)]
    touches = boundaries["final_srgb_clip_touches"]
    ends = np.cumsum([0, *(len(points) for points in primary)])
    slices = {
        "sensor_neutrals": slice(ends[0], ends[1]),
        "sensor_cube_corners": slice(ends[1], ends[2]),
        "final_srgb_clip_faces": slice(ends[2], ends[3]),
        "final_srgb_clip_touches": slice(ends[-1], None),
    }
    return (
        ("original", common, slice(None), {}),
        ("held_out", np.concatenate([*primary, touches]), slice(0, ends[-1]), slices),
        ("fresh_global", fresh, slice(None), {}),
    )


def wide_values(enhanced, raw, bundle, total_ev):
    if enhanced._FORMAT_VERSION == 2:
        return study.tagged_prophoto(enhanced, raw, bundle, total_ev - .5)
    return enhanced._render_prophoto(raw, bundle, total_ev - .5)


def values(model, wide, to_srgb):
    linear = wide @ to_srgb.T
    return {"linear_prophoto": wide, "linear_srgb": linear, "encoded_srgb": study.srgb_code(model, linear)}


def score(reference, actual, raw, take, *, details):
    if details:
        return {space: study.stats(actual[space][take], reference[space][take], raw[take]) for space in study.SPACES}
    result = {}
    for space in study.SPACES:
        delta = np.abs(actual[space][take] - reference[space][take]) * 255
        result[space] = dict(zip(study.METRICS, map(float, (delta.mean(), *np.percentile(delta, (95, 99)), delta.max())),
                                 strict=True))
    return result


def score_set(versions, bundles, model, camera, ev, raw, primary, sections, to_prophoto, to_srgb):
    reference = values(model, study.direct_prophoto(model, camera, raw, ev, to_prophoto), to_srgb)
    result = {"points": len(raw[primary])}
    masks = {}
    for label, enhanced, bundle in zip(VERSIONS, versions, bundles, strict=True):
        actual = values(model, wide_values(enhanced, raw, bundle, ev), to_srgb)
        counters = score(reference, actual, raw, primary, details=True)
        marks = counters["linear_prophoto"], counters["encoded_srgb"]
        sample = np.vstack([raw[:8], *(mark["worst_rgb"] for mark in marks)])
        expected = np.vstack([actual["encoded_srgb"][:8], study.srgb_code(model, marks[0]["worst_exported"] @ to_srgb.T),
                              marks[1]["worst_exported"]])
        np.testing.assert_allclose(enhanced.render_enhanced(sample, bundle, ev - .5), expected, rtol=0, atol=1e-10)
        counters["sections"] = {
            name: {"points": len(raw[take]), **score(reference, actual, raw, take, details=False)}
            for name, take in sections.items() if len(raw[take])
        }
        if camera.space == "adobergb":
            masks[label], counters["adobergb_only"] = study.gamut_retention(reference["linear_srgb"][primary],
                                                                           actual["linear_srgb"][primary])
        result[label] = counters
    if masks:
        result["v4_adobergb_retention_changes"] = {}
        for tag in TAGS:
            lost = reference["linear_srgb"][primary][masks[tag] & ~masks[CANDIDATE]]
            result["v4_adobergb_retention_changes"][tag] = {
                "lost": len(lost), "recovered": int(np.count_nonzero(masks[CANDIDATE] & ~masks[tag])),
                "largest_lost_excursion_x255": float(np.max(np.maximum(-lost, lost - 1), initial=0) * 255),
            }
    return result


def verify_published(observed, published):
    if observed["points"] != published["points"]:
        raise ValueError("sample count changed from v3 evidence")
    for tag, name in REFERENCE_LABELS.items():
        actual, expected = observed[tag], published[name]
        actual_sections, expected_sections = actual["sections"], expected.get("sections", {})
        assert actual_sections.keys() == expected_sections.keys()
        for section in actual_sections:
            assert actual_sections[section]["points"] == expected_sections[section]["points"]
        for left, right in [(actual, expected), *((actual_sections[key], expected_sections[key]) for key in actual_sections)]:
            for space in study.SPACES:
                np.testing.assert_allclose([left[space][metric] for metric in study.METRICS],
                                           [right[space][metric] for metric in study.METRICS], rtol=0, atol=5e-7)
        if "adobergb_only" in actual:
            assert all(count == expected["adobergb_only"][key] for key, count in actual["adobergb_only"].items())


def tetrahedron(model, working):
    encoded = model.srgb_encode(np.clip(working, 0, 1))
    scaled = encoded * 31
    lower = np.minimum(scaled.astype(int), 30)
    frac = scaled - lower
    order = np.argsort(-frac)
    vertices = lower + np.vstack([np.zeros(3, dtype=int), np.eye(3, dtype=int)[order].cumsum(axis=0)])
    weights = -np.diff(np.r_[1., frac[order], 0.])
    np.testing.assert_allclose(weights @ vertices, scaled, atol=1e-12, rtol=0)
    return encoded, lower, vertices, weights


def witness_stages(camera, model, raw, to_prophoto, to_srgb, working_matrix, bundles, actual):
    cc0 = raw @ camera.matrix.T
    working = raw @ working_matrix.T
    clipped = np.clip(cc0, 0, 1)
    gamma = camera.gamma(clipped)
    ycc = gamma @ (camera.yc.T / 256.)
    suppressed = ycc.copy()
    suppressed[1:] *= camera.chroma_gain(np.clip(ycc[0], 0, 1))
    toned = suppressed + np.r_[0., np.asarray(camera.chroma_offset) / 1024.]
    limited = np.clip(toned, (0, -.5, -.5), (1, .5, .5))
    before_native_clip = limited @ model.JFIF_DECODE.T
    native = np.clip(before_native_clip, 0, 1)
    np.testing.assert_allclose(camera.encode(clipped), native, rtol=0, atol=1e-12)
    encoded, lower, vertices, weights = tetrahedron(model, working)
    table_codes = {key: bundle._samples[tuple(vertices.T)] for key, bundle in zip(VERSIONS, bundles, strict=True)}
    for key, samples in table_codes.items():
        wide = model.srgb_decode(weights @ samples.astype(float) / 65535)
        np.testing.assert_allclose(wide, actual[key]["linear_prophoto"], atol=1e-12, rtol=0)
    correction = camera.matrix @ np.linalg.inv(working_matrix)
    no_lut_cc0 = model.srgb_decode(encoded) @ correction.T
    no_lut_wide = camera.decode(camera.encode(no_lut_cc0)) @ to_prophoto.T
    residuals, unquantized_codes = stage_residuals(camera, model, correction, to_prophoto, to_srgb, vertices / 31., weights)
    np.testing.assert_array_equal(np.floor(unquantized_codes * 65535 + .5), table_codes["v0.1.2"])
    vertex_luma = (camera.gamma(np.clip(model.srgb_decode(vertices / 31.) @ correction.T, 0, 1))
                   @ (camera.yc.T / 256.))[:, 0] * 1023
    active = vertex_luma[weights > 1e-12]
    return {
        "exact_unclipped_CC0": cc0.tolist(), "exact_clipped_CC0": clipped.tolist(),
        "gamma": gamma.tolist(), "YC": ycc.tolist(), "chroma_suppression_gain": float(camera.chroma_gain(np.clip(ycc[0], 0, 1))),
        "after_chroma_suppression": suppressed.tolist(), "after_toning": toned.tolist(), "limited_YC": limited.tolist(),
        "native_before_channel_clip": before_native_clip.tolist(), "native_encoded_RGB": native.tolist(),
        "serialized_working_before_clip": working.tolist(), "lut_encoded_input": encoded.tolist(),
        "cell": lower.tolist(), "vertices": vertices.tolist(), "weights": weights.tolist(),
        "vertex_u16_codes": {key: codes.tolist() for key, codes in table_codes.items()},
        "vertex_y1023_before_csp": vertex_luma.tolist(),
        "crossed_csp_borders": [edge for edge in camera.csp_border if vertex_luma.min() <= edge <= vertex_luma.max()],
        "active_vertex_y1023_range": [float(active.min()), float(active.max())],
        "active_crossed_csp_borders": [edge for edge in camera.csp_border if active.min() <= edge <= active.max()],
        "stage_commutation_residuals": residuals,
        "same_serialized_matrix_with_continuous_color": {key: value.tolist() for key, value in values(model, no_lut_wide, to_srgb).items()},
    }


def stage_residuals(camera, model, correction, to_prophoto, to_srgb, nodes, weights):
    """Move interpolation through the continuous stages in order to isolate diagnostic jumps."""

    def suppress(ycc):
        gain = camera.chroma_gain(np.clip(ycc[..., 0], 0, 1))[..., None]
        return np.concatenate([ycc[..., :1], ycc[..., 1:] * gain], axis=-1)

    operations = (
        ("input_srgb_transfer", model.srgb_decode),
        ("CC0_correction", lambda rgb: rgb @ correction.T),
        ("CC0_clip", lambda rgb: np.clip(rgb, 0, 1)),
        ("gamma", camera.gamma),
        ("YC", lambda rgb: rgb @ (camera.yc.T / 256.)),
        ("chroma_suppression", suppress),
        ("toning", lambda ycc: ycc + np.r_[0., np.asarray(camera.chroma_offset) / 1024.]),
        ("YC_clip", lambda ycc: np.clip(ycc, (0, -.5, -.5), (1, .5, .5))),
        ("JFIF", lambda ycc: ycc @ model.JFIF_DECODE.T),
        ("native_channel_clip", lambda rgb: np.clip(rgb, 0, 1)),
        ("native_output_transfer", camera.decode),
        ("to_ProPhoto", lambda rgb: rgb @ to_prophoto.T),
        ("ProPhoto_clip", lambda rgb: np.clip(rgb, 0, 1)),
        ("LUT_srgb_transfer", model.srgb_encode),
    )

    def predict(point, start):
        for _, apply in operations[start:]:
            point = apply(point)
        return values(model, model.srgb_decode(point), to_srgb)

    previous = predict(weights @ nodes, 0)
    result = {}
    for index, (name, apply) in enumerate(operations, 1):
        nodes = apply(nodes)
        actual = predict(weights @ nodes, index)
        result[name] = {space: ((actual[space] - previous[space]) * 255).tolist() for space in actual}
        previous = actual
    return result, nodes


def local_points(model, working_matrix, raw):
    """Move in the LUT's free encoded axes, preserving clipped coordinates."""
    work = raw @ working_matrix.T
    encoded = np.clip(model.srgb_encode(work), 0, 1)
    free = (work > 0) & (work < 1)
    shifts = (-.25, -.125, 0., .125, .25)
    offsets = np.array(list(product(*(shifts if axis else (0.,) for axis in free)))) / 31
    shifted = encoded + offsets[np.any(offsets != 0., axis=1)]
    shifted = shifted[np.all((shifted >= 0) & (shifted <= 1), axis=1)]
    linear = np.where(free, model.srgb_decode(shifted), work)
    inputs = np.linalg.solve(working_matrix, linear.T).T
    return inputs[np.all((inputs >= 0) & (inputs <= 1), axis=1)], free


def harubeni_breakpoint_slice(versions, bundles, model, camera, center, to_prophoto, to_srgb):
    """Trace the published HARUBENI witness along the green-clipped LUT face."""
    base = versions[1].dcp.read_dcp(bundles[1].dcp)
    working_matrix = versions[1]._working_matrix(base["ForwardMatrix1"])
    center = np.array(center)
    working = center @ working_matrix.T
    assert working[1] >= 1 and 0 < working[0] < 1
    encoded_r = float(model.srgb_encode(working[0]))
    edge = 856
    for radius in (.125, .25, .5, 1., 2.):
        x = encoded_r * 31 + np.linspace(-radius, radius, 257)
        required = np.broadcast_to(working, (len(x), 3)).copy()
        required[:, 0] = model.srgb_decode(x / 31)
        raw = np.linalg.solve(working_matrix, required.T).T
        raw[128] = center
        if np.any((raw < 0) | (raw > 1)) or x[0] < 0 or x[-1] > 31:
            continue
        cc0 = np.clip(raw @ camera.matrix.T, 0, 1)
        luma = (camera.gamma(cc0) @ (camera.yc.T / 256.))[:, 0] * 1023
        brackets = np.flatnonzero((luma[:-1] < edge) != (luma[1:] < edge))
        if len(brackets):
            break
    else:
        raise ValueError("HARUBENI red slice failed to straddle the chroma suppression breakpoint")
    colors = {"reference": values(model, study.direct_prophoto(model, camera, raw, 0., to_prophoto), to_srgb)}
    for label, version, bundle in zip(VERSIONS, versions, bundles, strict=True):
        colors[label] = values(model, wide_values(version, raw, bundle, 0.), to_srgb)
    return {
        "case_id": "190/+0", "center_sensor_rgb": center.tolist(), "center_index": 128,
        "csp_breakpoint_y1023": edge, "breakpoint_bracketing_indices": [[int(i), int(i + 1)] for i in brackets],
        "lut_r_index": x.tolist(), "direct_y1023_before_csp": luma.tolist(),
        "red_encoded_srgb_x255": {label: (color["encoded_srgb"][:, 0] * 255).tolist() for label, color in colors.items()},
    }


def witnesses(row, frozen, versions, bundles, model, camera, to_prophoto, to_srgb):
    evidence = {tag: frozen["original"][source]["encoded_srgb"] for tag, source in REFERENCE_LABELS.items()}
    evidence[CANDIDATE] = row["original"][CANDIDATE]["encoded_srgb"]
    centers = {}
    for label, info in evidence.items():
        centers.setdefault(tuple(info["worst_rgb"]), []).append(label)
    traces = []
    base = versions[1].dcp.read_dcp(bundles[1].dcp)
    working_matrix = versions[1]._working_matrix(base["ForwardMatrix1"])
    for coords, maxima in centers.items():
        raw = np.array(coords)
        reference = values(model, study.direct_prophoto(model, camera, raw, 0., to_prophoto), to_srgb)
        actual = {label: values(model, wide_values(version, raw, bundle, 0.), to_srgb)
                  for label, version, bundle in zip(VERSIONS, versions, bundles, strict=True)}
        for label in maxima:
            mark = evidence[label]
            np.testing.assert_allclose(actual[label]["encoded_srgb"], mark["worst_exported"], atol=5e-10, rtol=0)
            np.testing.assert_allclose(reference["encoded_srgb"], mark["worst_direct"], atol=5e-10, rtol=0)
        entry = {
            "sensor_rgb": list(coords), "max_point_for": maxima,
            "reference": {space: value.tolist() for space, value in reference.items()},
            "actual": {label: {space: value.tolist() for space, value in rgb.items()} for label, rgb in actual.items()},
            "signed_error_x255": {label: {space: ((value - reference[space]) * 255).tolist() for space, value in rgb.items()}
                                  for label, rgb in actual.items()},
            "trace": witness_stages(camera, model, raw, to_prophoto, to_srgb, working_matrix, bundles, actual),
        }
        if camera.name == "harubeni":
            neighborhood, free = local_points(model, working_matrix, raw)
            entry["local_neighborhood"] = {"free_axes": free.tolist(), "points": len(neighborhood)}
            if len(neighborhood):
                local_reference = values(model, study.direct_prophoto(model, camera, neighborhood, 0., to_prophoto), to_srgb)
                for label, version, bundle in zip(VERSIONS, versions, bundles, strict=True):
                    local_actual = values(model, wide_values(version, neighborhood, bundle, 0.), to_srgb)
                    entry["local_neighborhood"][label] = score(local_reference, local_actual, neighborhood, slice(None), details=True)
        traces.append(entry)
    return traces


def summarize(rows, sample):
    result = {"cases": len(rows), "points": sum(row[sample]["points"] for row in rows)}
    for space in study.SPACES:
        scores = {label: np.array([[row[sample][label][space][k] for k in study.METRICS] for row in rows])
                  for label in VERSIONS}
        result[space] = {
            "largest_per_case": {label: dict(zip(study.METRICS, values.max(axis=0).tolist(), strict=True))
                                 for label, values in scores.items()},
            "worst_case": {label: rows[int(values[:, -1].argmax())]["case_id"] for label, values in scores.items()},
        }
        for tag in TAGS:
            change = scores[CANDIDATE] - scores[tag]
            result[space][f"v4_minus_{tag}"] = {
                k: {"cases_worse": int(np.count_nonzero(delta > REGRESSION_MARGIN)), "largest_increase": float(delta.max()),
                    "case_id": rows[int(delta.argmax())]["case_id"]}
                for k, delta in zip(study.METRICS, change.T, strict=True)
            }
    for key in ("adobergb_only", "sections"):
        result[key] = {}
        for label in VERSIONS:
            values = [row[sample][label][key] for row in rows if key in row[sample][label]]
            if key == "adobergb_only":
                result[key][label] = {name: sum(group[name] for group in values) for name in values[0]}
            else:
                for name in dict.fromkeys(name for group in values for name in group):
                    sections = [group[name] for group in values if name in group]
                    result[key].setdefault(name, {})[label] = {
                        "points": sum(section["points"] for section in sections),
                        "largest_per_case": {space: {metric: max(section[space][metric] for section in sections)
                                                     for metric in study.METRICS} for space in study.SPACES},
                    }
    result["v4_adobergb_retention_changes"] = {}
    for tag in TAGS:
        changes = [row[sample]["v4_adobergb_retention_changes"][tag] for row in rows
                   if "v4_adobergb_retention_changes" in row[sample]]
        result["v4_adobergb_retention_changes"][tag] = {
            name: (max if name.startswith("largest") else sum)(group[name] for group in changes) for name in changes[0]
        }
    return result


def verify_anchors(bundles):
    baseline, previous, candidate = bundles
    assert baseline.dcp == previous.dcp == candidate.dcp, "the serialized DCP changed"
    assert all(bundle._samples.shape == (32, 32, 32, 3) and bundle._samples.dtype == np.dtype("<u2") for bundle in bundles)
    for name, mask in ANCHORS.items():
        for following in bundles[1:]:
            assert np.array_equal(baseline._samples[mask], following._samples[mask]), f"changed anchor: {name}"


def run(repos):
    older, frozen = (checked_json(name) for name in PUBLISHED)
    hashes = {key: study.source_hashes(path) for key, path in repos.items()}
    if hashes["v0.1.2"] != frozen["baseline"]["source_sha256_canonical_lf"] or hashes["v0.1.3"] != frozen["candidate"]["source_sha256_canonical_lf"]:
        raise ValueError("a tagged release source differs from the published v3 source")
    versions = tuple(study.load_package(path, f"benchmark_fcs_{i}") for i, path in enumerate(repos.values()))
    expected = (2, 3, 4)
    if tuple(version._FORMAT_VERSION for version in versions) != expected:
        raise ValueError(f"expected enhanced LUT formats {expected}")
    model, profiles = versions[0].color_model, versions[0].profiles
    prophoto = study.normalized(model.PROPHOTO_TO_PCS)
    to_srgb = np.linalg.inv(study.normalized(model.SRGB_TO_PCS)) @ prophoto
    inverse_prophoto = np.linalg.inv(prophoto)
    rng = np.random.default_rng(FRESH_SEED)
    fresh = np.concatenate([rng.uniform(0, 1, (8192, 3)), 2 ** rng.uniform(-24, -4, (2048, 3))])
    common, held_out = study.points(), study.held_out_points()
    published = {row["case_id"]: row for row in (*frozen["cases"], *frozen["exposure_structure_cases"])}
    regressed = {
        row["case_id"] for row in frozen["cases"]
        if row["original"]["candidate"]["encoded_srgb"]["max"] - row["original"]["v0.1.2"]["encoded_srgb"]["max"] > REGRESSION_MARGIN
    }
    assert len(regressed) == 10 and len(published) == 230
    rows, exposure, investigations = [], [], []
    breakpoint_slice = None
    for i, (label, recipe) in enumerate(study.cases(profiles)):
        camera = profiles.camera_for_recipe(recipe)
        to_prophoto = inverse_prophoto @ study.normalized(camera.to_pcs)
        base_raw = np.concatenate([common, study.faces(camera)])
        bundles = tuple(version.build_enhanced(recipe) for version in versions)
        verify_anchors(bundles)
        ev_values = (0., *study.EXPOSURE) if label == "default" and recipe["mode"] in study.MODES_WITH_EXPOSURE else (0.,)
        for ev in ev_values:
            case_id = f"{i:03d}/{ev:+g}"
            expected = published[case_id]
            assert (recipe, label, ev) == (expected["recipe"], expected["case"], expected["total_ev"]), case_id
            row = {"case_id": case_id, "case": label, "recipe": recipe, "total_ev": ev}
            for sample, raw, primary, sections in data_sets(base_raw, held_out, fresh, camera, model, ev, to_prophoto, to_srgb):
                row[sample] = score_set(versions, bundles, model, camera, ev, raw, primary, sections, to_prophoto, to_srgb)
                if sample in expected:
                    verify_published(row[sample], expected[sample])
            historical = older["cases"][i] if not ev else older["exposure_structure_cases"][len(exposure)]
            np.testing.assert_allclose([row["original"]["v0.1.2"]["encoded_srgb"][metric] for metric in study.METRICS],
                                       [historical["staged_v2"][metric] for metric in study.METRICS], atol=5e-7, rtol=0)
            (exposure if ev else rows).append(row)
            if case_id in regressed:
                investigations.append({
                    "case_id": case_id, "case": label, "recipe": recipe,
                    "same_input_signed_witnesses": witnesses(row, expected, versions, bundles, model, camera, to_prophoto, to_srgb),
                    "max_encoded_srgb_x255": {sample: {version: row[sample][version]["encoded_srgb"]["max"] for version in VERSIONS}
                                              for sample in ("original", "held_out", "fresh_global")},
                })
            if case_id == "190/+0":
                center = expected["original"]["candidate"]["encoded_srgb"]["worst_rgb"]
                breakpoint_slice = harubeni_breakpoint_slice(versions, bundles, model, camera, center, to_prophoto, to_srgb)
        if (i + 1) % 50 == 0:
            print(f"Compared {i + 1}/{len(frozen['cases'])} original recipes", file=sys.stderr)
    assert (len(rows), len(exposure), len(investigations)) == (198, 32, 10)
    assert breakpoint_slice is not None
    if study.source_hashes(repos[CANDIDATE]) != hashes[CANDIDATE]:
        raise ValueError("candidate sources changed during the benchmark")
    return {
        "schema_version": 1,
        "method": {**frozen["method"],
                   "fresh_global": "8192 uniform and 2048 log-dark inputs (PCG64), unused for candidate design; same points across cases",
                   "fresh_global_seed": FRESH_SEED,
                   "local_neighborhood": "HARUBENI worst witnesses, center omitted, Cartesian offsets of 0, ±1/8, ±1/4 encoded LUT cell widths along free axes. Clipped coordinates fixed. Reported separately from whole-domain samples.",
                   "matched_witnesses": "Every renderer and the direct reference are evaluated at the same sensor coordinates for each distinct original-sample worst point of each version. Published v2/v3 coordinates are kept verbatim. Signed error is (output − reference) × 255.",
                   "stage_commutation_residuals": "Diagnostic signed jumps when moving interpolation through consecutive nonlinear stages. The decomposition depends on the operation order and does not by itself prove the mechanism for other points.",
                   "validation": "Both previous release tags replay all published v3 original and held-out results in both spaces; staged v2 encoded sRGB also replayed. DCP equality, LUT shape/quantization, anchors and offline sRGB renderer checked.",
                   "regression_threshold_x255": REGRESSION_MARGIN},
        "source": {"published_report_sha256_canonical_lf": PUBLISHED, "tag_commits": TAGS,
                   "source_sha256_canonical_lf": hashes, "numpy": np.__version__},
        "lut_anchors": {"points_per_recipe": {key: int(mask.sum()) for key, mask in ANCHORS.items()},
                        "recipes_checked": len(rows), "max_u16_delta": 0, "base_dcp_equal": True},
        "summary": {sample: {"nominal": summarize(rows, sample), "nonzero_ev": summarize(exposure, sample)}
                    for sample in ("original", "held_out", "fresh_global")},
        "v3_original_max_regressions": investigations,
        "harubeni_190_breakpoint_slice": breakpoint_slice,
        "cases": rows, "exposure_structure_cases": exposure,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-repo", required=True, type=Path, help="v4 Firmware Color Studio checkout with both baseline tags")
    parser.add_argument("--output", required=True, type=Path, help="new JSON report file")
    args = parser.parse_args()
    if not __debug__:
        parser.error("assertions are required for benchmark validation")
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        parser.error("output must be a new file in an existing directory")
    repo = args.app_repo.resolve()
    with TemporaryDirectory() as directory:
        repos = {tag: archive_tag(repo, Path(directory), tag, commit) for tag, commit in TAGS.items()}
        result = run({**repos, CANDIDATE: repo})
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print("Compared 198 recipe cases, 32 EV cases and 10 matched-coordinate regressions")


if __name__ == "__main__":
    main()
