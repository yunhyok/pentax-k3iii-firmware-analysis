"""Measure held-out K-3 II #1376 color residuals after neutral-only tone fitting."""
# SPDX-License-Identifier: GPL-2.0-only
if not __debug__:
    raise RuntimeError("Run without -O so the fixture checks remain enabled.")
import argparse
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

sys.dont_write_bytecode = True

import numpy as np
import scipy
from scipy.interpolate import PchipInterpolator
from skimage.color import rgb2hsv

import check_lightroom_render as render
from check_lightroom_gamut import xyz_columns

SOURCE_HASHES_LF = {
    "lightroom-render-comparison": "6c59220ec5dee4db3b6353374603195198079b0266bd3b2f95ef3223f161e19b",
    "lightroom-tone-comparison": "1079489ee7dd92b75d161e73d8f4db94c276bfc8c50e03ff8407223dd6da2975",
    "lightroom-look-controls": "e6fe7be64e66bf587a1fc3642986b51fd7ed11dd6bc9b828f6784f10b0a510e8",
}
TONE_NAMES = ("matrix", "tone_identity", "tone_lift", "tone_acr3")
NEUTRAL = np.arange(18, 24)
COLOR = np.arange(18)
WHITE = np.array([0.9642, 1.0, 0.8249])
STEP = 6 / 29


def load(name):
    data = (render.ROOT / f"analysis/{name}.json").read_bytes().replace(b"\r\n", b"\n")
    assert render.sha256(data).hexdigest() == SOURCE_HASHES_LF[name], f"{name}: source record SHA-256 mismatch"
    return json.loads(data)


def xyz_from_lab(lab):
    l, a, b = np.moveaxis(lab.astype(np.float64), -1, 0)
    fy = (l + 16) / 116
    f = np.stack((fy + a / 500, fy, fy - b / 200), axis=-1)
    return WHITE * np.where(f > STEP, f**3, 3 * STEP**2 * (f - 4 / 29))


def lab_from_xyz(xyz):
    t = xyz / WHITE
    f = np.where(t > STEP**3, np.cbrt(t), t / (3 * STEP**2) + 4 / 29)
    x, y, z = np.moveaxis(f, -1, 0)
    return np.stack((116 * y - 16, 500 * (x - y), 200 * (y - z)), axis=-1)


def median(frame, inset):
    return render.medians(frame[:, inset:200 - inset, inset:200 - inset])


def rgb_tone(rgb, curve):
    low, high = rgb.min(axis=-1, keepdims=True), rgb.max(axis=-1, keepdims=True)
    span = high - low
    rank = np.divide(rgb - low, span, out=np.zeros_like(rgb), where=span > 0)
    flo, fhi = curve(low), curve(high)
    return flo + rank * (fhi - flo)


def xy_fit(source_lab, target_lab, training, model):
    src_y = xyz_from_lab(source_lab[training])[:, 1]
    dst_y = xyz_from_lab(target_lab[training])[:, 1]
    order = np.argsort(src_y)
    x, y = np.r_[0.0, src_y[order], 1.0], np.r_[0.0, dst_y[order], 1.0]
    assert np.all(np.diff(x) > 0) and np.all(np.diff(y) > 0), (x, y)
    if model == "pchip":
        evaluate = PchipInterpolator(x, y, extrapolate=False)
    else:
        def evaluate(values):
            return np.interp(values, x, y)
    return x, y, evaluate


def metric(target, fitted):
    error = render.delta(target, fitted)
    diff = fitted - target
    return {
        "mean_delta_e00": float(error.mean()),
        "max_delta_e00": float(error.max()),
        "mean_abs_delta_lstar": float(np.abs(diff[:, 0]).mean()),
        "mean_ab_distance": float(np.linalg.norm(diff[:, 1:], axis=1).mean()),
    }


def estimate(source, target, matrix, inverse, inset):
    source_med, target_med = median(source, inset), median(target, inset)
    source = source[:, inset:200 - inset, inset:200 - inset]
    source_linear = xyz_from_lab(source) @ inverse.T
    assert source_linear.min() > -1e-4 and source_linear.max() < 1.0001
    source_linear = np.clip(source_linear, 0, 1)
    base_error = render.delta(target_med, source_med)
    result = {"baseline_color": metric(target_med[COLOR], source_med[COLOR]),
              "baseline_neutral": metric(target_med[NEUTRAL], source_med[NEUTRAL])}
    # Per-patch medians diagnostic for hue invariance. In linear RGB the hue of
    # the DNG SDK's ordered-channel model survives any strictly monotonic curve.
    base_rgb = xyz_from_lab(source_med) @ inverse.T
    goal_rgb = xyz_from_lab(target_med) @ inverse.T
    assert min(base_rgb.min(), goal_rgb.min()) >= -1e-5
    base_hsv, goal_hsv = rgb2hsv(base_rgb), rgb2hsv(goal_rgb)
    hue = ((goal_hsv[:, 0] - base_hsv[:, 0] + 0.5) % 1.0 - 0.5) * 360
    result["held_out_hue"] = {
        "median_abs_degrees": float(np.median(np.abs(hue[COLOR]))),
        "max_abs_degrees": float(np.max(np.abs(hue[COLOR]))),
        "count_abs_gt_2_degrees": int(np.count_nonzero(np.abs(hue[COLOR]) > 2)),
        "source_saturation_min": float(base_hsv[COLOR, 1].min()),
        "target_saturation_min": float(goal_hsv[COLOR, 1].min()),
    }
    # Robustness to component-wise Lab medians: each hue sample is formed from one pixel.
    # Compare central hue intervals in a common locally unwrapped coordinate.
    source_hue = rgb2hsv(source_linear)[..., 0]
    target_linear = xyz_from_lab(target[:, inset:200 - inset, inset:200 - inset]) @ inverse.T
    assert target_linear.min() > -1e-4 and target_linear.max() < 1.0001
    target_linear = np.clip(target_linear, 0, 1)
    target_hue = rgb2hsv(target_linear)[..., 0]
    hue_origin = base_hsv[:, 0, None, None]

    def hue_interval(values):
        angles = ((values - hue_origin + 0.5) % 1.0 - 0.5) * 360
        return np.quantile(angles, (0.25, 0.5, 0.75), axis=(1, 2))

    sh, th = hue_interval(source_hue), hue_interval(target_hue)
    actual_hue_gap = th[1] - sh[1]
    result["pixel_hue_diagnostic"] = {
        "median_of_absolute_patch_median_gaps_degrees": float(np.median(np.abs(actual_hue_gap[COLOR]))),
        "max_absolute_patch_median_gap_degrees": float(np.max(np.abs(actual_hue_gap[COLOR]))),
        "patch_median_hue_target_minus_source_degrees": actual_hue_gap[COLOR].tolist(),
        "patches_with_disjoint_inner_50pct_hue_intervals":
            (COLOR[(sh[2, COLOR] < th[0, COLOR]) | (th[2, COLOR] < sh[0, COLOR])] + 1).tolist(),
    }
    for model in ("linear", "pchip"):
        x, y, curve = xy_fit(source_med, target_med, NEUTRAL, model)
        fitted = render.medians(lab_from_xyz(rgb_tone(source_linear, curve) @ matrix.T))
        errors = render.delta(target_med, fitted)
        covered = np.all((base_rgb >= x[1]) & (base_rgb <= x[-2]), axis=1)
        neutral_cv = []
        for idx in NEUTRAL:
            fold = NEUTRAL[NEUTRAL != idx]
            _, _, fold_curve = xy_fit(source_med, target_med, fold, model)
            prediction = render.medians(lab_from_xyz(rgb_tone(source_linear[[idx]], fold_curve) @ matrix.T))
            neutral_cv.append(float(render.delta(target_med[[idx]], prediction)[0]))
        result[model] = {
            "neutral_xy": np.column_stack((x, y)).tolist(),
            "held_out_color": metric(target_med[COLOR], fitted[COLOR]),
            "fitted_neutral": metric(target_med[NEUTRAL], fitted[NEUTRAL]),
            "held_out_neutral_leave_one_out_delta_e00": neutral_cv,
            "held_out_inner_neutral_mean_delta_e00": float(np.mean(neutral_cv[1:-1])),
            "held_out_neutral_mean_delta_e00": float(np.mean(neutral_cv)),
            "color_patches_inside_neutral_range": (COLOR[covered[COLOR]] + 1).tolist(),
            "color_inside_neutral_range": metric(target_med[COLOR[covered[COLOR]]],
                                               fitted[COLOR[covered[COLOR]]]),
            "patches": [
                {"patch": i + 1, "target_lab": target_med[i].tolist(),
                 "source_lab": source_med[i].tolist(), "fitted_lab": fitted[i].tolist(),
                 "baseline_delta_e00": float(base_error[i]), "fitted_delta_e00": float(errors[i]),
                 "hue_target_minus_source_degrees": float(hue[i]),
                 "source_median_rgb_inside_neutral_range": bool(covered[i])}
                for i in range(24)
            ],
        }
    return result


def sources(exports, record, tone, look):
    tone_entries = tone["inputs"]["renders"]
    tone_profiles = tone["inputs"]["profiles"]
    result = {}
    for key, entry in zip(TONE_NAMES, ("omitted_original", "identity", "lift", "acr3"), strict=True):
        spec = tone_entries[entry]
        profile = tone_profiles[spec["profile"]]
        result[key] = (exports / spec["folder"] / render.EXPORT_NAME,
                       spec["sha256"], profile["name"], spec["profile_digest"])
    for key in ("identity", "sat80"):
        spec = look["renders"][key]
        result[f"look_{key}"] = (exports / f"look-{key}-prophoto" / render.EXPORT_NAME,
                                 spec["tiff_sha256"], spec["name"], spec["xmp_profile_digest"])
    for spec in record["gamut"]["renders"][:2]:
        result[spec["id"]] = (exports / (spec["id"] + "-prophoto") / render.EXPORT_NAME,
                               spec["sha256"], spec["profile"], spec["profile_digest"])
    profile_hashes = {
        key: tone_profiles[entry]["sha256"]
        for key, entry in zip(TONE_NAMES, ("omitted", "identity", "lift", "acr3"), strict=True)
    }
    profile_hashes.update({f"look_{key}": look["renders"][key]["dcp_sha256"] for key in ("identity", "sat80")})
    return result, profile_hashes


def report(args):
    record = load("lightroom-render-comparison")
    assert record == render.load_record()
    tone, look = load("lightroom-tone-comparison"), load("lightroom-look-controls")
    raw = args.samples / "pentax-k3ii-1376.dng"
    jpeg = args.samples / "pentax-k3ii-1376-preview.jpg"
    reference, patches, preview, camera_meta = render.check_inputs(raw, jpeg, args.exiftool, record)
    specs, dcp_hashes = sources(args.exports, record, tone, look)
    geometry = record["baseline"]["roi_geometry"]
    icc_sha = record["gamut"]["prophoto_icc_sha256"]
    result = {"schema_version": 1,
              "scope": "Rendered-domain experiment within one K-3 II #1376 scene. Fit patches 19–24; hold out color patches 1–18.",
              "raw_and_preview": reference, "camera_metadata": camera_meta,
              "recorded_dcp_sha256": dcp_hashes, "tiff_inputs": {}, "experiments": {},
              "versions": {"python": sys.version.split()[0], "numpy": np.__version__, "scipy": scipy.__version__,
                           "opencv": render.cv2.__version__, "scikit_image": render.skimage_version,
                           "tifffile": render.tifffile.__version__},
              "dng_sdk_reference": {
                  "source": "Adobe DNG SDK 1.7.1 Build 2768 dng_reference.cpp:1871–1906",
                  "archive_sha256": "c1d3a545ed45b150e59af2e6aa0695c1551f0e2bed34ad87436898a05194d2b1",
                  "source_sha256": "912afda9ed871fe50ff0037a1be3361d37c1b8ee1230b907eed36d7512c422b6",
              },
              "public_record_lf_sha256": SOURCE_HASHES_LF,
              "model": "Fit a monotone Y-to-Y map with identity endpoints from six neutral medians. For each linear ProPhoto pixel apply the map to min/max channels and interpolate the middle channel by its original rank fraction. Compute D50 Lab medians after mapping. Use source/target rendered XYZ from ICC, not RAW-domain values."}
    alignment = record["baseline"]["registration"]
    sites = np.rint(render.mapped([
        item["preview_xy"] for item in alignment["corner_matches"] + alignment["held_out"]
    ], np.array(alignment["preview_to_tiff_homography"]))).astype(int)
    frames = {}
    with TemporaryDirectory(dir=args.scratch, prefix="tone-residual-") as tmp:
        temp = Path(tmp)
        roi = render.stack(preview, geometry, "preview_xyxy")
        frames["native_jpeg"], banner = render.lab_stack(roi, None, temp, "jpeg", args.tificc)
        result["lab_engine"] = banner
        result["jpeg_roi_endpoints"] = render.endpoint_counts(roi)
        srgb_path = args.exports / "matrix-test" / render.EXPORT_NAME
        srgb_spec = record["baseline"]["renders"][2]
        assert srgb_spec["id"] == "matrix-test"
        assert render.digest(srgb_path) == srgb_spec["sha256"]
        with render.tifffile.TiffFile(srgb_path) as tif:
            srgb = tif.pages[0].tags[34675].value
        assert render.sha256(srgb).hexdigest() == srgb_spec["icc_sha256"]
        frames["native_jpeg_alt_icc"], _ = render.lab_stack(roi, srgb, temp, "jpeg-alternate", args.tificc)
        result["jpeg_alternate_icc"] = {"source_srgb_tiff_sha256": srgb_spec["sha256"],
                                       "icc_sha256": srgb_spec["icc_sha256"]}
        for key, (path, pin, profile, profile_digest) in specs.items():
            rgb, icc, attrs, nested, _, _ = render.read_export(path, pin, icc_sha)
            assert attrs["CameraProfile"] == profile and attrs["CameraProfileDigest"] == profile_digest
            assert len(attrs) == 114 and len(nested) == 6
            assert [attrs[k] for k in ("ProcessVersion", "WhiteBalance", "Exposure2012", "HasCrop")] == [
                "15.4", "As Shot", "0.00", "False"]
            grad = render.gradient(rgb)
            if key == "matrix":
                matrix = xyz_columns(icc)
                inverse = np.linalg.inv(matrix)
                base_attrs, base_nested, base_gradient = attrs, nested, grad
                check_transform, check_registration, _ = render.register(render.gradient(preview), grad, patches)
                check_boxes = render.box_pairs(patches, check_transform)
                assert max(np.linalg.norm(np.array(a["tiff_xyxy"][:2]) - b["tiff_xyxy"][:2])
                           for a, b in zip(geometry, check_boxes, strict=True)) <= 4.0
                result["preview_to_matrix_max_held_out_residual_px"] = check_registration["max_held_out_residual_px"]
            distances = [render.locate(base_gradient, grad, tuple(site), 8) for site in sites]
            shift = max(np.linalg.norm(move) for move, _ in distances)
            corr = min(value for _, value in distances)
            assert shift < 1 and corr > 0.8, (key, shift, corr)
            roi = render.stack(rgb, geometry, "tiff_xyxy")
            frames[key], local_banner = render.lab_stack(roi, icc, temp, key, args.tificc)
            assert local_banner == banner
            changes = sorted(k for k in attrs.keys() | base_attrs.keys() if attrs.get(k) != base_attrs.get(k))
            expected_changes = set() if key == "matrix" else {"CameraProfile", "CameraProfileDigest"}
            expected_wb = ("5200", "+2")
            if key in ("adobe-standard", "camera-natural"):
                expected_changes.update(("Temperature", "Tint"))
                expected_wb = ("5300", "-2")
            assert set(changes) == expected_changes and nested == base_nested, (key, changes)
            assert (attrs["Temperature"], attrs["Tint"]) == expected_wb, key
            result["tiff_inputs"][key] = {
                "sha256": pin, "profile": profile, "icc_sha256": icc_sha,
                "xmp_profile_digest": profile_digest, "temperature": attrs["Temperature"], "tint": attrs["Tint"],
                "develop_differences_vs_matrix": changes,
                "nested_develop_equals_matrix": nested == base_nested,
                "roi_endpoints": render.endpoint_counts(roi),
                "max_shift_px": float(shift), "min_gradient_correlation": corr,
            }
            del rgb
    pairs = (
        ("matrix", "native_jpeg"),
        ("matrix", "native_jpeg_alt_icc"),
        ("tone_identity", "native_jpeg"),
        ("tone_lift", "native_jpeg"),
        ("tone_acr3", "native_jpeg"),
        ("camera-natural", "native_jpeg"),
        ("adobe-standard", "native_jpeg"),
        ("tone_identity", "tone_lift"),
        ("look_identity", "look_sat80"),
        ("matrix", "tone_acr3"),
    )
    for src, dst in pairs:
        result["experiments"][f"{src}_to_{dst}"] = {
            f"{200-2*inset}px": estimate(frames[src], frames[dst], matrix, inverse, inset)
            for inset in (0, 50)
        }
    matrix_native_srgb = record["gamut"]["renders"][2]
    clipped = {p["patch"] for p in matrix_native_srgb["patches"]
               if any(p["endpoint_masks"][key]["actual"][i]
                      for key in ("zero_native_vs_icc", "max_native_vs_icc") for i in range(3))}
    result["matrix_jpeg_srgb_clip_sensitivity"] = {"excluded_patches": sorted(clipped)}
    for size, experiment in result["experiments"]["matrix_to_native_jpeg"].items():
        result["matrix_jpeg_srgb_clip_sensitivity"][size] = {
            mode: {
                "mean_delta_e00": float(np.mean([p["fitted_delta_e00"] for p in experiment[mode]["patches"][:18]
                                                 if p["patch"] not in clipped])),
                "median_abs_hue_degrees": float(np.median([abs(p["hue_target_minus_source_degrees"])
                                                          for p in experiment[mode]["patches"][:18]
                                                          if p["patch"] not in clipped])),
            }
            for mode in ("linear", "pchip")
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=Path, required=True, help="directory containing the #1376 DNG and extracted preview")
    parser.add_argument("--exports", type=Path, required=True, help="directory containing the nine TIFF fixture subfolders")
    parser.add_argument("--scratch", type=Path, required=True, help="existing directory for temporary conversions")
    parser.add_argument("--exiftool", default="exiftool")
    parser.add_argument("--tificc", default="tificc")
    parser.add_argument("--output", type=Path, required=True, help="new JSON output path")
    args = parser.parse_args()
    render.output_and_scratch(parser, args)
    try:
        result = report(args)
        render.write_report(args.output, result)
    except (AssertionError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Color tone residual check failed: {exc or 'fixture/transform validation failed'}\n")


if __name__ == "__main__":
    main()
