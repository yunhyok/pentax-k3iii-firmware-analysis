"""Apply the frozen #1376 rendered-domain tone curve to the held-out #1363 scene."""
# SPDX-License-Identifier: GPL-2.0-only

if not __debug__:
    raise RuntimeError("Run without -O to retain the fixture checks")

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

import cv2
import numpy as np
from PIL import Image
from scipy.interpolate import PchipInterpolator
import tifffile

sys.dont_write_bytecode = True
import check_color_engine_bridge as engine
import check_lightroom_render as render
from check_lightroom_gamut import xyz_columns
from check_color_tone_residual import lab_from_xyz, rgb_tone, xyz_from_lab

PLAN_SHA = "c7ffca0212d486b794eb5ce9713d83f3dda153ac9ecf21eca4e91d1697a3b324"
SCENE_SHA = "81c61590abdd8331e4ff5b245a19e888a1c0fa028b75c483d83c516be2165498"
PROFILE_FIELDS = {"CameraProfile", "CameraProfileDigest", "Temperature", "Tint"}
EXPORT_NAME = "pentax-k3ii-1363.tif"


def read_plan():
    raw = (render.ROOT / "analysis/color-scene-plan.json").read_bytes().replace(b"\r\n", b"\n")
    assert render.sha256(raw).hexdigest() == PLAN_SHA, "fixed plan SHA mismatch"
    plan = json.loads(raw)
    chart = (render.ROOT / "analysis/color-tone-residual.json").read_bytes().replace(b"\r\n", b"\n")
    assert render.sha256(chart).hexdigest() == plan["curve"]["chart_report_sha256_lf"]
    value = json.loads(chart)
    for key in plan["curve"]["source_json_pointer"].strip("/").split("/"):
        value = value[key]
    assert value == plan["curve"]["xy"], "frozen chart knots mismatch"
    return plan


def read_preview(args, spec):
    assert render.digest(args.raw) == spec["raw_sha256"], "RAW SHA-256 mismatch"
    assert render.digest(args.preview) == spec["preview_sha256"], "JPEG SHA-256 mismatch"
    full = subprocess.run([args.exiftool, "-b", "-SubIFD1:PreviewImage", str(args.raw)],
                          check=True, capture_output=True).stdout
    assert render.sha256(full).hexdigest() == spec["preview_sha256"]
    with Image.open(args.preview) as image:
        assert image.mode == "RGB" and not image.info.get("icc_profile")
        pixels = np.asarray(image)
    assert list(pixels.shape) == spec["shape_yxc"]
    return pixels


def read_crs(xmp):
    attrs, nested = {}, {}
    for element in render.ET.fromstring(xmp).iter():
        for key, value in element.attrib.items():
            if key.startswith(render.CRS):
                name = key.removeprefix(render.CRS)
                assert name not in attrs, f"duplicate XMP setting {name}"
                attrs[name] = value
        if element.tag.startswith(render.CRS):
            name = element.tag.removeprefix(render.CRS)
            assert name not in nested, f"duplicate nested XMP setting {name}"
            nested[name] = render.ET.tostring(element, encoding="unicode")
    return {"crs_attributes": attrs, "crs_nested": nested}


def read_export(path, shape, profile, filename, expected_sha):
    with path.open("rb") as stream:
        sha = render.file_digest(stream, "sha256").hexdigest()
        assert expected_sha is None or sha == expected_sha, f"{path}: TIFF SHA-256 mismatch"
        size = stream.tell()
        stream.seek(0)
        with tifffile.TiffFile(stream) as tif:
            assert len(tif.pages) == 1
            page = tif.pages[0]
            assert list(page.shape) == shape and page.dtype == np.dtype("uint16")
            assert page.bitspersample == 16 and page.samplesperpixel == 3 and not page.extrasamples
            assert (int(page.photometric), int(page.planarconfig),
                    int(page.sampleformat), int(page.compression)) == (2, 1, 1, 1)
            orientation = page.tags.get(274)
            assert orientation is None or orientation.value == 1
            icc = bytes(page.tags[34675].value)
            assert render.sha256(icc).hexdigest() == profile["icc_sha256"], "wrong ProPhoto ICC"
            xmp = bytes(page.tags[700].value)
            fields = read_crs(xmp)
            attrs = fields["crs_attributes"]
            assert attrs["RawFileName"] == filename, "wrong source RAW name"
            assert attrs["CameraProfile"] == profile["profile"], "wrong camera profile"
            assert attrs["CameraProfileDigest"] == profile["xmp_profile_digest"], "wrong profile digest"
            assert attrs["Version"] == "19.0" and attrs["ProcessVersion"] == "15.4"
            assert attrs["WhiteBalance"] == "As Shot" and float(attrs["Exposure2012"]) == 0
            assert attrs["HasCrop"] == "False" and attrs["AlreadyApplied"] == "True"
            assert attrs["LensProfileEnable"] == attrs["AutoLateralCA"] == attrs["HDREditMode"] == "0"
            software = page.tags[305].value
            assert "Lightroom Classic 16.0" in software
            pixels = page.asarray()
        stream.seek(0)
        assert render.file_digest(stream, "sha256").hexdigest() == sha, "TIFF changed while reading"
    rgb = memoryview(np.ascontiguousarray(pixels, dtype="<u2")).cast("B")
    record = {"file_sha256": sha, "file_bytes": size, "pixel_sha256_le_uint16_rgb": render.sha256(rgb).hexdigest(),
              "software": software, "shape_yxc": shape, "storage": "unsigned uint16 RGB TIFF, uncompressed",
              "icc_sha256": profile["icc_sha256"], "xmp_sha256": render.sha256(xmp).hexdigest(),
              **fields}
    return pixels, icc, record


def require_same_controls(reference, other, allowed):
    first, second = (record["crs_attributes"] for record in (reference, other))
    differences = {key: [first.get(key), second.get(key)] for key in sorted(first.keys() | second.keys())
                   if first.get(key) != second.get(key)}
    assert differences.keys() <= allowed, f"unexpected develop differences: {differences}"
    assert reference["crs_nested"] == other["crs_nested"], "nested develop settings differ"
    return differences


def gradient(rgb):
    green = np.ascontiguousarray(rgb[:, :, 1], dtype=np.float32)
    if rgb.dtype == np.uint16:
        green /= 257.0
    blurred = cv2.GaussianBlur(green, (7, 7), 1.4)
    return cv2.magnitude(cv2.Sobel(blurred, cv2.CV_32F, 1, 0),
                         cv2.Sobel(blurred, cv2.CV_32F, 0, 1))


def match_sites(first, second, spec):
    w, r = spec["template_half_px"], spec["search_radius_px"]
    rows = []
    for iy, y in enumerate(spec["y"]):
        for ix, x in enumerate(spec["x"]):
            template = first[y-w:y+w, x-w:x+w]
            texture = float(template.std())
            row = {"xy": [x, y], "fit": (ix + iy) % 2 == 0, "texture": texture}
            rows.append(row)
            if texture < spec["minimum_template_standard_deviation_8bit_scale"]:
                row["excluded"] = "low texture"
                continue
            search = second[y-w-r:y+w+r, x-w-r:x+w+r]
            corr = cv2.matchTemplate(search, template, cv2.TM_CCOEFF_NORMED)
            _, peak, _, (dx, dy) = cv2.minMaxLoc(corr)
            row["correlation"] = peak
            if not (0 < dx < 2*r and 0 < dy < 2*r) or peak < spec["minimum_correlation"]:
                row["excluded"] = "low correlation or search edge"
                continue

            def subpixel(left, right):
                curvature = float(left + right - 2 * peak)
                return float(0.5 * (left - right) / curvature) if curvature < 0 else 0.0

            row["shift_xy"] = [dx - r + subpixel(corr[dy, dx-1], corr[dy, dx+1]),
                               dy - r + subpixel(corr[dy-1, dx], corr[dy+1, dx])]
    return rows


def fit_affine(rows, spec):
    valid = [row for row in rows if "shift_xy" in row]
    counts = [sum(row["fit"] == flag for row in valid) for flag in (True, False)]
    assert counts[0] >= spec["minimum_fit_sites"] and counts[1] >= spec["minimum_held_out_sites"], rows
    points = np.array([row["xy"] + [1] for row in valid])
    shifts = np.array([row["shift_xy"] for row in valid])
    fit = np.array([row["fit"] for row in valid])
    coeff, _, rank, _ = np.linalg.lstsq(points[fit], shifts[fit], rcond=None)
    assert rank == 3, "affine registration rank"
    residual = np.linalg.norm(points @ coeff - shifts, axis=1)
    for row, error in zip(valid, residual, strict=True):
        row["residual_px"] = float(error)
    assert residual[fit].max() <= spec["max_fit_residual_px"], rows
    assert residual[~fit].max() <= spec["max_held_out_residual_px"], rows
    return coeff + np.array([[1, 0], [0, 1], [0, 0]])


def roi_samples(rgb, centers, size, affine=None):
    frames = []
    for x, y in centers:
        grid_x, grid_y = np.meshgrid(np.arange(x-size//2, x+size//2, dtype=np.float32),
                                     np.arange(y-size//2, y+size//2, dtype=np.float32))
        if affine is not None:
            mx = grid_x * affine[0, 0] + grid_y * affine[1, 0] + affine[2, 0]
            my = grid_x * affine[0, 1] + grid_y * affine[1, 1] + affine[2, 1]
            assert 0 <= mx.min() and mx.max() < rgb.shape[1] - 1
            assert 0 <= my.min() and my.max() < rgb.shape[0] - 1
            frames.append(cv2.remap(rgb, mx.astype("float32"), my.astype("float32"), cv2.INTER_LINEAR))
        else:
            frames.append(rgb[y-size//2:y+size//2, x-size//2:x+size//2])
    return np.stack(frames)


def compare_regions(reference, methods, mask, minimum):
    selected = [i for i, keep in enumerate(mask) if np.count_nonzero(keep) >= minimum]
    assert selected, "no region meets the predeclared minimum"
    output = {}
    for name, sample in methods.items():
        delta = render.delta(reference, sample)
        diff = sample - reference
        rows = []
        for index in selected:
            keep = mask[index]
            values = delta[index][keep]
            difference = diff[index][keep]
            rows.append({"region_index": index, "samples": int(values.size), "median_delta_e00": float(np.median(values)),
                         "p90_delta_e00": float(np.quantile(values, 0.9)),
                         "mean_abs_delta_lstar": float(np.abs(difference[:, 0]).mean()),
                         "mean_ab_distance": float(np.linalg.norm(difference[:, 1:], axis=1).mean())})
        pool = np.concatenate([delta[i][mask[i]] for i in selected])
        output[name] = {"regions": rows, "pixels": int(pool.size),
                        "equal_region_mean": {key: float(np.mean([row[key] for row in rows]))
                                              for key in ("median_delta_e00", "p90_delta_e00",
                                                          "mean_abs_delta_lstar", "mean_ab_distance")},
                        "pooled_median_delta_e00": float(np.median(pool)),
                        "pooled_p90_delta_e00": float(np.quantile(pool, 0.9))}
    raw, adjusted = (output[key]["regions"] for key in ("matrix1376", "matrix1376_fixed_chart_tone"))
    changes = np.array([a["median_delta_e00"] - b["median_delta_e00"] for a, b in zip(adjusted, raw, strict=True)])
    return {"included_regions": selected, "methods": output, "fixed_tone_minus_matrix_region_median_delta_e00": changes.tolist(),
            "improved_regions": int((changes < 0).sum()), "worsened_regions": int((changes > 0).sum())}


def check(args, plan):
    spec = plan["fixture"]
    preview = read_preview(args, spec)
    g_preview = gradient(preview)
    p = plan["profiles"]
    bridge_pin = None if args.allow_fresh_export else plan["engine_bridge_16_tiff_sha256"]
    bridge_rgb, _, bridge_xmp, _, _, bridge_summary = engine.read_tiff(args.bridge, bridge_pin)
    del bridge_rgb
    engine.require_export(bridge_summary, engine.load_record()["new_tiff"])
    engine.require_develop(bridge_xmp, "16.0")
    bridge = read_crs(bridge_xmp)
    baseline = (render.ROOT / "analysis/color-scene-transfer.json").read_bytes().replace(b"\r\n", b"\n")
    assert render.sha256(baseline).hexdigest() == SCENE_SHA, "Published scene result SHA-256 mismatch"
    baseline_exports = json.loads(baseline)["exports"]
    reg = plan["registration"]
    region = plan["evaluation"]
    centers = [(x, y) for y in region["y"] for x in region["x"]]
    size = region["roi_size_px"]
    rois, inputs, comparisons, alignment = {}, {}, {}, {}
    for name, profile in p.items():
        path = args.exports / name / EXPORT_NAME
        expected = baseline_exports[name]
        expected_sha = None if args.allow_fresh_export else expected["file_sha256"]
        pixels, icc, record = read_export(path, spec["shape_yxc"], profile, spec["raw_filename"], expected_sha)
        if args.allow_fresh_export:
            require_same_controls(expected, record, set())
        inputs[name] = record
        comparisons[name] = require_same_controls(bridge, record, PROFILE_FIELDS | {"RawFileName"})
        grad = gradient(pixels)
        if name == "matrix1376":
            g_matrix = grad
            rows = match_sites(g_preview, g_matrix, reg)
            affine = fit_affine(rows, reg)
            alignment[name] = {"affine_xy1_to_xy": affine.tolist(), "sites": rows}
            prophoto = icc
        else:
            require_same_controls(inputs["matrix1376"], record, PROFILE_FIELDS)
            rows = match_sites(g_matrix, grad, reg)
            valid = [row for row in rows if "shift_xy" in row]
            assert len(valid) >= reg["tiff_to_matrix_min_sites"], rows
            assert max(np.linalg.norm(row["shift_xy"]) for row in valid) <= reg["tiff_to_matrix_max_shift_px"], rows
            alignment[name] = {"tiff_to_matrix_registration_sites": rows}
        rois[name] = roi_samples(pixels, centers, size, affine)
    assert render.digest(args.raw) == spec["raw_sha256"], "RAW changed during analysis"
    assert render.digest(args.preview) == spec["preview_sha256"], "JPEG changed during analysis"
    result = {"plan_sha256": PLAN_SHA, "scope": plan["scope"], "scene": spec, "exports": inputs,
              "develop_differences_vs_16_bridge": comparisons, "alignment": alignment, "roi_centers_xy": centers}
    if args.allow_fresh_export:
        result["fresh_export_validation"] = {"historical_file_sha_required": False,
            "bridge_tiff_sha256": bridge_summary["file_sha256"],
            "bridge_pixels_icc_and_develop_settings_pinned": True,
            "scene_develop_settings_pinned": True}
    if args.registration_only:
        return result
    jpeg = roi_samples(preview, centers, size)
    jpeg_gradient = roi_samples(g_preview, centers, size)
    with TemporaryDirectory(dir=args.scratch, prefix="scene-lab-") as tmp:
        tmp = Path(tmp)
        reference, banner = render.lab_stack(jpeg, None, tmp, "native-jpeg", args.tificc)
        labs = {name: render.lab_stack(rgb, prophoto, tmp, name, args.tificc)[0] for name, rgb in rois.items()}
    columns = xyz_columns(prophoto)
    linear = xyz_from_lab(labs["matrix1376"]) @ np.linalg.inv(columns).T
    assert linear.min() > -1e-4 and linear.max() < 1.0001
    linear = np.clip(linear, 0, 1)
    knots = np.array(plan["curve"]["xy"])
    curve = PchipInterpolator(*knots.T, extrapolate=False)
    labs["matrix1376_fixed_chart_tone"] = lab_from_xyz(rgb_tone(linear, curve) @ columns.T)
    masks = region["mask_sensitivity"]
    jlo, jhi = masks["jpeg_all_codes_open_interval"]
    tlo, thi = masks["prophoto_all_codes_open_interval"]
    clean = (jpeg_gradient <= masks["jpeg_green_sobel_max_8bit_scale"]) & np.all((jpeg > jlo) & (jpeg < jhi), axis=-1)
    for rgb in rois.values():
        clean &= np.all((rgb > tlo) & (rgb < thi), axis=-1)
    covered = np.all((linear >= knots[1, 0]) & (linear <= knots[-2, 0]), axis=-1)
    minimum = region["minimum_samples_for_subset_region"]
    result["lab_engine"] = banner
    result["metrics"] = {
        "all": compare_regions(reference, labs, np.ones_like(clean), minimum),
        "low_gradient_nonendpoint": compare_regions(reference, labs, clean, minimum),
        "low_gradient_nonendpoint_inner_knot_range": compare_regions(reference, labs, clean & covered, minimum),
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("raw", "preview", "exports", "bridge", "exiftool", "output", "scratch"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--tificc", type=Path)
    parser.add_argument("--registration-only", action="store_true")
    parser.add_argument("--allow-fresh-export", action="store_true",
                        help="relax TIFF file SHA pins; require recorded chart pixels and all develop settings")
    args = parser.parse_args()
    render.output_and_scratch(parser, args)
    if not args.registration_only and not args.tificc:
        parser.error("--tificc is required for color metrics")
    try:
        render.write_report(args.output, check(args, read_plan()))
    except (AssertionError, OSError, ValueError, render.ET.ParseError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Scene transfer failed: {error or 'fixture validation failed'}\n")


if __name__ == "__main__":
    main()
