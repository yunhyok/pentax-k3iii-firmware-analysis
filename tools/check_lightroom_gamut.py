"""Probe #1376 output-gamut clipping without fitting any profile."""
if not __debug__:
    raise RuntimeError("Run without -O so the input and transform checks remain enabled.")

import argparse
import sys

sys.dont_write_bytecode = True
import json
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory

import numpy as np
import tifffile

import check_lightroom_render as baseline

PROPHOTO_SHA = "0a8ef7d1d958d98225b3b71d93d9e8e3cecd9c302e014973d025d2a977ecf27c"


def xyz_columns(profile):
    assert profile[16:24] == b"RGB XYZ "
    count, = struct.unpack_from(">I", profile, 128)
    rows = [struct.unpack_from(">4sII", profile, 132 + index * 12) for index in range(count)]
    assert all(offset + size <= len(profile) for _, offset, size in rows)
    tags = {name: profile[offset:offset + size] for name, offset, size in rows}
    assert not any(k.startswith((b"A2B", b"B2A")) for k in tags)
    columns = []
    for k in (b"rXYZ", b"gXYZ", b"bXYZ"):
        value = tags[k]
        assert value[:4] == b"XYZ "
        columns.append(np.array(struct.unpack_from(">iii", value, 8)) / 65536.0)
    return np.column_stack(columns)


def unclamped_linear_srgb(lab, srgb):
    # LittleCMS CIELAB uses ICC PCS D50 (0.9642, 1, 0.8249).
    # Invert the exact output profile's colorant matrix before applying TRCs.
    l, a, b = np.moveaxis(lab.astype(np.float64), -1, 0)
    fy = (l + 16) / 116
    f = np.stack((fy + a / 500, fy, fy - b / 200), axis=-1)
    step = 6 / 29
    xyz = np.where(f > step, f ** 3, 3 * step ** 2 * (f - 4 / 29))
    xyz *= np.array([0.9642, 1.0, 0.8249])
    return xyz @ np.linalg.inv(xyz_columns(srgb)).T


def srgb_predict(pixels, prophoto, srgb, temp, label, tificc, precalc=0):
    src = temp / f"{label}-prophoto-rgb.tif"
    dst = temp / f"{label}-predicted-srgb-rgb.tif"
    icc = temp / f"{label}-srgb.icc"
    icc.write_bytes(srgb)
    count, height, width, channels = pixels.shape
    tifffile.imwrite(src, pixels.reshape(count * height, width, channels), photometric="rgb", metadata=None,
                     extratags=[(34675, 7, len(prophoto), prophoto, False)])
    run = subprocess.run([tificc, "-t1", f"-c{precalc}", "-w16", "-e", f"-o{icc}", str(src), str(dst)],
                         capture_output=True, text=True, check=True)
    with tifffile.TiffFile(dst) as tif:
        page = tif.pages[0]
        assert page.dtype == np.uint16 and page.bitspersample == 16
        assert page.tags[34675].value == srgb
        predicted = page.asarray().reshape(pixels.shape)
    return predicted, run.stderr.splitlines()[0]


def classify(actual, predicted, axis=(0, 1, 2)):
    return {"actual": actual.sum(axis=axis).tolist(), "predicted": predicted.sum(axis=axis).tolist(),
            "intersection": np.logical_and(actual, predicted).sum(axis=axis).tolist(),
            "predicted_only": np.logical_and(predicted, ~actual).sum(axis=axis).tolist(),
            "actual_only": np.logical_and(actual, ~predicted).sum(axis=axis).tolist()}


def masks(actual, predicted, linear, axis=(0, 1, 2)):
    return {
        "zero_native_vs_icc": classify(actual == 0, predicted == 0, axis),
        "max_native_vs_icc": classify(actual == 65535, predicted == 65535, axis),
        "zero_native_vs_negative_linear": classify(actual == 0, linear < 0, axis),
        "max_native_vs_over_one_linear": classify(actual == 65535, linear > 1, axis),
    }


def residuals(native, predicted):
    difference = np.abs(native.astype(np.int32) - predicted)
    quantiles = np.quantile(difference, [0.50, 0.90, 0.99], axis=(0, 1, 2))
    return {"mean_abs_codes_rgb": np.mean(difference, axis=(0, 1, 2)).tolist(),
            "median_abs_codes_rgb": quantiles[0].tolist(), "p90_abs_codes_rgb": quantiles[1].tolist(),
            "p99_abs_codes_rgb": quantiles[2].tolist(), "max_abs_codes_rgb": np.max(difference, axis=(0, 1, 2)).tolist()}


def run(record, args):
    base = record["baseline"]
    baseline.check_exports(args.exports, base["renders"])
    baseline.check_exports(args.exports, record["gamut"]["renders"], "-prophoto")
    boxes = base["roi_geometry"]
    registration = base["registration"]
    targets = [tuple(row) for row in np.rint(baseline.mapped([
        item["preview_xy"] for item in registration["corner_matches"] + registration["held_out"]
    ], np.array(registration["preview_to_tiff_homography"]))).astype(int)]
    base_lookup = {entry["id"]: entry for entry in base["renders"]}
    report = {"baseline_sha256": baseline.PUBLIC_BASELINE_SHA, "scope": "Matched same-profile TIFF export-space diagnostic on #1376",
              "geometry": "Same 24 native 200x200 ROIs; local structural registration over 19 sites per export pair.",
              "prophoto_icc_sha256": PROPHOTO_SHA, "srgb_icc_sha256": baseline.ICC_SHA,
              "method": "ProPhoto native to float32 Lab D50 and to RGB16 using exact embedded sRGB destination ICC. LittleCMS relative intent, BPC off, precomputation disabled (-c0) for main RGB16 prediction. Also records -c1 endpoint sensitivity. Independent signed linear sRGB estimate inverts the sRGB ICC D50 colorant matrix before TRCs. Differences can include CMM/quantization as well as export processing.",
              "renders": []}
    with TemporaryDirectory(dir=args.scratch, prefix="gamut-") as tmp:
        temp = Path(tmp)
        for entry in record["gamut"]["renders"]:
            identifier = entry["id"]
            original = base_lookup[identifier]
            srgb_path = args.exports / identifier / baseline.EXPORT_NAME
            wide_path = args.exports / (identifier + "-prophoto") / baseline.EXPORT_NAME
            s_rgb, s_icc, s_attrs, s_nested, _, _ = baseline.read_export(srgb_path, original["sha256"], baseline.ICC_SHA)
            p_rgb, p_icc, p_attrs, p_nested, _, _ = baseline.read_export(wide_path, entry["sha256"], PROPHOTO_SHA)
            differences = sorted(k for k in s_attrs.keys() | p_attrs.keys() if s_attrs.get(k) != p_attrs.get(k))
            nested_differences = sorted(k for k in s_nested.keys() | p_nested.keys() if s_nested.get(k) != p_nested.get(k))
            assert not differences and not nested_differences
            p_gray, s_gray = baseline.gradient(p_rgb), baseline.gradient(s_rgb)
            registered = [baseline.locate(s_gray, p_gray, center, 8) for center in targets]
            max_shift = max(float(np.linalg.norm(value)) for value, _ in registered)
            assert max_shift < 1.0 and min(score for _, score in registered) > 0.8
            p_stack = baseline.stack(p_rgb, boxes, "tiff_xyxy")
            actual = baseline.stack(s_rgb, boxes, "tiff_xyxy")
            del s_rgb, p_rgb, p_gray, s_gray
            native_lab, _ = baseline.lab_stack(p_stack, p_icc, temp, identifier + "-native", args.tificc)
            actual_lab, _ = baseline.lab_stack(actual, s_icc, temp, identifier + "-actual-srgb", args.tificc)
            predicted, banner = srgb_predict(p_stack, p_icc, s_icc, temp, identifier, args.tificc)
            normal, _ = srgb_predict(p_stack, p_icc, s_icc, temp, identifier + "-optimized", args.tificc, precalc=1)
            predicted_lab, _ = baseline.lab_stack(predicted, s_icc, temp, identifier + "-predicted-srgb", args.tificc)
            report["tificc_banner"] = banner
            if "prophoto_precision_witness" not in report:
                synthetic = np.array([[[[32768] * 3, [32769] * 3]]], dtype=np.uint16)
                precision, _ = baseline.lab_stack(synthetic, p_icc, temp, "prophoto-precision", args.tificc)
                step = float(precision[0, 0, 1, 0] - precision[0, 0, 0, 0])
                assert step > 0
                report["prophoto_precision_witness"] = {"adjacent_input_codes": [32768, 32769], "delta_lstar": step}
            linear = unclamped_linear_srgb(native_lab, s_icc)
            p_med = baseline.medians(native_lab)
            s_med = baseline.medians(actual_lab)
            predicted_med = baseline.medians(predicted_lab)
            reference = np.array([patch["preview_median_lab_d50"] for patch in original["patches"]])
            actual_patches = np.array([patch["tiff_median_lab_d50"] for patch in original["patches"]])
            assert np.array_equal(s_med, actual_patches)
            wide_to_native = baseline.delta(p_med, s_med)
            predicted_to_native = baseline.delta(predicted_med, s_med)
            wide_to_preview = baseline.delta(reference, p_med)
            report["renders"].append({
                "id": identifier, "sha256": entry["sha256"], "srgb_tiff_sha256": original["sha256"], "profile": original["profile"],
                "profile_digest": original["profile_digest"],
                "common_develop_attributes": len(s_attrs), "develop_difference_keys": differences,
                "nested_develop_difference_keys": nested_differences,
                "max_prophoto_to_native_srgb_shift_px": max_shift,
                "min_prophoto_to_native_srgb_gradient_correlation": min(score for _, score in registered),
                "prophoto_native_endpoints": baseline.endpoint_counts(p_stack),
                "endpoint_masks": masks(actual, predicted, linear),
                "default_c1_endpoints_only": {
                    "zero_native_vs_icc": classify(actual == 0, normal == 0),
                    "max_native_vs_icc": classify(actual == 65535, normal == 65535),
                },
                "icc_reconversion_rgb16_code_residuals": residuals(actual, predicted),
                "direct_prophoto_vs_preview_delta_e00": baseline.summarize(wide_to_preview),
                "direct_prophoto_vs_native_srgb_delta_e00": baseline.summarize(wide_to_native),
                "predicted_srgb_vs_native_srgb_delta_e00": baseline.summarize(predicted_to_native),
                "patches": [
                    {"patch": box["patch"], "name": box["name"], "signed_linear_srgb_min": np.min(l, axis=(0, 1)).tolist(),
                     "signed_linear_srgb_max": np.max(l, axis=(0, 1)).tolist(),
                     "prophoto_native_endpoints": baseline.endpoint_counts(px[None]),
                     "endpoint_masks": masks(a, p, l, (0, 1)),
                     "delta_e00_prophoto_vs_preview": float(ref),
                     "delta_e00_prophoto_vs_native_srgb": float(wide),
                     "delta_e00_predicted_vs_native_srgb": float(pred)}
                    for box, l, a, p, px, ref, wide, pred in zip(boxes, linear, actual, predicted, p_stack,
                        wide_to_preview, wide_to_native, predicted_to_native, strict=True)
                ],
            })
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True, help="existing private directory for temporary conversion files")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tificc", default="tificc")
    args = parser.parse_args()
    baseline.output_and_scratch(parser, args)
    try:
        report = run(baseline.load_record(), args)
        baseline.write_report(args.output, report)
    except (AssertionError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Gamut check failed: {exc or 'fixture/transform validation failed'}\n")
    for item in report["renders"]:
        print(item["id"], item["predicted_srgb_vs_native_srgb_delta_e00"])


if __name__ == "__main__":
    main()
