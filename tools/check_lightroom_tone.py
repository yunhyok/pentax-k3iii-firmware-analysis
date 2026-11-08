"""Reproduce the five hash-pinned K-3 II #1376 Lightroom tone exports."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

if not __debug__:
    raise RuntimeError("Run without -O so the fixture checks remain enabled.")
sys.dont_write_bytecode = True

import check_lightroom_render as color
import numpy as np
import tifffile

sys.path.insert(0, str(color.ROOT))
from inspect_adobe_profiles import describe

FIXTURE = color.ROOT / "analysis/lightroom-tone-comparison.json"
FIXTURE_SHA256 = "f6e07ea1d91ed301acd757e5c1f64d7de952912e907727ee21c74fab1bab5e38"
ORDER = ("omitted_original", "identity", "lift", "omitted_repeat", "acr3")
PAIRS = (
    ("omitted_original", "identity"), ("identity", "lift"), ("omitted_original", "lift"),
    ("omitted_original", "omitted_repeat"), ("omitted_repeat", "acr3"),
)
PROFILE_KEYS = {"CameraProfile", "CameraProfileDigest"}
REQUIRED = {
    "WhiteBalance": "As Shot", "Temperature": "5200", "Tint": "+2", "Exposure2012": "0.00",
    "ProcessVersion": "15.4", "HasCrop": "False", "HDREditMode": "0",
}


def canonical_sha256(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return sha256(data.encode("utf-8")).hexdigest()


def check_profiles(fixtures, directory):
    """Compare exact file and IFD payload digests with the observed profile set."""
    common = {"UniqueCameraModel", "ColorMatrix1", "ColorMatrix2",
              "CalibrationIlluminant1", "CalibrationIlluminant2"}
    observed = {}
    for key in ("omitted", "identity", "lift", "acr3"):
        fixture = fixtures[key]
        source = directory / fixture["file"]
        assert source.stat().st_size == fixture["bytes"], f"{key}: DCP length mismatch"
        data = source.read_bytes()
        assert sha256(data).hexdigest() == fixture["sha256"], f"{key}: DCP SHA-256 mismatch"
        profile = describe(data)
        tags = profile["tags"]
        curve = fixture["curve"]
        assert set(tags) == common | ({"ProfileName", "ProfileToneCurve"} if curve else {"ProfileName"})
        assert tags["ProfileName"]["text"] == fixture["name"]
        if curve:
            assert tags["ProfileToneCurve"] == {"type": 11, "count": curve["count"], "sha256": curve["sha256"]}
        payloads = {name: tags[name] for name in sorted(common)}
        if key == "omitted":
            baseline = payloads
        assert payloads == baseline, f"{key}: common DCP tags differ"
        observed[key] = profile
    return observed


def metadata_fields(source):
    """Read storage and non-develop XMP for field-by-field equality only."""
    et = color.ET
    rdf = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"
    with tifffile.TiffFile(source) as tif:
        page = tif.pages[0]
        assert int(page.compression) == 1
        tiff = {tag.name: repr(tag.value) for tag in page.tags.values()
                if tag.code not in (700, 34675, 273, 324)}
        xmp = et.fromstring(page.tags[700].value)
    count = sum(k.startswith(color.CRS) for element in xmp.iter() for k in element.attrib)
    nested = sum(element.tag.startswith(color.CRS) for element in xmp.iter())
    assert (count, nested) == (114, 6)
    packet = {}
    for description in xmp.findall(f".//{rdf}Description"):
        for name, value in description.attrib.items():
            if not name.startswith(color.CRS):
                packet.setdefault(name, []).append(value)
        for child in description:
            if not child.tag.startswith(color.CRS):
                packet.setdefault(child.tag, []).append(et.tostring(child, encoding="unicode"))
    return tiff, packet


def differing_fields(first, second):
    return sorted(key for key in first.keys() | second.keys() if first.get(key) != second.get(key))


def whole_rgb_difference(left, right):
    assert left.shape == right.shape == (4000, 6016, 3)
    total = left.shape[0] * left.shape[1]
    changed_pixels = 0
    changed, positive, negative, abs_sum = np.zeros((4, 3), np.int64)
    minimum = np.full(3, 65535)
    maximum = np.full(3, -65535)
    for y in range(0, left.shape[0], 128):
        diff = right[y:y + 128].astype(np.int32) - left[y:y + 128]
        changed_pixels += int(np.count_nonzero(np.any(diff != 0, axis=-1)))
        changed += np.count_nonzero(diff, axis=(0, 1))
        positive += np.count_nonzero(diff > 0, axis=(0, 1))
        negative += np.count_nonzero(diff < 0, axis=(0, 1))
        abs_sum += np.abs(diff).sum(axis=(0, 1), dtype=np.int64)
        minimum = np.minimum(minimum, diff.min(axis=(0, 1)))
        maximum = np.maximum(maximum, diff.max(axis=(0, 1)))
    return {
        "total_pixels": total, "identical_pixel_arrays": changed_pixels == 0,
        "changed_pixels": changed_pixels, "changed_pixels_percent": 100 * changed_pixels / total,
        "changed_samples_rgb": changed.tolist(), "positive_delta_samples_rgb": positive.tolist(),
        "negative_delta_samples_rgb": negative.tolist(), "min_delta_codes_rgb": minimum.tolist(),
        "max_delta_codes_rgb": maximum.tolist(), "mean_abs_delta_codes_rgb": (abs_sum / total).tolist(),
    }


def comparison(left, right, before, after, geometry):
    rgb_before, roi_before, lab_before, metadata_before = before
    rgb_after, roi_after, lab_after, metadata_after = after
    whole = whole_rgb_difference(rgb_before, rgb_after)
    roi_change = np.any(roi_before != roi_after, axis=-1)
    shifts = lab_after - lab_before
    error = color.delta(lab_before, lab_after)
    return {
        "from": left, "to": right, "whole_rgb": whole,
        "roi_changed_pixels": int(np.count_nonzero(roi_change)), "roi_total_pixels": roi_change.size,
        "delta_e00": color.summarize(error),
        "all_patches_delta_lstar_positive": bool(np.all(shifts[:, 0] > 0)),
        "neutral_delta_lstar_min_max": [float(np.min(shifts[-6:, 0])), float(np.max(shifts[-6:, 0]))],
        "neutral_max_abs_delta_astar": float(np.max(np.abs(shifts[-6:, 1]))),
        "neutral_max_abs_delta_bstar": float(np.max(np.abs(shifts[-6:, 2]))),
        "metadata_field_differences": {
            label: differing_fields(a, b) for label, a, b in zip(
                ("tiff_tags_except_offsets_icc_xmp", "non_develop_xmp"), metadata_before, metadata_after, strict=True)
        },
        "patches": [
            {"patch": patch["patch"], "name": patch["name"], "lab_before": a.tolist(),
             "lab_after": b.tolist(), "delta_lab": d.tolist(), "delta_e00": float(e)}
            for patch, a, b, d, e in zip(geometry, lab_before, lab_after, shifts, error, strict=True)
        ],
    }


def measure(fixture, args):
    reference = color.load_record()
    base = reference["baseline"]
    provenance = fixture["provenance"]
    assert provenance["baseline_sha256"] == color.PUBLIC_BASELINE_SHA
    assert color.digest(args.raw) == provenance["raw_sha256"] == base["reference"]["raw_sha256"], "RAW SHA-256 mismatch"
    icc_sha = provenance["prophoto_icc_sha256"]
    assert icc_sha == reference["gamut"]["prophoto_icc_sha256"]
    original = next(item for item in reference["gamut"]["renders"] if item["id"] == "matrix-test")
    profiles = fixture["inputs"]["profiles"]
    renders = fixture["inputs"]["renders"]
    assert renders["omitted_original"]["sha256"] == original["sha256"]
    dcp_audit = check_profiles(profiles, args.profiles)
    geometry = base["roi_geometry"]
    assert [patch["patch"] for patch in geometry] == list(range(1, 25))
    registration = base["registration"]
    sites = np.rint(color.mapped([
        item["preview_xy"] for item in registration["corner_matches"] + registration["held_out"]
    ], np.array(registration["preview_to_tiff_homography"]))).astype(int)
    frames, checks, results, engines = {}, {}, {}, set()

    with TemporaryDirectory(dir=args.scratch, prefix="tone-") as tmp:
        for index, key in enumerate(ORDER):
            spec = renders[key]
            source = args.exports / spec["folder"] / color.EXPORT_NAME
            rgb, icc, attrs, nested, software, orientation = color.read_export(source, spec["sha256"], icc_sha)
            assert len(attrs) == 114 and len(nested) == 6
            assert attrs["CameraProfile"] == profiles[spec["profile"]]["name"]
            assert attrs["CameraProfileDigest"] == spec["profile_digest"]
            assert all(attrs[name] == value for name, value in REQUIRED.items()), f"{key}: baseline develop controls differ"
            if key == "omitted_original":
                baseline_attrs, baseline_nested = attrs, nested
                baseline_format = software, orientation
            assert (software, orientation) == baseline_format and nested == baseline_nested
            differences = differing_fields(baseline_attrs, attrs)
            assert set(differences) == (set() if spec["profile"] == "omitted" else PROFILE_KEYS), (key, differences)
            gradient = color.gradient(rgb)
            if key == "omitted_original":
                original_gradient = gradient
            if key == "omitted_repeat":
                repeat_gradient = gradient
            geometry_ref = "omitted_repeat" if key == "acr3" else "omitted_original"
            target = repeat_gradient if key == "acr3" else original_gradient
            aligned = [color.locate(target, gradient, tuple(site), 8) for site in sites]
            shift = max(float(np.linalg.norm(delta)) for delta, _ in aligned)
            correlation = min(value for _, value in aligned)
            assert shift < 1 and correlation > 0.8, (key, shift, correlation)
            roi = color.stack(rgb, geometry, "tiff_xyxy")
            lab, engine = color.lab_stack(roi, icc, Path(tmp), key, args.tificc)
            engines.add(engine)
            frames[key] = (rgb, roi, color.medians(lab), metadata_fields(source))
            checks[key] = {
                "native_rgb16_le_pixel_sha256": sha256(np.ascontiguousarray(rgb, dtype="<u2")).hexdigest(),
                "software": software, "orientation_tag": orientation, "dimensions_xy": list(color.DIMENSIONS),
                "develop_attribute_count": len(attrs), "nested_elements": sorted(nested),
                "develop_differences_vs_original": {name: [baseline_attrs[name], attrs[name]] for name in differences},
                "nested_equal_vs_original": True,
                "develop_controls": {name: attrs[name] for name in (*color.CONTROLS, "HDREditMode")},
                "registration": {"reference": geometry_ref, "site_count": len(sites), "max_shift_px": shift,
                                 "minimum_gradient_correlation": correlation},
                "whole_image_endpoints_rgb": color.endpoint_counts(rgb[None]),
                "roi_endpoints_rgb": color.endpoint_counts(roi),
                "patch_endpoints_rgb": [color.endpoint_counts(patch[None]) for patch in roi],
            }
            for left, right in PAIRS:
                if right == key:
                    results[left, right] = comparison(left, right, frames[left], frames[right], geometry)
            upcoming = {left for left, right in PAIRS if right in ORDER[index + 1:]}
            frames = {name: frame for name, frame in frames.items() if name in upcoming}
    engine, = engines
    return {"engine": engine, "dcp_audit": dcp_audit, "renders": checks,
            "comparisons": [results[pair] for pair in PAIRS]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True, help="original #1376 DNG")
    parser.add_argument("--exports", type=Path, required=True, help="root containing the five export subdirectories")
    parser.add_argument("--profiles", type=Path, required=True, help="directory containing the four hash-pinned DCPs")
    parser.add_argument("--scratch", type=Path, required=True, help="existing private directory for temporary ICC conversions")
    parser.add_argument("--output", type=Path, required=True, help="new replay JSON file")
    parser.add_argument("--tificc", default="tificc")
    args = parser.parse_args()
    color.output_and_scratch(parser, args)
    try:
        fixture = json.loads(FIXTURE.read_bytes())
        assert fixture["schema_version"] == 1 and canonical_sha256(fixture) == FIXTURE_SHA256, "Tone fixture SHA-256 mismatch"
        computed = measure(fixture, args)
        assert computed == fixture["measurements"], "Replay measurements differ from the published fixture"
        color.write_report(args.output, {**fixture, "measurements": computed})
    except (AssertionError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Tone check failed: {exc or 'fixture/transform validation failed'}\n")
    for pair in computed["comparisons"]:
        print(pair["from"], "to", pair["to"], "changed pixels:", pair["whole_rgb"]["changed_pixels"],
              "delta E00:", pair["delta_e00"])


if __name__ == "__main__":
    main()
