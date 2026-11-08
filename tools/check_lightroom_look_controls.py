"""Reproduce the K-3 II #1376 Lightroom LookTable controls."""
if not __debug__:
    raise RuntimeError("Run without -O so the input checks remain enabled.")

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np
import check_lightroom_render as color
import check_lightroom_tone as tone
from check_lightroom_profile_fingerprints import fingerprints, stream_segments
from build_lightroom_tone_controls import BASE_DCP_SHA, BASE_JSON_SHA
from profile_bridge import build_dcp, unique_fields


RECIPE = color.ROOT / "analysis/lightroom-matrix-1376.json"
PROFILES = {
    "identity": {
        "name": "PENTAX II look identity control v1",
        "sat_scale": 1.0,
        "dcp_sha256": "7793c427b848bb6c8c354758ee19a54f57e8f6d7be17cc60c2872fef4fc27b30",
        "tiff_sha256": "108b42d7564933b2c46b2f7df1462970637c279bc8151ac77e52fbc7ebc62210",
    },
    "sat80": {
        "name": "PENTAX II look sat80 control v1",
        "sat_scale": 0.8,
        "dcp_sha256": "02d9cf7ba3cf69e803ff246a67a9ff54db34431a31182c86ee11316d6473a049",
        "tiff_sha256": "983c3d38e7ab489241360f961836e99b77572d2e0b7a5b6f9986cc56fd502e95",
    },
}
LOOK_DIMS = (1, 2, 1)
OMITTED_CURRENT_TIFF_SHA = "2da838831463ae821ab1e700db78877e6cb3f22a8701f9f45d883882cd1c9263"
IDENTITY_REPEAT_TIFF_SHA = "66e20ab5ca27dc7f3beea7f2583e58bc9ce987b30c14c7cf3e5fa7dbf33fb759"


def load_recipe(data):
    lf = data.replace(b"\r\n", b"\n")
    assert sha256(lf).hexdigest() == BASE_JSON_SHA, "Baseline recipe SHA-256 mismatch"
    return json.loads(lf, object_pairs_hook=unique_fields)


def control_spec(base, name, sat_scale):
    return {**base, "ProfileName": name, "ProfileLookTableDims": list(LOOK_DIMS),
            "ProfileLookTableData": [[0, sat_scale, 1] for _ in range(2)]}


def look_fingerprints(base_segments, name, sat_scale):
    """Extend the pinned matrix-only fingerprint stream with a LookTable."""
    # Adobe DNG SDK dng_camera_profile.cpp:526–556, 655–677, 720–730.
    # V outermost, H next, S innermost. Linear encoding emits no extra word.
    segments = {**base_segments, "profile_name": name.encode("ascii"),
                "look_table": struct.pack("<3I6f", *LOOK_DIMS, 0, sat_scale, 1, 0, sat_scale, 1)}
    return fingerprints(segments)


def check_develop(attrs, nested, baseline_attrs, baseline_nested, profile, full_md5, look_present):
    assert len(attrs) == 114 and len(nested) == 6, "Unexpected develop metadata counts"
    assert attrs.get("CameraProfile") == profile, "CameraProfile mismatch"
    assert attrs.get("CameraProfileDigest") == full_md5, "CameraProfileDigest mismatch"
    assert all(attrs.get(key) == value for key, value in tone.REQUIRED.items()), "Develop controls differ"
    assert nested == baseline_nested, "Nested develop metadata differs"
    differences = set(tone.differing_fields(baseline_attrs, attrs))
    assert differences == (tone.PROFILE_KEYS if look_present else set()), "Unexpected develop field differences"
    return sorted(differences)


def comparison(before, after, first, second, geometry):
    rgb_a, lab_a = before
    rgb_b, lab_b = after
    whole = tone.whole_rgb_difference(rgb_a, rgb_b)
    delta_e = color.delta(lab_a, lab_b)
    delta_chroma = np.linalg.norm(lab_b[:, 1:], axis=1) - np.linalg.norm(lab_a[:, 1:], axis=1)
    return {
        "from": first, "to": second, "whole_rgb": whole,
        "mean_abs_delta_code_all_channels": sum(whole["mean_abs_delta_codes_rgb"]) / 3,
        "identical_lab_patch_medians": bool(np.array_equal(lab_a, lab_b)),
        "delta_e00": color.summarize(delta_e),
        "neutral_delta_e00_max": float(delta_e[-6:].max()),
        "patches": [
            {"patch": item["patch"], "name": item["name"], "delta_e00": float(de),
             "delta_lstar": float(lstar), "delta_cstar_ab": float(dc)}
            for item, de, lstar, dc in zip(geometry, delta_e, lab_b[:, 0] - lab_a[:, 0],
                                          delta_chroma, strict=True)
        ],
    }


def measure(args):
    tone_fixture = json.loads(tone.FIXTURE.read_bytes())
    assert tone.canonical_sha256(tone_fixture) == tone.FIXTURE_SHA256, "Tone fixture SHA-256 mismatch"
    tone_provenance = tone_fixture["provenance"]
    raw_sha, icc_sha = (tone_provenance[k] for k in ("raw_sha256", "prophoto_icc_sha256"))
    baseline = color.load_record()["baseline"]
    assert raw_sha == baseline["reference"]["raw_sha256"] == color.digest(args.raw), "RAW SHA-256 mismatch"
    recipe = load_recipe(RECIPE.read_bytes())
    base_dcp = build_dcp(recipe)
    assert sha256(base_dcp).hexdigest() == BASE_DCP_SHA, "Baseline DCP SHA-256 mismatch"
    base_segments, _ = stream_segments(base_dcp)
    prior = tone_fixture["inputs"]["renders"]["omitted_repeat"]
    base_full, base_render = fingerprints(base_segments)
    assert base_full == prior["profile_digest"]
    specs = {"omitted_repeat": {
        "name": recipe["ProfileName"], "dcp_sha256": BASE_DCP_SHA, "tiff_sha256": prior["sha256"],
        "look_table_dims": None, "sat_scale": None, "sdk_full_md5": base_full,
        "sdk_render_md5": base_render,
    }}
    for key, pin in PROFILES.items():
        source = getattr(args, f"{key}_dcp")
        expected = build_dcp(control_spec(recipe, pin["name"], pin["sat_scale"]))
        assert sha256(expected).hexdigest() == pin["dcp_sha256"], f"{key}: rebuilt DCP SHA-256 mismatch"
        with source.open("rb") as stream:
            assert stream.read(len(expected) + 1) == expected, f"{key}: DCP bytes differ from the pin"
        full, render = look_fingerprints(base_segments, pin["name"], pin["sat_scale"])
        specs[key] = {**pin, "look_table_dims": list(LOOK_DIMS), "sdk_full_md5": full, "sdk_render_md5": render}
    assert len({spec["sdk_full_md5"] for spec in specs.values()}) == 3
    assert len({spec["sdk_render_md5"] for spec in specs.values()}) == 3
    specs["omitted_current"] = {**specs["omitted_repeat"], "tiff_sha256": OMITTED_CURRENT_TIFF_SHA}
    specs["identity_repeat"] = {**specs["identity"], "tiff_sha256": IDENTITY_REPEAT_TIFF_SHA}

    geometry = baseline["roi_geometry"]
    assert [item["patch"] for item in geometry] == list(range(1, 25))
    registration = baseline["registration"]
    sites = np.rint(color.mapped([
        item["preview_xy"] for item in registration["corner_matches"] + registration["held_out"]
    ], np.array(registration["preview_to_tiff_homography"]))).astype(int)
    frames, rendered, engines = {}, {}, set()
    with TemporaryDirectory(dir=args.scratch, prefix="look-") as tmp:
        for key, spec in specs.items():
            path = args.omitted_tiff if key == "omitted_repeat" else getattr(args, f"{key}_tiff")
            rgb, icc, attrs, nested, software, orientation = color.read_export(path, spec["tiff_sha256"], icc_sha)
            gradient = color.gradient(rgb)
            if key == "omitted_repeat":
                base_attrs, base_nested, base_gradient = attrs, nested, gradient
                base_storage = software, orientation
            assert (software, orientation) == base_storage
            changed = check_develop(attrs, nested, base_attrs, base_nested, spec["name"], spec["sdk_full_md5"],
                                    spec["look_table_dims"] is not None)
            alignment = [color.locate(base_gradient, gradient, tuple(site), 8) for site in sites]
            shift = max(float(np.linalg.norm(offset)) for offset, _ in alignment)
            correlation = min(coefficient for _, coefficient in alignment)
            assert shift < 1 and correlation > 0.8, (key, shift, correlation)
            roi = color.stack(rgb, geometry, "tiff_xyxy")
            lab, engine = color.lab_stack(roi, icc, Path(tmp), key, args.tificc)
            engines.add(engine)
            frames[key] = rgb, color.medians(lab)
            rendered[key] = {
                **spec, "tiff_bytes": path.stat().st_size,
                "native_rgb16_le_pixel_sha256": sha256(np.ascontiguousarray(rgb, dtype="<u2")).hexdigest(),
                "xmp_profile_digest": attrs["CameraProfileDigest"],
                "develop_attribute_count": len(attrs), "develop_differences_vs_omitted": changed,
                "nested_develop_element_count": len(nested), "nested_develop_equal_vs_omitted": True,
                "registration": {"sites": len(sites), "max_shift_px": shift,
                                 "minimum_gradient_correlation": correlation},
            }
    engine, = engines
    return {
        "schema_version": 1,
        "scope": "Native K-3 II #1376 Lightroom LookTable controls with no-LookTable and identity repeat exports.",
        "provenance": {
            "raw_source_record": 1376, "raw_license": "CC0-1.0", "raw_sha256": raw_sha,
            "camera_model": recipe["UniqueCameraModel"], "baseline_recipe_sha256_lf": BASE_JSON_SHA,
            "tone_fixture_sha256_canonical": tone.FIXTURE_SHA256, "registration_baseline_sha256": color.PUBLIC_BASELINE_SHA,
            "software": software, "orientation_tag": orientation, "dimensions_xy": list(color.DIMENSIONS),
            "sample_format": "unsigned RGB16", "icc_description": "ProPhoto RGB", "icc_sha256": icc_sha,
            "develop_controls": {key: base_attrs[key] for key in (*color.CONTROLS, "HDREditMode")},
            "lab_conversion": tone_provenance["conversion"], "lab_engine": engine,
            "sdk_archive_sha256": tone_provenance["sdk_control"]["zip_sha256"],
            "sdk_fingerprint_source": "dng_camera_profile.cpp:526–556, 655–677, 720–730",
            "sdk_fingerprint_member_sha256": "988d3d9531ddfefd0faa0b6b4ebf85276a872a55b1956fd2bb964f89c1dd801f",
        },
        "renders": rendered,
        "comparisons": [
            comparison(frames[first], frames[second], first, second, geometry)
            for first, second in (
                ("omitted_repeat", "omitted_current"), ("identity", "identity_repeat"),
                ("omitted_current", "identity"), ("identity", "sat80"),
            )
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("raw", "omitted-tiff", "omitted-current-tiff", "identity-dcp", "identity-tiff",
                 "identity-repeat-tiff", "sat80-dcp", "sat80-tiff", "scratch", "output"):
        parser.add_argument(f"--{flag}", type=Path, required=True)
    parser.add_argument("--tificc", default="tificc")
    parser.add_argument("--compare", type=Path, help="optionally require exact replay of a report")
    args = parser.parse_args()
    color.output_and_scratch(parser, args)
    try:
        result = measure(args)
        if args.compare:
            snapshot = json.loads(args.compare.read_bytes(), object_pairs_hook=unique_fields)
            assert tone.canonical_sha256(snapshot) == tone.canonical_sha256(result), "Replay measurements differ"
        color.write_report(args.output, result)
    except (AssertionError, OSError, ValueError, KeyError, struct.error, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"LookTable check failed: {exc or 'input or transform validation failed'}\n")


if __name__ == "__main__":
    main()
