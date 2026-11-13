"""Build or verify the frozen K-3 II composed-tone Lightroom experiment."""

if not __debug__:
    raise RuntimeError("Run without -O to retain validation")

import argparse
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
REPORT = "analysis/lightroom-composed-tone.json"
REPORT_SHA = "1b3c35817b60485c6be69eeec6c2743594a941ae8ea12f2fdafc3d529858806d"
SCENE_MASK_SHA = {
    "low_gradient_nonendpoint": "e8197bacde4167d81eb7a487567db426b032f65449a7b226adb6f9d717d386c3",
    "low_gradient_nonendpoint_inner_knot_range": "695d2dfdfefb1d71c40cdec21c0f7dcde8d9d292f1ca46688e4e659d38ecfcd7",
}
PROFILE_FIELDS = {"CameraProfile", "CameraProfileDigest"}
# Execution order for the frozen sibling source files.
REPLAY_MODULES = {
    "check_lightroom_render": "3af04e07832bd7bed553868d228d915ce1ead89d212035805652c42820453a40",
    "check_color_engine_bridge": "9e2f75d25edfef50816544c9a61bc5cbad96bc093428156e0c134a2a902897e4",
    "check_lightroom_gamut": "fe86f772b5b1d3e2c3bfe9c1efe1ef0395ed6fb6bf868f8da1f85e670a77fad6",
    "check_color_tone_residual": "437293cfb04b8b4b2274c878a4718a0e783554e104142431b007fb0024a7a08f",
    "check_color_scene_transfer": "9c0dfd8468810f0e1f58d67f14d0123e45b9ebf953fefbe1978981929bb148e6",
}
BUILD_MODULES = {
    "inspect_adobe_profiles": (
        "inspect_adobe_profiles.py",
        "83c9ea9d745a4ac12bba4164ff729aeb8e64bdd3783e8575727251758ee3a7e7",
    ),
    "tools.profile_bridge": (
        "tools/profile_bridge.py",
        "bf332ac3744e2570741cbbb359d55be28c55dd9d350c4a09bd57fd8a87ee487c",
    ),
    "build_lightroom_tone_controls": (
        "tools/build_lightroom_tone_controls.py",
        "22aa21059f83725740c22bc98e5eb62b40c48c6d131129bc9eabf306d2de736f",
    ),
}
RECORDS = {
    "chart": (
        "analysis/lightroom-render-comparison.json",
        "6c59220ec5dee4db3b6353374603195198079b0266bd3b2f95ef3223f161e19b",
    ),
    "scene": (
        "analysis/color-scene-transfer.json",
        "81c61590abdd8331e4ff5b245a19e888a1c0fa028b75c483d83c516be2165498",
    ),
    "protocol": (
        "analysis/color-comparison-protocol.json",
        "eb974b4a891ee444295ee0a08a5f09237e4bd590f9be0fe6b2949472344c562f",
    ),
    "plan": (
        "analysis/color-scene-plan.json",
        "c7ffca0212d486b794eb5ce9713d83f3dda153ac9ecf21eca4e91d1697a3b324",
    ),
    "curve": (
        "analysis/color-tone-residual.json",
        "6b417e8b69940157495fcc751ab4c5560effa5a089c62cf273ab7a66bf9de0ee",
    ),
}


def pinned_text(path, expected):
    data = path.read_bytes().replace(b"\r\n", b"\n")
    if sha256(data).hexdigest() != expected:
        raise ValueError(f"SHA-256 mismatch: {path.name}")
    return data


def pinned_json(name, expected):
    return json.loads(pinned_text(ROOT / name, expected))


def load_modules(specs):
    sources = [
        (name, ROOT / path, pinned_text(ROOT / path, pin))
        for name, (path, pin) in specs.items()
    ]
    sys.dont_write_bytecode = True
    for name, path, source in sources:
        module = ModuleType(name)
        module.__file__ = str(path)
        module.__package__ = name.rpartition(".")[0]
        exec(compile(source, module.__file__, "exec"), module.__dict__)
        sys.modules[name] = module


def replay_export(reader, path, shape, profile, filename, archived, fresh):
    pixels, icc, record = reader(
        path, shape, profile, filename, None if fresh else archived["file_sha256"]
    )
    for key in (
        "software",
        "shape_yxc",
        "storage",
        "icc_sha256",
        "crs_attributes",
        "crs_nested",
    ):
        if record[key] != archived[key]:
            raise ValueError(f"{filename}: archived export control differs: {key}")
    return pixels, icc, record


def require_chart_matrix_pixels(record, archived):
    if record["pixel_sha256_le_uint16_rgb"] != archived["pixel_sha256_le_uint16_rgb"]:
        raise ValueError(
            "#1376 matrix pixels differ; frozen chart coordinates require the archived baseline pixels"
        )


def build(args, reference):
    from scipy.interpolate import PchipInterpolator
    from zipfile import ZipFile

    recipe = reference["domain_recipe"]
    spec = pinned_json(
        "analysis/lightroom-matrix-1376.json", recipe["baseline_spec_sha256_lf"]
    )
    load_modules(BUILD_MODULES)
    from build_lightroom_tone_controls import build_dcp, describe, read_acr3

    baseline = build_dcp(spec)
    assert sha256(baseline).hexdigest() == recipe["baseline_dcp_sha256"]
    default = read_acr3(args.sdk)
    with args.sdk.open("rb") as stream:
        assert file_digest(stream, "sha256").hexdigest() == recipe["sdk_archive_sha256"]
        stream.seek(0)
        with ZipFile(stream) as archive:
            prefix = "dng_sdk_1_7_1/"
            flags = archive.read(prefix + "dng_sdk/source/dng_flags.h")
            license_text = archive.read(prefix + "LICENSE.txt")
    assert sha256(flags).hexdigest() == recipe["sdk_flags_member_sha256"]
    assert sha256(license_text).hexdigest() == recipe["sdk_license_member_sha256"]
    g = PchipInterpolator(*zip(*reference["frozen_curve_xy"]), extrapolate=False)
    points = [
        [x, float(y)]
        for (x, _), y in zip(default, g([y for _, y in default]), strict=True)
    ]
    data = build_dcp(
        {**spec, "ProfileName": recipe["name"], "ProfileToneCurve": points}
    )
    assert (
        sha256(data).hexdigest() == recipe["dcp_sha256"]
    ), "Generated DCP identity mismatch"
    old, new = describe(baseline)["tags"], describe(data)["tags"]
    assert set(new) == set(old) | {"ProfileToneCurve"}
    assert all(new[k] == old[k] for k in recipe["same_non_tone_tags"])
    assert new["ProfileToneCurve"]["sha256"] == recipe["tone_tag_payload_sha256"]
    with args.output.open("xb") as stream:
        stream.write(data)
    print(json.dumps({"dcp_sha256": recipe["dcp_sha256"], "bytes": len(data)}))


def check(args, expected):
    records = {key: pinned_json(*spec) for key, spec in RECORDS.items()}
    load_modules(
        {name: (f"tools/{name}.py", pin) for name, pin in REPLAY_MODULES.items()}
    )
    import numpy as np
    from scipy.interpolate import PchipInterpolator
    import check_color_scene_transfer as scene
    import check_lightroom_render as render
    from check_lightroom_gamut import xyz_columns
    from check_color_tone_residual import lab_from_xyz, rgb_tone, xyz_from_lab

    chart, historical, fixed = (records[key] for key in ("chart", "scene", "plan"))
    frozen = expected["original_fixtures"]
    knots = np.array(fixed["curve"]["xy"])
    assert (
        records["curve"]["experiments"]["matrix_to_native_jpeg"]["200px"]["pchip"][
            "neutral_xy"
        ]
        == knots.tolist()
    )
    assert expected["frozen_curve_xy"] == knots.tolist()
    curve = PchipInterpolator(*knots.T, extrapolate=False)
    assert render.digest(args.dcp) == frozen["candidate"], "DCP SHA mismatch"
    matrix_profile = fixed["profiles"]["matrix1376"]
    candidate_profile = {
        **matrix_profile,
        "profile": expected["candidate_name"],
        "xmp_profile_digest": expected["domain_recipe"]["expected_full_md5"],
    }
    shape = fixed["fixture"]["shape_yxc"]
    eval_config, reg = fixed["evaluation"], fixed["registration"]
    centers = [(x, y) for y in eval_config["y"] for x in eval_config["x"]]
    size = eval_config["roi_size_px"]
    affine = np.array(historical["alignment"]["matrix1376"]["affine_xy1_to_xy"])
    boxes = chart["baseline"]["roi_geometry"]
    registration = chart["baseline"]["registration"]
    chart_sites = [
        tuple(row["preview_xy"])
        for row in registration["corner_matches"] + registration["held_out"]
    ]
    chart_tiff_sites = (
        np.rint(
            render.mapped(
                chart_sites, np.array(registration["preview_to_tiff_homography"])
            )
        )
        .astype(int)
        .tolist()
    )

    def roi_metrics(reference, values, mask, minimum):
        # The published helper computes the chosen descriptive statistics; keep
        # its method rows and derive only the comparisons used in this experiment.
        metrics = scene.compare_regions(reference, values, mask, minimum)
        return {
            "included_regions_zero_based": metrics["included_regions"],
            "methods": metrics["methods"],
        }

    def scores(matrix, target, candidate_lab, jpeg, masks, minimum):
        all_scores = {}
        for label, mask in masks.items():
            delivery = roi_metrics(
                target,
                {"matrix1376": matrix, "matrix1376_fixed_chart_tone": candidate_lab},
                mask,
                minimum,
            )
            delivery["methods"]["unchanged_matrix"] = delivery["methods"].pop(
                "matrix1376"
            )
            delivery["methods"]["actual_candidate"] = delivery["methods"].pop(
                "matrix1376_fixed_chart_tone"
            )
            model_mean = delivery["methods"]["unchanged_matrix"]["equal_region_mean"][
                "median_delta_e00"
            ]
            actual_mean = delivery["methods"]["actual_candidate"]["equal_region_mean"][
                "median_delta_e00"
            ]
            camera = roi_metrics(
                jpeg,
                {
                    "matrix1376": matrix,
                    "matrix1376_fixed_chart_tone": target,
                    "actual_candidate": candidate_lab,
                },
                mask,
                minimum,
            )
            camera["methods"]["unchanged_matrix"] = camera["methods"].pop("matrix1376")
            camera["methods"]["fixed_g_of_matrix"] = camera["methods"].pop(
                "matrix1376_fixed_chart_tone"
            )
            effect = roi_metrics(
                matrix,
                {"matrix1376": target, "matrix1376_fixed_chart_tone": candidate_lab},
                mask,
                minimum,
            )
            effect["methods"]["fixed_g_of_matrix"] = effect["methods"].pop("matrix1376")
            effect["methods"]["actual_candidate"] = effect["methods"].pop(
                "matrix1376_fixed_chart_tone"
            )
            all_scores[label] = {
                "delivery_to_offline_target": delivery,
                "relative_to_unchanged_matrix": effect,
                "camera_jpeg_residual": camera,
                "delivery_ratio": actual_mean / model_mean if model_mean else None,
            }
        return all_scores

    output = {**expected, "scenes": {}}
    for raw_id, baseline_key, wb in (
        ("1376", "chart_matrix", [5200, 2]),
        ("1363", "scene_matrix", [4650, 28]),
    ):
        filename = f"pentax-k3ii-{raw_id}.dng"
        archived = expected["scenes"][raw_id]
        assert archived["matrix"]["file_sha256"] == frozen[baseline_key]
        matrix, icc, matrix_record = replay_export(
            scene.read_export,
            getattr(args, f"matrix_{raw_id}"),
            shape,
            matrix_profile,
            filename,
            archived["matrix"],
            args.fresh_exports,
        )
        if raw_id == "1376":
            require_chart_matrix_pixels(matrix_record, archived["matrix"])
        candidate_rgb, candidate_icc, candidate_record = replay_export(
            scene.read_export,
            getattr(args, f"candidate_{raw_id}"),
            shape,
            candidate_profile,
            filename,
            archived["candidate"],
            args.fresh_exports,
        )
        assert (
            icc == candidate_icc
            and matrix_record["software"] == candidate_record["software"]
        )
        differences = scene.require_same_controls(
            matrix_record, candidate_record, PROFILE_FIELDS
        )
        assert set(differences) == PROFILE_FIELDS
        for record in (matrix_record, candidate_record):
            attrs = record["crs_attributes"]
            assert [int(attrs[key]) for key in ("Temperature", "Tint")] == wb

        extra_baselines = {}
        if raw_id == "1376":
            raw, preview_path = args.raw_1376, args.preview_1376
            reference, _, preview, raw_settings = render.check_inputs(
                raw, preview_path, args.exiftool, chart
            )
            first, second = render.gradient(matrix), render.gradient(candidate_rgb)
            rows = []
            for preview_xy, tiff_xy in zip(chart_sites, chart_tiff_sites, strict=True):
                shift, corr = render.locate(first, second, tuple(tiff_xy), 8)
                rows.append(
                    {
                        "preview_xy": preview_xy,
                        "tiff_xy": tiff_xy,
                        "shift_xy": shift.tolist(),
                        "correlation": corr,
                    }
                )
            assert (
                len(rows) == 19 and min(r["correlation"] for r in rows) > 0.85
            ), "#1376 TIFF correlation gate"
            del first, second
            base_rois, candidate_rois, jpeg_rois = (
                render.stack(image, boxes, key)
                for image, key in (
                    (matrix, "tiff_xyxy"),
                    (candidate_rgb, "tiff_xyxy"),
                    (preview, "preview_xyxy"),
                )
            )
            fixed_alignment = {
                "roi_geometry": boxes,
                "sampling": "frozen translated boxes; no candidate shift applied",
            }
        else:
            raw, preview_path = args.raw_1363, args.preview_1363
            reference, raw_settings = fixed["fixture"], None
            preview = scene.read_preview(
                SimpleNamespace(raw=raw, preview=preview_path, exiftool=args.exiftool),
                reference,
            )
            rows = scene.match_sites(
                scene.gradient(matrix), scene.gradient(candidate_rgb), reg
            )
            jpeg_gradient = scene.roi_samples(scene.gradient(preview), centers, size)
            assert (
                len(rows) == 20
                and sum("shift_xy" in row for row in rows)
                >= reg["tiff_to_matrix_min_sites"]
            ), "#1363 TIFF site count"
            base_rois = scene.roi_samples(matrix, centers, size, affine)
            candidate_rois = scene.roi_samples(candidate_rgb, centers, size, affine)
            jpeg_rois = scene.roi_samples(preview, centers, size)
            fixed_alignment = {
                "roi_centers_xy": centers,
                "roi_size_px": size,
                "jpeg_to_matrix_affine": affine.tolist(),
                "sampling": "frozen affine; shared matrix and candidate sampling; no candidate shift applied",
            }
        valid = [row for row in rows if "shift_xy" in row]
        max_shift = max(float(np.linalg.norm(row["shift_xy"])) for row in valid)
        assert max_shift < 1.0, f"#{raw_id} TIFF registration gate: {max_shift:.6f} px"
        min_correlation = min(row["correlation"] for row in valid)
        del matrix, candidate_rgb, preview

        with TemporaryDirectory(dir=args.scratch, prefix="composed-tone-lab-") as tmp:
            tmp = Path(tmp)
            matrix_lab, banner = render.lab_stack(
                base_rois, icc, tmp, "matrix", args.tificc
            )
            candidate_lab, other_banner = render.lab_stack(
                candidate_rois, icc, tmp, "candidate", args.tificc
            )
            jpeg_lab, jpeg_banner = render.lab_stack(
                jpeg_rois, None, tmp, "jpeg", args.tificc
            )
            assert banner == other_banner == jpeg_banner
        columns = xyz_columns(icc)
        linear = xyz_from_lab(matrix_lab) @ np.linalg.inv(columns).T
        assert linear.min() > -1e-4 and linear.max() < 1.0001
        linear = np.clip(linear, 0, 1)
        target = lab_from_xyz(rgb_tone(linear, curve) @ columns.T)
        masks = {"all": np.ones(base_rois.shape[:-1], dtype=bool)}
        if raw_id == "1363":
            # The old mask excluded endpoints in all original exports. Rebuild
            # it from those files; candidate color never decides which pixels enter.
            mask = eval_config["mask_sensitivity"]
            jlo, jhi = mask["jpeg_all_codes_open_interval"]
            lo, hi = mask["prophoto_all_codes_open_interval"]
            clean = (jpeg_gradient <= mask["jpeg_green_sobel_max_8bit_scale"]) & np.all(
                (jpeg_rois > jlo) & (jpeg_rois < jhi), axis=-1
            )
            clean &= np.all((base_rois > lo) & (base_rois < hi), axis=-1)
            for key in ("camera-natural", "adobe-standard"):
                extra, _, record = replay_export(
                    scene.read_export,
                    (
                        args.natural_1363
                        if key == "camera-natural"
                        else args.standard_1363
                    ),
                    shape,
                    fixed["profiles"][key],
                    filename,
                    historical["exports"][key],
                    args.fresh_exports,
                )
                roi = scene.roi_samples(extra, centers, size, affine)
                clean &= np.all((roi > lo) & (roi < hi), axis=-1)
                extra_baselines[key] = (
                    {
                        field: record[field]
                        for field in (
                            "file_sha256",
                            "pixel_sha256_le_uint16_rgb",
                            "icc_sha256",
                            "xmp_sha256",
                        )
                    }
                    if args.fresh_exports
                    else record["file_sha256"]
                )
                del extra, roi
            covered = np.all(
                (linear >= knots[1, 0]) & (linear <= knots[-2, 0]), axis=-1
            )
            masks.update(
                low_gradient_nonendpoint=clean,
                low_gradient_nonendpoint_inner_knot_range=clean & covered,
            )
        mask_hashes = {}
        if raw_id == "1363":
            mask_hashes = {
                key: sha256(
                    np.packbits(masks[key], bitorder="little").tobytes()
                ).hexdigest()
                for key in SCENE_MASK_SHA
            }
            if mask_hashes != SCENE_MASK_SHA:
                raise ValueError(f"#1363 frozen mask differs: {mask_hashes}")
        metrics = scores(
            matrix_lab,
            target,
            candidate_lab,
            jpeg_lab,
            masks,
            eval_config["minimum_samples_for_subset_region"],
        )
        if raw_id == "1363" and not args.fresh_exports:
            for label in masks:
                old = historical["metrics"][label]
                for now, then in (
                    ("unchanged_matrix", "matrix1376"),
                    ("fixed_g_of_matrix", "matrix1376_fixed_chart_tone"),
                ):
                    actual = metrics[label]["camera_jpeg_residual"]["methods"][now]
                    expected = old["methods"][then]
                    assert actual["pixels"] == expected["pixels"]
                    assert (
                        abs(
                            actual["equal_region_mean"]["median_delta_e00"]
                            - expected["equal_region_mean"]["median_delta_e00"]
                        )
                        < 1e-10
                    )
        ratio = metrics["all"]["delivery_ratio"]
        result = {
            "matrix": matrix_record,
            "candidate": candidate_record,
            "camera_source": reference,
            "camera_settings": raw_settings,
            "develop_differences": differences,
            "icc_converter": banner,
            "registration": {
                **fixed_alignment,
                "tiff_pair_sites": rows,
                "max_pair_shift_px": max_shift,
                "min_pair_correlation": min_correlation,
            },
            "metrics": metrics,
            "ratio_lt_half": ratio is not None and ratio < 0.5,
            "candidate_roi_endpoints_rgb": render.endpoint_counts(candidate_rois),
            "mask_reference_tiff_sha256": extra_baselines,
        }
        if raw_id == "1376":
            sensitivity = {}
            for name, crop in (
                ("full_200", slice(None)),
                ("center_100", slice(50, -50)),
            ):
                patch = render.delta(
                    render.medians(target[:, crop, crop]),
                    render.medians(candidate_lab[:, crop, crop]),
                )
                sensitivity[name] = {
                    "patch_median_lab_delta_e00": render.summarize(patch),
                    "by_patch": patch.tolist(),
                    "neutral_6_mean": float(patch[18:].mean()),
                    "chromatic_18_mean": float(patch[:18].mean()),
                }
            result["chart_patch_delivery"] = sensitivity
            result["chart_camera_patch_median_lab"] = {}
            for method, sample in (
                ("unchanged_matrix", matrix_lab),
                ("fixed_g_of_matrix", target),
                ("actual_candidate", candidate_lab),
            ):
                errors = render.delta(render.medians(jpeg_lab), render.medians(sample))
                result["chart_camera_patch_median_lab"][method] = {
                    "all_24": render.summarize(errors),
                    "by_patch": errors.tolist(),
                    "neutral_6_mean": float(errors[18:].mean()),
                    "chromatic_18_mean": float(errors[:18].mean()),
                }
        assert (
            render.digest(raw) == reference["raw_sha256"]
            and render.digest(preview_path) == reference["preview_sha256"]
        )
        if raw_id == "1376":
            values = sensitivity["full_200"]["patch_median_lab_delta_e00"]
            result["chart_patch_tolerance_met"] = (
                values["mean"] <= 0.25 and values["max"] <= 0.75
            )
        if args.fresh_exports:
            result["registration_gate_passed"] = True
            if raw_id == "1363":
                result["mask_sha256_packbits_little"] = mask_hashes
                result["mask_matches_historical"] = True
                result["mask_reference_tiffs"] = result.pop(
                    "mask_reference_tiff_sha256"
                )
        output["scenes"][raw_id] = result
    output["delivery_tolerances_met"] = (
        all(s["ratio_lt_half"] for s in output["scenes"].values())
        and output["scenes"]["1376"]["chart_patch_tolerance_met"]
    )
    if args.fresh_exports:
        output.pop("canonical_original_sha256")
        output["canonical_replay_verified"] = False
        output["historical_report_sha256_lf"] = REPORT_SHA
        output["archived_fixture_pins"] = output.pop("original_fixtures")
        output["public_replay_note"] = (
            "Fresh exports measured under archived settings, exact chart matrix pixels and exact frozen masks; archival TIFF container or metric equality is not required."
        )
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser(
        "build", help="rebuild the exact experimental DCP from the historical SDK"
    )
    make.add_argument("--sdk", type=Path, required=True)
    make.add_argument("--output", type=Path, required=True)
    replay = sub.add_parser(
        "replay", help="recompute the canonical four-TIFF comparison"
    )
    for key in (
        "raw-1376",
        "raw-1363",
        "preview-1376",
        "preview-1363",
        "matrix-1376",
        "matrix-1363",
        "candidate-1376",
        "candidate-1363",
        "natural-1363",
        "standard-1363",
        "dcp",
        "scratch",
        "output",
    ):
        replay.add_argument("--" + key, type=Path, required=True)
    replay.add_argument(
        "--fresh-exports",
        action="store_true",
        help="measure fresh TIFF bytes under archived controls and masks",
    )
    replay.add_argument("--exiftool", default="exiftool")
    replay.add_argument("--tificc", default="tificc")
    args = parser.parse_args()
    if os.path.lexists(args.output):
        parser.error("Output must be new, including hardlinks and dangling symlinks")
    if args.command == "replay" and not args.scratch.is_dir():
        parser.error("Scratch must be an existing directory")
    try:
        expected = pinned_json(REPORT, REPORT_SHA)
        if args.command == "build":
            build(args, expected)
        else:
            result = check(args, expected)
            actual = json.dumps(
                result,
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            )
            frozen = json.dumps(
                expected,
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            )
            if not args.fresh_exports and actual != frozen:
                raise ValueError(
                    "Replay differs from frozen report (including metric/engine data)"
                )
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(result, stream, ensure_ascii=False, allow_nan=False, indent=2)
                stream.write("\n")
            print(
                json.dumps(
                    {
                        "canonical_replay_verified": not args.fresh_exports,
                        "delivery_tolerances_met": result["delivery_tolerances_met"],
                    }
                )
            )
    except (OSError, AssertionError, ValueError) as error:
        parser.exit(
            1, f"Composed tone verification failed: {error or 'fixture check failed'}\n"
        )


if __name__ == "__main__":
    main()
