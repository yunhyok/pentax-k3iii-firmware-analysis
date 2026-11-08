"""Compare hash-pinned Lightroom RGB16 exports with K-3 II #1376 Natural JPEG."""
if not __debug__:
    raise RuntimeError("Run without -O so the fixture checks remain enabled.")

import argparse
import os
import sys

sys.dont_write_bytecode = True
from hashlib import file_digest, sha256
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import xml.etree.ElementTree as ET

import cv2
import numpy as np
from PIL import Image
from skimage import __version__ as skimage_version
from skimage.color import deltaE_ciede2000
import tifffile

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "analysis/lightroom-render-comparison.json"
PUBLIC_BASELINE_SHA = "5dd24d05fc52f98f5b2e5811ada85bf0acdd663f871af550414e95fc928446b5"
EXPORT_NAME = "pentax-k3ii-1376.tif"
PROFILE_IDS = ("adobe-standard", "camera-natural", "matrix-test")
PROTOCOL = ROOT / "analysis/color-comparison-protocol.json"
ICC_SHA = "2b3aa1645779a9e634744faf9b01e9102b0c9b88fd6deced7934df86b949af7e"
SHARMA_SHA = "44aebb39107128328add54fbef5ac8ee89909e50508f448a1580adea2058a4b8"
CRS = "{http://ns.adobe.com/camera-raw-settings/1.0/}"
CONTROLS = (
    "ProcessVersion", "WhiteBalance", "Temperature", "Tint", "Exposure2012",
    "Contrast2012", "Highlights2012", "Shadows2012", "Whites2012", "Blacks2012",
    "HasCrop", "CropTop", "CropLeft", "CropBottom", "CropRight", "CropAngle",
    "LensProfileEnable", "AutoLateralCA", "Sharpness", "SharpenRadius", "SharpenDetail",
    "SharpenEdgeMasking", "LuminanceSmoothing", "ColorNoiseReduction",
)
DIMENSIONS = (6016, 4000)
CHART = (3250, 350, 5600, 3540)
CORNERS = ((3525, 574), (5364, 576), (3525, 3260), (5333, 3290))


def digest(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def load_record():
    record = json.loads(RECORD.read_bytes())
    assert record["schema_version"] == 1
    payload = (json.dumps(record["baseline"], indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    assert sha256(payload).hexdigest() == PUBLIC_BASELINE_SHA, "Public baseline SHA-256 mismatch"
    for key in ("baseline", "gamut"):
        assert tuple(x["id"] for x in record[key]["renders"]) == PROFILE_IDS
    return record


def check_inputs(raw, jpeg, exiftool, record):
    protocol_bytes = PROTOCOL.read_bytes()
    assert sha256(protocol_bytes.replace(b"\r\n", b"\n")).hexdigest() == record["provenance"]["protocol_sha256_lf"]
    protocol = json.loads(protocol_bytes)
    reference = dict(protocol["reference"])
    reference.pop("preview_path", None)
    assert reference == record["baseline"]["reference"]
    assert digest(raw) == reference["raw_sha256"], "DNG SHA-256 mismatch"
    assert digest(jpeg) == reference["preview_sha256"], "JPEG SHA-256 mismatch"
    extracted = subprocess.run([exiftool, "-b", "-SubIFD1:PreviewImage", str(raw)],
                               capture_output=True, check=True).stdout
    assert sha256(extracted).hexdigest() == reference["preview_sha256"]
    with Image.open(jpeg) as image:
        assert image.mode == "RGB" and image.size == DIMENSIONS and not image.info.get("icc_profile")
        preview = np.array(image)
    camera_fields = subprocess.run([
        exiftool, "-G1", "-a", "-s", "-j", "-PreviewColorSpace", "-ImageTone",
        "-WhiteBalance", "-ColorTemperature", "-AsShotNeutral", "-BaselineExposure",
        "-ExposureCompensation", "-Sharpness", "-HighISONoiseReduction", "-Contrast",
        "-Saturation", "-ShadowCorrection", str(raw),
    ], capture_output=True, text=True, check=True)
    metadata, = json.loads(camera_fields.stdout)
    metadata.pop("SourceFile")
    assert metadata["SubIFD1:PreviewColorSpace"] == "sRGB"
    assert metadata["Pentax:ImageTone"] == "Natural"
    return reference, protocol["patches"], preview, metadata


def check_exports(exports, entries, suffix=""):
    for entry in entries:
        path = exports / (entry["id"] + suffix) / EXPORT_NAME
        assert digest(path) == entry["sha256"], f'{entry["id"]}{suffix}: TIFF SHA-256 mismatch'


def read_export(source, expected_sha, icc_sha):
    assert digest(source) == expected_sha, f"{source.name}: TIFF SHA-256 mismatch"
    with tifffile.TiffFile(source) as tif:
        assert len(tif.pages) == 1
        page = tif.pages[0]
        assert page.shape == (*DIMENSIONS[::-1], 3) and page.dtype == np.dtype("uint16")
        assert int(page.photometric) == 2 and int(page.planarconfig) == 1 and page.bitspersample == 16
        orientation_tag = page.tags.get(274)
        orientation = orientation_tag.value if orientation_tag else None
        assert orientation in (None, 1)
        icc = page.tags[34675].value
        assert sha256(icc).hexdigest() == icc_sha
        software = page.tags[305].value
        assert "Lightroom Classic 15.6" in software
        xmp = ET.fromstring(page.tags[700].value)
        attrs = {
            key.removeprefix(CRS): val
            for element in xmp.iter()
            for key, val in element.attrib.items()
            if key.startswith(CRS)
        }
        nested = {
            element.tag.removeprefix(CRS): ET.tostring(element, encoding="unicode")
            for element in xmp.iter()
            if element.tag.startswith(CRS)
        }
        return page.asarray(), icc, attrs, nested, software, orientation


def read_tiff(entry, source, exiftool):
    rgb, icc, attrs, nested, software, orientation = read_export(source, entry["sha256"], ICC_SHA)
    assert attrs["CameraProfile"] == entry["profile"]
    assert attrs["CameraProfileDigest"] == entry["profile_digest"]
    assert [attrs[k] for k in ("ProcessVersion", "WhiteBalance", "Exposure2012", "HasCrop")] == [
        "15.4", "As Shot", "0.00", "False",
    ]
    assert int(attrs["Temperature"]) == entry["as_shot_temperature"]
    assert int(attrs["Tint"]) == entry["as_shot_tint"]
    assert attrs["LensProfileEnable"] == attrs["AutoLateralCA"] == "0"
    description = subprocess.run([exiftool, "-s3", "-ICC_Profile:ProfileDescription", str(source)],
                                 capture_output=True, text=True, check=True).stdout.strip()
    assert description == "sRGB IEC61966-2.1"
    return rgb, icc, attrs, nested, {
        "software": software, "dimensions_xy": list(DIMENSIONS), "storage": "uint16 chunky RGB",
        "orientation_tag": orientation,
        "icc_description": description, "icc_sha256": sha256(icc).hexdigest(),
        "develop_controls": {k: attrs[k] for k in CONTROLS},
    }


def gradient(rgb):
    x0, y0, x1, y1 = CHART
    green = np.ascontiguousarray(rgb[y0:y1, x0:x1, 1], dtype=np.float32)
    blurred = cv2.GaussianBlur(green, (7, 7), 1.4)
    return cv2.magnitude(cv2.Sobel(blurred, cv2.CV_32F, 1, 0), cv2.Sobel(blurred, cv2.CV_32F, 0, 1))


def locate(first, second, center, search_radius=65):
    x, y = np.array(center) - CHART[:2]
    width, radius = 70, search_radius
    template = first[y - width:y + width, x - width:x + width]
    search = second[y - width - radius:y + width + radius, x - width - radius:x + width + radius]
    assert template.shape == (2 * width, 2 * width)
    assert search.shape == (2 * (width + radius), 2 * (width + radius))
    correlation = cv2.matchTemplate(search, template, cv2.TM_CCOEFF_NORMED)
    _, peak, _, (dx, dy) = cv2.minMaxLoc(correlation)
    assert 0 < dx < 2 * radius and 0 < dy < 2 * radius

    def subpixel(left, right):
        curvature = float(left + right - 2 * peak)
        return float(0.5 * (left - right) / curvature) if curvature < 0 else 0.0

    return np.array([
        dx - radius + subpixel(correlation[dy, dx - 1], correlation[dy, dx + 1]),
        dy - radius + subpixel(correlation[dy - 1, dx], correlation[dy + 1, dx]),
    ]), float(peak)


def mapped(coords, transform):
    return cv2.perspectiveTransform(np.float64([coords]), transform)[0]


def register(preview, tiff, patches):
    corners = np.float32(CORNERS)
    matches = [locate(preview, tiff, center) for center in CORNERS]
    assert min(score for _, score in matches) > 0.95
    shifts = np.float32([shift for shift, _ in matches])
    transform = cv2.getPerspectiveTransform(corners, corners + shifts)
    centers = {}
    for item in patches:
        x0, y0, x1, y1 = item["roi_xyxy_half_open"]
        centers[tuple(item["row_column_in_preview"])] = ((x0 + x1) / 2, (y0 + y1) / 2)
    held_out = [
        tuple(np.rint(np.mean([centers[r + dy, c + dx] for dy in (0, 1) for dx in (0, 1)], axis=0)).astype(int))
        for r in range(1, 6) for c in range(1, 4)
    ]
    check = []
    for center, projected in zip(held_out, mapped(held_out, transform), strict=True):
        shift, score = locate(preview, tiff, center)
        residual = shift - (projected - center)
        assert score > 0.85 and np.linalg.norm(residual) < 4.0
        check.append({"preview_xy": [int(x) for x in center], "shift_xy": shift.tolist(),
                      "gradient_correlation": score, "residual_xy": residual.tolist(),
                      "residual_px": float(np.linalg.norm(residual))})
    return transform, {
        "method": "Green Sobel magnitude, Gaussian sigma 1.4, normalized 140px template correlation; four-corner homography; 15 held-out grid junctions",
        "corner_matches": [
            {"preview_xy": list(point), "shift_xy": shift.tolist(), "gradient_correlation": score}
            for point, (shift, score) in zip(CORNERS, matches, strict=True)
        ],
        "preview_to_tiff_homography": transform.tolist(),
        "held_out": check,
        "max_held_out_residual_px": max(item["residual_px"] for item in check),
    }, held_out


def box_pairs(patches, transform):
    output = []
    for item in patches:
        x0, y0, x1, y1 = item["roi_xyxy_half_open"]
        assert x1 - x0 == y1 - y0 == 200
        points = [(x0, y0), (x1, y0), (x1, y1), (x0, y1), ((x0 + x1) / 2, (y0 + y1) / 2)]
        shifted = mapped(points, transform)
        shift = np.rint(shifted[-1] - points[-1]).astype(int)
        dx, dy = map(int, shift)
        mismatch = float(np.linalg.norm(shifted[:4] - np.array(points[:4]) - shift, axis=1).max())
        assert mismatch < 4.0
        target = [x0 + dx, y0 + dy, x1 + dx, y1 + dy]
        assert 0 <= target[0] < target[2] <= DIMENSIONS[0] and 0 <= target[1] < target[3] <= DIMENSIONS[1]
        output.append({"patch": item["patch"], "name": item["name"], "preview_xyxy": [x0, y0, x1, y1],
                       "tiff_xyxy": target, "shift_xy": [dx, dy],
                       "max_projected_corner_from_translated_box_px": mismatch})
    return output


def stack(rgb, boxes, key):
    return np.stack([rgb[y0:y1, x0:x1] for x0, y0, x1, y1 in (item[key] for item in boxes)])


def lab_stack(rgb, icc, temp, name, tificc):
    src, dst = temp / f"{name}-rgb.tif", temp / f"{name}-lab.tif"
    n, h, w, channels = rgb.shape
    assert channels == 3 and rgb.dtype in (np.uint8, np.uint16)
    tags = [(34675, 7, len(icc), icc, False)] if icc is not None else []
    tifffile.imwrite(src, rgb.reshape(n * h, w, 3), photometric="rgb", extratags=tags, metadata=None)
    opts = [] if icc is not None else ["-i*sRGB"]
    converted = subprocess.run(
        [tificc, "-t1", "-o*Lab4", "-w32", *opts, str(src), str(dst)],
        capture_output=True, text=True, check=True,
    )
    with tifffile.TiffFile(dst) as tif:
        page = tif.pages[0]
        assert int(page.photometric) == 8 and page.bitspersample == 32
        lab = page.asarray().reshape(rgb.shape)
    assert lab.dtype == np.float32 and np.isfinite(lab).all()
    return lab, converted.stderr.splitlines()[0] if converted.stderr else ""


def medians(lab):
    return np.median(lab, axis=(1, 2)).astype(np.float64)


def delta(reference, sample):
    return deltaE_ciede2000(reference, sample, kL=1, kC=1, kH=1)


def summarize(values):
    return {"mean": float(np.mean(values)), "median": float(np.median(values)),
            "p90": float(np.quantile(values, 0.9)), "max": float(np.max(values)),
            "max_patch": int(np.argmax(values)) + 1}


def endpoint_counts(pixels):
    return {"zero": np.sum(pixels == 0, axis=(0, 1, 2)).tolist(),
            "max": np.sum(pixels == np.iinfo(pixels.dtype).max, axis=(0, 1, 2)).tolist()}


def run(record, args):
    expected = record["baseline"]
    sharma = args.sharma_data
    assert digest(sharma) == SHARMA_SHA, "CIEDE2000 reference SHA-256 mismatch"
    check_exports(args.exports, expected["renders"])
    reference, patches, preview, camera_metadata = check_inputs(args.raw, args.preview, args.exiftool, record)
    assert [x["patch"] for x in patches] == list(range(1, 25))
    table = np.loadtxt(sharma)
    err = float(np.max(abs(delta(table[:, :3], table[:, 3:6]) - table[:, 6])))
    assert len(table) == 34 and err <= 0.00005

    preview_gradient = gradient(preview)
    report = {"scope": "Same DNG camera Natural embedded JPEG agreement; not reference-chart accuracy or firmware-mode calibration.",
              "reference": reference, "protocol_sha256": expected["protocol_sha256"],
              "camera_raw_metadata": camera_metadata,
              "engine": {"numpy": np.__version__, "opencv": cv2.__version__, "scikit_image": skimage_version,
                         "tifffile": tifffile.__version__, "ciede2000_reference_sha256": SHARMA_SHA,
                         "ciede2000_reference_cases": len(table), "ciede2000_reference_max_error": err,
                         "conversion": "LittleCMS tificc, relative colorimetric intent, BPC off, float32 CIELAB D50; TIFF embedded ICC; JPEG assigned builtin sRGB",
                         "roi": "Native 200×200 half-open boxes shifted by rounded transformed centers. No resampling; median per Lab component. Inset sensitivity uses center 100×100."},
              "renders": []}
    with TemporaryDirectory(dir=args.scratch, prefix="convert-") as temp_name:
        temp = Path(temp_name)
        for index, entry in enumerate(expected["renders"]):
            source = args.exports / entry["id"] / EXPORT_NAME
            rgb, icc, attrs, nested, meta = read_tiff(entry, source, args.exiftool)
            identity = {k: entry[k] for k in ("id", "sha256", "profile", "profile_digest",
                                              "as_shot_temperature", "as_shot_tint")}
            tiff_gradient = gradient(rgb)
            if index == 0:
                transform, reg, held_out = register(preview_gradient, tiff_gradient, patches)
                boxes = box_pairs(patches, transform)
                report["registration"] = reg
                report["roi_geometry"] = boxes
                ref_stack = stack(preview, boxes, "preview_xyxy")
                ref_lab, banner = lab_stack(ref_stack, None, temp, "preview", args.tificc)
                ref_icc_lab, _ = lab_stack(ref_stack, icc, temp, "preview-same-profile", args.tificc)
                # Same precision witness as verify_color_engines.py, using the actual embedded export ICC.
                samples = np.array([[[[0, 0, 0], [65535, 65535, 65535], [32768, 32768, 32768],
                                      [32769, 32769, 32769], [65535, 0, 0]]]], dtype=np.uint16)
                precise, _ = lab_stack(samples, icc, temp, "actual-icc-precision", args.tificc)
                precise = precise[0, 0]
                assert abs(precise[0, 0]) < 0.01 and abs(precise[1, 0] - 100) < 0.01
                assert precise[3, 0] > precise[2, 0]
                assert np.max(abs(precise[4] - [54.29, 80.81, 69.89])) < 0.1
                report["engine"]["one_uint16_step_delta_lstar"] = float(precise[3, 0] - precise[2, 0])
                reference = medians(ref_lab)
                reference_inset = medians(ref_lab[:, 50:150, 50:150])
                reference_icc = medians(ref_icc_lab)
                report["engine"]["tificc_banner"] = banner
                report["reference_endpoints_rgb"] = endpoint_counts(ref_stack)
                report["jpeg_srgb_assignment_sensitivity"] = summarize(delta(reference, reference_icc))
                first_gradient = tiff_gradient
                first_attrs, first_nested = attrs, nested
                anchors = [tuple(row) for row in np.rint(mapped([*CORNERS, *held_out], transform)).astype(int)]
            positions = [locate(first_gradient, tiff_gradient, center, 8) for center in anchors]
            relative_shift = max(float(np.linalg.norm(shift)) for shift, _ in positions)
            assert relative_shift < 1.0 and min(score for _, score in positions) > 0.8
            data = stack(rgb, boxes, "tiff_xyxy")
            converted, _ = lab_stack(data, icc, temp, entry["id"], args.tificc)
            lab = medians(converted)
            inset = medians(converted[:, 50:150, 50:150])
            difference = delta(reference, lab)
            controls = sorted(key for key in attrs.keys() | first_attrs.keys() if attrs.get(key) != first_attrs.get(key))
            nested_diff = sorted(key for key in nested.keys() | first_nested.keys()
                                 if nested.get(key) != first_nested.get(key))
            report["renders"].append({
                **identity, **meta, "develop_attribute_count": len(attrs),
                "develop_attribute_difference_keys_vs_first": controls,
                "nested_develop_difference_keys_vs_first": nested_diff,
                "unexpected_develop_difference_keys_vs_first": sorted(set(controls) -
                    {"CameraProfile", "CameraProfileDigest", "Temperature", "Tint"}),
                "tiff_to_first_registration_max_shift_px": relative_shift,
                "tiff_to_first_registration_min_correlation": min(score for _, score in positions),
                "endpoint_counts_rgb": endpoint_counts(data),
                "delta_e00": summarize(difference),
                "neutral_patch_19_to_24_delta_e00": summarize(difference[-6:]) | {
                    "max_patch": int(np.argmax(difference[-6:])) + 19,
                },
                "center_100px_delta_e00": summarize(delta(reference_inset, inset)),
                "center_100px_delta_e00_max_patchwise_change": float(np.max(abs(delta(reference_inset, inset) - difference))),
                "jpeg_same_embedded_icc_delta_e00": summarize(delta(reference_icc, lab)),
                "patches": [{"patch": box["patch"], "name": box["name"], "preview_median_lab_d50": r.tolist(),
                             "tiff_median_lab_d50": t.tolist(), "delta_lab_tiff_minus_preview": (t-r).tolist(),
                             "delta_e00": float(de), "endpoint_counts_rgb": endpoint_counts(px[None]),
                             "tiff_median_rgb_code": np.median(px, axis=(0, 1)).tolist()}
                            for box, r, t, de, px in zip(boxes, reference, lab, difference, data, strict=True)],
            })
    return report


def output_and_scratch(parser, args):
    if os.path.lexists(args.output):
        parser.error("output path already exists, including links")
    if not args.output.parent.is_dir() or not args.scratch.is_dir():
        parser.error("output parent and private scratch directory must already exist")


def write_report(path, report):
    payload = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--preview", type=Path, required=True)
    parser.add_argument("--exports", type=Path, required=True, help="directory containing the three profile export folders")
    parser.add_argument("--sharma-data", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True, help="existing private directory for temporary conversion files")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exiftool", default="exiftool")
    parser.add_argument("--tificc", default="tificc")
    args = parser.parse_args()
    output_and_scratch(parser, args)
    try:
        report = run(load_record(), args)
        write_report(args.output, report)
    except (AssertionError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Render check failed: {exc or 'fixture/transform validation failed'}\n")
    for item in report["renders"]:
        print(item["id"], item["delta_e00"])


if __name__ == "__main__":
    main()
