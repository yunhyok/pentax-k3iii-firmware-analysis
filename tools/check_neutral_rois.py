"""Replay six registered neutral CFA patches from raw.pixls.us #1376.

Requires NumPy, tifffile and imagecodecs. The JPEG is identity-checked;
its existing linear-sRGB Y statistics come from the pinned ROI protocol.
"""

import argparse
from hashlib import file_digest, sha256
import json
from pathlib import Path
import platform

import imagecodecs
import numpy as np
import tifffile


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "analysis/color-comparison-protocol.json"
PROTOCOL_SHA256 = "eb974b4a891ee444295ee0a08a5f09237e4bd590f9be0fe6b2949472344c562f"
PHASES = ((0, 0), (0, 1), (1, 0), (1, 1))
NAMES = ("R", "G1", "G2", "B")
PATCHES = tuple(range(19, 25))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as file:
        return file_digest(file, "sha256").hexdigest()


def cfa_planes(sensor, box, origin):
    x0, y0, x1, y1 = box
    ox, oy = origin
    require(0 <= x0 < x1 <= sensor.shape[1] and 0 <= y0 < y1 <= sensor.shape[0],
            "CFA box outside the sensor")
    planes = [sensor[y0 + (row - (y0 - oy)) % 2:y1:2, x0 + (col - (x0 - ox)) % 2:x1:2]
              for row, col in PHASES]
    require(all(plane.size for plane in planes), "CFA box misses a phase")
    return planes


def quadrants(box):
    x0, y0, x1, y1 = box
    xm, ym = (x0 + x1) // 2, (y0 + y1) // 2
    return ((x0, y0, xm, ym), (xm, y0, x1, ym), (x0, ym, xm, y1), (xm, ym, x1, y1))


def normalize(values, black, white):
    return (np.asarray(values, dtype=float) - black) / (white - black)


def medians(planes):
    return np.array([np.median(plane) for plane in planes])


def ratios(values):
    r, g1, g2, b = values
    green = (g1 + g2) / 2
    return dict(G_mean=float(green), G1_minus_G2_percent=float(100 * (g1 - g2) / green),
                R_over_G=float(r / green), B_over_G=float(b / green))


def inspect(dng, preview):
    # Treat Git CRLF conversion as the same protocol document.
    protocol_bytes = PROTOCOL.read_bytes().replace(b"\r\n", b"\n")
    require(sha256(protocol_bytes).hexdigest() == PROTOCOL_SHA256, "ROI protocol SHA-256 mismatch")
    protocol = json.loads(protocol_bytes)
    reference = protocol["reference"]
    raw_rois = protocol["raw_cfa_checks"]
    summary = raw_rois["summary"]
    preview_sha = digest(preview)
    require(preview_sha == reference["preview_sha256"], "Preview JPEG SHA-256 mismatch")

    with dng.open("rb") as source:
        raw_sha = file_digest(source, "sha256").hexdigest()
        require(raw_sha == reference["raw_sha256"] == summary["source_sha256"], "DNG SHA-256 mismatch")
        source.seek(0)
        with tifffile.TiffFile(source) as tif:
            page = tif.pages[0].pages[0]
            expected_tags = {259: 7, 262: 32803, 33421: (2, 2), 33422: b"\0\1\1\2", 50711: 1,
                             50713: (2, 2), 50714: (1, 1, 1, 1), 50717: 16317,
                             50719: (6, 12), 50720: (6016, 4000), 50829: (4, 10, 4028, 6038)}
            require(all(code in page.tags and page.tags[code].value == value
                        for code, value in expected_tags.items()),
                    "Unexpected TIFF/DNG tag or registration basis")
            require(all(page.tags.get(code) is None for code in (50710, 50712, 50715, 50716)),
                    "Unexpected CFAPlaneColor, LinearizationTable or black delta")
            require(page.shape == (4032, 6080) and page.dtype == np.uint16 and page.samplesperpixel == 1,
                    "Unexpected CFA geometry")
            sensor = page.asarray()
    black, white = expected_tags[50714][0], expected_tags[50717]
    top, left, _, _ = expected_tags[50829]
    crop_x, crop_y = left + expected_tags[50719][0], top + expected_tags[50719][1]
    require([crop_x, crop_y] == summary["nominal_sensor_offset_xy"], "Crop offset mismatch")
    observations = []
    for patch in PATCHES:
        raw, jpg = raw_rois["patches"][patch - 1], protocol["patches"][patch - 1]
        require(raw["patch"] == jpg["patch"] == patch, "Incorrect patch sequence")
        x0, y0, x1, y1 = raw["raw_crop_roi_xyxy_half_open"]
        jx, jy, jx1, jy1 = jpg["roi_xyxy_half_open"]
        require(x1 - x0 == y1 - y0 == jx1 - jx == jy1 - jy == 200,
                "Unexpected patch dimensions")
        box = x0 + crop_x, y0 + crop_y, x1 + crop_x, y1 + crop_y
        planes = cfa_planes(sensor, box, (left, top))
        require([int(plane.max()) for plane in planes] == raw["max_sample"] and
                all(plane.size == 10_000 and black < plane.min() <= plane.max() < white for plane in planes),
                "CFA phase, count, clipping or registration mismatch")
        dns = medians(planes)
        whole = normalize(dns, black, white)
        quadrants_dn = np.array([medians(cfa_planes(sensor, q, (left, top))) for q in quadrants(box)])
        quads = normalize(quadrants_dn, black, white)
        observations.append(dict(
            patch=patch, name=jpg["name"], jpeg_roi_xyxy_half_open=jpg["roi_xyxy_half_open"],
            raw_crop_roi_xyxy_half_open=raw["raw_crop_roi_xyxy_half_open"],
            raw_sensor_roi_xyxy_half_open=list(box), raw_crop_minus_preview_shift_xy=[x0-jx, y0-jy],
            samples_per_cfa_plane=10_000, cfa_median_dn=dns.tolist(),
            cfa_median_normalized=whole.tolist(), cfa_quadrant_median_dn=quadrants_dn.tolist(),
            cfa_quadrant_median_normalized=quads.tolist(),
            cfa_quadrant_range_over_whole_median_percent=(100 * np.ptp(quads, axis=0) / whole).tolist(),
            **ratios(whole), cfa_quadrant_ratios=[ratios(row) for row in quads],
            jpeg_linear_Y_median=jpg["preview_linear_srgb_Y_quantiles_05_50_95"][1],
            jpeg_Y_quadrant_range_over_whole_median_percent=jpg["preview_Y_quadrant_median_range_over_median_percent"],
        ))

    def rank(key):
        values = [row[key] for row in observations]
        require(len(set(values)) == len(values), f"Ties require explicit ranking for {key}")
        return [row["patch"] for row in sorted(observations, key=lambda row: row[key], reverse=True)]

    green_rank, jpeg_rank = rank("G_mean"), rank("jpeg_linear_Y_median")
    difference_sq = sum((green_rank.index(p) - jpeg_rank.index(p)) ** 2 for p in PATCHES)
    n = len(PATCHES)
    stability = {}
    for key in ("R_over_G", "B_over_G"):
        values = np.array([row[key] for row in observations])
        stability[key] = dict(min=float(values.min()), max=float(values.max()),
                              range_over_median_percent=float(100 * np.ptp(values) / np.median(values)))

    return dict(
        scope="Neutral patch sensor statistics and JPEG brightness rank only. No WB fit, DCP fit, or Lightroom render.",
        sources=dict(raw_pixls_source_id=reference["raw_pixls_source_id"],
                     license=reference["license"], dng_sha256=raw_sha, preview_jpeg_sha256=preview_sha,
                     roi_protocol="analysis/color-comparison-protocol.json", roi_protocol_sha256_lf=PROTOCOL_SHA256),
        jpeg_statistics_source="Pinned ROI protocol; JPEG bytes verified by SHA-256",
        versions=dict(python=platform.python_version(), numpy=np.__version__, tifffile=tifffile.__version__,
                      imagecodecs=imagecodecs.__version__),
        cfa_phase_order=list(NAMES), quadrant_order=["top-left", "top-right", "bottom-left", "bottom-right"],
        tags=dict(CFARepeatPatternDim=[2, 2], CFAPattern=[0, 1, 1, 2], CFALayout=1, CFAPlaneColor=None,
                  LinearizationTable=None, BlackLevelRepeatDim=[2, 2], BlackLevel=[black] * 4,
                  BlackLevelDeltaH=None, BlackLevelDeltaV=None, WhiteLevel=white),
        normalization=f"(DN - {black}) / ({white} - {black}); common black and white values, no linearization or deltas",
        geometry=dict(active_area_tlbr=list(expected_tags[50829]),
                      default_crop_origin_xy=list(expected_tags[50719]), absolute_sensor_crop_origin_xy=[crop_x, crop_y],
                      registration_method=protocol["raw_cfa_checks"]["summary"]["registration_method"],
                      registration_corner_checks=summary["registration_checks"]),
        patches=observations,
        summary=dict(G_rank_bright_to_dark=green_rank, JPEG_Y_rank_bright_to_dark=jpeg_rank,
                     spearman_G_vs_JPEG_Y=1-6*difference_sq/(n*(n*n-1)),
                     max_abs_G1_G2_percent=max(abs(row["G1_minus_G2_percent"]) for row in observations),
                     ratio_stability=stability),
    )


def self_test():
    rows, cols = np.indices((10, 11))
    base = np.array([[10, 20], [30, 40]])
    sensor = base[(rows - 1) % 2, (cols - 2) % 2] + 40 * (rows >= 5) + 20 * (cols >= 6)
    boxes = quadrants((3, 2, 9, 8))
    result = np.array([medians(cfa_planes(sensor, box, (2, 1))) for box in boxes])
    np.testing.assert_array_equal(result, [[10, 20, 30, 40], [30, 40, 50, 60],
                                          [50, 60, 70, 80], [70, 80, 90, 100]])
    np.testing.assert_array_equal(normalize([10, 60, 110], 10, 110), [0, 0.5, 1])
    print("Synthetic CFA phase, odd quadrant origin, quadrant order and normalization passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dng", nargs="?", type=Path)
    parser.add_argument("preview_jpeg", nargs="?", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        if args.dng is not None or args.preview_jpeg is not None:
            parser.error("--self-test takes no input files")
        self_test()
        return
    if args.dng is None or args.preview_jpeg is None:
        parser.error("--output requires DNG and extracted preview JPEG paths")
    if args.output.exists():
        parser.error("output path already exists")
    try:
        result = inspect(args.dng, args.preview_jpeg)
        payload = json.dumps(result, indent=2, allow_nan=False) + "\n"
        with args.output.open("x", encoding="utf-8", newline="\n") as file:
            file.write(payload)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
