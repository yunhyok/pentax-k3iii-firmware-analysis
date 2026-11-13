"""Compare the K-3 II #1376 matrix export in Lightroom Classic 15.6 and 16.0."""
# SPDX-License-Identifier: GPL-2.0-only
if not __debug__:
    raise RuntimeError("Run without -O so the fixture checks remain enabled.")

import argparse
from io import BytesIO
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True

import numpy as np
from PIL import ImageCms
import tifffile

import check_lightroom_render as render

RECORD = render.ROOT / "analysis/color-engine-bridge.json"
RECORD_SHA = "97116d4e8d99381b6f2bb7001773dfe46c2961eb6525a689b711e9d63f6acb39"
RAW_NAME = "pentax-k3ii-1376.dng"
TIFF_NAME = "pentax-k3ii-1376.tif"
CHART_CRS_SHA = {
    "15.6": "8ac4dc50f599c1c1d2381537b6130952a6ed9f331eaa14e31240b4f992db3e59",
    "16.0": "7a77a9e4825cd50e35b628c9f68c75340ec227de87fd863f18410aac9906a4df",
}
RAW_SHA = "992c969286dc06b1690128a7b14ea74c5b5a46209b0fbf21e83df00807b050b9"
ICC_SHA = "0a8ef7d1d958d98225b3b71d93d9e8e3cecd9c302e014973d025d2a977ecf27c"
PROFILE = "PENTAX RAW matrix test 1376"
PROFILE_DIGEST = "1C7CF75BBFB3AA224BCEB9DAF7FBBBC9"
RDF_DESCRIPTION = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}Description"


def load_record():
    data = RECORD.read_bytes().replace(b"\r\n", b"\n")
    assert render.sha256(data).hexdigest() == RECORD_SHA, "Public engine bridge SHA-256 mismatch"
    return json.loads(data)


def rgb_difference(before, after):
    assert before.shape == after.shape and before.ndim == 3 and before.shape[2] == 3
    assert before.dtype == after.dtype == np.dtype("uint16") and before.size
    changed_pixels = 0
    changed, positive, negative, abs_sum = np.zeros((4, 3), dtype=np.int64)
    minimum, maximum = np.full(3, 65535), np.full(3, -65535)
    for start in range(0, before.shape[0], 128):
        diff = after[start:start + 128].astype(np.int32) - before[start:start + 128]
        changed_pixels += int(np.count_nonzero(np.any(diff, axis=2)))
        changed += np.count_nonzero(diff, axis=(0, 1))
        positive += np.count_nonzero(diff > 0, axis=(0, 1))
        negative += np.count_nonzero(diff < 0, axis=(0, 1))
        abs_sum += np.abs(diff).sum(axis=(0, 1), dtype=np.int64)
        minimum = np.minimum(minimum, diff.min(axis=(0, 1)))
        maximum = np.maximum(maximum, diff.max(axis=(0, 1)))
    pixels = before.shape[0] * before.shape[1]
    return {
        "total_pixels": pixels,
        "identical_pixel_arrays": changed_pixels == 0,
        "changed_pixels": changed_pixels,
        "changed_pixels_percent": changed_pixels * 100 / pixels,
        "changed_samples_rgb": changed.tolist(),
        "positive_delta_samples_rgb": positive.tolist(),
        "negative_delta_samples_rgb": negative.tolist(),
        "minimum_delta_rgb": minimum.tolist(),
        "maximum_delta_rgb": maximum.tolist(),
        "maximum_absolute_delta_rgb": np.maximum(np.abs(minimum), np.abs(maximum)).tolist(),
        "maximum_absolute_delta": int(max(np.abs(minimum).max(), np.abs(maximum).max())),
        "mean_absolute_delta_rgb": (abs_sum / pixels).tolist(),
    }


def field_diff(before, after):
    return {
        "added": {key: after[key] for key in sorted(after.keys() - before.keys())},
        "removed": {key: before[key] for key in sorted(before.keys() - after.keys())},
        "changed": {key: {"before": before[key], "after": after[key]}
                    for key in sorted(before.keys() & after.keys()) if before[key] != after[key]},
    }


def element_value(element):
    return {
        "tag": element.tag,
        "attributes": dict(sorted(element.attrib.items())),
        "text": (element.text or "").strip(),
        "children": [element_value(child) for child in element],
    }


def develop_fields(xmp):
    attributes, nested = {}, {}
    for node in xmp.iter(RDF_DESCRIPTION):
        for key, value in node.attrib.items():
            if key.startswith(render.CRS):
                name = key.removeprefix(render.CRS)
                attributes.setdefault(name, []).append(value)
        for element in node:
            if element.tag.startswith(render.CRS):
                name = element.tag.removeprefix(render.CRS)
                nested.setdefault(name, []).append(element_value(element))
    return attributes, nested


def require_develop(xmp, version):
    values = develop_fields(render.ET.fromstring(xmp))
    payload = json.dumps(values, sort_keys=True, ensure_ascii=False).encode("utf-8")
    assert render.sha256(payload).hexdigest() == CHART_CRS_SHA[version], "Chart CRS settings mismatch"


def read_tiff(path, expected_sha=None):
    if not path.is_file():
        raise ValueError(f"Not a TIFF file: {path}")
    with path.open("rb") as stream:
        file_sha = render.file_digest(stream, "sha256").hexdigest()
        assert expected_sha is None or file_sha == expected_sha, "Chart TIFF SHA-256 mismatch"
        size = stream.tell()
        stream.seek(0)
        with tifffile.TiffFile(stream) as tiff:
            assert len(tiff.pages) == 1
            page = tiff.pages[0]
            assert page.shape == (4000, 6016, 3) and page.dtype == np.dtype("uint16")
            assert page.bitspersample == 16 and page.samplesperpixel == 3 and not page.extrasamples
            assert int(page.compression) == 1 and int(page.sampleformat) == 1
            assert int(page.photometric) == 2 and int(page.planarconfig) == 1
            orientation = page.tags.get(274)
            assert orientation is None or orientation.value == 1
            icc = page.tags[34675].value
            icc_sha = render.sha256(icc).hexdigest()
            assert icc_sha == ICC_SHA, "ProPhoto ICC SHA-256 mismatch"
            assert int.from_bytes(icc[:4], "big") == len(icc)
            assert icc[16:24] == b"RGB XYZ " and icc[36:40] == b"acsp"
            description = ImageCms.ImageCmsProfile(BytesIO(icc)).profile.profile_description
            assert description == "ProPhoto RGB"
            xmp = page.tags[700].value
            attributes, nested = develop_fields(render.ET.fromstring(xmp))
            assert attributes.get("CameraProfile") == [PROFILE]
            assert attributes.get("CameraProfileDigest") == [PROFILE_DIGEST]
            assert attributes.get("RawFileName") == [RAW_NAME]
            software = page.tags[305].value
            assert "Lightroom Classic" in software
            pixels = page.asarray()
        stream.seek(0)
        assert render.file_digest(stream, "sha256").hexdigest() == file_sha, "TIFF changed during reading"
    pixels_le = np.ascontiguousarray(pixels, dtype="<u2")
    return pixels, icc, xmp, attributes, nested, {
        "filename": TIFF_NAME, "bytes": size, "file_sha256": file_sha,
        "pixels_le_rgb16_sha256": render.sha256(memoryview(pixels_le).cast("B")).hexdigest(),
        "software": software, "shape_yxc": list(pixels.shape), "bits_per_sample": 16,
        "sample_format": "unsigned integer", "compression": "none", "photometric": "RGB",
        "orientation_tag": None if orientation is None else orientation.value,
        "icc_sha256": icc_sha, "icc_description": description,
        "xmp_sha256": render.sha256(xmp).hexdigest(),
        "develop_attribute_count": sum(map(len, attributes.values())),
        "develop_nested_count": sum(map(len, nested.values())),
        "recorded_controls": {key: attributes.get(key) for key in (
            "RawFileName", "Version", "CameraProfile", "CameraProfileDigest", *render.CONTROLS,
        )},
    }


def require_export(actual, expected):
    """Allow fresh export metadata while pinning the observed rendering controls."""
    changing = {"bytes", "file_sha256", "xmp_sha256"}
    assert {key: value for key, value in actual.items() if key not in changing} == {
        key: value for key, value in expected.items() if key not in changing
    }, "Chart export does not match the required geometry, engine, profile or develop settings"


def compare(raw, old_path, new_path, allow_fresh_export=False):
    assert not new_path.samefile(old_path), "Use distinct chart TIFFs"
    frozen = load_record()
    raw_before = render.digest(raw)
    assert raw_before == RAW_SHA, "Research catalog RAW copy SHA-256 mismatch"
    old_spec, new_spec = frozen["old_tiff"], frozen["new_tiff"]
    old_rgb, old_icc, old_xmp, old_attrs, old_nested, old = read_tiff(
        old_path, None if allow_fresh_export else old_spec["file_sha256"])
    new_rgb, new_icc, new_xmp, new_attrs, new_nested, new = read_tiff(
        new_path, None if allow_fresh_export else new_spec["file_sha256"])
    require_export(old, old_spec)
    require_export(new, new_spec)
    require_develop(old_xmp, "15.6")
    require_develop(new_xmp, "16.0")
    xmp_diff = {"attributes": field_diff(old_attrs, new_attrs), "nested": field_diff(old_nested, new_nested)}
    assert xmp_diff == frozen["develop_xmp_diff"], "Unexpected CRS develop settings difference"
    raw_after = render.digest(raw)
    assert raw_before == raw_after, "Research catalog RAW copy changed during comparison"
    return {
        "scope": "Same pinned K-3 II #1376 RAW/profile, two exports. RGB code comparison; only exact ICC equality implies the same encoded color space.",
        "catalog_raw_copy": {"filename": RAW_NAME, "sha256_before": raw_before, "sha256_after": raw_after},
        "old_tiff": old, "new_tiff": new,
        "icc_bytes_equal": old_icc == new_icc,
        "whole_xmp_bytes_equal": old_xmp == new_xmp,
        "develop_xmp_diff": xmp_diff,
        "pixels": rgb_difference(old_rgb, new_rgb),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--old-tiff", required=True, type=Path)
    parser.add_argument("--new-tiff", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-fresh-export", action="store_true",
                        help="allow new TIFF container hashes while requiring recorded pixels and controls")
    args = parser.parse_args()
    if os.path.lexists(args.output) or not args.output.parent.is_dir():
        parser.error("output must be a new file in an existing directory")
    try:
        result = compare(args.raw, args.old_tiff, args.new_tiff, args.allow_fresh_export)
        render.write_report(args.output, result)
    except (AssertionError, OSError, ValueError, render.ET.ParseError) as error:
        parser.exit(1, f"Export comparison failed: {error or 'fixture validation failed'}\n")


if __name__ == "__main__":
    main()
