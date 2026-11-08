"""Replay hash-pinned K-3 III #4678 and Q7 #1760 Lightroom export checks."""
import argparse
from fractions import Fraction
from hashlib import file_digest, sha256
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

if not __debug__:
    raise RuntimeError("Run without -O so validation remains enabled.")
sys.dont_write_bytecode = True

import numpy as np
from PIL import Image
import tifffile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from inspect_adobe_profiles import describe

RECORD = ROOT / "analysis/lightroom-model-exports.json"
SOURCE = ROOT / "analysis/raw-test-inputs.json"
SOURCE_SHA = "a06f1b920f7270d96bb095de424d0b801b55bd47520c2bd534fff9b16c0ce455"
RECORD_SHA = "77243cba4f02d164362839d111110c17c26cbec79a11f2c98ae66d5a48e79136"
SAMPLES = {"k3iii": 4678, "q7": 1760}
PROPHOTO_SHA = "0a8ef7d1d958d98225b3b71d93d9e8e3cecd9c302e014973d025d2a977ecf27c"
CRS = "{http://ns.adobe.com/camera-raw-settings/1.0/}"
EXPECTED_XMP = {"WhiteBalance": "As Shot", "Exposure2012": "0.00",
                "ProcessVersion": "15.4", "HDREditMode": "0"}
CROP_TAGS = ("CropLeft", "CropTop", "CropRight", "CropBottom")
CONTROLS = ("Contrast2012", "Highlights2012", "Shadows2012", "Whites2012", "Blacks2012",
            "LensProfileEnable", "AutoLateralCA", "Sharpness", "SharpenRadius", "SharpenDetail",
            "SharpenEdgeMasking", "LuminanceSmoothing", "ColorNoiseReduction", "HasSettings")
DCP_TAGS = {"UniqueCameraModel", "ProfileName", "ColorMatrix1", "ColorMatrix2",
            "CalibrationIlluminant1", "CalibrationIlluminant2"}


def digest(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def canonical_digest(value):
    return sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def load_source(data):
    normalized = data.replace(b"\r\n", b"\n")
    assert sha256(normalized).hexdigest() == SOURCE_SHA, "Source fixture SHA-256 mismatch"
    return json.loads(normalized)


def exif_metadata(exiftool, path, *tags):
    process = subprocess.run([exiftool, "-G1", "-a", "-s", "-j", *tags, str(path)],
                             capture_output=True, text=True, check=True)
    record, = json.loads(process.stdout)
    record.pop("SourceFile")
    return record


def raw_geometry(path):
    with tifffile.TiffFile(path) as tif, path.open("rb") as stream:
        main = tif.pages[0]
        raw = main.pages[0]
        assert int(raw.photometric) == 32803 and 51125 not in main.tags and 51125 not in raw.tags
        orientation = int(main.tags[274].value)
        assert orientation == 1 and 274 not in raw.tags
        assert raw.tags[50718].value == (1, 1, 1, 1)
        x, y = raw.tags[50719].value
        width, height = raw.tags[50720].value
        top, left, bottom, right = raw.tags[50829].value
        assert 0 <= x and 0 <= y and x + width <= right - left and y + height <= bottom - top
        assert bottom <= raw.shape[0] and right <= raw.shape[1]
        tag = main.tags[50708]
        assert int(tag.dtype) == 2 and tag.count > 4
        stream.seek(tag.valueoffset)
        model = stream.read(tag.count)
        assert model.endswith(b"\0")
        return {
            "model": main.tags["Model"].value, "unique_camera_model": model[:-1].decode("ascii"),
            "unique_camera_model_ascii_hex_including_nul": model.hex(), "ifd0_orientation": orientation,
            "cfa_size_xy": list(raw.shape[::-1]), "cfa_bits_per_sample": raw.bitspersample,
            "active_area_tlbr": [top, left, bottom, right],
            "default_crop_origin_xy_relative_to_active_area": [x, y],
            "default_crop_bounds_xyxy_in_cfa": [left + x, top + y, left + x + width, top + y + height],
            "default_scale_xy": [1, 1], "default_user_crop_tag_present": False,
            "expected_unresized_tiff_size_xy": [width, height],
        }


def check_raw(raw, record, exiftool):
    assert raw.stat().st_size == record["bytes"] and digest(raw) == record["sha256"], "RAW SHA-256/size mismatch"
    geometry = raw_geometry(raw)
    assert geometry["model"] == record["metadata_numeric"]["IFD0:Model"]
    assert geometry["unique_camera_model"] == record["metadata_numeric"]["IFD0:UniqueCameraModel"]
    labels = exif_metadata(exiftool, raw, "-Pentax:ImageTone", "-Pentax:WhiteBalance", "-Pentax:ColorSpace",
                           "-SubIFD1:PreviewColorSpace", "-IFD0:AsShotNeutral", "-IFD0:BaselineExposure")
    for name in ("Pentax:ImageTone", "Pentax:WhiteBalance", "Pentax:ColorSpace", "SubIFD1:PreviewColorSpace"):
        assert labels.get(name) == record["maker_note_labels"].get(name)
    preview = record["embedded_previews"][0]
    assert preview["tag"] == "SubIFD1:PreviewImage"
    data = subprocess.run([exiftool, "-b", "-SubIFD1:PreviewImage", str(raw)],
                          capture_output=True, check=True).stdout
    assert len(data) == preview["bytes"] and sha256(data).hexdigest() == preview["sha256"]
    with Image.open(BytesIO(data)) as image:
        assert image.format == "JPEG" and image.mode == "RGB" and list(image.size) == preview["dimensions"]
        assert not image.info.get("icc_profile")
        tags = image.getexif()
        assert 274 not in tags and 272 not in tags
        image.verify()
    return {
        "source_id": record["source_id"], "source_url": record["download_url"], "license": record["license"],
        "sha256": record["sha256"], "bytes": record["bytes"], "geometry": geometry, "camera_metadata": labels,
        "preview": {"tag": preview["tag"], "sha256": preview["sha256"], "dimensions_xy": preview["dimensions"],
                    "embedded_icc": False, "jpeg_orientation_tag": None, "jpeg_model_tag": None,
                    "dng_preview_color_space": preview["dng_preview_color_space"],
                    "interpretation": preview["interpretation"]},
    }


def check_dcp(path, record, geometry):
    expected = record["private_experimental_dcp"]
    assert path.stat().st_size == expected["output_bytes"], "DCP size mismatch"
    data = path.read_bytes()
    assert sha256(data).hexdigest() == expected["output_sha256"], "DCP SHA-256 mismatch"
    parsed = describe(data)
    tags = parsed["tags"]
    assert set(tags) == DCP_TAGS
    unique = tags["UniqueCameraModel"]
    model = bytes.fromhex(geometry["unique_camera_model_ascii_hex_including_nul"])
    assert unique["text"] == geometry["unique_camera_model"] and unique["sha256"] == sha256(model).hexdigest()
    profile = tags["ProfileName"]["text"]
    assert profile == f'PENTAX RAW matrix test {record["source_id"]}'
    return {"profile_name": profile, "sha256": parsed["sha256"], "bytes": parsed["bytes"],
            "unique_camera_model_exact_bytes_match": True}


def check_develop(attrs, profile, pins, crop):
    assert attrs.get("CameraProfile") == profile, "CameraProfile name mismatch"
    assert attrs.get("CameraProfileDigest") == pins["profile_digest"], "CameraProfileDigest mismatch"
    assert all(attrs.get(tag) == value for tag, value in EXPECTED_XMP.items()), "Develop setting mismatch"
    assert (int(attrs["Temperature"]), int(attrs["Tint"])) == (pins["temperature"], pins["tint"]), "As Shot readout mismatch"
    active = "True" if crop is not None else "False"
    expected = crop if crop is not None else (0, 0, 1, 1)
    assert attrs.get("HasCrop") == active, "HasCrop mismatch"
    assert tuple(Fraction(attrs[tag]) for tag in CROP_TAGS) == expected, "Crop bounds mismatch"
    assert Fraction(attrs["CropAngle"]) == 0, "Crop angle mismatch"


def read_tiff(path, geometry, profile, pins, crop, exiftool):
    tiff_sha = digest(path)
    assert tiff_sha == pins["tiff_sha256"], "TIFF SHA-256 mismatch"
    width, height = geometry["expected_unresized_tiff_size_xy"]
    with tifffile.TiffFile(path) as tif:
        assert len(tif.pages) == 1
        page = tif.pages[0]
        assert page.shape == (height, width, 3) and page.dtype == np.dtype("uint16"), "TIFF shape or uint16 type mismatch"
        assert (page.photometric, page.planarconfig, page.samplesperpixel) == (2, 1, 3)
        assert (page.bitspersample, page.sampleformat, page.compression) == (16, 1, 1)
        orientation = page.tags[274].value if 274 in page.tags else None
        assert orientation in (None, 1)
        assert page.tags["Model"].value == geometry["model"], "TIFF model mismatch"
        assert sha256(page.tags[34675].value).hexdigest() == PROPHOTO_SHA, "ProPhoto ICC SHA-256 mismatch"
        software = page.tags["Software"].value
        assert "Lightroom Classic 15.6" in software
        xmp = ET.fromstring(page.tags[700].value)
        pairs = [(key.removeprefix(CRS), value) for node in xmp.iter() for key, value in node.attrib.items()
                 if key.startswith(CRS)]
        attrs = dict(pairs)
        assert len(attrs) == len(pairs)
        check_develop(attrs, profile, pins, crop)
        rgb = page.asarray()
        assert rgb.shape == (height, width, 3) and rgb.dtype == np.dtype("uint16")
    icc = exif_metadata(exiftool, path, "-ICC_Profile:ProfileDescription")["ICC_Profile:ProfileDescription"]
    assert icc == "ProPhoto RGB"
    return {
        "tiff_sha256": tiff_sha, "tiff_bytes": path.stat().st_size, "model": geometry["model"],
        "dimensions_xy": [width, height], "bits_per_sample": 16, "sample_format": "unsigned integer",
        "samples_per_pixel": 3, "photometric": "RGB", "planar": "chunky", "compression": "none",
        "orientation_tag": orientation, "icc_description": icc, "icc_sha256": PROPHOTO_SHA,
        "software": software, "profile": attrs["CameraProfile"], "profile_digest": attrs["CameraProfileDigest"],
        "develop_attribute_count": len(attrs),
        "develop_controls": {key: attrs[key] for key in (*EXPECTED_XMP, "Temperature", "Tint", "HasCrop",
                                                        *CROP_TAGS, "CropAngle", *CONTROLS) if key in attrs},
        "decoded_pixel_count": width * height,
        "decoded_little_endian_rgb16_sha256": sha256(np.ascontiguousarray(rgb, dtype="<u2")).hexdigest(),
        "decoded_channel_min_rgb": rgb.min(axis=(0, 1)).tolist(),
        "decoded_channel_max_rgb": rgb.max(axis=(0, 1)).tolist(),
    }


def measure(fixture, source, args):
    records = {item["source_id"]: item for item in source["samples"]}
    measured = {}
    for key, number in SAMPLES.items():
        raw, dcp, tiff = getattr(args, key)
        pins = fixture["pins"][key]
        record = records[number]
        raw_report = check_raw(raw, record, args.exiftool)
        geometry = raw_report["geometry"]
        profile = check_dcp(dcp, record, geometry)
        crop = None
        if key == "q7":
            top, left, bottom, right = geometry["active_area_tlbr"]
            x, y = geometry["default_crop_origin_xy_relative_to_active_area"]
            w, h = geometry["expected_unresized_tiff_size_xy"]
            crop = (Fraction(x, right - left), Fraction(y, bottom - top),
                    Fraction(x + w, right - left), Fraction(y + h, bottom - top))
        result = read_tiff(tiff, geometry, profile["profile_name"], pins, crop, args.exiftool)
        measured[key] = {"raw": raw_report, "dcp": profile, "render": result}
    return measured


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--k3iii", type=Path, nargs=3, required=True, metavar=("RAW", "DCP", "TIFF"))
    parser.add_argument("--q7", type=Path, nargs=3, required=True, metavar=("RAW", "DCP", "TIFF"))
    parser.add_argument("--exiftool", default="exiftool")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output) or not args.output.parent.is_dir():
        parser.error("output must be a new file in an existing directory, including links")
    try:
        source = load_source(SOURCE.read_bytes())
        fixture = json.loads(RECORD.read_bytes())
        assert fixture["schema_version"] == 1 and canonical_digest(fixture) == RECORD_SHA, "Export fixture SHA-256 mismatch"
        assert fixture["provenance"]["source_record_sha256_lf"] == SOURCE_SHA
        result = measure(fixture, source, args)
        assert result == fixture["measurements"], "Replay differs from recorded measurements"
        text = json.dumps({**fixture, "measurements": result}, ensure_ascii=False, indent=2, allow_nan=False)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text + "\n")
    except (AssertionError, OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Lightroom model export check failed: {error or 'metadata or pixel validation failed'}\n")
    print("Verified K-3 III #4678 and Q7 #1760: source, DCP, TIFF metadata, and full RGB16 decode.")


if __name__ == "__main__":
    main()
