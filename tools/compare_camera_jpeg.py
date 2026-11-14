"""Compare firmware-derived colour with the JPEG the camera made from the same RAW data.

Two renderings of a K-3 Mark III RAW file (PEF or DNG) are compared with the
camera's own JPEG (a separate file, or the preview stored in the RAW file):

  model    the firmware colour stages evaluated directly (colour matrix, gamma
           curve, YC conversion, chroma suppress), with the exposure scale the
           firmware itself implies.  Nothing is fitted.
  profile  a DCP built by build_firmware_dcp.py, applied with the DNG reference
           pipeline (ForwardMatrix, exposure, LookTable, tone curve).

Only geometry is aligned (the JPEG has lens corrections and a small crop).
The result is colour difference CIEDE2000 over 16x16-pixel block means of the
half-size image.

Needs: unicorn, numpy, rawpy, opencv-python.  The RAW/JPEG files are yours;
nothing is downloaded.

Example
    python tools/compare_camera_jpeg.py IMGP0001.PEF --jpeg IMGP0001.JPG \\
        --decoded .private/my-decode/decoded.bin --output my-comparison.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from math import log2
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

import firmware_color_model as model          # noqa: E402

IMAGE_TONE = {0: "natural", 1: "bright", 2: "portrait", 3: "landscape", 4: "vibrant", 5: "monochrome",
              6: "muted", 7: "reversal-film", 8: "bleach-bypass", 9: "radiant", 11: "flat"}
ADOBE_RGB_TO_XYZ = np.array([[0.5767309, 0.1855540, 0.1881852], [0.2973769, 0.6273491, 0.0752741], [0.0270343, 0.0706872, 0.9911085]])
SRGB_TO_XYZ = np.array([[0.4124564, 0.3575761, 0.1804375], [0.2126729, 0.7151522, 0.0721750], [0.0193339, 0.1191920, 0.9503041]])


# -- PENTAX maker note (own reader; tag numbers as documented by ExifTool) ------

def _ifd(data, offset, order, base=0):
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8}
    entries = {}
    for i in range(struct.unpack_from(order + "H", data, offset)[0]):
        tag, kind, count = struct.unpack_from(order + "HHI", data, offset + 2 + 12 * i)
        size = sizes.get(kind, 1) * count
        at = offset + 2 + 12 * i + 8
        if size > 4:
            at = struct.unpack_from(order + "I", data, at)[0] + base
        entries[tag] = (kind, count, data[at:at + size])
    return entries


def _first(entry, order):
    kind, count, payload = entry
    fmt = {1: "B", 3: "H", 4: "I", 8: "h", 9: "i"}.get(kind)
    return struct.unpack_from(order + fmt, payload)[0] if fmt else None


CUSTOM_IMAGE_SETTINGS = 0x247      # maker-note tag with the Custom Image setting values of the shot
SETTINGS = ("saturation", "hue", "key", "contrast", "highlight", "shadow")


def capture_info(path: Path) -> dict:
    """Image tone, its six settings, colour space, exposure gain value and DNG BaselineExposure of a RAW file."""
    data = Path(path).read_bytes()
    order = "<" if data[:2] == b"II" else ">"
    ifd0 = _ifd(data, struct.unpack_from(order + "I", data, 4)[0], order)
    info = {}
    if 50730 in ifd0:
        numerator, denominator = struct.unpack(order + "ii", ifd0[50730][2])
        info["baseline_exposure"] = numerator / denominator
    note = None
    if 0x8769 in ifd0:
        exif = _ifd(data, _first(ifd0[0x8769], order), order)
        note = exif.get(0x927C, (0, 0, None))[2]
    if note is None and 0xC634 in ifd0:
        note = ifd0[0xC634][2]
    if note:
        start = data.find(note[:64])
        if note[:4] == b"AOC\0":
            note_order, first = (">" if note[4:6] == b"MM" else "<"), start + 6
        elif note[:8] == b"PENTAX \0":
            note_order, first = (">" if note[8:10] == b"MM" else "<"), start + 10
        else:
            raise ValueError("unknown maker note header")
        tags = _ifd(data, first, note_order, base=start)
        for name, tag in (("image_tone", 0x4F), ("color_space", 0x37), ("mid_level", 0x9D), ("white_level", 0x7E)):
            if tag in tags:
                info[name] = _first(tags[tag], note_order)
        if CUSTOM_IMAGE_SETTINGS in tags and len(tags[CUSTOM_IMAGE_SETTINGS][2]) >= 12:
            # The camera stores its setting record as it is: little-endian 16-bit values, -4..+4,
            # 0x8000 where a setting does not apply.  Routine 0x52f835dc copies the first six
            # into the tuning input in this order.
            values = struct.unpack_from(f"<{len(tags[CUSTOM_IMAGE_SETTINGS][2]) // 2}h", tags[CUSTOM_IMAGE_SETTINGS][2])
            info["settings"] = {name: (value if -4 <= value <= 4 else 0) for name, value in zip(SETTINGS, values)}
            info["toning"] = values[12] if len(values) > 12 and 0 <= values[12] <= 8 else 0
    return info


def firmware_baseline_exposure(exposure_gain: int, white: float, black: float, bits: int = 14) -> float:
    """BaselineExposure as the firmware computes it for a DNG (routine at 0x53127888)."""
    return log2(1448.0 / (2048.0 * (((1 << bits) - 1) / (white - black)) * (exposure_gain / 8192.0)))


# -- colour difference ---------------------------------------------------------------

def to_lab(linear_rgb, rgb_to_xyz=SRGB_TO_XYZ):
    t = (np.asarray(linear_rgb) @ rgb_to_xyz.T) / np.array([0.95047, 1.0, 1.08883])
    f = np.where(t > (6 / 29) ** 3, np.cbrt(np.maximum(t, 1e-12)), t / (3 * (6 / 29) ** 2) + 4 / 29)
    return np.stack([116 * f[..., 1] - 16, 500 * (f[..., 0] - f[..., 1]), 200 * (f[..., 1] - f[..., 2])], axis=-1)


def delta_e_2000(lab1, lab2):
    l1, a1, b1 = lab1[..., 0], lab1[..., 1], lab1[..., 2]
    l2, a2, b2 = lab2[..., 0], lab2[..., 1], lab2[..., 2]
    c_mean = (np.hypot(a1, b1) + np.hypot(a2, b2)) / 2
    g = 0.5 * (1 - np.sqrt(c_mean ** 7 / (c_mean ** 7 + 25.0 ** 7)))
    a1p, a2p = (1 + g) * a1, (1 + g) * a2
    c1p, c2p = np.hypot(a1p, b1), np.hypot(a2p, b2)
    h1p, h2p = np.degrees(np.arctan2(b1, a1p)) % 360, np.degrees(np.arctan2(b2, a2p)) % 360
    dl, dc = l2 - l1, c2p - c1p
    dh = h2p - h1p
    dh = np.where(dh > 180, dh - 360, np.where(dh < -180, dh + 360, dh))
    dh = np.where(c1p * c2p == 0, 0, dh)
    dhp = 2 * np.sqrt(c1p * c2p) * np.sin(np.radians(dh / 2))
    lpm, cpm = (l1 + l2) / 2, (c1p + c2p) / 2
    hsum = h1p + h2p
    hpm = np.where(np.abs(h1p - h2p) > 180, (hsum + 360) / 2, hsum / 2)
    hpm = np.where(c1p * c2p == 0, hsum, hpm)
    t = (1 - 0.17 * np.cos(np.radians(hpm - 30)) + 0.24 * np.cos(np.radians(2 * hpm))
         + 0.32 * np.cos(np.radians(3 * hpm + 6)) - 0.20 * np.cos(np.radians(4 * hpm - 63)))
    rc = 2 * np.sqrt(cpm ** 7 / (cpm ** 7 + 25.0 ** 7))
    sl = 1 + 0.015 * (lpm - 50) ** 2 / np.sqrt(20 + (lpm - 50) ** 2)
    sc, sh = 1 + 0.045 * cpm, 1 + 0.015 * cpm * t
    rt = -np.sin(np.radians(60 * np.exp(-((hpm - 275) / 25) ** 2))) * rc
    return np.sqrt((dl / sl) ** 2 + (dc / sc) ** 2 + (dhp / sh) ** 2 + rt * (dc / sc) * (dhp / sh))


# -- images --------------------------------------------------------------------------

def load_raw(path: Path):
    import rawpy

    raw = rawpy.imread(str(path))
    cfa = raw.raw_image_visible.astype(np.float64)
    black = np.array(raw.black_level_per_channel, dtype=np.float64)
    white = float(raw.white_level)
    pattern = raw.raw_pattern
    height, width = (n - n % 2 for n in cfa.shape)
    planes = {}
    for dy in (0, 1):
        for dx in (0, 1):
            colour = int(pattern[dy, dx])
            planes.setdefault(colour, []).append((cfa[dy:height:2, dx:width:2] - black[colour]) / (white - black[colour]))
    green = planes[1] + planes.get(3, [])
    rgb = np.dstack([planes[0][0], np.mean(green, axis=0), planes[2][0]])
    balance = np.array(raw.camera_whitebalance[:3], dtype=np.float64)
    sizes = raw.sizes
    crop = (sizes.crop_left_margin // 2, sizes.crop_top_margin // 2, sizes.crop_width // 2, sizes.crop_height // 2)
    preview = None
    try:
        thumb = raw.extract_thumb()
        if thumb.format == rawpy.ThumbFormat.JPEG:
            preview = thumb.data
    except Exception:
        pass
    return rgb, balance / balance[1], white, float(black.max()), crop, preview


def block_mean(image, size):
    height, width = (n // size * size for n in image.shape[:2])
    return image[:height, :width].reshape(height // size, size, width // size, size, -1).mean(axis=(1, 3))


def align(render, reference):
    """Affine registration of `render` onto `reference` (camera JPEG), by ECC on a quarter-size image."""
    import cv2

    a = cv2.cvtColor(render.astype(np.float32), cv2.COLOR_RGB2GRAY)
    b = cv2.cvtColor(reference.astype(np.float32), cv2.COLOR_RGB2GRAY)
    warp = np.eye(2, 3, dtype=np.float32)
    criteria = (cv2.TERM_CRITERIA_EPS | cv2.TERM_CRITERIA_COUNT, 200, 1e-7)
    _, warp = cv2.findTransformECC(cv2.resize(b, None, fx=0.25, fy=0.25, interpolation=cv2.INTER_AREA),
                                   cv2.resize(a, None, fx=0.25, fy=0.25, interpolation=cv2.INTER_AREA),
                                   warp, cv2.MOTION_AFFINE, criteria)
    warp[:, 2] *= 4
    return warp


def warp_image(image, warp):
    import cv2

    return cv2.warpAffine(image.astype(np.float32), warp, (image.shape[1], image.shape[0]),
                          flags=cv2.INTER_LINEAR | cv2.WARP_INVERSE_MAP, borderMode=cv2.BORDER_REPLICATE).astype(np.float64)


def statistics(delta, reference_lab, flat):
    chroma = np.hypot(reference_lab[..., 1], reference_lab[..., 2])

    def describe(mask):
        values = delta[mask]
        if values.size == 0:
            return {"blocks": 0}
        return {"blocks": int(values.size), "mean": round(float(values.mean()), 3), "median": round(float(np.median(values)), 3),
                "p95": round(float(np.percentile(values, 95)), 3), "max": round(float(values.max()), 3)}

    everything = np.ones_like(flat)
    return {"all_blocks": describe(everything), "flat_blocks": describe(flat),
            "flat_neutral_chroma_below_5": describe(flat & (chroma < 5)),
            "flat_chroma_5_to_30": describe(flat & (chroma >= 5) & (chroma < 30)),
            "flat_chroma_30_and_above": describe(flat & (chroma >= 30))}


def compare(raw_path: Path, decoded: Path, jpeg_path: Path | None = None, mode: str | None = None,
            profile_path: Path | None = None, block: int = 16, settings: dict | None = None) -> dict:
    import cv2
    import k3iii_tuning_emulator as emulator
    from build_firmware_dcp import build_profile

    info = capture_info(raw_path)
    rgb, balance, white, black, crop, preview = load_raw(raw_path)
    mode = mode or IMAGE_TONE.get(info.get("image_tone"))
    if mode is None:
        raise ValueError("Custom Image not recognised from the maker note; pass --mode")
    adobe = info.get("color_space") == 1
    exposure_gain = 4 * info["mid_level"] if info.get("mid_level") else 0x2000
    if jpeg_path:
        jpeg = cv2.imread(str(jpeg_path), cv2.IMREAD_COLOR)
    elif preview:
        jpeg = cv2.imdecode(np.frombuffer(preview, np.uint8), cv2.IMREAD_COLOR)
    else:
        raise ValueError("no camera JPEG: pass --jpeg")
    jpeg = jpeg[:, :, ::-1].astype(np.float64) / 255.0
    left, top, width, height = crop
    if width and height:
        rgb = rgb[top:top + height, left:left + width]
    height, width = rgb.shape[:2]
    jpeg = cv2.resize(jpeg, (width, height), interpolation=cv2.INTER_AREA)
    camera_rgb = np.clip(rgb * balance, 0.0, 1.0)          # neutral = equal values, raw clip at 1

    # Settings of the shot: from the maker note unless given.
    settings = {**dict.fromkeys(SETTINGS, 0), **(info.get("settings") or {}), **(settings or {})}
    rtos = emulator.load_rtos(decoded)
    toning = info.get("toning", 0)          # the model follows it; a profile cannot (it tints grey)
    tuning = emulator.StillTuning(rtos).make(emulator.MODES[mode], adobe_rgb=adobe, toning=toning, **settings)
    space = "adobergb" if adobe else "srgb"
    camera = model.CameraColour.from_tuning(tuning, mode, space)
    # The camera works on (raw - black) / 2^14 scaled by 8192 / exposure gain.
    scale = (white - black) / 16384.0 * 8192.0 / exposure_gain
    render_model = camera.render(camera_rgb * scale)       # code values in the JPEG's colour space

    if profile_path:
        profile = model.read_dcp(Path(profile_path).read_bytes())
    else:
        profile = model.read_dcp(build_profile(rtos, mode, settings, color_space=space)[0])
    baseline = info.get("baseline_exposure")
    baseline_source = "DNG tag"
    if baseline is None:
        baseline = firmware_baseline_exposure(exposure_gain, white, black)
        baseline_source = "firmware formula with the maker-note exposure gain"
    total_exposure = baseline + profile["BaselineExposureOffset"]
    # Rendered to the JPEG's colour space and encoded like it, so both are averaged as code values.
    render_profile = model.RGB_SPACES[space][1](model.dng_render(
        camera_rgb, profile["ForwardMatrix1"], profile["LookTable"], profile["curve_x"], profile["curve_y"],
        total_exposure, output=space))

    warp = align(render_model, jpeg)
    to_xyz = ADOBE_RGB_TO_XYZ if adobe else SRGB_TO_XYZ

    decode = model.RGB_SPACES[space][2]

    jpeg_blocks = block_mean(jpeg, block)
    reference_lab = to_lab(decode(jpeg_blocks), to_xyz)
    gy, gx = np.gradient(jpeg_blocks.mean(-1) * 255.0)
    flat = np.hypot(gx, gy) < 2.0
    flat[:3] = flat[-3:] = False
    flat[:, :3] = flat[:, -3:] = False
    model_blocks = block_mean(warp_image(render_model, warp), block)
    profile_blocks = block_mean(warp_image(render_profile, warp), block)
    results = {
        "model": statistics(delta_e_2000(to_lab(decode(model_blocks), to_xyz), reference_lab), reference_lab, flat),
        "profile": statistics(delta_e_2000(to_lab(decode(profile_blocks), to_xyz), reference_lab), reference_lab, flat),
    }
    return {
        "raw_sha256": hashlib.sha256(Path(raw_path).read_bytes()).hexdigest(),
        "camera_jpeg": "separate file" if jpeg_path else "preview stored in the RAW file",
        "custom_image": mode, "color_space": "AdobeRGB" if adobe else "sRGB",
        "settings": settings, "toning": toning,
        "settings_source": "maker note tag 0x0247" if info.get("settings") else "all zero (not recorded)",
        "exposure_gain": exposure_gain, "model_exposure_scale": round(scale, 5),
        "baseline_exposure": round(baseline, 4), "baseline_exposure_source": baseline_source,
        "profile_total_exposure_ev": round(total_exposure, 4), "profile_name": profile["ProfileName"],
        "half_size_image": [int(width), int(height)], "block_size": block,
        "alignment_affine": [[round(float(v), 5) for v in row] for row in warp],
        "fitted_colour_or_tone_parameters": 0,
        "delta_e_2000": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("raw", type=Path)
    parser.add_argument("--decoded", type=Path, required=True, help="decoded.bin written by inspect_firmware.py")
    parser.add_argument("--jpeg", type=Path, help="camera JPEG of the same exposure (default: preview in the RAW file)")
    parser.add_argument("--mode", help="Custom Image (default: read from the maker note)")
    parser.add_argument("--profile", type=Path, help="DCP to test (default: built on the fly)")
    parser.add_argument("--output", type=Path)
    for name in SETTINGS:
        parser.add_argument(f"--{name}", type=int, choices=range(-4, 5), metavar="-4..4",
                            help="override the setting read from the maker note")
    args = parser.parse_args()
    override = {name: getattr(args, name) for name in SETTINGS if getattr(args, name) is not None}
    try:
        result = compare(args.raw, args.decoded, args.jpeg, args.mode, args.profile, settings=override)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Comparison failed: {error}\n")
    text = json.dumps(result, indent=2)
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
