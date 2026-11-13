"""Count CFA sample ranges and model one pinned DNG SDK integer stage-2 path."""
import argparse
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
from stat import S_ISREG
from zipfile import ZipFile

DNG = (31652772, "4639584e7c807b46747ab4fac90b90b8459943c8e0f680ea68dfec6cdc580b07")
PEF = (36368721, "28b0a4a0fae9b3c60d4950d8d4baeaa5a056a7fb130dfba0c2c212119ed29543")
SDK = (80509918, "c1d3a545ed45b150e59af2e6aa0695c1551f0e2bed34ad87436898a05194d2b1")
ARRAY = "b5dbb0a1bcaf6d4002a54c0069fbfd52e17964156cdf7359ae10395519b145b3"
REFERENCE = "bdd372448cc6e9634d81aaf16748d634cac5b24abb4155a5318f7272c049211e"
MEMBERS = {
    "dng_flags.h": "619bee441fd1f844c1c40b6f8228de20b97f5010eaa1aecb2421db511432e704",
    "dng_ifd.cpp": "3f9a0e2e803d3a349c575b6c190bcfb6414bf293957a64b7dd6f125a95ee9d61",
    "dng_negative.cpp": "ed2b54b89b13813d51226010967b78cfe100e00c1ebcd660a1190e409bdd8a6a",
    "dng_linearization_info.cpp": "257ddbd012cdfa4341be95e8593e393d86d859fa4b14fb405c61a622671cc8bd",
    "dng_rect.h": "3674e610597c6be9a23e79fe654760848bc5cf9851c95b10e78b12476d0f8c6c",
    "dng_utils.h": "0eb910dd59b46928d5fee734a0cc096eb1a99bab8594d6d2fec77ae0d6fb11e9",
}
PREFIX = "dng_sdk_1_7_1/dng_sdk/source/"
BLACK, WHITE = 64, 16315
SOURCES = {
    "dng_flags.h": "30–31 build",
    "dng_ifd.cpp": "1835–1876 H,V crop tags; 2038–2051 ActiveArea T,L,B,R; 4724–4779 crop bounds",
    "dng_rect.h": "132–136 half-open point containment",
    "dng_negative.cpp": "1507 initial Stage3BlackLevel; 3146–3157 default crop; 5314–5338 stage-2 type/size; 5548–5550 opcode1; 6504–6509 default black preservation",
    "dng_linearization_info.cpp": "136–154 scale; 217–277 repeating black pattern; 455–495 integer scale LUT; 517–528 ActiveArea rebasing; 733–825 integer offset, shift, saturation; 1411–1536 MaxBlackLevel; 1588–1625 preservation/active overlap",
    "dng_utils.h": "156–178 uint16 saturation; 651–672 rounding",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def capture(path, pin):
    size, digest = pin
    require(path.is_file() and path.stat().st_size == size, "input size or type mismatch")
    with path.open("rb") as src:
        st = os.fstat(src.fileno())
        require(S_ISREG(st.st_mode) and st.st_size == size, "input changed before capture")
        data = src.read(size + 1)
    require(len(data) == size and sha256(data).hexdigest() == digest, "input SHA mismatch")
    return data


def crop_rect(shape, active, origin_xy, size_xy):
    height, width = shape
    t, l, b, r = active
    require(0 <= t < b <= height and 0 <= l < r <= width, "ActiveArea outside stored CFA")
    x, y = origin_xy
    w, h = size_xy
    require(x >= 0 and y >= 0 and w > 0 and h > 0
            and x + w <= r - l and y + h <= b - t, "default crop outside ActiveArea")
    return t + y, l + x, t + y + h, l + x + w


def sdk_stage2_before_saturation(raw_code):
    # Positive fixed-point terms are individually rounded with SDK Round_int32.
    scale = 1.0 / (WHITE - BLACK)
    raw = int(((raw_code * scale) * 65535) * 256 + 0.5)
    black = int((BLACK * scale) * (65535 * 256) + 0.5)
    return (raw - black + 128) >> 8


def histogram_stats(counts, stage2):
    n = int(counts.sum())
    require(n > 0, "empty parity")
    nonzero = counts.nonzero()[0]
    total = lambda a, b: int(counts[a:b].sum())
    return {
        "samples": n, "min": int(nonzero[0]), "max": int(nonzero[-1]),
        "below_black": total(0, BLACK), "equal_black": int(counts[BLACK]),
        "strictly_inside_black_white": total(BLACK + 1, WHITE),
        "equal_dng_white": int(counts[WHITE]), "above_dng_white": total(WHITE + 1, len(counts)),
        "above_pef_makernote_white_code": total(16379, len(counts)),
        "equal_or_above_pef_libraw_maximum_code": total(16383, len(counts)),
        "modeled_stage2_zero": int(counts[stage2 <= 0].sum()),
        "modeled_stage2_u16_max": int(counts[stage2 >= 65535].sum()),
        "modeled_stage2_pre_saturation_negative": int(counts[stage2 < 0].sum()),
        "modeled_stage2_pre_saturation_above_u16_max": int(counts[stage2 > 65535].sum()),
    }


def summarize(np, raw, rect, active, stage2):
    t, l, b, r = rect
    y0, x0 = active[:2]
    parts = {}
    total = np.zeros(65536, dtype=np.int64)
    for dy, dx, label in ((0, 0, "R"), (0, 1, "G_on_R_row"), (1, 0, "G_on_B_row"), (1, 1, "B")):
        row = t + (y0 + dy - t) % 2
        col = l + (x0 + dx - l) % 2
        view = raw[row:b:2, col:r:2]
        counts = np.bincount(view.ravel(), minlength=len(total))
        parts[label] = {"active_relative_row_col_parity": [dy, dx], **histogram_stats(counts, stage2)}
        total += counts
    count = int(total.sum())
    all_samples = raw[t:b, l:r]
    require(count == all_samples.size, "parity population mismatch")
    require(np.array_equal(total, np.bincount(all_samples.ravel(), minlength=len(total))),
            "parities do not partition the region")
    return {"sensor_TLBR_half_open": list(rect), "total": histogram_stats(total, stage2), "CFA": parts}


def inspect(dng):
    import imagecodecs
    import numpy as np
    import tifffile

    with tifffile.TiffFile(BytesIO(dng)) as tf:
        main = tf.pages[0]
        (page,) = [p for p in main.pages if p.photometric == 32803]
        tags = page.tags
        expected = {
            254: 0, 258: 16, 259: 7, 262: 32803, 277: 1,
            33421: (2, 2), 33422: b"\0\1\1\2",
            50710: b"\0\1\2", 50711: 1,
            50713: (2, 2), 50714: (16384, 256) * 4,
            50717: WHITE, 50718: (1, 1, 1, 1),
            50719: (28, 1, 24, 1), 50720: (6192, 1, 4128, 1),
            50829: (34, 26, 4194, 6250), 50780: (1, 1),
        }
        require(main.tags[274].value == 1 and main.tags[50708].value == "PENTAX K-3 Mark III",
                "orientation or model mismatch")
        require(all(tags[k].value == v for k, v in expected.items()), "RAW IFD tag mismatch")
        require(all(k not in p.tags for p in (main, page) for k in
                    (50712, 50715, 50716, 50830, 51008, 51009, 51022)),
                "unexpected linearization table, black deltas, masked area or opcode")
        require(page.shape == (4224, 6304) and page.dtype == np.dtype("uint16"),
                "stored CFA shape or type mismatch")
        active = tags[50829].value
        crop = crop_rect(page.shape, active, tags[50719].value[::2], tags[50720].value[::2])
        raw = page.asarray()
        require(raw.shape == page.shape and raw.dtype == page.dtype and int(raw.max()) <= 16383,
                "decoded CFA shape, type or range mismatch")
        require(sha256(raw.astype("<u2", copy=False).tobytes(order="C")).hexdigest() == ARRAY,
                "stored CFA differs from archived three-array witness")
        tags_evidence = {
            "raw_ifd_offset": page.offset, "raw_shape_yx": list(page.shape),
            "photometric": 32803, "compression": 7, "bits_per_sample": 16, "sample_format": "uint16",
            "orientation": 1, "CFARepeatPatternDim_yx": tags[33421].value,
            "CFAPattern_codes": list(tags[33422].value), "black_level_rational": tags[50714].value,
            "white_level": tags[50717].value, "DefaultScale_xy_rational": tags[50718].value,
            "DefaultCropOrigin_xy_rational": tags[50719].value, "DefaultCropSize_xy_rational": tags[50720].value,
            "ActiveArea_TLBR": active, "linearization_table_black_delta_masked_area_and_opcode_tags_absent": True,
        }
    stage2 = np.asarray([sdk_stage2_before_saturation(i) for i in range(65536)])
    full = (0, 0, raw.shape[0], raw.shape[1])
    regions = {name: summarize(np, raw, rect, active, stage2) for name, rect in
               (("stored_cfa", full), ("active_area", active), ("default_crop", crop))}
    require(regions["stored_cfa"]["total"]["above_dng_white"] == 8565, "public witness count mismatch")
    for report in regions.values():
        count = report["total"]
        require(count["modeled_stage2_zero"] == count["below_black"] + count["equal_black"]
                and count["modeled_stage2_u16_max"] == count["above_dng_white"] + count["equal_dng_white"]
                and count["modeled_stage2_pre_saturation_negative"] == count["below_black"]
                and count["modeled_stage2_pre_saturation_above_u16_max"] == count["above_dng_white"],
                "modeled endpoint and threshold counts disagree")
    return tags_evidence, regions, {
        "numpy": np.__version__, "tifffile": tifffile.__version__, "imagecodecs": imagecodecs.__version__,
        "rawpy": "not used in this run; stored-array SHA rechecked against its accepted public witness",
    }


def self_test():
    import numpy as np

    assert crop_rect((10, 12), (1, 2, 9, 11), (3, 2), (4, 5)) == (3, 5, 8, 9)
    for args in (((10, 12), (1, 2, 9, 11), (3, 2), (7, 5)),
                 ((10, 12), (1, 2, 11, 12), (0, 0), (2, 2)),
                 ((10, 12), (1, 2, 9, 11), (-1, 0), (2, 2))):
        try:
            crop_rect(*args)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid crop accepted")
    cases = {63: -4, 64: 0, 65: 4, 16314: 65531, 16315: 65535, 16316: 65539}
    assert {i: sdk_stage2_before_saturation(i) for i in cases} == cases
    # Odd absolute rectangle origin must not restart CFA at R.
    raw = np.array([[63, 64, 65], [16314, 16315, 16316], [65, 0, 0]], dtype=np.uint16)
    endpoints = np.asarray([sdk_stage2_before_saturation(i) for i in range(65536)])
    s = summarize(np, raw, (1, 1, 3, 3), (0, 0, 3, 3), endpoints)
    assert s["CFA"]["B"]["equal_dng_white"] == 1
    assert s["CFA"]["G_on_B_row"]["above_dng_white"] == 1
    assert s["total"]["below_black"] == 2 and s["total"]["modeled_stage2_u16_max"] == 2
    print("PASS: crop coordinates/bounds, CFA phase, signed fixed-point and endpoint vectors")


def verify_payload(result):
    payload = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    require(sha256(payload).hexdigest() == REFERENCE, "complete CFA range witness mismatch")
    return payload


def main():
    require(__debug__, "optimized Python unsupported")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dng", type=Path)
    parser.add_argument("--pef", type=Path)
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        require(not any((args.dng, args.pef, args.sdk, args.output)), "self-test takes no files")
        return self_test()
    require(all((args.dng, args.pef, args.sdk, args.output)), "all four paths required")
    require(not os.path.lexists(args.output) and args.output.parent.is_dir(), "new output path required")
    capture(args.pef, PEF)  # identity only; this run does not invoke a PEF decoder
    dng = capture(args.dng, DNG)
    with ZipFile(BytesIO(capture(args.sdk, SDK))) as archive:
        for name, digest in MEMBERS.items():
            require(sha256(archive.read(PREFIX + name)).hexdigest() == digest, "SDK member SHA mismatch")
    tags, regions, runtime = inspect(dng)
    result = {
        "schema": 1, "scope": "One fixed DNG CFA decode plus a model of the SDK 2768 default uint16 stage-2 arithmetic. No PEF rendering, DNG SDK execution, demosaic, output image, Lightroom, or proprietary tag inference.",
        "input_sha256": {"dng": DNG[1], "pef_identity_only": PEF[1], "sdk_zip": SDK[1]},
        "input_bytes": {"dng": DNG[0], "pef_identity_only": PEF[0], "sdk_zip": SDK[0]},
        "sdk_member_sha256": MEMBERS, "sdk_member_lines": SOURCES, "runtime": runtime,
        "cfa_sha256_little_endian_uint16": ARRAY, "tags": tags,
        "threshold_sources": {"dng_black": BLACK, "dng_white": WHITE,
                              "pef_makernote_white_code_only": 16378, "pef_libraw_maximum_code_only": 16383},
        "model": {
            "scale": 1.0 / (WHITE - BLACK), "denominator_white_minus_max_black": WHITE - BLACK,
            "dst_black_code_default_zero": 0,
            "integer_formula": "clip((round(raw*scale*65535*256) - round(64*scale*65535*256) + 128) >> 8, 0, 65535); round each positive term as SDK binary64 plus 0.5, truncate",
            "selected_codes": {i: [sdk_stage2_before_saturation(i), min(65535, max(0, sdk_stage2_before_saturation(i)))]
                               for i in (0, 63, 64, 65, 16314, 16315, 16316, 16378, 16382)},
            "stored_max_normalized_before_clip": (16382 - BLACK) / (WHITE - BLACK),
            "applied_area": "SDK stage-2 operates on ActiveArea; stored whole-image count is diagnostic, and default crop is a nested coordinate subset.",
        },
        "regions": regions,
    }
    payload = verify_payload(result)
    with args.output.open("xb") as f:
        f.write(payload)
    print({name: row["total"]["above_dng_white"] for name, row in regions.items()})


if __name__ == "__main__":
    main()
