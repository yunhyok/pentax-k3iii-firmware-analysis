"""Cross-check the profile math with the Adobe DNG SDK's own reference routines.

tools/firmware_color_model.py re-implements two SDK routines, the LookTable step
(RefBaselineHueSatMap) and the tone-curve step (RefBaselineRGBTone).  This tool
compiles those routines from a DNG SDK source folder you supply, feeds them the
LookTable and tone curve of a DCP together with random linear ProPhoto colours,
and reports how far the Python result is from the SDK result.

The SDK sources that do not compile without optional libraries (libjxl, XMP)
are skipped; the routines used here do not need them.  Not covered: profile
parsing, colour matrices and exposure handling by SDK code, and Lightroom.

    python tools/check_dcp_against_sdk.py --sdk-source dng_sdk_1_7_1/dng_sdk/source \\
        --work-dir /existing/empty/folder My-Natural.dcp

Needs g++ and numpy.  The SDK is not part of this repository.
"""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

import firmware_color_model as model          # noqa: E402

FLAGS = ["-std=c++17", "-O1", "-w", "-DqLinux=1", "-DqDNGUseXMP=0", "-DqDNGUseLibJPEG=0", "-DqDNGSupportJXL=0",
         "-DqDNGValidateTarget=1", "-DqDNGThreadSafe=1", "-DqDNGValidate=0"]
SKIP = {"dng_validate", "dng_xmp", "dng_xmp_sdk", "dng_jxl"}


def build(sdk_source: Path, work: Path) -> Path:
    objects = work / "obj"
    objects.mkdir()

    def compile_one(source: Path):
        target = objects / (source.stem + ".o")
        done = subprocess.run(["g++", *FLAGS, f"-I{sdk_source}", "-c", str(source), "-o", str(target)],
                              capture_output=True, text=True)
        return target if done.returncode == 0 else None

    sources = [p for p in sorted(sdk_source.glob("*.cpp")) if p.stem not in SKIP]
    with ThreadPoolExecutor(max_workers=4) as pool:
        built = [p for p in pool.map(compile_one, sources) if p]
    needed = {"dng_reference", "dng_hue_sat_map", "dng_1d_table", "dng_tone_curve", "dng_spline", "dng_color_space"}
    missing = needed - {p.stem for p in built}
    if missing:
        raise RuntimeError(f"SDK sources did not compile: {sorted(missing)}")
    archive = work / "libdng.a"
    subprocess.run(["ar", "rcs", str(archive), *map(str, built)], check=True)
    harness = work / "harness"
    subprocess.run(["g++", *FLAGS, f"-I{sdk_source}", str(Path(__file__).with_name("dng_sdk_harness.cpp")),
                    f"-L{work}", "-ldng", "-lpthread", "-o", str(harness)], check=True)
    return harness


def colours(count: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    base = rng.random((count, 3))
    base /= base.max(axis=1, keepdims=True)
    return (base * (rng.random(count) ** 2.0)[:, None]).astype(np.float32)


def check(harness: Path, work: Path, profile_path: Path, count: int = 200_000) -> dict:
    profile = model.read_dcp(profile_path.read_bytes())
    table, x, y = profile["LookTable"], profile["curve_x"], profile["curve_y"]
    rgb = colours(count, 7)
    source, result = work / "in.bin", work / "out.bin"
    with source.open("wb") as stream:
        stream.write(struct.pack("<6I", table.hue, table.sat, table.val, table.encoding, len(x), len(rgb)))
        stream.write(table.rows().astype("<f4").tobytes())
        stream.write(np.stack([x, y], axis=1).astype("<f4").tobytes())
        stream.write(rgb.tobytes())
    subprocess.run([str(harness), str(source), str(result)], check=True)
    sdk = np.fromfile(result, dtype="<f4").reshape(-1, 3).astype(np.float64)
    mine = model.rgb_tone(table.apply(rgb.astype(np.float64)), x, y)

    def code(prophoto):
        return model.srgb_encode(np.clip(prophoto @ model.PROPHOTO_TO_SRGB.T, 0.0, 1.0)) * 255.0

    difference = np.abs(code(sdk) - code(mine))
    return {"profile": profile["ProfileName"], "colours": count,
            "srgb_8bit_code_difference": {"mean": round(float(difference.mean()), 4),
                                          "p99": round(float(np.percentile(difference, 99)), 4),
                                          "max": round(float(difference.max()), 4)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("profiles", nargs="+", type=Path)
    parser.add_argument("--sdk-source", type=Path, required=True, help="the SDK's dng_sdk/source folder")
    parser.add_argument("--work-dir", type=Path, required=True, help="existing empty folder for the build")
    args = parser.parse_args()
    try:
        if not (args.sdk_source / "dng_reference.cpp").is_file():
            raise ValueError("--sdk-source: dng_reference.cpp not found")
        if not args.work_dir.is_dir() or any(args.work_dir.iterdir()):
            raise ValueError("--work-dir must be an existing empty folder")
        harness = build(args.sdk_source, args.work_dir)
        results = [check(harness, args.work_dir, path) for path in args.profiles]
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Cross-check failed: {error}\n")
    print(json.dumps({"routines": ["RefBaselineHueSatMap", "RefBaselineRGBTone"], "results": results}, indent=2))


if __name__ == "__main__":
    main()
