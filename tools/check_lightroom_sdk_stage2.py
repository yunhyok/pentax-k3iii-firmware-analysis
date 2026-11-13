"""Rebuild and check the fixed Windows x64 Adobe DNG SDK Stage 2 observation."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import zipfile


ASSETS = Path(__file__).resolve().parents[1] / "analysis/sdk-stage2"
RECIPE = "e302fad6da65065323d62ea622aa10493b68832691da0809a8593981a278bf2d"
OBSERVATION = "9355f35257b9717d2e9ef4ce852f61bdde6bb36762e5fd876c0b88bca9637704"
PROBE_LF = "8d4b798cb427ca685869a8b9db4a3ffc7282109ba2f840f4197df0db9c665076"
PROBE_COMPILED = "27cc415df82a58df696d1afed1b3c7fa7ab3bebcb6a965a1418978fb099e2d7e"


def digest(data):
    return sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def capture(path, limit, size=None, pin=None, normalize_lf=False):
    require(path.is_file(), f"expected a regular file: {path}")
    with path.open("rb") as f:
        file_stat = os.fstat(f.fileno())
        require(stat.S_ISREG(file_stat.st_mode) and file_stat.st_size <= limit,
                f"input type or size rejected: {path}")
        data = f.read(limit + 1)
    require(len(data) == file_stat.st_size, f"input size changed while reading: {path}")
    if normalize_lf:
        data = data.replace(b"\r\n", b"\n")
    require(size is None or len(data) == size, f"unexpected input size: {path}")
    require(pin is None or digest(data) == pin, f"input SHA-256 mismatch: {path}")
    return data


def new_work_path(path):
    require(not os.path.lexists(path), "work directory must be a new path")
    return path.parent.resolve(strict=True) / path.name


def exclusive_bytes(path, data):
    if os.path.lexists(path):
        raise FileExistsError(f"output already exists: {path}")
    with path.open("xb") as f:
        f.write(data)


def with_xmp_guards(original):
    # Preserve the rest of the ZIP member, including the XMP bytes in dead branches.
    start = original.index(b"\t\t// XMP.")
    end = original.index(b"\t\t// IPTC.", start)
    parse_start = original.index(b"\tif (fInfo)", original.index(b"void dng_jxl_decoder::ProcessXMPBox"))
    parse_end = original.index(b"\n\t}\n", parse_start)
    original = (original[:parse_start] + b"#if qDNGUseXMP\n" + original[parse_start:parse_end]
                + b"\n#endif\n" + original[parse_end:])
    return original[:start] + b"#if qDNGUseXMP\n" + original[start:end] + b"#endif\n" + original[end:]


def extract_sdk(captured_zip, work, recipe):
    prefix = recipe["archive_prefix"]
    with zipfile.ZipFile(io.BytesIO(captured_zip)) as archive:
        for name, pin in recipe["sdk_member_pins"].items():
            require(digest(archive.read(prefix + name)) == pin, f"SDK member SHA-256 mismatch: {name}")
        entries = [item for item in archive.infolist()
                   if not item.is_dir() and not item.filename.startswith(prefix + "sample_files/")]
        require(sum(item.file_size for item in entries) <= 512 * 1024**2, "SDK extraction exceeds bound")
        for item in entries:
            name = item.filename
            relative = PurePosixPath(name)
            require(name.startswith(prefix) and relative.as_posix() == name and
                    not {"..", "."}.intersection(relative.parts) and "\\" not in name and ":" not in name
                    and not stat.S_ISLNK(item.external_attr >> 16), f"unsafe SDK member: {name}")
            path = work / "source" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            exclusive_bytes(path, archive.read(item))
    original_jxl = work / "source" / prefix / "dng_sdk/source/dng_jxl.cpp"
    exclusive_bytes(work / "dng_jxl_no_xmp_v2.cpp", with_xmp_guards(original_jxl.read_bytes()))


def build(zig, work, recipe):
    env = dict(os.environ, TEMP=str(work), TMP=str(work),
               ZIG_GLOBAL_CACHE_DIR=str(work / "zig-global"), ZIG_LOCAL_CACHE_DIR=str(work / "zig-local"))
    commands = []
    (work / "obj-scalar").mkdir()
    for obj, group, source, pin in recipe["compile_units_in_link_order"]:
        capture(work / source, 16 * 1024**2, pin=pin)
        flags = [arg.replace("@WORK@", str(work)) for arg in recipe["flag_groups"][group]]
        commands.append([str(zig), *flags, "-c", str(work / source), "-o", str(work / obj)])

    def compile_one(argv):
        completed = subprocess.run(argv, cwd=work, env=env, capture_output=True, timeout=240)
        return Path(argv[-1]).name, completed

    failures = []
    with (work / "compile.log").open("xb") as log, ThreadPoolExecutor(7) as pool:
        for obj, result in pool.map(compile_one, commands):
            log.write(f"{result.returncode} {obj}\n".encode() + result.stdout + result.stderr + b"\n")
            log.flush()
            if result.returncode:
                failures.append(obj)
    require(not failures, f"compiler failures: {', '.join(failures)} (see compile.log)")
    response = [*recipe["link_flags"], *(row[0] for row in recipe["compile_units_in_link_order"])]
    exclusive_bytes(work / "link.rsp", ("\n".join(response) + "\n").encode())
    with (work / "link.log").open("xb") as log:
        linked = subprocess.run([str(zig), "c++", "@link.rsp"], cwd=work, env=env,
                                stdout=log, stderr=subprocess.STDOUT, timeout=180)
    require(linked.returncode == 0, "link failed (see link.log)")


def summarize(data, np, shape):
    array = np.frombuffer(data, dtype="<u2").reshape(shape)
    return array, describe(array)


def describe(array):
    return {"shape_yx": list(array.shape), "dtype": "uint16 LE", "samples": array.size,
            "sha256_le_u16": digest(array.tobytes(order="C")), "min": int(array.min()),
            "max": int(array.max()), "zero": int((array == 0).sum()),
            "at_u16_max": int((array == 65535).sum())}


def expected_stage2(codes, np):
    denominator = 16315 - 64
    lut_codes = np.arange(65536, dtype=np.int64)
    q8 = (2 * lut_codes * (65535 * 256) + denominator) // (2 * denominator)
    lut = np.clip((q8 - q8[64] + 128) // 256, 0, 65535).astype("<u2")
    return lut[codes]


def require_canonical_fields(fields, historical):
    expected = {key: historical[key] for key in fields}
    options = {"sort_keys": True, "separators": (",", ":"), "allow_nan": False}
    require(json.dumps(fields, **options) == json.dumps(expected, **options),
            "canonical Stage 1/2 witness mismatch")


def observe(work, historical, binary_sha, np):
    decoder = work / "stage2_probe.exe"
    completed = subprocess.run([str(decoder), "input.dng", "stage1.u16", "stage2.u16"],
                               cwd=work, capture_output=True, timeout=90)
    exclusive_bytes(work / "native.stdout.log", completed.stdout)
    exclusive_bytes(work / "native.stderr.log", completed.stderr)
    require(completed.returncode == 0 and not completed.stderr, "SDK probe failed (see native logs)")
    source, stage1 = summarize(capture(work / "stage1.u16", 53256192, size=53256192), np, (4224, 6304))
    stage2_pixels, stage2 = summarize(capture(work / "stage2.u16", 51783680, size=51783680), np, (4160, 6224))
    mismatches = int(np.count_nonzero(stage2_pixels != expected_stage2(source[34:4194, 26:6250], np)))
    fields = {
        "stage1": stage1, "stage2": stage2, "active_crop_subset": describe(stage2_pixels[24:4152, 28:6220]),
        "stage2_cfa_max_counts": {name: int((stage2_pixels[y::2, x::2] == 65535).sum())
                                  for y, x, name in ((0, 0, "R"), (0, 1, "G_on_R_row"),
                                                     (1, 0, "G_on_B_row"), (1, 1, "B"))},
        "exact_every_stage2_sample_matches": mismatches == 0,
        "stage2_mismatched_samples": mismatches,
        "pre_stage3_log": completed.stdout.decode("ascii").splitlines(),
    }
    require_canonical_fields(fields, historical)
    return {"schema": 1, "canonical_observation_sha256": OBSERVATION, "canonical_measurements_equal": True,
            "build": {"recipe_sha256": RECIPE, "probe_source_sha256_lf": PROBE_LF,
                      "compiled_probe_source_sha256": PROBE_COMPILED,
                      "linked_objects": 276, "probe_exe_sha256": binary_sha,
                      "historical_probe_exe_sha256": historical["inputs"]["probe_exe_sha256"],
                      "matches_historical_exe_sha256": binary_sha == historical["inputs"]["probe_exe_sha256"]},
            "input_sha256": {key: historical["inputs"][key] for key in ("dng_sha256", "sdk_zip_sha256", "zig_sha256")},
            "runtime": {"numpy": np.__version__, "native_stdout_sha256": digest(completed.stdout),
                        "native_stderr_sha256": digest(completed.stderr)},
            "observed": fields}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True, help="exact Adobe DNG SDK 1.7.1 Build 2768 ZIP")
    parser.add_argument("--dng", type=Path, required=True, help="exact first archival converted DNG")
    parser.add_argument("--zig", type=Path, required=True, help="pinned Zig 0.15.2 Windows x64 executable")
    parser.add_argument("--work", type=Path, required=True, help="new private output directory (existing parent)")
    args = parser.parse_args()
    try:
        work = new_work_path(args.work)
        require(os.name == "nt", "this frozen build targets Windows x64")
        recipe = json.loads(capture(ASSETS / "recipe.json", 128 * 1024, pin=RECIPE, normalize_lf=True))
        historical = json.loads(capture(ASSETS / "observation.json", 16 * 1024, pin=OBSERVATION, normalize_lf=True))
        authored = capture(ASSETS / "probe.cpp", 16 * 1024, pin=PROBE_LF, normalize_lf=True)
        # The historical compiler input had CRLF only on its final line.
        authored = authored[:-1] + b"\r\n"
        require(digest(authored) == PROBE_COMPILED, "historical compiled probe SHA-256 mismatch")
        zig = args.zig.resolve(strict=True)
        pins = recipe["input_pins"]
        for key, path in (("zig", zig), ("sdk_zip", args.sdk), ("dng", args.dng)):
            pin = pins[key]
            data = capture(path, pin["bytes"], size=pin["bytes"], pin=pin["sha256"])
            if key == "sdk_zip":
                sdk_data = data
            elif key == "dng":
                dng_data = data
            del data
        import numpy as np

        work.mkdir()
        exclusive_bytes(work / "input.dng", dng_data)
        exclusive_bytes(work / "stage2_probe.cpp", authored)
        extract_sdk(sdk_data, work, recipe)
        del sdk_data, dng_data
        print("Pinned inputs verified. Building 276 objects in the new work directory.", flush=True)
        build(zig, work, recipe)
        binary_sha = digest(capture(work / "stage2_probe.exe", 128 * 1024**2))
        pin = pins["zig"]
        capture(zig, pin["bytes"], size=pin["bytes"], pin=pin["sha256"])
        report = observe(work, historical, binary_sha, np)
        pin = pins["dng"]
        capture(work / "input.dng", pin["bytes"], size=pin["bytes"], pin=pin["sha256"])
        output = work / "result.json"
        exclusive_bytes(output, (json.dumps(report, indent=2) + "\n").encode())
        print(f"Canonical measurements reproduced: {output}")
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
