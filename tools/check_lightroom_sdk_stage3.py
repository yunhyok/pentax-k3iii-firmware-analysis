"""Reproduce the fixed Adobe DNG SDK Stage 3 and Bayer observations on Windows x64."""
import argparse
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
import subprocess
from types import ModuleType
import zipfile


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "analysis/sdk-stage3"
HELPER_PIN = "dcaaeaf05b742cc15ca156bc455a5511a4cc2e79aad51ee3d68589d3233ebbb9"
PROBE_PIN = "f4347e4584d201f642edc3f3588668471955bef8a8264385114c3876116bec66"
OBSERVATION_PIN = "e24a23684fb0eac347472826c741b9bbbc96f590f6a7edd21061de972f743277"
BILINEAR_PIN = "dc15ed084aac0ebacfd30f7b4304e0b2c0111bed9f612094b019503e2af416ed"
BUILD_PIN = "0f19b816e62c405cdda97d213c5e6e1da4c4fe8ecb2ebb8cdc93a16d3330a843"
STAGE3_BYTES = 155351040
PARITIES = ((0, 0, 0, "R"), (0, 1, 1, "G_on_R_row"), (1, 0, 1, "G_on_B_row"), (1, 1, 2, "B"))
SITE = ((0, 0),)
HORIZONTAL = ((0, -1), (0, 1))
VERTICAL = ((-1, 0), (1, 0))
CROSS = HORIZONTAL + VERTICAL
DIAGONALS = ((-1, -1), (-1, 1), (1, -1), (1, 1))
KERNELS = ((SITE, CROSS, DIAGONALS), (HORIZONTAL, SITE, VERTICAL),
           (VERTICAL, SITE, HORIZONTAL), (DIAGONALS, CROSS, SITE))


def require(condition, error):
    if not condition:
        raise ValueError(error)


def new_work(path):
    require(not os.path.lexists(path), "work directory must be a new path")
    return path.parent.resolve(strict=True) / path.name


def load_stage2_helper(root):
    path = root / "tools/check_lightroom_sdk_stage2.py"
    require(path.is_file(), "Stage 2 helper is not a regular file")
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 32768, "Stage 2 helper exceeds file/type bound")
        data = stream.read(32769)
    require(len(data) == info.st_size, "Stage 2 helper size changed")
    data = data.replace(b"\r\n", b"\n")
    require(sha256(data).hexdigest() == HELPER_PIN, "Stage 2 helper SHA-256 mismatch")
    module = ModuleType("_checked_stage2")
    module.__file__ = str(path)
    exec(compile(data, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


def typed(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def verify_witness(actual, expected, label):
    require(typed(actual) == typed(expected), f"{label} canonical witness mismatch")


def describe(array, helper, np):
    return {"shape_yx_or_yxc": list(array.shape), "samples": int(array.size),
            "min": int(array.min()), "max": int(array.max()), "zero": int(np.count_nonzero(array == 0)),
            "at_65535": int(np.count_nonzero(array == 65535)),
            "sha256_le_u16_c_order": helper.digest(array.astype("<u2", copy=False).tobytes(order="C"))}


def interpolate_plane(src, y, x, taps, np):
    ys, xs = np.arange(y, src.shape[0], 2), np.arange(x, src.shape[1], 2)
    total = np.zeros((ys.size, xs.size), dtype=np.uint32)
    # One-pixel tap radius and even bounds: repeat the edge's same-phase sample.
    for dy, dx in taps:
        ry = np.clip(ys + dy, y ^ abs(dy), src.shape[0] - 2 + (y ^ abs(dy)))
        rx = np.clip(xs + dx, x ^ abs(dx), src.shape[1] - 2 + (x ^ abs(dx)))
        total += src[np.ix_(ry, rx)]
    return (total + len(taps) // 2) // len(taps)


def bilinear_witness(src, dst, stage2_sha, stage3_sha, np):
    groups = []
    for parity, kernels in enumerate(KERNELS):
        y, x = divmod(parity, 2)
        for plane, taps in enumerate(kernels):
            actual = dst[y::2, x::2, plane]
            expected = interpolate_plane(src, y, x, taps, np)
            groups.append({"parity_yx": [y, x], "plane": plane, "taps_yx": list(taps),
                           "samples": int(actual.size), "mismatches": int(np.count_nonzero(expected != actual)),
                           "at_65535": int(np.count_nonzero(actual == 65535))})
    return {"source_stage2_sha256": stage2_sha, "native_stage3_sha256": stage3_sha,
            "samples": sum(group["samples"] for group in groups), "groups": groups,
            "native_site_at_65535": sum(g["at_65535"] for g in groups if len(g["taps_yx"]) == 1),
            "interpolated_site_at_65535": sum(g["at_65535"] for g in groups if len(g["taps_yx"]) > 1)}


def run_command(command, log, cwd, env, timeout):
    require(not os.path.lexists(log), "log path must be new")
    with log.open("xb") as stream:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    require(result.returncode == 0, f"command failed; see {log}")


def check_original_members(helper, sdk_bytes, manifest):
    with zipfile.ZipFile(io.BytesIO(sdk_bytes)) as archive:
        for name, pin in manifest["source_members"].items():
            require(helper.digest(archive.read(name)) == pin, f"Stage 3 SDK source pin mismatch: {name}")


def extract_compile_inputs(helper, sdk_bytes, work, recipe):
    # The archived stock recipe only includes these trees. Omitting Xcode/XMP
    # projects keeps unrelated paths out of the Windows compiler work tree.
    prefix = recipe["archive_prefix"]
    trees = ("dng_sdk/source/", "libjxl/libjxl/", "libjxl/client_projects/include/",
             "xmp/toolkit/third-party/zlib/")
    with zipfile.ZipFile(io.BytesIO(sdk_bytes)) as archive:
        entries = [item for item in archive.infolist() if not item.is_dir()
                   and (item.filename == prefix + "LICENSE.txt" or
                        item.filename.removeprefix(prefix).startswith(trees))]
        require(sum(item.file_size for item in entries) <= 128 * 1024**2, "SDK compile inputs exceed bound")
        for item in entries:
            name = item.filename
            relative = Path(name)
            require(name.startswith(prefix) and relative.as_posix() == name and ".." not in relative.parts
                    and ":" not in name and not stat.S_ISLNK(item.external_attr >> 16), f"unsafe member: {name}")
            path = work / "source" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            helper.exclusive_bytes(path, archive.read(item))
    original = work / "source" / prefix / "dng_sdk/source/dng_jxl.cpp"
    original_bytes = helper.capture(original, 131072, pin=recipe["sdk_member_pins"]["dng_sdk/source/dng_jxl.cpp"])
    helper.exclusive_bytes(work / "dng_jxl_no_xmp_v2.cpp", helper.with_xmp_guards(original_bytes))


def stage2_references(helper, stock, canonical):
    refs = []
    for name, size in (("stage1", 53256192), ("stage2", 51783680)):
        refs.append(helper.capture(stock / (name + ".u16"), size, size=size,
                                   pin=canonical[name]["sha256_le_u16"]))
    return refs


def object_records(helper, recipe, stock, expected=None):
    historical = {row["object"]: row for row in expected} if expected is not None else None
    for name, group, source, source_pin in recipe["compile_units_in_link_order"]:
        if source == "stage2_probe.cpp":
            continue
        record = historical[name] if historical is not None else None
        if record is not None:
            verify_witness([record["original_flag_group"], record["source"], record["source_sha256"]],
                           [group, source, source_pin], name)
        blob = helper.capture(stock / name, 16 * 1024**2,
                              size=record["object_bytes"] if record else None,
                              pin=record["object_sha256"] if record else None)
        yield {"object": name, "object_sha256": helper.digest(blob), "object_bytes": len(blob),
               "source": source, "source_sha256": source_pin, "original_flag_group": group}, blob


def build_stage3(helper, work, source_root, stock, zig, recipe, authored, historical_objects):
    env = dict(os.environ, TEMP=str(work), TMP=str(work),
               ZIG_GLOBAL_CACHE_DIR=str(work / "zig-global"), ZIG_LOCAL_CACHE_DIR=str(work / "zig-local"))
    helper.exclusive_bytes(work / "stage3_probe.cpp", authored)
    (work / "obj-scalar").mkdir()
    current_objects = []
    for record, blob in object_records(helper, recipe, stock, historical_objects):
        helper.exclusive_bytes(work / record["object"], blob)
        current_objects.append(record)
    require(len(current_objects) == 275, "Stage 3 stock object count mismatch")
    flags = [flag.replace("@WORK@", str(source_root)) for flag in recipe["flag_groups"][0]]
    run_command([str(zig), *flags, "-c", str(work / "stage3_probe.cpp"), "-o", str(work / "stage3_probe.o")],
                work / "compile.log", work, env, 160)
    response = [*recipe["link_flags"][:-1], "stage3_probe.exe"]
    response += ["stage3_probe.o" if row[2] == "stage2_probe.cpp" else row[0]
                 for row in recipe["compile_units_in_link_order"]]
    helper.exclusive_bytes(work / "link.rsp", ("\n".join(response) + "\n").encode())
    run_command([str(zig), "c++", "@link.rsp"], work / "link.log", work, env, 180)
    return {"probe_exe_sha256": helper.digest(helper.capture(work / "stage3_probe.exe", 128 * 1024**2)),
            "probe_object_sha256": helper.digest(helper.capture(work / "stage3_probe.o", 1024**2)),
            "link_response_sha256": helper.digest(helper.capture(work / "link.rsp", 32768)),
            "reused_objects": current_objects}


def measure(helper, work, canonical_stage2, refs, np):
    names = ["reference-stage1.u16", "reference-stage2.u16"]
    for name, data in zip(names, refs, strict=True):
        helper.exclusive_bytes(work / name, data)
    exe = work / "stage3_probe.exe"
    completed = subprocess.run([str(exe), "input.dng", "stage1.u16", "stage2.u16", "stage3.u16", *names],
                               cwd=work, capture_output=True, timeout=150)
    helper.exclusive_bytes(work / "native.stdout.log", completed.stdout)
    helper.exclusive_bytes(work / "native.stderr.log", completed.stderr)
    require(completed.returncode == 0 and not completed.stderr, "SDK probe failed (see native logs)")
    stage1_bytes, stage2_bytes = stage2_references(helper, work, canonical_stage2)
    stage3_bytes = helper.capture(work / "stage3.u16", STAGE3_BYTES, size=STAGE3_BYTES)
    raw2 = np.frombuffer(stage2_bytes, dtype="<u2").reshape(4160, 6224)
    full = np.frombuffer(stage3_bytes, dtype="<u2").reshape(4160, 6224, 3)
    crop = full[24:4152, 28:6220]
    sensor_samples = {}
    for row, col, plane, label in PARITIES:
        before, after = raw2[row::2, col::2], full[row::2, col::2, plane]
        sensor_samples[label] = {"samples": int(before.size), "changed": int(np.count_nonzero(before != after))}
    fields = {
        "stage1_sha256_le_u16": helper.digest(stage1_bytes), "stage2_sha256_le_u16": helper.digest(stage2_bytes),
        "stage1_stage2_native_full_byte_reference_checked_before_stage3": True,
        "stage3": describe(full, helper, np), "stage3_default_crop_subset": describe(crop, helper, np),
        "stage3_plane_order": ["camera_R", "camera_G", "camera_B"],
        "stage3_planes": {p: describe(full[:, :, i], helper, np) for i, p in enumerate(("R", "G", "B"))},
        "stage3_crop_planes": {p: describe(crop[:, :, i], helper, np) for i, p in enumerate(("R", "G", "B"))},
        "stage3_vs_stage2_at_matching_sensor_sites": sensor_samples,
        "native_log": completed.stdout.decode("ascii").splitlines(),
        "native_stdout_sha256": helper.digest(completed.stdout), "native_stderr_sha256": helper.digest(completed.stderr),
    }
    bilinear = bilinear_witness(raw2, full, fields["stage2_sha256_le_u16"],
                                fields["stage3"]["sha256_le_u16_c_order"], np)
    return fields, bilinear


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--dng", type=Path, required=True)
    parser.add_argument("--zig", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True, help="new private work directory")
    parser.add_argument("--stage2-work", type=Path,
                        help="optional exact historical Stage 2 work, including all 275 stock object hashes")
    args = parser.parse_args()
    try:
        work = new_work(args.work)
        require(os.name == "nt", "this frozen build targets Windows x64")
        stock = args.stage2_work.resolve(strict=True) if args.stage2_work else None
        require(stock is None or (stock.is_dir() and not work.is_relative_to(stock)),
                "new work directory must be outside the supplied Stage 2 work")
        helper = load_stage2_helper(ROOT)
        assets2 = helper.ASSETS
        recipe = json.loads(helper.capture(assets2 / "recipe.json", 131072, pin=helper.RECIPE, normalize_lf=True))
        stage2 = json.loads(helper.capture(assets2 / "observation.json", 16384, pin=helper.OBSERVATION, normalize_lf=True))
        authored = helper.capture(ASSETS / "probe.cpp", 16384, pin=PROBE_PIN, normalize_lf=True)
        stage3 = json.loads(helper.capture(ASSETS / "observation.json", 16384, pin=OBSERVATION_PIN, normalize_lf=True))
        bilinear_ref = json.loads(helper.capture(ASSETS / "bilinear.json", 16384, pin=BILINEAR_PIN, normalize_lf=True))
        build_ref = json.loads(helper.capture(ASSETS / "historical-build.json", 262144, pin=BUILD_PIN, normalize_lf=True))
        require(build_ref["parent_recipe_sha256"] == helper.RECIPE and stage3["build_receipt_sha256"] == BUILD_PIN,
                "historical build linkage mismatch")
        pins = recipe["input_pins"]
        zig = args.zig.resolve(strict=True)
        for name, path in (("zig", zig), ("sdk_zip", args.sdk), ("dng", args.dng)):
            pin = pins[name]
            data = helper.capture(path, pin["bytes"], size=pin["bytes"], pin=pin["sha256"])
            if name == "sdk_zip":
                sdk_data = data
            elif name == "dng":
                dng_data = data
            del data
        check_original_members(helper, sdk_data, build_ref)
        historical_objects = build_ref["reused_objects"] if stock else None
        import numpy as np

        if stock:
            helper.capture(stock / "result.json", 16384, pin=build_ref["parent_build_receipt_sha256"])
            helper.capture(stock / "link.rsp", 32768, pin=build_ref["parent_link_response_sha256"])
            refs = stage2_references(helper, stock, stage2)
        work.mkdir()
        helper.exclusive_bytes(work / "input.dng", dng_data)
        if stock is None:
            stock = work / "s2"
            stock.mkdir()
            helper.exclusive_bytes(stock / "input.dng", dng_data)
            source_root = stock
            baseline_probe = helper.capture(assets2 / "probe.cpp", 16384, pin=helper.PROBE_LF, normalize_lf=True)
            baseline_probe = baseline_probe[:-1] + b"\r\n"
            require(helper.digest(baseline_probe) == helper.PROBE_COMPILED, "compiled Stage 2 probe pin mismatch")
            helper.exclusive_bytes(stock / "stage2_probe.cpp", baseline_probe)
            extract_compile_inputs(helper, sdk_data, stock, recipe)
            print("Building the fresh Stage 2 prerequisites with the existing recipe.", flush=True)
            helper.build(zig, stock, recipe)
            exe_sha = helper.digest(helper.capture(stock / "stage2_probe.exe", 128 * 1024**2))
            receipt = helper.observe(stock, stage2, exe_sha, np)
            helper.exclusive_bytes(stock / "result.json", (json.dumps(receipt, indent=2) + "\n").encode())
            refs = stage2_references(helper, stock, stage2)
        else:
            source_root = work
            extract_compile_inputs(helper, sdk_data, work, recipe)
        del sdk_data, dng_data
        print("Linking the Stage 3 harness against 275 checked stock objects.", flush=True)
        build = build_stage3(helper, work, source_root, stock, zig, recipe, authored, historical_objects)
        fields, bilinear = measure(helper, work, stage2, refs, np)
        pin = pins["dng"]
        helper.capture(work / "input.dng", pin["bytes"], size=pin["bytes"], pin=pin["sha256"])
        pin = pins["zig"]
        helper.capture(zig, pin["bytes"], size=pin["bytes"], pin=pin["sha256"])
        telemetry = {"schema", "scope", "build_receipt_sha256", "probe_exe_sha256", "dng_sha256", "numpy"}
        verify_witness(fields, {key: value for key, value in stage3.items() if key not in telemetry}, "Stage 3")
        verify_witness(bilinear, bilinear_ref, "Bilinear")
        output = {"schema": 1, "canonical_observations_equal": True,
                  "historical_stage3_sha256": OBSERVATION_PIN, "historical_bilinear_sha256": BILINEAR_PIN,
                  "historical_build_sha256": BUILD_PIN, "stage2_helper_sha256_lf": HELPER_PIN,
                  "object_provenance": "historical object hashes matched" if historical_objects else "built in this run",
                  "inputs": {name: pin["sha256"] for name, pin in pins.items()}, "numpy": np.__version__,
                  "build": build, "observed": fields, "bilinear": bilinear}
        helper.exclusive_bytes(work / "result.json", (json.dumps(output, indent=2, allow_nan=False) + "\n").encode())
        print(f"Canonical measurements reproduced: {work / 'result.json'}")
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
