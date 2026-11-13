"""Verify static K-3 III text viewport sources and reproduce the frozen observation."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from struct import unpack_from


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "8cfc497bc6239683897de871f91a3f7e1286a47fc6ed6a996ccdf0fd1754c89f"
OBSERVATION = "d26716263db49e69e4f8e36f1e18de8506d79463bce7a9a20a523ab1912d4633"
ORIGINAL_SCRIPT = "cb276c653662a0a6bf207d8748c09e1aa7fc50875a4617b2234db0362daefcad"
REVIEW = "cc129794cba1034d1da6cdd427a8a17c3de11c7a55f829c6b637c3952783de42"
ARCHIVE = "e1eafc09c4f1d78be167527f8cac5eed32af8b31923a399ecb6c335c3f13ee84"


def sha(data):
    return sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def capture(path, size, digest, *, normalize_lf=False):
    require(path.is_file(), f"input must be a regular file: {path.name}")
    limit = 2 * size if normalize_lf else size
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, f"input size/type mismatch: {path.name}")
        data = stream.read(limit + 1)
    require(len(data) == info.st_size, f"input size changed: {path.name}")
    if normalize_lf:
        data = data.replace(b"\r\n", b"\n")
    require(len(data) == size and sha(data) == digest, f"input length or SHA-256 mismatch: {path.name}")
    return data


def exclusive_write(path, data):
    require(not os.path.lexists(path), "fresh output required")
    with path.open("xb") as stream:
        stream.write(data)


def encode(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()


def geometry(local, local_clip, parent_absolute, parent_clip):
    # Small signed coordinates without A32 overflow, as in the frozen illustrations.
    values = [*local, *local_clip, *parent_absolute, *parent_clip]
    require(all(type(x) is int and -10000 <= x <= 10000 for x in values), "illustration domain")
    x = parent_absolute[0] + local[0]
    y = parent_absolute[1] + local[1]
    left = max(x + local_clip[0], parent_clip[0])
    top = max(y + local_clip[1], parent_clip[1])
    right = max(left, min(x + local_clip[0] + local_clip[2], parent_clip[0] + parent_clip[2]))
    bottom = max(top, min(y + local_clip[1] + local_clip[3], parent_clip[1] + parent_clip[3]))
    return [x, y, local[2], local[3]], [left, top, right - left, bottom - top]


def aligned_text(absolute, measured, h_align, v_align):
    require(h_align in (0, 1, 2) and v_align in (0, 1, 2), "alignment domain")
    require(all(type(x) is int and 0 <= x <= 10000 for x in [*absolute[2:], *measured]), "size domain")
    x, y, w, h = absolute
    tw, th = measured

    def delta(size, text, mode):
        if mode == 0:
            return 0
        if mode == 1:
            return size // 2 - text // 2
        return size - text

    return [x + delta(w, tw, h_align), y + delta(h, th, v_align), tw, th]


def checked_spans(blob, base, spans):
    for name, row in spans.items():
        a = int(row["start"], 16) - base
        z = int(row["end_exclusive"], 16) - base
        require(0 <= a < z <= len(blob), f"span outside RTOS: {name}")
        part = blob[a:z]
        require(len(part) == row["bytes"] and sha(part) == row["sha256"], f"span mismatch: {name}")


def direct_candidates(blob, base):
    candidates = []
    for offset in range(0, len(blob) - 3, 4):
        word = unpack_from("<I", blob, offset)[0]
        if ((word >> 25) & 7) != 5 or word >> 28 == 15:
            continue
        immediate = word & 0xFFFFFF
        if immediate & 0x800000:
            immediate -= 1 << 24
        if (base + offset + 8 + (immediate << 2)) & 0xFFFFFFFF == 0x528C24E4:
            candidates.append({"site": hex(base + offset), "link": bool(word & (1 << 24))})
    return candidates


def historical_fields(refs):
    history = json.loads(refs["analysis/colorspace-text.json"])["cases"][-1]
    observed = history["geometry"]
    models = []
    for label, clip, expected in (
        ("historical_fixture", [10, 12, 180, 60], [110, 22, 80, 40]),
        ("narrow_parent", [50, 20, 100, 30], [110, 22, 40, 28]),
        ("disjoint_parent", [0, 0, 50, 10], [110, 22, 0, 0]),
    ):
        absolute, viewport = geometry([100, 10, 580, 40], [0, 0, 580, 40], [10, 12, 180, 60], clip)
        require(viewport == expected, "geometry illustration")
        models.append({"case": label, "parent_clip": clip, "absolute": absolute,
                       "viewport": viewport, "kind": "authored arithmetic, not native execution"})
    require(models[0]["absolute"] == observed["absolute_rect"] and models[0]["viewport"] == observed["view_clip"],
            "historical geometry mismatch")
    require(aligned_text(models[0]["absolute"], [76, 40], 0, 0) == observed["native_config_rect"],
            "historical text rectangle")
    require(observed["native_config_clip"] == models[0]["viewport"], "historical config clip")
    require(aligned_text([10, 20, 101, 81], [76, 40], 1, 1) == [22, 40, 76, 40], "center truncation model")
    require(aligned_text([10, 20, 100, 80], [75, 39], 1, 1) == [23, 41, 75, 39], "half rounding model")
    require(aligned_text([10, 20, 101, 81], [76, 40], 2, 2) == [35, 61, 76, 40], "right bottom alignment")
    calls = history["modeled_calls_by_stage_and_entry"]
    require(sum(sum(stage.values()) for stage in calls.values()) == 72 and calls["text-transfer"] == {},
            "historical modeled boundary")
    clip = json.loads(refs["analysis/colorspace-clip.json"])["observations"]
    require(len(clip["cases"]) == 7 and clip["surface"]["size"] == [256, 144], "clip archive scope")
    for index, case in enumerate(clip["cases"]):
        require(case["models"] == 0 and sum(case["modeled_setup_counts"].values()) == 72,
                "historical case model boundary")
        same_config = case["original_config_sha256"] == case["supplied_config_sha256"]
        require(same_config == (index == 0) and case["unchanged_non_rectangle_config_bytes"],
                "historical case injection boundary")
    return observed, models


def exact_observation(actual):
    require(sha(encode(actual)) == OBSERVATION, "complete original observation SHA-256 mismatch")
    return actual


def exact_archive(actual):
    data = encode(actual)
    require(sha(data) == ARCHIVE, "complete public witness SHA-256 mismatch")
    return data


def verify(manifest, template, decoded, refs):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

    rtos = manifest["rtos"]
    base = int(rtos["base"], 16)
    blob = memoryview(decoded)[rtos["offset"]:rtos["offset"] + rtos["bytes"]]
    require(len(blob) == rtos["bytes"] and sha(blob) == rtos["sha256"], "RTOS SHA-256 mismatch")
    checked_spans(blob, base, manifest["spans"])
    checked_spans(blob, base, manifest["additional_review_spans"])
    engine = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for row in manifest["instruction_contracts"]:
        a = int(row["address"], 16)
        offset = a - base
        require(0 <= offset <= len(blob) - 4, "instruction address outside RTOS")
        part = bytes(blob[offset:offset + 4])
        instruction = list(engine.disasm(part, a))
        require(sha(part) == row["sha256"] and len(instruction) == 1, f"instruction bytes: {a:#x}")
        decoded_pair = [instruction[0].mnemonic, instruction[0].op_str]
        pair_hash = sha(json.dumps(decoded_pair, separators=(",", ":")).encode())
        require(pair_hash == row["decoded_instruction_sha256"], f"instruction interpretation: {a:#x}")

    def table_words(addresses):
        return {hex(a): hex(unpack_from("<I", blob, a - base)[0]) for a in addresses}

    original_tables = table_words((0x52C03164, 0x5386FE44, 0x5386FE48, 0x5386FE70))
    review_tables = table_words((0x52BEE40C, 0x52BEE414, 0x5386FED4))
    require(review_tables == {"0x52bee40c": "0x5386fe10", "0x52bee414": "0x5386fec0", "0x5386fed4": "0x52bedb40"},
            "additional constructor table linkage")
    observed, models = historical_fields(refs)
    # The frozen template supplies only fixed text/contracts. Replace all data
    # fields calculated by the 37 verifier before checking its full typed JSON.
    observation = exact_observation({
        **template, "source_manifest_sha256": manifest["original_source_manifest_sha256"],
        "decoded_sha256": manifest["decoded"]["sha256"], "rtos_sha256": rtos["sha256"],
        "checked_source_spans": manifest["spans"],
        "checked_instruction_contract_count": len(manifest["instruction_contracts"]), "table_links": original_tables,
        "A32_aligned_direct_branch_candidates": direct_candidates(blob, base),
        "historical_geometry": observed, "arithmetic_illustrations": models,
    })
    return {"schema": 1, "original_observation_sha256": OBSERVATION,
            "original_verifier_sha256": ORIGINAL_SCRIPT, "public_source_manifest_sha256": MANIFEST,
            "original_observation": observation,
            "additional_static_review": {
                "review_findings_sha256": REVIEW, "checked_spans": manifest["additional_review_spans"],
                "constructor_and_nested_draw_table_links": review_tables,
                "temporary_to_storage": {"start": "0x52beebec", "end_exclusive": "0x52beec40",
                                         "last_write": "0x52beec3c", "bytes": 63},
                "storage_to_stack": {"start": "0x52bedba8", "end_exclusive": "0x52bedbc8",
                                     "last_write": "0x52bedbc4", "bytes": 64},
                "unrotated_dispatch": {"surface_type": 5, "rotation": 0, "entry": "0x528c24e4"},
                "new_original_CPU_execution": False,
            }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not os.path.lexists(args.output) and args.output.parent.is_dir(), "fresh output and existing parent required")
        manifest_path = ROOT / "analysis/ui-viewport-sources.json"
        archive_path = ROOT / "analysis/ui-viewport-producers.json"
        manifest = json.loads(capture(manifest_path, 23828, MANIFEST, normalize_lf=True))
        archive = json.loads(capture(archive_path, 13898, ARCHIVE, normalize_lf=True))
        template = exact_observation(archive["original_observation"])
        refs = {name: capture(ROOT / name, pin["bytes"], pin["sha256"], normalize_lf=True)
                for name, pin in manifest["reference_files"].items()}
        pin = manifest["decoded"]
        data = capture(args.decoded, pin["bytes"], pin["sha256"])
        result = exact_archive(verify(manifest, template, data, refs))
        exclusive_write(args.output, result)
        print(sha(result))
    except (OSError, ValueError, ImportError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
