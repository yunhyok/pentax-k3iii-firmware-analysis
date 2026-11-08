"""Reduce an offline candidate by preserving unaffected original LZ blocks.

This consumes a previously validated, same-size single-record candidate. It is
not a general compressor and does not execute a camera decoder or updater.
"""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import package_roundtrip as package
from inspect_firmware import decode
from verify_package_roundtrip import compare_outer
from verify_update_resources import require

MAX_DISTANCE = 8191  # Five upper distance bits and eight lower bits in the LZ token.


def stored(data):
    require(bool(data), "Empty stored block")
    return b"".join(struct.pack(">H", 0x8000 | len(data[i:i + 0x6000])) + data[i:i + 0x6000]
                    for i in range(0, len(data), 0x6000))


def preserve_blocks(source, before, target, blocks):
    require(len(before) == len(target) and bool(blocks), "Same-size nonempty stream required")
    output_cursor = 0
    for block in blocks:
        require(block["output_start"] == output_cursor < block["output_end"] <= len(before),
                "Invalid decoded block coverage")
        output_cursor = block["output_end"]
    require(output_cursor == len(before), "Incomplete decoded block coverage")
    # An unchanged block can only see edited history within this bounded window.
    selected = {i for i, b in enumerate(blocks)
                if before[max(0, b["output_start"] - MAX_DISTANCE):b["output_end"]]
                != target[max(0, b["output_start"] - MAX_DISTANCE):b["output_end"]]}
    pieces = [stored(target[b["output_start"]:b["output_end"]]) if i in selected
              else source[b["input_start"]:b["input_end"]] for i, b in enumerate(blocks)]
    parity_extra = None
    split_extra = None
    stream_size = sum(map(len, pieces)) + 2
    if stream_size % 2:
        choices = []
        for i, b in enumerate(blocks):
            if i not in selected and b["kind"] == "lz":
                length = b["output_end"] - b["output_start"]
                delta = length + 2 * ((length + 0x5fff) // 0x6000) - len(pieces[i])
                if delta % 2:
                    choices.append((delta, i))
        require(bool(choices), "Cannot preserve word alignment with stored replacement")
        delta, parity_extra = min(choices)
        b = blocks[parity_extra]
        pieces[parity_extra] = stored(target[b["output_start"]:b["output_end"]])
        selected.add(parity_extra)
        stream_size += delta
    if stream_size % 4:
        split_extra = next((i for i in sorted(selected)
                            if (int.from_bytes(pieces[i][:2], "big") & 0x7fff) > 1), None)
        require(split_extra is not None, "No stored block available for alignment split")
        piece = pieces[split_extra]
        first_size = int.from_bytes(piece[:2], "big") & 0x7fff
        pieces[split_extra] = stored(piece[2:3]) + stored(piece[3:2 + first_size]) + piece[2 + first_size:]
    stream = b"".join(pieces) + b"\0\0"
    require(len(stream) % 4 == 0, "Final stream is not word-aligned")
    decoded, end, new_blocks = decode(stream, 0, len(target))
    require(decoded == target and end == len(stream), "Selective stream decode mismatch")
    return stream, {"replaced_original_blocks": sorted(selected), "parity_extra_block": parity_extra,
                    "split_extra_block": split_extra, "original_blocks": len(blocks),
                    "candidate_blocks": len(new_blocks), "preserved_original_blocks": len(blocks) - len(selected),
                    "maximum_history_distance": MAX_DISTANCE}


def rebuild(original, candidate):
    require(package.sha256(original) == package.ORIGINAL_SHA, "Expected pinned original package")
    before, original_info = package.parse_package(original)
    target, input_info = package.parse_package(candidate)
    compare_outer(original, candidate, original_info, input_info)
    changes = []
    for old, new in zip(original_info["named_records"], input_info["named_records"]):
        if old["sha256"] != new["sha256"]:
            require(old["kind"] == 4, "Only kind-4 record replacement is supported")
            changes.append(old["name"])
    require(len(changes) <= 1, "Only one record may change")
    tail = original_info["opaque_tail_offset"]
    require(before[tail:-4] == target[tail:-4], "Opaque resource tail changed")
    decoded, end, blocks = decode(original, 128, len(before))
    require(decoded == before and end == original_info["stream_end"], "Original stream identity mismatch")
    stream, report = preserve_blocks(original, before, target, blocks)
    footer = bytearray(original[original_info["footer_start"]:])
    struct.pack_into("<III", footer, 12, len(stream), len(target), 0)
    result = bytearray(original[:128] + stream + original[original_info["version_start"]:original_info["footer_start"]] + footer)
    checksum = (-package.sum32(result)) & 0xffffffff
    require(checksum != 0xffffffff, "Outer checksum collides with bypass sentinel")
    struct.pack_into("<I", result, len(result) - 4, checksum)
    after, info = package.parse_package(result)
    compare_outer(original, result, original_info, info)
    require(after == target, "Reopened package differs from input candidate")
    if not changes:
        require(bytes(result) == original, "Unchanged package did not round-trip exactly")
    report.update(original_sha256=original_info["package_sha256"], input_candidate_sha256=input_info["package_sha256"],
                  candidate_sha256=info["package_sha256"], decoded_sha256=info["decoded_sha256"],
                  original_bytes=len(original), input_candidate_bytes=len(candidate), candidate_bytes=len(result),
                  changed_records=changes, decoded_changed_bytes=sum(a != b for a, b in zip(before, target)),
                  verified_decode_matches_input=True, hardware_tested=False,
                  scope="Conservative original-block preservation; no general compressor, camera decoder, updater or boot test.")
    return bytes(result), report


def write_outputs(directory, candidate, report):
    directory.mkdir(parents=True)
    with ExitStack() as rollback:
        rollback.callback(directory.rmdir)
        for name, data in (("candidate.bin", candidate), ("evidence.json", (json.dumps(report, indent=2) + "\n").encode())):
            path = directory / name
            with path.open("xb") as output:
                rollback.callback(path.unlink)
                require(output.write(data) == len(data), "Short output write")
        rollback.pop_all()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory under this checkout's .private")
    args = parser.parse_args()
    try:
        output = args.output_dir.resolve()
        private = (ROOT / ".private").resolve()
        require(output.is_relative_to(private) and output != private and not output.exists(),
                "Expected a new output directory under .private")
        candidate, report = rebuild(package.read_bounded(args.original), package.read_bounded(args.candidate))
        write_outputs(output, candidate, report)
        print(json.dumps(report, indent=2))
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
