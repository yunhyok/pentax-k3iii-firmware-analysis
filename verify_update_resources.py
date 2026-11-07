"""Read-only checks of one known firmware package and its decoded image.

Requires Python's standard library and this repository's inspect_firmware.py.
Checks source bytes/metadata only; does not establish updater acceptance,
cryptographic authenticity, absence of other signature checks, or actual boot.
No firmware bytes or decompiled code are embedded or exported.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from inspect_firmware import named_records

ROOT = Path(__file__).resolve().parent
LAYOUT_SHA256 = "f6fba3c2f83e454403781504a11bdf0c0ebccf8faac7c4e9a50bf454e305d707"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_layout():
    raw = (ROOT / "analysis/update-resource-layout.json").read_bytes()
    require(digest(raw) == LAYOUT_SHA256, "Layout metadata SHA256 mismatch")
    return json.loads(raw)


def u32(data, offset):
    require(0 <= offset <= len(data) - 4, "u32 read outside input")
    return struct.unpack_from("<I", data, offset)[0]


def sum32(data):
    require(len(data) % 4 == 0, "Checksum input must have a whole number of u32 words")
    return sum(word for word, in struct.iter_unpack("<I", data)) & 0xffffffff


def stream_boundary(data, start):
    """Walk compressed block envelopes; this does not decompress block contents."""
    cursor, count = start, 0
    while True:
        require(cursor + 2 <= len(data), "Truncated compressed block length")
        size = int.from_bytes(data[cursor:cursor + 2], "big")
        cursor += 2
        if size == 0:
            return cursor, count
        cursor += size & 0x7fff
        require(cursor <= len(data), "Compressed block outside input")
        count += 1


def package_fields(original, decoded, layout):
    header, footer = layout["header"], layout["footer"]
    footer_start = len(original) - 24
    observed_header = dict(project=u32(original, 0x30), count=u32(original, 0x3c),
                           project_repeat=u32(original, 0x78), magic=u32(original, 0x7c))
    require(observed_header == header, "Header fields differ from recorded metadata")
    require(header["project_repeat"] == (header["project"] | header["project"] << 16) & 0xffffffff,
            "Header repeated-project relationship failed")
    require(u32(original, footer_start) == header["project_repeat"], "Footer project mismatch")
    require(u32(original, footer_start + 4) == header["magic"], "Footer magic mismatch")
    observed_footer = {name: u32(original, footer_start + offset) for name, offset in
                       [("type", 8), ("compressed_length", 12), ("decoded_length", 16), ("checksum_word", 20)]}
    require(observed_footer == footer, "Footer fields differ from recorded metadata")
    end, blocks = stream_boundary(original, layout["original"]["stream_start"])
    require(end == layout["original"]["stream_end"], "Compressed stream end mismatch")
    require(footer["compressed_length"] == end - layout["original"]["stream_start"], "Compressed input length mismatch")
    require(footer["decoded_length"] == len(decoded), "Decoded output length mismatch")
    require(u32(decoded, len(decoded) - 4) == layout["decoded_checksum_word"], "Decoded checksum word mismatch")
    outer, inner = sum32(original), sum32(decoded)
    require(outer == inner == 0, "Original or decoded modulo-2^32 sum is nonzero")
    return dict(header=observed_header, footer=observed_footer, footer_offset=footer_start,
                compressed_stream_end=end, compressed_block_count=blocks,
                original_u32le_sum_mod_2_32=outer, decoded_u32le_sum_mod_2_32=inner,
                decoded_checksum_word=layout["decoded_checksum_word"])


def version_records(original, layout, stream_end):
    expected = layout["version_table"]
    count = u32(original, 0x3c)
    start, end = len(original) - 24 - (count << 7), len(original) - 24
    require(count == expected["count"] == 2, "Version record count mismatch")
    require(start == expected["table_start"] == stream_end and end == expected["table_end"], "Version table boundaries mismatch")
    require(end - start == expected["table_size"] == count * expected["record_stride"] == 256, "Version table size mismatch")
    table_hash = digest(original[start:end])
    require(table_hash == expected["table_sha256"], "Version table SHA256 mismatch")
    rows = []
    for index in range(count):
        offset = start + index * 128
        high, low = struct.unpack_from(">HH", original, offset + 8)
        row = dict(index=index, offset=offset, selector=hex(u32(original, offset)),
                   version_high=high, version_low=low, record_sha256=digest(original[offset:offset + 128]))
        rows.append(row)
    require(rows == expected["records"], "Version record fields mismatch")
    return dict(count=count, record_stride=128, table_start=start, table_end=end,
                table_size=end-start, table_sha256=table_hash, records=rows)


def thumb_reference(payload, reference):
    """Decode the selected Thumb literal LDR, high-register ADD and B.W forms."""
    load, pool, add, target, tail, callee = [int(reference[k], 16) for k in
        ("load", "literal", "add_pc", "target", "tail_call", "target_function")]
    insn = struct.unpack_from("<H", payload, load)[0]
    require(insn & 0xf800 == 0x4800, "Expected Thumb literal LDR")
    register = (insn >> 8) & 7
    actual_pool = ((load + 4) & ~3) + (insn & 255) * 4
    require(actual_pool == pool, "Thumb literal pool address mismatch")
    relative = u32(payload, pool)
    addition = struct.unpack_from("<H", payload, add)[0]
    require(addition & 0xff00 == 0x4400, "Expected Thumb high-register ADD")
    destination = (addition & 7) | ((addition >> 4) & 8)
    source = (addition >> 3) & 15
    require(destination == register and source == 15, "Thumb ADD operands do not consume the literal register and PC")
    actual_target = (relative + add + 4) & 0xffffffff
    require(actual_target == target, "PC-relative banner target mismatch")
    first, second = struct.unpack_from("<HH", payload, tail)
    require(first & 0xf800 == 0xf000 and second & 0xd000 == 0x9000, "Expected unconditional Thumb B.W tail transfer")
    sign = (first >> 10) & 1
    i1, i2 = 1 ^ ((second >> 13) & 1) ^ sign, 1 ^ ((second >> 11) & 1) ^ sign
    displacement = (sign << 24) | (i1 << 23) | (i2 << 22) | ((first & 0x3ff) << 12) | ((second & 0x7ff) << 1)
    if sign:
        displacement -= 1 << 25
    require(tail + 4 + displacement == callee, "Thumb tail transfer target mismatch")
    return dict(load=load, literal=pool, relative_value=relative, add_pc=add,
                target=actual_target, register=register, tail_call=tail,
                transfer_kind="b.w", target_function=callee)


def verify(original, decoded, layout):
    require(len(original) == layout["original"]["input_size"] and digest(original) == layout["original"]["input_sha256"], "Original firmware SHA256 or size mismatch")
    require(len(decoded) == layout["decoded"]["decoded_size"] and digest(decoded) == layout["decoded"]["decoded_sha256"], "Decoded image SHA256 or size mismatch")
    fields = package_fields(original, decoded, layout)
    versions = version_records(original, layout, fields["compressed_stream_end"])
    records, end = named_records(decoded)
    require(len(records) == layout["named_record_count"], "Named record count mismatch")
    require(end == layout["decoded"]["opaque_decoded_tail_offset"] and len(decoded)-end == layout["decoded"]["opaque_decoded_tail_size"], "Named-record boundary mismatch")
    selected = [r for r in records if r["name"] in ("ICONBIN", "PARTPARA", "LINUX")]
    require(selected == layout["selected_records"], "Selected named records differ from metadata")
    icon = next(r for r in selected if r["name"] == "ICONBIN")
    require(icon["kind"] == 4 and icon["index"] == 4, "ICONBIN kind/index mismatch")
    linux = next(r for r in selected if r["name"] == "LINUX")
    component = layout["linux_component"]
    require((linux["payload_offset"], linux["size"], linux["sha256"]) ==
            (component["payload_offset"], component["payload_size"], component["payload_sha256"]), "LINUX component identity mismatch")
    payload = decoded[linux["payload_offset"]:linux["payload_offset"]+linux["size"]]
    regions = []
    for r in component["regions"]:
        start, stop = int(r["offset"], 16), int(r["end"], 16)
        require(0 <= start < stop <= len(payload), "LINUX region outside payload")
        actual = digest(payload[start:stop])
        require(actual == r["sha256"], "LINUX region SHA256 mismatch")
        regions.append(dict(label=r["label"], offset=start, end=stop, sha256=actual))
    references = [thumb_reference(payload, r) for r in component["pic_references"]]
    return dict(passed=True, layout_sha256=LAYOUT_SHA256,
                original_sha256=digest(original), decoded_sha256=digest(decoded),
                package=fields, version_table=versions, named_record_count=len(records),
                selected_records=selected, linux_regions=regions, linux_pic_references=references,
                limitations=["Static byte and metadata verification only; no updater or boot execution.",
                             "Compressed block boundaries are checked without repeating decompression.",
                             "No package acceptance or cryptographic authenticity claim.",
                             "The LINUX banner reference is component-specific; it does not establish absence of other signature checks.",
                             "Remaining version-record fields and dotted version interpretation remain unresolved."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path, help="Original firmware package")
    parser.add_argument("decoded", type=Path, help="Complete decoded.bin from inspect_firmware.py")
    parser.add_argument("--output", type=Path, help="Optional JSON output; otherwise print JSON")
    args = parser.parse_args()
    try:
        result = verify(args.original.read_bytes(), args.decoded.read_bytes(), load_layout())
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        parser.error(str(error))
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8", newline="\n")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
