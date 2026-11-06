"""Offline, read-only inspection of the documented Ricoh/Pentax LZ container.

Original implementation of the stream format described at:
https://github.com/Trimz/Ricoh3x/blob/main/tools/pdec.py
https://github.com/Trimz/Ricoh3x/blob/main/docs/firmware.md
No firmware, third-party implementation, flashing or patching is included.
"""

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def decode(data, start=0x80, limit=256 * 1024 * 1024):
    """Return payload, stream end and a block-level compressed/output mapping."""
    if not 0 <= start <= len(data) or limit < 0:
        raise ValueError("invalid start or output bound")
    output = bytearray()
    blocks = []
    cursor = start
    while True:
        block_start = cursor
        if cursor + 2 > len(data):
            raise ValueError(f"truncated length at {cursor:#x}")
        size = int.from_bytes(data[cursor:cursor + 2], "big")
        cursor += 2
        if size == 0:
            return bytes(output), cursor, blocks
        stored = bool(size & 0x8000)
        size &= 0x7fff
        end = cursor + size
        if end > len(data):
            raise ValueError(f"truncated block at {block_start:#x}")
        out_start = len(output)
        if stored:
            if size > limit - len(output):
                raise ValueError("output limit exceeded")
            output.extend(data[cursor:end])
        else:
            if size < 2 or data[end - 2:end] != b"\0\0":
                raise ValueError(f"invalid LZ trailer at {block_start:#x}")
            token_end = end - 2
            while cursor < token_end:
                if cursor + 2 > token_end:
                    raise ValueError("truncated flag word")
                flags = int.from_bytes(data[cursor:cursor + 2], "big")
                cursor += 2
                for bit in range(15, -1, -1):
                    if cursor == token_end:
                        break
                    if flags & (1 << bit):
                        if cursor + 2 > token_end:
                            raise ValueError("truncated copy token")
                        token = int.from_bytes(data[cursor:cursor + 2], "big")
                        cursor += 2
                        length = ((token >> 8) & 7) + 3
                        distance = ((token >> 11) << 8) | (token & 255)
                        if length == 10:
                            while True:
                                if cursor >= token_end:
                                    raise ValueError("truncated extended copy")
                                extra = data[cursor]
                                cursor += 1
                                length += extra
                                if extra != 255:
                                    break
                        if not 0 < distance <= len(output):
                            raise ValueError("invalid backward distance")
                        if length > limit - len(output):
                            raise ValueError("output limit exceeded")
                        # Repeating a short history slice handles overlapping copies.
                        history = bytes(output[-distance:])
                        output.extend((history * ((length + distance - 1) // distance))[:length])
                    else:
                        if len(output) >= limit:
                            raise ValueError("output limit exceeded")
                        output.append(data[cursor])
                        cursor += 1
        blocks.append({"input_start": block_start, "input_end": end,
                       "output_start": out_start, "output_end": len(output),
                       "kind": "stored" if stored else "lz"})
        cursor = end


def named_records(data):
    """Walk consecutive bounded name/kind/index/size records from offset zero.

    Stop at the first unrecognized record; the remainder stays opaque.
    """
    result = []
    offset = 0
    while offset + 16 <= len(data):
        name = data[offset:offset + 8]
        if not re.fullmatch(rb"[A-Z][A-Z0-9_]{1,7}\x00*", name):
            break
        kind, index, size = struct.unpack_from("<HHI", data, offset + 8)
        if not 1 <= kind <= 9 or not size or offset + 16 + size > len(data):
            break
        result.append({"name": name.rstrip(b"\0").decode("ascii"),
                       "header_offset": offset, "kind": kind, "index": index,
                       "payload_offset": offset + 16, "size": size,
                       "sha256": sha256(data[offset + 16:offset + 16 + size])})
        offset += 16 + size
    return result, offset


def self_test():
    literal = b"\x00\x05\x00\x00A\x00\x00\x00\x00"
    overlap = b"\x00\x07\x40\x00A\x02\x01\x00\x00\x00\x00"
    extended = b"\x00\x08\x40\x00A\x07\x01\x01\x00\x00\x00\x00"
    stored = b"\x80\x03xyz\x00\x00"
    for source, expected in [(literal, b"A"), (overlap, b"AAAAAA"),
                             (extended, b"A" * 12), (stored, b"xyz")]:
        actual, end, blocks = decode(source, 0)
        assert actual == expected and end == len(source) and len(blocks) == 1
    for source in [b"", b"\x00", stored[:-2], literal[:4],
                   b"\x00\x06\x80\x00\x00\x01\x00\x00\x00\x00",
                   b"\x00\x07\x40\x00A\x07\x01\x00\x00\x00\x00",
                   b"\x00\x05\x00\x00A\x00\x01\x00\x00"]:
        try:
            decode(source, 0)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed stream accepted")
    try:
        decode(overlap, 0, 5)
    except ValueError:
        pass
    else:
        raise AssertionError("output bound ignored")
    fixture = b"RTOS\0\0\0\0" + struct.pack("<HHI", 4, 1, 3) + b"abc"
    records, end = named_records(fixture)
    assert records[0]["size"] == 3 and end == len(fixture)
    print("self-check: 13 checks passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--start", type=lambda value: int(value, 0), default=0x80)
    parser.add_argument("--max-output-mib", type=int, default=256)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.input or not args.output_dir:
        parser.error("input and --output-dir are required")
    # Exclusive directory creation prevents accidental replacement of earlier evidence.
    if args.output_dir.exists():
        parser.error("output directory must not exist")
    source = args.input.read_bytes()
    payload, end, blocks = decode(source, args.start, args.max_output_mib * 1024 * 1024)
    records, records_end = named_records(payload)
    report = {"input_size": len(source), "input_sha256": sha256(source),
              "stream_start": args.start, "stream_end": end,
              "trailing_size": len(source) - end,
              "trailing_sha256": sha256(source[end:]),
              "decoded_size": len(payload), "decoded_sha256": sha256(payload),
              "input_u32le_sum_mod_2_32": (sum(word[0] for word in struct.iter_unpack("<I", source)) & 0xffffffff) if len(source) % 4 == 0 else None,
              "block_counts": {kind: sum(block["kind"] == kind for block in blocks) for kind in ("lz", "stored")},
              "blocks": blocks, "named_records": records,
              "opaque_decoded_tail_offset": records_end,
              "opaque_decoded_tail_size": len(payload) - records_end,
              "limitations": ["Only one LZ stream is decoded per invocation.",
                              "No signature/authenticity verification is performed.",
                              "Named records do not establish CPU addresses or a memory map.",
                              "The remainder after the named records is retained without interpretation."]}
    args.output_dir.mkdir(parents=True)
    (args.output_dir / "decoded.bin").write_bytes(payload)
    (args.output_dir / "inventory.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key not in ("blocks",)}, indent=2))
    print(f"blocks: {len(blocks)}")


if __name__ == "__main__":
    main()
