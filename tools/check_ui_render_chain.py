"""Recalculate Q7 draw checkpoints from pinned local assets and check recorded evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

REVISION = "3e2cee712f5470ce565534d99f8df273c263eabe"
PACKAGE_SHA = "8a928b574623c28624127501526d8496a98a42eac3d843def6d3b5ceb074ff3b"
ELF_SHA = "a973912dbce5c8e09422c0009892dd47e1d7088e8bd8c9020f2a9c8804149796"
FONT_SHA = "9ba8e0f0b4fe85a9c097f7cd3e992ca6a159eef76ddc2340c2b6f6d22c1cc44b"
REPORT_SHA = "08bebb175b153e72c76a4654720c4e5fab1de3c07af6d82a7743c58ce350b585"
BOUNDARY_SHA = "9faa778d2172071d28cba8cf29fcbd0fb1f2774b3af07c1f82bea424e59283c7"
RANGES = (
    (0x80AE00F0, 0x80AE0158, "01e17c5269f51764a8477c5ac0f3ae2617cc8f38a6527d963e796c25f26d74ee"),
    (0x80ADF734, 0x80ADFE20, "30c737ffd611f8d3c36db5c1c063169c943d97659bd4be8b4712583c46eac9d1"),
    (0x80ADF300, 0x80ADF4B4, "27bc33f6e94b6351ce45abf86626562a6db1addd9c34e0cf3836f243164cc974"),
    (0x8024A59C, 0x8024A62C, "d311a9e0ca806574a898d904f313487a1f7f5186d3047f409823b2a906f1eab8"),
    (0x8024BF9C, 0x8024C594, "c07af25e23d36691b7e96d506d5835814dc5129c02bfab7fbaefb3f296b2db00"),
    (0x8024928C, 0x802493B4, "70356f53d32ed40e9633e3c980dc82e9e1f76b2579c63d6fdf3a58090a4ea9e4"),
    (0x80226748, 0x80226D54, "67963c2405cfa2958483805d287ae61f36fe4153a5337f46846e905f291e04f1"),
    (0x8043F42C, 0x8043FA74, "a5044ab841f79dc6299859d124de24124bc99d7b03f78fa0454bffed8bcba453"),
    (0x8043CA4C, 0x8043CB2C, "5444a651a481504657d5a54bf72acea9a22273bf44b1ee449cc3e2293ab44a57"),
)
OPTIONS = (("0x191d00b", 0x8092D830, 64), ("0x191d010", 0x8092D510, 112))
STRIDE, HEIGHT, FILL = 960, 480, 0xA5
SIZE = STRIDE * HEIGHT
FRAME, CONTEXT, FONT = 0x20000000, 0x21000000, 0x23000000
PALETTE = (None, 2, 1, 3)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked(path, expected):
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError(f"{path.name}: SHA-256 mismatch")
    return data


def u32(data, offset=0):
    return struct.unpack_from("<I", data, offset)[0]


def elf_reader(data):
    """Map file-backed MIPS32 LE PT_LOAD addresses for the already hash-pinned ELF."""
    assert data[:7] == b"\x7fELF\x01\x01\x01"
    assert struct.unpack_from("<H", data, 18)[0] == 8
    phoff = u32(data, 28)
    entry_size, count = struct.unpack_from("<HH", data, 42)
    assert entry_size == 32 and phoff + count * entry_size <= len(data)
    loads = []
    for index in range(count):
        kind, offset, va, _, length, capacity, _, _ = struct.unpack_from(
            "<8I", data, phoff + index * entry_size
        )
        if kind == 1:
            assert offset + length <= len(data) and length <= capacity
            loads.append((offset, va, length))

    def read(address, size):
        matches = [
            data[offset + address - va:offset + address - va + size]
            for offset, va, length in loads if va <= address < address + size <= va + length
        ]
        if len(matches) != 1:
            raise ValueError(f"{address:#x}+{size:#x}: expected one file-backed ELF range")
        return matches[0]

    return read


def verify_record(report, boundary, read):
    """Validate the scope and structure of immutable observations, without replay."""
    assert report["revision"] == boundary["revision"] == REVISION
    for key in ("sources", "package_sha256", "elf_sha256", "font_sha256", "engine", "stop",
                "draw_returns", "vex_block_count", "draw_traversal_return_blocks",
                "active_context_stores", "traces", "write_bytes", "pixel_write_events",
                "skipped_calls", "cache_requests"):
        assert report[key] == boundary[key], f"recorded {key} mismatch"
    assert (report["package_sha256"], report["elf_sha256"], report["font_sha256"]) == (
        PACKAGE_SHA, ELF_SHA, FONT_SHA
    )
    assert (report["stride"], report["height"]) == (boundary["stride"], boundary["height"]) == (STRIDE, HEIGHT)
    assert boundary["status"] == "observed_before_postprocessing"
    assert report["stop"] == {"pc": "0x80adf468", "before_instruction": True, "consumer_returned": False}
    assert report["whole_frame_equal"] is True
    assert boundary["queue_words"] == [128, 1, 0, 0] and boundary["publish_requests"] == [[0, 17, 1]]
    assert boundary["active_context_stores"] == ["0x21000000", "0x21040000"]
    assert (boundary["active_context"], boundary["draw_id"], boundary["show_id"]) == ("0x21040000", 18, 17)
    assert boundary["canaries"] == {
        name: ["47" * 8, "47" * 8] for name in ("draw_frame", "other_frame", "marker_scratch")
    }
    assert boundary["frames"]["other"] == {
        "address": "0x20100000", "sha256": digest(bytes([FILL]) * SIZE), "changed_bytes": 0,
    }
    cache = report["cache_requests"]
    assert len(cache) == 3
    for entry, callsite, role, file_arg, line_arg in zip(
        cache, (0x802296C8, 0x802296C8, 0x8043CA94),
        ("GdiTextOutDB", "GdiTextOutDB", "ScreenOsdLayer_Roll"),
        (0x80237C70, 0x80237C70, 0x804F0368), (0x316, 0x316, 0x13E), strict=True,
    ):
        # Original JAL to the modeled cache function, with a3 set in the delay slot.
        call, delay = struct.unpack("<II", read(callsite, 8))
        assert call == 0x0C000000 | ((0x800B3D40 >> 2) & 0x03FFFFFF)
        assert delay == 0x24070000 | line_arg
        assert entry == {"return_address": callsite + 8, "role": role,
                         "args": [FRAME, SIZE, file_arg, line_arg]}
    assert report["validated_roll_cache"] == {"original_callsite": "0x8043ca94", **cache[-1]}


def verify_pixels(report, boundary, read, font):
    """Independent indexed renderer for this fixed fixture and original resources."""
    assert font[:10] == b"LatinFont\0"
    assert (u32(font, 0x24), u32(font, 0x2C), font[0x37]) == (64, 48, 2)
    frame = bytearray([FILL]) * SIZE
    marker = read(0x808AEE78, 296)
    pixels = b"".join(bytes([i]) * n for i, n in zip(marker[::2], marker[1::2], strict=True))
    assert len(pixels) == 21 * 48
    assert digest(marker) == report["marker_rle_sha256"] == boundary["marker_scratch"]["source_rle_sha256"]
    assert digest(pixels) == boundary["marker_scratch"]["sha256"]
    marker_call, = [row for row in report["traces"] if row["kind"] == "marker"]
    assert marker_call["args"] == [0x25, 16, 64, 0, 0]
    for index, pixel in enumerate(pixels):
        if pixel:
            y, x = divmod(index, 21)
            frame[(64 + y) * STRIDE + 16 + x] = pixel

    checkpoints = report["draw_returns"]
    assert len(checkpoints) == 3
    observed_counts = {}

    def match(index, name, return_pc, written):
        row = checkpoints[index]
        assert row["primitive"] == name and row["return_pc"] == return_pc
        assert row["frame_sha256"] == digest(frame)
        assert row["changed_bytes"] == sum(pixel != FILL for pixel in frame)
        assert row["write_bytes"] == written
        observed_counts[name] = written

    match(0, "marker", "0x80acdf50", sum(bool(pixel) for pixel in pixels))
    font_range = u32(font, 0x40) + 0x18
    assert struct.unpack_from("<II", font, font_range + 0x20) == (0, 0xAA)
    widths = u32(font, 0x44) + u32(font, font_range + 0x18)
    bitmaps = u32(font, 0x4C) + 2 * u32(font, font_range + 0x14)
    glyphs = iter(row for row in report["traces"] if row.get("pc") == "0x80226748")
    for index, (widget, table, y) in enumerate(OPTIONS, 1):
        descriptor = u32(read(table, 4))
        assert read(descriptor, 1) == b"\x01"
        lengths, pointers = struct.unpack("<II", read(descriptor + 4, 8))
        count = read(lengths, 1)[0]
        text = read(u32(read(pointers, 4)), 2 * count)
        units = tuple(code for (code,) in struct.iter_unpack("<H", text))
        draw, = [row for row in report["traces"] if row["kind"] == "text" and row["widget"] == widget]
        assert tuple(draw["units"]) == units and draw["staged_sha256"] == digest(text)
        assert draw["args"][:2] == [0, 0xFFFF] and draw["args"][3:] == [96, y, count, 1]
        x, writes = 96, 0
        for code in units:
            assert 0 <= code <= 0xAA
            width = font[widths + code]
            dest = (3 * width) // 4
            source = bitmaps + code * 16 * 48
            native = next(glyphs)
            assert native["args"] == [CONTEXT, FONT + source, 64, x, y, width, 48, dest, 48]
            assert native["transparent"] == 1 and native["palette"] == [0, 2, 1, 3]
            step = (width << 16) // dest
            for row in range(48):
                for col in range(dest):
                    sample = (col * step + step // 2) >> 16
                    packed = font[source + row * 16 + sample // 4]
                    pixel = (packed >> (6 - 2 * (sample % 4))) & 3
                    if pixel:
                        frame[(y + row) * STRIDE + x + col] = PALETTE[pixel]
                        writes += 1
            x += dest
        match(index, "text-" + widget, "0x802493ec", writes)
    assert next(glyphs, None) is None
    assert report["write_bytes"] == observed_counts
    assert report["frame_sha256"] == digest(frame)
    assert report["changed_bytes"] == sum(observed_counts.values())
    assert boundary["frames"]["draw"] == {
        "address": "0x20000000", "sha256": report["frame_sha256"], "changed_bytes": report["changed_bytes"],
    }


def main():
    if not __debug__:
        raise SystemExit("verification requires assertions")
    analysis = Path(__file__).resolve().parents[1] / "analysis"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--report", type=Path, default=analysis / "ui-render-chain.json")
    parser.add_argument("--boundary", type=Path, default=analysis / "ui-render-chain-boundary.json")
    args = parser.parse_args()
    try:
        report = json.loads(checked(args.report, REPORT_SHA))
        boundary = json.loads(checked(args.boundary, BOUNDARY_SHA))
        assert report["boundary_snapshot_sha256"] == BOUNDARY_SHA
        package = checked(args.firmware, PACKAGE_SHA)
        read = elf_reader(checked(args.elf, ELF_SHA))
        font = package[0x9D1AC0:0x9D1AC0 + 130886]
        assert digest(font) == FONT_SHA
        for start, end, expected in RANGES:
            assert digest(read(start, end - start)) == expected, f"ELF range {start:#x}"
        verify_record(report, boundary, read)
        verify_pixels(report, boundary, read, font)
    except (OSError, ValueError, AssertionError) as exc:
        parser.exit(1, f"verification failed: {exc}\n")
    print("PASS 3 independently calculated draw checkpoints and final indexed frame")
    print("PASS pinned execution record, cache call sites, and recorded canaries")
    print("Recorded execution evidence verified; no emulator run performed.")


if __name__ == "__main__":
    main()
