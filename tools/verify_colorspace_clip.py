"""Replay K-3 III unrotated text clipping on the same native sRGB bitmap."""
if not __debug__:
    raise SystemExit("Run without -O. Assertions are required.")

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
import stat
from pathlib import Path
from struct import pack, unpack, unpack_from
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
TEXT_CLI = "tools/verify_colorspace_text.py"
PINS = {
    TEXT_CLI: "d4e8b90007d99a83de3dbbf4b895df1a8a511fa5bc6834ddf61a18112410f941",
    "tools/verify_colorspace_render.py": "fccd1a8bf11edee56aae7a1a9d61a850d2f4ecccfb2354289dbcceaa8d59e09d",
    "tools/_colorspace_row_replay.py": "aba5c183718c6678889c7fb86b527f0fe0123bca8e12cb3c696d97a4495df91b",
    "tools/_colorspace_font_replay.py": "f0e4922a1039b9dcec81ba3591bab7ab191050e90d743dfb277c724dc59c38a8",
    "icon_resource_probe.py": "222d409696c04af5719c2b9520b78e64216953442936f69f21bfaa60ffda1a26",
    "tools/_colorspace_text_replay.py": "0f554ee194c5c1dc59ccca65e75639e8a898cb92e63d113c986abe02de59bc20",
}
BASELINE = "analysis/colorspace-text.json"
CROSS = "analysis/cross-ui-text.json"
BASELINE_PIN = "9f61bd541c1369a5b94438a8ae07d1caabdcd94efd939caf23511a52bbfc3aa0"
CROSS_PIN = "4d963ada9cadc03f5d9954030074901b15554450df2abcc0b94e20260d54002f"
SOURCE_LIMIT = 256 * 1024
Q7_PIN = "2b867c1968b978252009406702ed182b063b4e8e"
CASES = (
    ("interior", 110, 22, (110, 22, 80, 40)),
    ("left", -9, 22, (0, 0, 256, 144)),
    ("top", 110, -12, (0, 0, 256, 144)),
    ("upper_left", -9, -12, (0, 0, 256, 144)),
    ("right", 217, 22, (0, 0, 256, 144)),
    ("bottom", 110, 127, (0, 0, 256, 144)),
    ("touch_bottom", 110, -40, (0, 0, 256, 144)),
)
BOUNDARY_SPANS = {
    "config_arguments": (0x528C24E4, 0x528C2564),
    "intersection_and_exit": (0x530FA324, 0x530FA438),
    "rect_and_signed_endpoints": (0x530FA084, 0x530FA234),
    "offsets_and_anchor": (0x528C2590, 0x528C267C),
    "row_and_word_loop": (0x528C267C, 0x528C2704),
    "palette_ready": (0x528C697C, 0x528C69A8),
    "palette_word": (0x52A6C6B0, 0x52A6C6C4),
    "blend_cache": (0x528C21F8, 0x528C24E4),
    "blend_weights": (0x533D2EE4, 0x533D2F64),
}


def digest(data):
    return sha256(data).hexdigest()


def checked_sources():
    sources = {}
    for name, pin in (PINS | {BASELINE: BASELINE_PIN, CROSS: CROSS_PIN}).items():
        data = read_regular(ROOT / name, SOURCE_LIMIT, name).replace(b"\r\n", b"\n")
        if digest(data) != pin:
            raise ValueError(f"SHA-256 mismatch: {name}")
        sources[name] = data
    return sources


def overlap(rect, clip):
    x, y, w, h = rect
    vx, vy, vw, vh = clip
    left, top = max(x, vx), max(y, vy)
    right, bottom = min(x + w, vx + vw), min(y + h, vy + vh)
    return int(left <= right and top <= bottom), [left, top, right - left, bottom - top]


def f32(value):
    return unpack("<f", pack("<f", value))[0]


def scalar_oracle(before, bitmap, rect, clip, weights, foreground, solid):
    assert len(before) == 256 * 144 * 4 and len(bitmap) == 76 * 40
    status, crop = overlap(rect, clip)
    assert status == 1
    x, y, w, h = crop
    # The native blend cache uses one destination anchor for the entire crop.
    assert 0 <= x < 256 and 0 <= y < 144 and x + w <= 256 and y + h <= 144
    anchor = 4 * (256 * y + x)
    background = unpack_from("<I", before, anchor)[0]
    output = bytearray(before)
    reads, writes = [], []
    counts = {"zero": 0, "partial": 0, "solid_ff": 0}
    # Visit source cells in raster order and test each destination point
    # against the requested viewport, independently of native pointer arithmetic.
    for index, sample in enumerate(bitmap):
        yy, xx = divmod(index, 76)
        px, py = xx + rect[0], yy + rect[1]
        if not (clip[0] <= px < clip[0] + clip[2] and clip[1] <= py < clip[1] + clip[3]):
            continue
        assert 0 <= px < 256 and 0 <= py < 144
        reads.append(index)
        if sample == 0:
            counts["zero"] += 1
            continue
        if sample == 0xff:
            counts["solid_ff"] += 1
            color = solid
        else:
            assert 1 <= sample <= 15
            counts["partial"] += 1
            color = 0
            for bit in range(0, 32, 8):
                front = (foreground >> bit) & 255
                back = (background >> bit) & 255
                byte = int(f32(f32(front * weights[sample]) + f32(back * weights[16 + sample])))
                color |= byte << bit
        address = 4 * (256 * py + px)
        writes.append((address, color))
        output[address:address + 4] = pack("<I", color)
    return bytes(output), reads, writes, counts, anchor, crop


def extend_source(text, source, measure):
    def patch(before, after):
        nonlocal source
        source = text.replace_one(source, before, after)

    source = text.add_overlays(source, measure.patch_native, True)
    patch("    palette_alloc=None", """    palette_alloc=None
    original_config=None
    transfer_pcs=[]
    native_anchor_reads=[]""")
    patch("cache_object,palette_alloc\n", "cache_object,palette_alloc,original_config\n")
    patch("        if phase=='text-transfer':\n            if a==0x528c2384:", """        if phase=='text-draw' and a==0x528c24e4:
            address=reg('r1')
            assert original_config is None
            original_config=bytes(vm.mem_read(address,64))
            assert bytes(vm.mem_read(nested+0x6c,64))==original_config
            assert [r(address+4*i) for i in range(1,5)]==[110,22,76,40]
            assert [r(address+4*i) for i in range(5,9)]==[110,22,80,40]
            if CASE[0]!='interior':
                vm.mem_write(address+4,pack('<8i',CASE[1],CASE[2],76,40,*CASE[3]))
        if phase=='text-transfer':
            transfer_pcs.append(a)
            if a==0x528c2384:""")
    patch("            rect,clip=draw['clip_input_rects']\n            assert rect==presentation['native_config_rect'] and clip==presentation['view_clip']\n            x,y=max(rect[0],clip[0]),max(rect[1],clip[1])\n            expected_crop=[x,y,min(rect[0]+rect[2],clip[0]+clip[2])-x,min(rect[1]+rect[3],clip[1]+clip[3])-y]\n            assert draw['clip_status']==1 and draw['clip_intersection']==expected_crop", """            raw_rect,raw_clip=draw['clip_input_rects']
            rect,clip=[s32(n) for n in raw_rect],[s32(n) for n in raw_clip]
            assert rect==[CASE[1],CASE[2],76,40] and clip==list(CASE[3])
            expected_status,expected_crop=OVERLAP(rect,clip)
            assert draw['clip_status']==expected_status and draw['clip_intersection']==expected_crop""")
    patch("        assert bytes(vm.mem_read(config,64))==bytes(vm.mem_read(nested+0x6c,64))", """        supplied_config=bytes(vm.mem_read(config,64))
        assert original_config==bytes(vm.mem_read(nested+0x6c,64))
        assert supplied_config[:4]+supplied_config[36:]==original_config[:4]+original_config[36:]
        assert supplied_config[4:36]==pack('<8i',*rect,*clip)""")
    patch("        frame,words,reads,table,background,coverage,crop=PREDICT(\n            before,pitch,surface_rows,raw,stride,rect,clip,x_offset,\n            unpack('<32f',weights_bytes),foreground,solid)", """        weights=unpack('<32f',weights_bytes)
        frame,reads,words,coverage,anchor_offset,crop=ORACLE(before,raw,rect,clip,weights,foreground,solid)
        background=r(DEST+anchor_offset)
        table=BLEND(weights,foreground,background)""")
    patch("                transfer['destination_anchor_read']=hex(a)", """                transfer['destination_anchor_read']=hex(a)
                native_anchor_reads.append(a-DEST)""")
    patch("        assert transfer['destination_anchor_read']==hex(expected_transfer['anchor'])", """        assert native_anchor_reads==[anchor_offset]
        assert transfer['destination_anchor_read']==hex(expected_transfer['anchor'])""")
    patch("        text_results[-1].update(draw=draw,transfer=transfer)", """        text_results[-1].update(draw=draw,transfer=transfer)
        transfer['clip_observation']=dict(
            rect=rect,viewport=clip,status=draw['clip_status'],intersection=crop,
            source_origin=[crop[0]-rect[0],crop[1]-rect[1]],
            source_offset_first=reads[0] if reads else None,
            source_offset_last=reads[-1] if reads else None,
            ordered_source_offsets_sha256=digest(b''.join(pack('<I',n) for n in bitmap_reads)),
            ordered_destination_offset_words_sha256=transfer['destination_writes_sha256'],
            frame_sha256=transfer['frame_sha256'],before_sha256=digest(before),
            clipped_row_zero_stores=sum(offset//(4*pitch)==0 for offset,_ in transfer_writes),
            row_0_store_columns=[offset//4 for offset,_ in transfer_writes if offset//(4*pitch)==0],
            coverage=coverage,source_reads=len(bitmap_reads),stores=len(transfer_writes),
            anchor_offset=anchor_offset,original_config_sha256=digest(original_config),
            supplied_config_sha256=digest(supplied_config),
            transfer_pc_sha256=digest(b''.join(pack('<I',pc) for pc in transfer_pcs)),
            instructions=len(transfer_pcs),models=0,unchanged_source_bitmap=True,
            unchanged_surface_and_allocation_guards=True,unchanged_non_rectangle_config_bytes=True)""")
    return source


def s32(value):
    return value if value < 0x80000000 else value - 0x100000000


def run(data, sources, cases):
    text_cli = ModuleType("_clip71_verified_text_cli")
    text_cli.__file__ = str(ROOT / TEXT_CLI)
    exec(compile(sources[TEXT_CLI], text_cli.__file__, "exec", dont_inherit=True), vars(text_cli))
    assert text_cli.HELPERS == {name: pin for name, pin in PINS.items() if name != TEXT_CLI}
    measure = text_cli.load_measure(sources[text_cli.MEASURE])
    parser = measure.execute_helper(text_cli.PARSER, sources[text_cli.PARSER])
    font = measure.execute_helper(text_cli.FONT, sources[text_cli.FONT])
    text = measure.execute_helper(text_cli.TEXT, sources[text_cli.TEXT])
    blob = parser.bounded(data, parser.RTOS_OFFSET, parser.RTOS_SIZE, "RTOS")
    icons = parser.bounded(data, parser.ICON_OFFSET, parser.ICON_SIZE, "ICONBIN")
    assert digest(blob) == parser.RTOS_SHA and digest(icons) == parser.ICON_SHA
    assets, _ = font.read_font_assets(data)
    descriptors = parser.parse_descriptors(blob, len(icons))
    row_source = sources[text_cli.ROW].decode("utf-8")
    baseline = json.loads(sources[BASELINE])["cases"][-1]
    cross = json.loads(sources[CROSS])
    assert cross["k3_iii"]["surface"]["size"] == [256,144]
    assert baseline["frame_sha256"] == cross["k3_iii"]["native_transfer"]["frame_sha256"]
    env = font.extend("rt", assets, row_source, parser, PINS[text_cli.PARSER],
                      patch=lambda source: extend_source(text, source, measure),
                      initial=0xA5, endpoint=0x30000000)
    env.update(DRAW_FILL=0xA5, DRAW_END=text.CLIP_END, UI28_FRAME=text_cli.PRE_FRAME_SHA,
               WEIGHTS_SHA=text_cli.WEIGHTS_SHA, s32=s32, OVERLAP=overlap,
               ORACLE=scalar_oracle, BLEND=text.blend_table)
    env["RANGES"] += (measure.MEASURE_RANGES + text.DRAW_RANGES + text.CLIP_RANGES
                     + text.PALETTE_RANGES + text.GEOMETRY_RANGES + text.TRANSFER_RANGES
                     + [(a, z) for a, z, _ in (text.ASSERT, text.MEMSET)])
    if env["uc"].__version__ != "2.1.4":
        raise ValueError("expected Unicorn 2.1.4")
    results = []
    for case in cases:
        env["CASE"] = case
        observed = env["run"](blob, icons, descriptors, 0, 0, False, True)
        row = observed["text_resolution"][0]
        transfer = row["transfer"]
        evidence = transfer.pop("clip_observation")
        assert observed["guards_unchanged"] and observed["source_images_unchanged"]
        assert observed["relocated_fixture_unchanged"] and transfer["all_allocation_canaries_unchanged"]
        evidence.update(case=case[0], full_trace_sha256=observed["trace_sha256"],
                        full_witness_sha256=text_cli.digest(observed),
                        bitmap_sha256=row["draw"]["bitmap_sha256"],
                        modeled_setup_counts=dict(Counter(item[0] for item in observed["stubs"])))
        if case[0] == "interior":
            assert evidence["full_witness_sha256"] == text_cli.CASES[-1][-1]
            assert evidence["frame_sha256"] == baseline["frame_sha256"]
            assert evidence["ordered_destination_offset_words_sha256"] == baseline["transfer"]["destination_writes_sha256"]
        results.append(evidence)
    return {
        "schema": "k3iii-srgb-unrotated-clip-private-1",
        "decoded_sha256": parser.DECODED_SHA, "rtos_sha256": parser.RTOS_SHA,
        "iconbin_sha256": parser.ICON_SHA, "cpu": "Cortex-A15", "unicorn": env["uc"].__version__,
        "source_lf_sha256": PINS | {BASELINE: BASELINE_PIN, CROSS: CROSS_PIN},
        "source_spans": {name: [hex(a),hex(z),digest(blob[a-parser.RTOS_BASE:z-parser.RTOS_BASE])]
                         for name,(a,z) in BOUNDARY_SPANS.items()},
        "surface": {"size": [256,144], "pitch_words":256, "word_bytes":4, "guard_bytes_per_end":64},
        "bitmap": {"size": [76,40], "stride_bytes":76, "source_x_offset":0},
        "q7_reference_commit": Q7_PIN,
        "cases": results,
    }


ARCHIVE = ROOT / "analysis/colorspace-clip.json"
ORIGINAL_RESEARCH_SHA256 = "bc22e065144569eb7329cc7829128bf75658125ebcab4f001eae0df90f3aa1f3"
ORIGINAL_OBSERVATION_SHA256 = "ec9daaf7f43cb1620bc2c56c87f0aadb35ec8b34705bfd197fe5c24e1d893e36"
ARCHIVE_LIMIT = 32_768


def json_bytes(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")


def read_regular(path, limit, label, *, exact_size=None):
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"{label} must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if exact_size is not None and info.st_size != exact_size:
            raise ValueError(f"{label} size mismatch")
        if info.st_size > limit:
            raise ValueError(f"{label} exceeds {limit} bytes")
        data = stream.read(limit + 1)
    if len(data) > limit or (exact_size is not None and len(data) != exact_size):
        raise ValueError(f"{label} size mismatch")
    return data


def load_archive(path):
    raw = read_regular(path, ARCHIVE_LIMIT, "Compare archive")
    archive = json.loads(raw)
    if not isinstance(archive, dict) or not isinstance(archive.get("observations"), dict):
        raise ValueError("invalid compare archive")
    reference = archive["observations"]
    if digest(json_bytes(reference)) != ORIGINAL_OBSERVATION_SHA256:
        raise ValueError("complete original observation SHA-256 mismatch")
    expected = package(reference, "all seven cases")
    if raw.replace(b"\r\n", b"\n") != json_bytes(expected):
        raise ValueError("compare archive metadata or serialization mismatch")
    return reference


def package(observations, scope):
    return {"schema": "k3iii-srgb-unrotated-clip-1", "execution_scope": scope,
            "original_research_script_sha256": ORIGINAL_RESEARCH_SHA256,
            "original_full_observation_sha256": ORIGINAL_OBSERVATION_SHA256,
            "observations": observations}


def check_replay(observed, reference, case_name):
    if case_name is None:
        if digest(json_bytes(observed)) != ORIGINAL_OBSERVATION_SHA256:
            raise ValueError("complete replay observation SHA-256 mismatch")
        return package(observed, "all seven cases")
    cases = [case for case in reference["cases"] if case["case"] == case_name]
    if len(cases) != 1:
        raise ValueError(f"missing or duplicate compare case: {case_name}")
    # Each comparison includes the complete case witness digest and all metadata.
    if json_bytes(observed) != json_bytes({**reference, "cases": cases}):
        raise ValueError(f"replay metadata or case witness mismatch: {case_name}")
    return package(observed, f"one case: {case_name}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=[name for name, *_ in CASES])
    parser.add_argument("--compare", type=Path, default=ARCHIVE,
                        help="pinned full seven-case archive, default: %(default)s")
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        parser.error("Output already exists")
    reference = load_archive(args.compare)
    sources = checked_sources()
    data = read_regular(args.decoded, 78_683_892, "Decoded input", exact_size=78_683_892)
    if digest(data) != "7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9":
        raise ValueError("Decoded input SHA-256 mismatch")
    selected = [case for case in CASES if args.case in (None, case[0])]
    result = check_replay(run(data, sources, selected), reference, args.case)
    encoded = json_bytes(result)
    with args.output.open("xb") as stream:
        stream.write(encoded)
    print(digest(encoded))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
