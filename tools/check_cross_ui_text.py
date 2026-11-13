"""Check the K-3 III/Q7 text contract from pinned public records and pure arithmetic."""

if not __debug__:
    raise SystemExit("Run without -O. Assertions are required.")

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from struct import pack, unpack


ROOT = Path(__file__).resolve().parents[1]
III_COMMIT = "fdadab5940de992c18ff7750ce37c98c2b9e105b"
Q7_COMMIT = "77dfa9db8b9a93ed1e413a157ccba8595141fd24"
III_TEXT = "analysis/colorspace-text.json"
III_CHAIN = "analysis/ui-render-chain.json"
III_BOUNDARY = "analysis/ui-render-chain-boundary.json"
Q7_ATTR = "analysis/colorspace-attributes.json"
Q7_BINDING = "analysis/context-binding.json"
SOURCES = {
    "iii": {
        III_TEXT: "9f61bd541c1369a5b94438a8ae07d1caabdcd94efd939caf23511a52bbfc3aa0",
        III_CHAIN: "08bebb175b153e72c76a4654720c4e5fab1de3c07af6d82a7743c58ce350b585",
        III_BOUNDARY: "9faa778d2172071d28cba8cf29fcbd0fb1f2774b3af07c1f82bea424e59283c7",
    },
    "q7": {
        Q7_ATTR: "7604d1cb9649e705b8bb6f2a381841c3bf183eac3268432cac5a5bff0dba5305",
        Q7_BINDING: "06202757da1b222f384ea79188d64f23f3f8625c2dea097ec8881303948ec3ec",
    },
}
MAX_RECORD_BYTES = 64 * 1024


def capture_record(path, expected):
    if not path.is_file():
        raise ValueError(f"Source record must be a regular file: {path.name}")
    with path.open("rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_RECORD_BYTES:
            raise ValueError(f"Source record type or size mismatch: {path.name}")
        data = source.read(MAX_RECORD_BYTES + 1)
    if len(data) > MAX_RECORD_BYTES:
        raise ValueError(f"Source record exceeds byte bound: {path.name}")
    normalized = data.replace(b"\r\n", b"\n")
    if sha256(normalized).hexdigest() != expected:
        raise ValueError(f"Source record SHA-256 mismatch: {path.name}")
    return normalized


def f32(value):
    return unpack("<f", pack("<f", value))[0]


def blend_word(foreground, background, front_weight, back_weight):
    """Blend four packed byte lanes using float32 rounding and integer truncation."""
    return int.from_bytes(bytes(
        int(f32(f32(((foreground >> shift) & 255) * f32(front_weight))
                + f32(((background >> shift) & 255) * f32(back_weight))))
        for shift in (0, 8, 16, 24)
    ), "little")


def q7_columns(width):
    """Source columns for the observed 64→48 horizontal scaling and cell range."""
    if not 2 <= width <= 64:
        raise ValueError("Width outside positive-destination 64-pixel cell range")
    factor = (48 << 16) // 64
    dest = (width * factor) >> 16
    step = (width << 16) // dest
    return dest, step, [(j*step + (step >> 1)) >> 16 for j in range(dest)]


def q7_codes(byte):
    """Unpack four high-bit-first 2-bit codes, without resolving actual display colors."""
    if not 0 <= byte <= 255:
        raise ValueError("Expected a single unsigned source byte")
    return [(byte >> shift) & 3 for shift in (6,4,2,0)]


def overlap(rect, clip):
    x, y = max(rect[0],clip[0]), max(rect[1],clip[1])
    end_x = min(rect[0]+rect[2],clip[0]+clip[2])
    end_y = min(rect[1]+rect[3],clip[1]+clip[3])
    return [x,y,max(end_x-x,0),max(end_y-y,0)]


def project_iii(report):
    fixture = report["fixture"]
    case = next(case for case in report["cases"] if case["name"] == "a5-native-assert")
    geometry, transfer = case["geometry"], case["transfer"]
    width, height = fixture["surface_size"]
    assert case["surface_size"] == [width,height] == [256,144]
    assert fixture["surface_pitch_words"] == width
    rect, clip = geometry["native_config_rect"], geometry["native_config_clip"]
    intersection = overlap(rect,clip)
    assert intersection == transfer["clip"] == [110,22,76,40]
    assert transfer["source_stride"] == rect[2] == 76 and transfer["source_x_offset"] == 0
    assert case["modeled_calls_by_stage_and_entry"]["text-transfer"] == {}
    assert transfer["coverage"] == {"zero":2335,"partial":705,"solid_ff":0}
    assert transfer["writes"] == 705 and not transfer["palette_constructor_returned"]
    assert fixture["profile_byte"] == 0 and case["palette_prefix"]["palette_stop"] == "0x529191b0"
    fg, bg = (int(transfer[key],16) for key in ("partial_palette_word","background_word"))
    # The prior source audit verified the two original binary32 weights for sample 1.
    sample1 = hex(blend_word(fg,bg,0.4,0.6))
    assert sample1 == "0x838d97a2"
    return {
        "mode":"unrotated packed-word transfer; recorded native assertion A5",
        "rtos_sha256":report["rtos_sha256"], "decoded_sha256":report["decoded_sha256"],
        "full_native_case_sha256":case["full_witness_sha256"],
        "surface":{"size":[width,height],"pitch_words":width,"bytes":width*height*4,
                   "first_pixel_byte_offset":4*(intersection[1]*width+intersection[0])},
        "geometry":{"parent":fixture["parent_rectangle"],"local":geometry["local_rect"],
                    "text":rect,"view_clip":clip,"intersection":intersection,"source_origin":[0,0]},
        "bitmap":{"stride_bytes":transfer["source_stride"],"sha256":case["draw_bitmap"]["bitmap_sha256"],
                  "coverage":transfer["coverage"]},
        "palette":{"prepared_profile":fixture["profile_byte"],"host_ready_flags":[
                    fixture["observer_manager_ready_flag"],fixture["palette_ready_flag"]],
                   "incomplete_stop":case["palette_prefix"]["first_unproduced_input"],
                   "partial_index":transfer["partial_palette_index"],"solid_index":transfer["solid_palette_index"],
                   "partial_word":transfer["partial_palette_word"],"solid_word":transfer["solid_palette_word"]},
        "packed_sample_one":{"background":hex(bg),"foreground":hex(fg),"front_weight_f32":f32(0.4),
                             "back_weight_f32":f32(0.6),"computed_word":sample1},
        "weight_table_reference":report["interpolation_weights"],
        "native_transfer":{"cache_table_sha256":transfer["cache_table_sha256"],
                           "frame_sha256":transfer["frame_sha256"],"destination_writes":transfer["writes"],
                           "ordered_writes_sha256":transfer["destination_writes_sha256"],
                           "models_in_resumed_transfer":0},
        "sites":{"geometry":"0x52c003f0","snapshot":"0x52c02538","draw":"0x52bedb40",
                 "intersection":"0x530fa324","background_anchor":"0x528c2664",
                 "table_generator":"0x528c21f8","sample_store":"0x528c26c8"},
    }


def project_q7(attrs,binding,chain,boundary):
    replay = attrs["bounded_replay"]
    config = replay["context_template"]
    assert config["font_cell"] == [64,48] and config["origin"] == [96,64]
    assert config["source_row_bytes"] == 16 and config["source_bits_per_pixel"] == 2
    assert config["orientation"] == 0 and config["pixel_indices"] == [None,2,1,3]
    assert replay["scaled"]["attributes"][:2] == [[17,7,48,48,0,0],[17,12,0,0,0,0]]
    assert attrs["analysis_elf_sha256"] == chain["elf_sha256"] == boundary["elf_sha256"]
    assert attrs["input_sha256"] == chain["package_sha256"] == boundary["package_sha256"]
    assert chain["frame_sha256"] == boundary["frames"]["draw"]["sha256"]
    assert chain["stop"] == boundary["stop"]
    assert chain["stop"] == {"pc":"0x80adf468","before_instruction":True,"consumer_returned":False}
    calls = replay["scaled"]["renderer_calls"]
    connected = [row for row in chain["traces"] if row.get("pc") == "0x80226748" and row["args"][4] == 64]
    assert len(calls) == len(connected) == 4
    x,y = config["origin"]
    glyphs = []
    for isolated, later in zip(calls,connected,strict=True):
        assert isolated["args"] == later["args"] and later["palette"] == [0,2,1,3] and later["transparent"] == 1
        _,_,cell,observed_x,observed_y,source_width,source_height,destination_width,destination_height = isolated["args"]
        width,step,columns = q7_columns(source_width)
        assert (cell,observed_x,observed_y,source_height,destination_width,destination_height) == (64,x,y,48,width,48)
        glyphs.append({"origin":[x,y],"widths":[source_width,width],"inverse_step_q16":step,"source_columns":columns})
        x += width
    missing = binding["bounded_replay"]["replay"]["missing_slot"]
    assert missing["draw_after"] == 18
    assert [row["context"] for row in missing["events"] if "context" in row] == [missing["active_after"]]*2
    extents = [
        {"name":row["names"][0],"start":hex(row["address"]),"end":hex(row["candidate_end"]),"sha256":row["sha256"]}
        for row in attrs["selected_functions"] if row["address"] in (0x8022C058,0x80226748)
    ]
    assert len(extents) == 2
    return {
        "recorded_candidate_function_extents":extents,
        "mode":"orientation zero; indexed draw; horizontal 64→48 scaling",
        "package_sha256":attrs["input_sha256"],"analysis_elf_sha256":attrs["analysis_elf_sha256"],
        "font_sha256":replay["resource"]["sha256"],
        "glyphs":glyphs,"output_extent":[x-config["origin"][0],48],
        "cell_request":[48,48],"factor_q16":(48<<16)//64,
        "packed_source":{"bits_per_pixel":2,"bytes_per_row":16,"index_map":config["pixel_indices"]},
        "isolated_surface":{"pitch_bytes":config["stride"],"rows":config["height"],
                            "first_pixel_byte_offset":64*config["stride"]+96,
                            "changed_bytes":replay["scaled"]["changed_bytes"],
                            "frame_sha256":replay["scaled"]["frame_sha256"]},
        "connected_fixture":{"revision":chain["revision"],"pitch_bytes":chain["stride"],"rows":chain["height"],
                             "first_pixel_byte_offset":64*chain["stride"]+96,"stop":chain["stop"],
                             "srgb_write_bytes":chain["write_bytes"]["text-0x191d00b"],
                             "frame_sha256":chain["frame_sha256"]},
        "context_control":{"draw_id_after_missing_slot":missing["draw_after"],
                           "active_context_retained":missing["active_after"],
                           "active_pointer_global":binding["contracts"]["active_draw_context"]},
        "sites":{"context_setter":"0x8024a59c","active_pointer_store":"0x8024a614","draw":"0x8024928c",
                 "width_factor":"0x8022c0d8","scaled_width":"0x8022c1e0","stretch":"0x80226748",
                 "inverse_step":"0x802268a8","half_step":"0x80226938","byte_store":"0x80226c5c",
                 "frame_row_and_x_guards":["0x80226a5c","0x80226a90"]},
    }


def compare(records):
    iii = project_iii(records["iii"][III_TEXT])
    q7 = project_q7(records["q7"][Q7_ATTR],records["q7"][Q7_BINDING],
                    records["iii"][III_CHAIN],records["iii"][III_BOUNDARY])
    width, dest = q7["glyphs"][0]["widths"]
    columns = q7["glyphs"][0]["source_columns"]
    assert (width,dest) == (24,18)
    return {
        "schema":"pentax-cross-ui-text-1",
        "comparison_scope":"Pinned public native execution records plus standalone arithmetic; no new native or device execution",
        "source_revisions":{"iii":III_COMMIT,"q7":Q7_COMMIT},
        "source_records_sha256_lf":SOURCES,
        "historical_metadata_correction":{
            "previous_revision":"d249dcb74cb3e16b070525b83d4a4c74e664bd6c","resolved_at":III_COMMIT,
            "previous_case_size":[256,40],"corrected_case_size":[256,144],
            "scope":"Recorded case surface height only; bitmap height 40, native pixels and full-frame digest retained"},
        "k3_iii":iii,"q7":q7,
        "counterexamples":{
            "sample_one":{"iii_packed_word":iii["packed_sample_one"]["computed_word"],"q7_palette_index":q7["packed_source"]["index_map"][1]},
            "q16_vs_exact_midpoint":{"output_column":1,"source_column_q16":columns[1],"source_column_exact_midpoint":(3*width)//(2*dest)},
            "q16_vs_left_edge":{"output_column":2,"source_column_q16":columns[2],"source_column_left_edge":(2*width)//dest},
            "authored_byte_0x1b":{"q7_2bit_codes":q7_codes(0x1b),"iii_coverage_if_copied":27,"iii_covered_by_replay":False},
        },
        "port_boundary":{
            "shared_semantic_input":["label identity","presentation role"],
            "target_specific":["resource and font lookup","geometry and clipping","destination context and stride",
                               "coverage transfer or indexed glyph rendering"],
            "tests_to_advance":["Resolve both labels and compare target glyph bounds and frame",
                                "Compare intended and observed attribute/text context after valid and missing registry slots",
                                "Exercise clipped target writes and guards, then establish display palette separately"],
        },
        "limits":["Fixed observed text paths only; Q7 partial clipping remains static evidence",
                  "No original firmware, ROM data, font, bitmap or frame loaded by this CLI",
                  "No physical palette or LCD verification and no cross-camera UI port"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iii-root",type=Path,default=ROOT)
    parser.add_argument("--q7-root",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        parser.error("Output already exists")
    try:
        roots = {"iii":args.iii_root,"q7":args.q7_root}
        captured = {camera:{name:capture_record(roots[camera]/name,pin) for name,pin in rows.items()}
                    for camera,rows in SOURCES.items()}
        records = {camera:{name:json.loads(data) for name,data in rows.items()} for camera,rows in captured.items()}
        text = json.dumps(compare(records),ensure_ascii=False,allow_nan=False,indent=2)+"\n"
        with args.output.open("x",encoding="utf-8",newline="\n") as output:
            output.write(text)
    except (OSError,ValueError) as error:
        parser.error(str(error))
    print("PASS: pinned public records and fixed III/Q7 text arithmetic")


if __name__ == "__main__":
    main()
