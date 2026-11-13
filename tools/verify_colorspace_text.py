"""Replay the K-3 III sRGB raster and transfer on a synthetic RAM surface."""

if not __debug__:
    raise SystemExit("Run without -O. Assertions are required for the replay.")

import argparse
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
MEASURE = "tools/verify_colorspace_render.py"
ROW = "tools/_colorspace_row_replay.py"
FONT = "tools/_colorspace_font_replay.py"
PARSER = "icon_resource_probe.py"
TEXT = "tools/_colorspace_text_replay.py"
HELPERS = {
    MEASURE: "fccd1a8bf11edee56aae7a1a9d61a850d2f4ecccfb2354289dbcceaa8d59e09d",
    ROW: "aba5c183718c6678889c7fb86b527f0fe0123bca8e12cb3c696d97a4495df91b",
    FONT: "f0e4922a1039b9dcec81ba3591bab7ab191050e90d743dfb277c724dc59c38a8",
    PARSER: "222d409696c04af5719c2b9520b78e64216953442936f69f21bfaa60ffda1a26",
    TEXT: "49cbbbcc97a7f6f53f4319ad942fe36fba4e0704ed18692f5257af8f73e92a91",
}
CASES = (
    ("a5", 0xA5, False, "732d62016ab35e3310c789c6debbed9586004b5af13561b0b955296d83133c54"),
    ("5a", 0x5A, False, "4c41280f2e1ff8adcd46a37daf1884bb57a9d807dbffabd17770ca1db3aa7114"),
    ("a5-native-assert", 0xA5, True, "781169b67d5846ad4f794fabf64961c87f238b6c20d6f33908a8bb832b8c1719"),
)
WEIGHTS_SHA = "9ae0149fd160f9afd2b90262a30ff53aa62d393ccdba0819a5507180018d4350"
PRE_FRAME_SHA = "a11c198912a9c496dd71049b2f87b49cfb8b3c988a5dd6f14be1d3afd1b09bd8"


def capture_sources():
    sources = {}
    for name, expected in HELPERS.items():
        data = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
        if sha256(data).hexdigest() != expected:
            raise ValueError(f"Dependency SHA-256 mismatch: {name}")
        sources[name] = data
    return sources


def load_measure(source):
    measure = ModuleType("_colorspace_text_checked_measure")
    measure.__file__ = str(ROOT / MEASURE)
    exec(compile(source, measure.__file__, "exec"), vars(measure))
    assert measure.HELPERS == {name: HELPERS[name] for name in (ROW, FONT, PARSER)}
    return measure


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return sha256(canonical(value).encode("utf-8")).hexdigest()


def equal(actual, expected, label):
    if canonical(actual) != canonical(expected):
        raise ValueError(f"Typed comparison failed: {label}")


def normalized_fills(case, fill):
    result = deepcopy(case)
    row = result["text_resolution"][0]
    values = [item.pop("host_fill") for item in row["draw"]["allocations"]]
    values.append(row["transfer"]["cache_allocation"].pop(2))
    values.append(row["presentation"]["palette_allocations"][0].pop(2))
    if len(values) != 5 or any(type(value) is not int or value != fill for value in values):
        raise ValueError("Unexpected draw, cache or palette fill")
    return result


def compare_native_assert(actual, expected):
    actual, expected = deepcopy(actual), deepcopy(expected)
    extra = actual["text_resolution"][0]["transfer"].pop("native_assert")
    equal([extra[k] for k in ("instructions", "stack_write_events", "stack_low", "stack_high")],
          [80, 32, -156, 0], "assertion success bounds")
    for record in (actual, expected):
        record.pop("trace_sha256")
        record.pop("executed_unique")
    actual["executed_instructions"] -= extra["instructions"]
    actual["segments"][-1]["instructions"] -= extra["instructions"]
    expected["stubs"].remove(["text-transfer", "0x530fdfc4", 1, None, "0x528c2434"])
    equal(actual, expected, "native assertion delta")


def project(name, case, witness_sha):
    text = case["text_resolution"][0]
    measure = text["measurement"]
    draw = text["draw"]
    presentation = text["presentation"]
    model_counts = {}
    for stage in case["segments"]:
        phase = stage["name"]
        model_counts[phase] = dict(sorted(Counter(item[1] for item in case["stubs"] if item[0] == phase).items()))
    return {
        "name": name,
        "full_witness_sha256": witness_sha,
        "native_trace_sha256": case["trace_sha256"],
        "native_instructions": case["executed_instructions"],
        "native_unique_addresses": case["executed_unique"],
        "segments": case["segments"],
        "modeled_calls_by_stage_and_entry": model_counts,
        "label": {key: text[key] for key in ("label", "label_descriptor", "utf16le", "RT_sha256", "LE_sha256")},
        "measured_config_sha256_63_bytes": measure["draw_config_sha256"],
        "geometry": {key: presentation[key] for key in ("local_rect", "absolute_rect", "view_clip",
                                                        "native_config_clip", "native_config_rect")},
        "palette_prefix": {key: presentation[key] for key in ("palette_stop", "first_unproduced_input",
                "palette_rgb_sha256", "palette_word_sha256", "palette_manager_bytes_written",
                "palette_bytes_written", "palette_source", "palette_canaries_unchanged", "palette_allocations")},
        "draw_bitmap": {key: draw[key] for key in ("allocations", "bitmap_layout", "bitmap_stride",
                "bitmap_sha256", "bitmap_nonzero", "bitmap_nonzero_bounds", "bitmap_value_count",
                "raster_blends", "raster_blend_sha256", "clip_status", "clip_intersection")},
        "transfer": text["transfer"],
        "surface_size": case["surface_size"],
        "total_pixel_writes": case["total_pixel_writes"],
        "frame_sha256": case["frame_sha256"],
        "guards": {key: case[key] for key in ("guards_unchanged", "source_images_unchanged",
                                              "relocated_fixture_unchanged")},
    }


def replay(data, sources, measure):
    parser = measure.execute_helper(PARSER, sources[PARSER])
    font = measure.execute_helper(FONT, sources[FONT])
    text = measure.execute_helper(TEXT, sources[TEXT])
    row_source = sources[ROW].decode("utf-8")
    blob = parser.bounded(data, parser.RTOS_OFFSET, parser.RTOS_SIZE, "RTOS")
    icons = parser.bounded(data, parser.ICON_OFFSET, parser.ICON_SIZE, "ICONBIN")
    assert sha256(blob).hexdigest() == parser.RTOS_SHA
    assert sha256(icons).hexdigest() == parser.ICON_SHA
    assets, font_rows = font.read_font_assets(data)
    descriptors = parser.parse_descriptors(blob, len(icons))

    def range_hash(start, end):
        data_slice = parser.bounded(blob, start-parser.RTOS_BASE, end-start, "native code or data")
        return sha256(data_slice).hexdigest()

    assert range_hash(0x533D2EE4, 0x533D2F64) == WEIGHTS_SHA
    for a, z, pinned in (text.ASSERT, text.MEMSET):
        assert range_hash(a, z) == pinned
    extras = (text.DRAW_RANGES + text.CLIP_RANGES + text.PALETTE_RANGES + text.GEOMETRY_RANGES
              + text.TRANSFER_RANGES)
    records, projections = [], []
    for name, fill, native_assert, witness_sha in CASES:
        env = font.extend("rt", assets, row_source, parser, HELPERS[PARSER],
                          patch=lambda source: text.add_overlays(source, measure.patch_native, native_assert),
                          initial=0xA5, endpoint=0x30000000)
        env.update(DRAW_FILL=fill, DRAW_END=text.CLIP_END,
                   PREDICT=text.predict, UI28_FRAME=PRE_FRAME_SHA, WEIGHTS_SHA=WEIGHTS_SHA)
        env["RANGES"] += measure.MEASURE_RANGES + extras
        if native_assert:
            env["RANGES"] += [(a, z) for a, z, _ in (text.ASSERT, text.MEMSET)]
        case = env["run"](blob, icons, descriptors, 0, 0, False, True)
        actual_sha = digest(case)
        if actual_sha != witness_sha:
            raise ValueError(f"Full original witness mismatch for {name}: {actual_sha}")
        records.append(case)
        projections.append(project(name, case, actual_sha))

    equal(normalized_fills(records[0], 0xA5), normalized_fills(records[1], 0x5A), "A5 and 5A controls")
    compare_native_assert(records[2], records[0])
    return {
        "schema": "k3iii-colorspace-text-1",
        "decoded_bytes": len(data),
        "decoded_sha256": measure.DECODED_SHA,
        "rtos_sha256": parser.RTOS_SHA,
        "iconbin_sha256": parser.ICON_SHA,
        "dependency_sha256_lf": HELPERS,
        "full_witness_canonicalization": "UTF-8 JSON, sorted keys, compact separators, non-ASCII retained, NaN rejected",
        "font_assets": [item for item in font_rows if item["name"].endswith(("RT_Latin.bin", "LE_Latin.bin"))],
        "fixture": {
            "selected_row": 0, "language_setting": 0, "profile_byte": 0,
            "parent_rectangle": [10, 12, 180, 60], "surface_type": 5, "surface_pitch_words": 256,
            "surface_size": [256, 144], "pre_icon_fill_word": "0x31425364",
            "observer_manager_ready_flag": {"address": "0x545a1980", "value": 1},
            "palette_ready_flag": {"address": "0x545a6c28", "value": 1},
            "inherited_measurement_allocation_fill": "a5",
        },
        "interpolation_weights": {"start": "0x533d2ee4", "end": "0x533d2f64", "sha256": WEIGHTS_SHA},
        "native_ranges": [{"start": hex(a), "end": hex(z), "sha256": range_hash(a, z)}
                          for a, z in dict.fromkeys(extras + [(a, z) for a, z, _ in (text.ASSERT, text.MEMSET)])],
        "cases": projections,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        parser.error(f"Output already exists: {args.output}")
    try:
        sources = capture_sources()
        measure = load_measure(sources[MEASURE])
        data = measure.read_decoded(args.decoded)
        result = replay(data, sources, measure)
        encoded = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
