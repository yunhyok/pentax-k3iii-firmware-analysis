"""Export the colour tables of the K-3 Mark III firmware 2.20 to JSON.

Reads the tables the camera's colour tuning code uses (colour matrices,
saturation and hue matrices, gamma base curves, DNG matrix tables, the
chroma-suppress parameters, the toning offsets) and the factory setting values
of every Custom Image from a decoded firmware image and writes them as plain
numbers.  With these tables tools/k3iii_color_engine.py reproduces the camera's
colour parameters without the firmware.

    python tools/export_color_tables.py .private/my-decode/decoded.bin --output new-tables.json
    python tools/export_color_tables.py .private/my-decode/decoded.bin --compare analysis/k3iii-color-tables.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import k3iii_tuning_emulator as emulator      # noqa: E402

MODE_INDEX_MAP = 0x53A767D8           # Custom Image number -> resource index (32 bytes)
MATRIX_DESCRIPTORS = 0x54562694       # first row of 35 descriptor pointers
YC_DESCRIPTORS = 0x54561B58           # first row of 35 hue descriptor pointers
COLOR_SPACE_MATRIX = 0x53A7BACC
GAIN_TABLE = 0x53A7BAA8               # 17 x u16
HUE_RIGHT_MATRIX = 0x53C17E6C         # 9 x i32
KEY_TABLE = 0x533DA58C                # 9 x i32
CURVE_FAMILIES = 0x54538D1C           # 3 pointers -> 6 curve pointers each
TRANSITION_WEIGHTS = 0x53AA8220       # 97 x u16
CURVE_NORMALISER = 0x53AAC8FC         # 1 x u16
REVERSAL_BOUNDS = 0x533DA5C8          # 9 x u32
REVERSAL_CURVES = 0x54538CE0          # 9 curve pointers
DNG_MATRIX_A = 0x53C16C08             # 9 (numerator, denominator) pairs
DNG_MATRIX_D65 = 0x53C16220
AUTO_SELECT_SCENES = 0x53C181D8       # 10 scenes x 9 bytes: Custom Image number and eight setting bytes (4 = centre)
SLIDERS = emulator.SLIDERS
TONING_NAMES = ("off", "green", "yellow", "orange", "red", "magenta", "purple", "blue", "cyan")
TUNING_FIELDS = {"saturation": 0x1F8, "hue": 0x1FA, "key": 0x1FC, "contrast": 0x1FE, "highlight": 0x200, "shadow": 0x202}


def export(decoded: Path) -> dict:
    rtos = emulator.load_rtos(decoded)

    def table(address, count, fmt):
        return emulator.read_table(rtos, address, count, fmt)

    def word(address):
        return table(address, 1, "I")[0]

    def named(store, values, prefix):
        """Store a list once and return its name (tables are shared between modes)."""
        for name, existing in store.items():
            if existing == values:
                return name
        name = f"{prefix}{len(store)}"
        store[name] = values
        return name

    factory = emulator.factory_settings(rtos)
    by_number = {number: name for name, number in emulator.MODES.items()}
    scenes = []
    for index in range(10):
        row = table(AUTO_SELECT_SCENES + 9 * index, 9, "B")
        scenes.append({"custom_image": by_number[row[0]],
                       **{key: row[1 + i] - 4 for i, key in enumerate(SLIDERS)}, "sharpness": row[8] - 4})

    matrices, saturation_sets, hue_sets, toning_offsets = {}, {}, {}, {}
    index_map = table(MODE_INDEX_MAP, 32, "B")
    modes = {}
    for name, number in emulator.MODES.items():
        resource = index_map[number]
        descriptor = word(MATRIX_DESCRIPTORS + 4 * resource)
        common, mode_matrix, filters = table(descriptor, 3, "I")
        saturation = [named(matrices, table(pointer, 9, "h"), "m") for pointer in table(filters, 9, "I")]
        hue_descriptor = word(YC_DESCRIPTORS + 4 * resource)
        hue = [table(pointer, 9, "i") for pointer in table(word(hue_descriptor), 9, "I")]
        # Which menu sliders reach the tuning code in this mode: probe each slider at +1.
        fields = {}
        for slider in SLIDERS:
            tuning = emulator.StillTuning(rtos)
            tuning.make(number, **{slider: 1})
            value = int.from_bytes(tuning.e.read(tuning.obj + TUNING_FIELDS[slider], 2), "little")
            fields[slider] = "slider" if value == 5 else value - 4      # fixed setting on the -4..+4 scale
        result = emulator.StillTuning(rtos).make(number)
        registers = result.registers
        offsets = [emulator.StillTuning(rtos).make(number, toning=value).registers.ycof[1:] for value in range(9)]
        if any(any(pair) for pair in offsets):
            toning_offsets.setdefault("chroma_offsets", offsets)
            if toning_offsets["chroma_offsets"] != offsets:
                raise ValueError(f"{name}: toning offsets differ from the other Custom Images")
        modes[name] = {
            "number": number,
            "resource_index": resource,
            "common_matrix": named(matrices, table(common, 9, "h"), "m"),
            "mode_matrix": named(matrices, table(mode_matrix, 9, "h"), "m"),
            "saturation_matrices": named(saturation_sets, saturation, "s"),
            "hue_matrices": named(hue_sets, hue, "h"),
            "sliders": fields,
            "gamma": ("per-channel" if any(list(result.channel_curves[c]) != list(result.gamma_curve) for c in "rgb")
                      else "reversal" if number == 10 else "auto" if number == 0 else "regular"),
            "chroma_fixed": bool(registers.chroma_fixed),
            "toning": any(any(pair) for pair in offsets),
            "factory_settings": factory.get(name),
            "default_registers": {"cc0": [int(v) for v in registers.cc0.reshape(-1)],
                                  "yc": [int(v) for v in registers.yc.reshape(-1)]},
        }
    reference = emulator.StillTuning(rtos).make(emulator.MODES["natural"]).registers
    families = [[table(pointer, 256, "H") for pointer in table(word(CURVE_FAMILIES + 4 * family), 6, "I")] for family in range(3)]
    return {
        "scope": "Colour tables read from PENTAX K-3 Mark III firmware 2.20 (RTOS record). Values as stored; see tools/k3iii_color_engine.py for how they are used.",
        "firmware": {"version": "2.20", "rtos_sha256": emulator.RTOS_SHA256},
        "fixed_point": {"matrices": "signed 16 bit, 1.0 = 8192", "hue_matrices": "signed 32 bit, 1.0 = 8192",
                        "gamma_curves": "unsigned 16 bit, 256 points, input step 16 of 4096",
                        "cc0_register": "signed 12 bit, 1.0 = 256", "yc_register": "signed 9 bit, 1.0 = 256",
                        "settings": "menu scale -4..+4; null = the Custom Image has no such setting"},
        "matrices": matrices,
        "saturation_matrix_sets": saturation_sets,
        "hue_matrix_sets": hue_sets,
        "hue_right_matrix": table(HUE_RIGHT_MATRIX, 9, "i"),
        "color_space_matrix": table(COLOR_SPACE_MATRIX, 9, "h"),
        "gain_table": table(GAIN_TABLE, 17, "H"),
        "gamma": {
            "key_table": table(KEY_TABLE, 9, "i"),
            "families": families,
            "transition_weights": table(TRANSITION_WEIGHTS, 97, "H"),
            "normaliser": table(CURVE_NORMALISER, 1, "H")[0],
            "reversal_bounds": table(REVERSAL_BOUNDS, 9, "I"),
            "reversal_curves": [table(pointer, 256, "H") for pointer in table(REVERSAL_CURVES, 9, "I")],
        },
        "chroma_suppress": {"control": list(reference.csp_control), "offset": reference.csp_offset,
                            "gain": reference.csp_gain, "border": reference.csp_border},
        "dng_color_matrix_tables": {"illuminant_a": table(DNG_MATRIX_A, 18, "i"), "d65": table(DNG_MATRIX_D65, 18, "i")},
        "toning": {"names": list(TONING_NAMES), "chroma_offsets": toning_offsets["chroma_offsets"],
                   "unit": "added to Cb and Cr after chroma suppression; 1024 = full chroma range (4 = one 8-bit step)"},
        "auto_select_scenes": scenes,
        "modes": modes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    try:
        result = export(args.decoded)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Export failed: {error}\n")
    text = json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(text)
    status = {"modes": len(result["modes"]), "matrices": len(result["matrices"])}
    if args.compare:
        status["matches_published"] = json.loads(args.compare.read_text(encoding="utf-8")) == json.loads(text)
    print(json.dumps(status))
    if args.compare and not status["matches_published"]:
        parser.exit(1, "Tables differ from the published file.\n")


if __name__ == "__main__":
    main()
