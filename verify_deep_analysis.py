"""Verify source bytes and address links behind the deeper RTOS analysis."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from decompile_sample import BASE, RTOS_OFFSET, RTOS_SHA256, RTOS_SIZE
from rtos_catalog import require
from verify_command_analysis import arm_transfer


TABLES = Path(__file__).resolve().parent / "analysis"


def verify_code(image, evidence):
    def section(start, size):
        require(BASE <= start and 0 < size <= BASE + len(image) - start, "Range outside RTOS")
        return image[start - BASE:start - BASE + size]

    ranges = evidence["ranges"]
    for record in ranges:
        start, end = int(record["start"], 16), int(record["end"], 16)
        require(hashlib.sha256(section(start, end - start)).hexdigest() == record["sha256"],
                f"Code range mismatch at {start:#x}")
    seen = set()
    for edge in evidence["transfers"]:
        site = int(edge["site"], 16)
        require(site % 4 == 0 and site not in seen, "Invalid or duplicate transfer site")
        seen.add(site)
        require(any(int(r["start"], 16) <= site < int(r["end"], 16) for r in ranges),
                "Transfer outside the recorded analysis windows")
        actual = arm_transfer(struct.unpack("<I", section(site, 4))[0], site)
        expected = (edge["kind"], None if edge["target"] is None else int(edge["target"], 16))
        require(actual == expected, f"Transfer mismatch at {site:#x}")
    for word in evidence["words"]:
        address = int(word["address"], 16)
        require(struct.unpack("<I", section(address, 4))[0] == int(word["value"], 16),
                f"Data word mismatch at {address:#x}")
    for binding in evidence["conditional_bindings"]:
        site = int(binding["callsite"], 16)
        slot = int(binding["table_slot"], 16)
        target = int(binding["target"], 16)
        require(arm_transfer(struct.unpack("<I", section(site, 4))[0], site)[0]
                in ("call-reg", "branch-reg"), "Binding site is not a register transfer")
        require(struct.unpack("<I", section(slot, 4))[0] == target,
                f"Conditional vtable target mismatch at {slot:#x}")
    return len(ranges), len(seen), len(evidence["words"])


def verify_color(image, evidence):
    init = evidence["initialized_data"]
    source, destination = int(init["source"], 16), int(init["destination"], 16)
    size = init["size"]
    require(struct.unpack_from("<III", image, 0x450) == (source, destination, size),
            "Initialized-data relocation does not match startup literals")

    def section(address, count):
        if destination <= address and address + count <= destination + size:
            address = source + address - destination
        require(BASE <= address and 0 < count <= BASE + len(image) - address,
                "Resource outside source-backed image")
        return image[address - BASE:address - BASE + count]

    require(hashlib.sha256(section(destination, size)).hexdigest() == init["sha256"],
            "Initialized-data payload mismatch")
    resources = evidence["resources"]
    for resource in resources.values():
        address = int(resource["address"], 16)
        expected_source = source + address - destination if destination <= address < destination + size else address
        require(int(resource["source_address"], 16) == expected_source and
                int(resource["file_offset"], 16) == expected_source - BASE, "Source address mismatch")
        require(hashlib.sha256(section(address, resource["size"])).hexdigest() == resource["sha256"],
                f"Resource hash mismatch at {address:#x}")
    arrays = {}
    for name, item in evidence["pointer_arrays"].items():
        resource = resources[item["resource"]]
        values = struct.unpack("<105I", section(int(resource["address"], 16), 420))
        require(values[:35] == values[35:70] == values[70:], "Project rows differ")
        arrays[name] = values[:35]
    mode_map = resources[evidence["mode_index_map"]]
    mapping = section(int(mode_map["address"], 16), mode_map["size"])
    table = resources[evidence["mode_table"]]
    modes = evidence["modes"]
    require(table["size"] == 8 * len(modes) == 176, "Mode table size mismatch")
    for index, mode in enumerate(modes):
        address = int(mode["selector_entry_address"], 16)
        require(address == int(table["address"], 16) + 8 * index, "Mode table order mismatch")
        token_address, number = struct.unpack("<II", section(address, 8))
        token = section(token_address, len(mode["shell_token"]) + 1)
        require(token == mode["shell_token"].encode("ascii") + b"\0" and
                number == mode["common_enum"], "Mode selector mismatch")
        resource_index = mapping[number]
        require(resource_index == mode["resource_index"], "Mode remapping mismatch")
        descriptor = resources[mode["descriptor"]]
        require(arrays["matrix"][resource_index] == int(descriptor["address"], 16),
                "Mode descriptor pointer mismatch")
        operands = struct.unpack("<III", section(int(descriptor["address"], 16), 12))
        for value, key in zip(operands, ("common_matrix", "mode_matrix", "filter_pointer_array")):
            require(value == int(resources[mode[key]]["address"], 16), "Matrix operand link mismatch")
        filters = struct.unpack("<9I", section(operands[2], 36))
        require(list(filters) == [int(resources[key]["address"], 16) for key in mode["filter_matrices"]],
                "Filter matrix links mismatch")
        for name in ("multiaxial", "colorreference"):
            require(arrays[name][resource_index] == int(mode[name + "_pointer"], 16),
                    "Auxiliary tuning pointer mismatch")
    cross_table = resources[evidence["cross_curve_pointers"]]
    cross_addresses = struct.unpack("<III", section(int(cross_table["address"], 16), 12))
    for name, expected in (("gold_curves", (0x53c1557c, 0x53c1598c, 0x53c15d8c)),
                           ("cross_curves", cross_addresses)):
        curves = [resources[key] for key in evidence[name]]
        require([int(r["address"], 16) for r in curves] == list(expected)
                and all(r["size"] == 512 for r in curves), "Channel curve order or size mismatch")
    return len(resources), len(modes)


def verify(decoded):
    with decoded.open("rb") as stream:
        stream.seek(RTOS_OFFSET)
        image = stream.read(RTOS_SIZE)
    require(hashlib.sha256(image).hexdigest() == RTOS_SHA256, "RTOS hash mismatch")
    code = json.loads((TABLES / "deep-evidence.json").read_text(encoding="utf-8"))
    color = json.loads((TABLES / "color-resources.json").read_text(encoding="utf-8"))
    ranges, transfers, words = verify_code(image, code)
    resources, modes = verify_color(image, color)
    print(f"Verified {ranges} analysis ranges, {transfers} transfer sites, {words} data words, "
          f"{resources} resource windows and {modes} internal mode entries.")
    print("Semantic attribution of indirect targets remains conditional on the documented object bindings.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    args = parser.parse_args()
    try:
        verify(args.decoded)
    except (OSError, ValueError, KeyError, IndexError, struct.error) as error:
        parser.exit(1, f"Deep-analysis verification failed: {error}\n")
