"""Verify bounded K-3 III PafMotor+0x43 evidence from original A32 bytes."""
if not __debug__:
    raise SystemExit("Run without -O")

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from struct import unpack

BASE = 0x52500000
RTOS_SIZE = 25483200
DECODED_SIZE = 78683892
OFFSET = 0x1C19C
RTOS = "342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4"
DECODED = "7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9"
FAMILY = (0x52f0b380, 0x52f0de00)
ORIGINAL_SCRIPT_SHA256 = "ffa08e815c2053d97345ae45eb8761bce7d5a8d34b4c2ebe5f923c01e0944c24"
ORIGINAL_WITNESS_SHA256 = "49f22a7eaf1c7fc5807c85f2ae4de3cba00aa1418061bba61bf18012524a03d2"
ORIGINAL_TYPED_SHA256 = "5de3aacad277e25fae1f9a7b7b9d778364c6a5abdf16a1308296cdb8209a6ad3"
CAPSTONE_VERSION = "5.0.7"
OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)

# This inventory is for explicit [base,#0x43] STRB in the stated range.
# Object provenance and branch semantics are reviewed separately in findings.md.
WRITERS = {
    0x52f0b568: (0x52f0b4b0, "r0", [0]),
    0x52f0b694: (0x52f0b674, "r0", [0]),
    0x52f0b9f0: (0x52f0b988, "r4", [0]),
    0x52f0bfa0: (0x52f0bf5c, "r4", [0,4]),
    0x52f0c034: (0x52f0bf5c, "r4", [1]),
    0x52f0c0b8: (0x52f0bf5c, "r4", [2]),
    0x52f0c0c0: (0x52f0bf5c, "r4", [3]),
    0x52f0c45c: (0x52f0c3e4, "r4", [5]),
    0x52f0c47c: (0x52f0c3e4, "r4", [3]),
    0x52f0c4a4: (0x52f0c3e4, "r4", [2]),
    0x52f0c4d8: (0x52f0c3e4, "r4", [1]),
    0x52f0cd58: (0x52f0cb84, "r4", [0]),
    0x52f0ce74: (0x52f0cdd0, "r4", [0]),
    0x52f0d8ec: (0x52f0d83c, "r4", [0]),
    0x52f0dae0: (0x52f0d83c, "r4", [0]),
    0x52f0db00: (0x52f0d83c, "r4", [0]),
    0x52f0db2c: (0x52f0d83c, "r4", [0]),
    0x52f0db40: (0x52f0d83c, "r4", [0]),
    0x52f0dbac: (0x52f0d83c, "r4", [0]),
    0x52f0dbdc: (0x52f0d83c, "r4", [0]),
    0x52f0dc04: (0x52f0d83c, "r4", [0]),
    0x52f0dc80: (0x52f0d83c, "r4", [4]),
}
SPANS = {
    "motor_family_a32_inventory": FAMILY,
    "motor_constructor": (0x52f0b4b0, 0x52f0b5fc),
    "motor_factory_constructor_result": (0x52f08c74, 0x52f08c98),
    "af_motor_factory_return": (0x52f08d80, 0x52f08dac),
    "joint_motor_pulse_bind": (0x52f07aec, 0x52f07bc0),
    "motor_driver_and_pulse_bind": (0x52f0b380, 0x52f0b490),
    "motor_vtable_typeinfo_slot": (0x538f25c4, 0x538f25dc),
    "motor_typeinfo_and_name": (0x538f2668, 0x538f267c),
    "motor_reset_caller": (0x52f08210, 0x52f08218),
    "motor_reset_calls": (0x52f0ba34, 0x52f0ba7c),
    "joint_mode_1_motor_entry": (0x52f083f0, 0x52f0847c),
    "joint_followup": (0x52f085b4, 0x52f08634),
    "producer_bf5c": (0x52f0bf5c, 0x52f0c0d4),
    "producer_c3e4": (0x52f0c3e4, 0x52f0c508),
    "producer_cb84": (0x52f0cb84, 0x52f0cdc0),
    "producer_cdd0": (0x52f0cdd0, 0x52f0cefc),
    "producer_d83c": (0x52f0d83c, 0x52f0dc88),
    "feedback_motor_forwarder": (0x52f0b490, 0x52f0b498),
    "feedback_driver": (0x53178310, 0x5317834c),
    "feedback_d1_lookup": (0x53177bd4, 0x53177be4),
    "feedback_d1_factory_config": (0x5326e4c4, 0x5326e514),
    "feedback_d1_ctor": (0x5326dd7c, 0x5326de24),
    "feedback_d1_rom_slot": (0x53ca9a6c, 0x53ca9a70),
    "feedback_d1_mmio_base_literal": (0x5326ee08, 0x5326ee0c),
    "feedback_d1_read": (0x5326d5e4, 0x5326d5f0),
    "wrapper_and_reset": (0x52f0bdec, 0x52f0bf14),
    "wrapper_callers_same_receiver": (0x52f0d3e8, 0x52f0d590),
    "adaptive": (0x52f0bd6c, 0x52f0bdec),
}


def digest(data):
    return sha256(data).hexdigest()


def load(path):
    if not path.is_file():
        raise ValueError("expected a regular RTOS or decoded carrier")
    with os.fdopen(os.open(path, OPEN_FLAGS), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size not in (RTOS_SIZE, DECODED_SIZE):
            raise ValueError("unexpected carrier size or file type")
        data = stream.read(info.st_size + 1)
    if len(data) != info.st_size:
        raise ValueError("carrier size changed while reading")
    if len(data) == DECODED_SIZE and digest(data) == DECODED:
        data = data[OFFSET:OFFSET + RTOS_SIZE]
    if len(data) != RTOS_SIZE or digest(data) != RTOS:
        raise ValueError("wrong original carrier SHA-256")
    return data


def scan(image):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, __version__
    from capstone.arm import ARM_OP_MEM

    if __version__ != CAPSTONE_VERSION:
        raise ValueError(f"expected Capstone runtime {CAPSTONE_VERSION}, got {__version__}")

    def take(start, end):
        if not BASE <= start < end <= BASE + len(image):
            raise ValueError("original range outside RTOS")
        return image[start-BASE:end-BASE]

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.skipdata = True
    md.detail = True
    original = {item.address: item for item in md.disasm(take(*FAMILY), FAMILY[0]) if item.id}
    found = [i.address for i in original.values() if i.mnemonic.startswith("strb")
             and any(op.type == ARM_OP_MEM and op.mem.disp == 0x43 for op in i.operands)]
    assert found == list(WRITERS)
    writers = []
    for pc, (entry, receiver, values) in WRITERS.items():
        i = original[pc]
        memory = next(op.mem for op in i.operands if op.type == ARM_OP_MEM)
        assert i.reg_name(memory.base) == receiver and memory.index == 0 and not i.writeback
        writers.append({"pc": hex(pc), "entry": hex(entry), "conditioned_store": i.mnemonic,
                        "receiver_register": receiver, "static_values": values,
                        "instruction_sha256": digest(i.bytes)})
    pointers = {
        0x52f0b5f8: 0x538f25c8,
        0x538f25c4: 0x538f2674,
        0x538f2678: 0x538f2668,
        0x53ca9a6c: 0x5326d5e4,
        0x5326de20: 0x53ca9a00,
        0x5326ee08: 0x1e000020,
    }
    for a,v in pointers.items():
        assert unpack("<I", take(a,a+4)) == (v,)
    assert take(0x538f2668,0x538f2672) == b"8PafMotor\0"
    switches = {
        0x52f0c40c: [0x52f0c4bc,0x52f0c48c,0x52f0c46c,0x52f0c42c],
        0x52f0d8bc: [0x52f0d8e4,0x52f0dba0,0x52f0dbd4,0x52f0d8e4,0x52f0d8e4,
                     0x52f0daf8,0x52f0db24,0x52f0dad8,0x52f0dbfc,0x52f0db38],
    }
    for start, targets in switches.items():
        assert list(unpack("<" + "I"*len(targets), take(start,start+4*len(targets)))) == targets
    # Confirm receiver/dispatch edges and the exact threshold and MMIO-read witnesses.
    checks = {
        0x52f08c80: ("bl","#0x52f0b4b0"), 0x52f08c94: ("str","r7, [r4, #0xc]"),
        0x52f07bac: ("ldr","r0, [r7, #0xc]"), 0x52f07bbc: ("str","r0, [r4, #0x1c]"),
        0x52f0b45c: ("ldr","r0, [sb, #0x10]"), 0x52f0b46c: ("str","r0, [r6, #0x14]"),
        0x52f08468: ("ldr","r0, [r4, #0xdc]"), 0x52f08474: ("ldr","r1, [r4, #0x74]"),
        0x52f08478: ("bl","#0x52f0d83c"),
        0x52f0862c: ("bl","#0x52f0bf5c"), 0x52f0d604: ("bl","#0x52f0c3e4"),
        0x52f0b490: ("ldr","r0, [r0, #8]"), 0x52f0b494: ("b","#0x53178310"),
        0x53178334: ("ldr","r0, [r0, #0x38]"), 0x5317833c: ("ldr","r3, [r3, #0x6c]"),
        0x53178344: ("uxth","r0, r0"), 0x53177bd4: ("mov","r1, #0xd1"),
        0x53177be0: ("str","r0, [r4, #0x38]"), 0x5326ddf0: ("str","r1, [r4, #0x38]"),
        0x5326e4c4: ("ldr","r3, [pc, #0x93c]"), 0x5326e4d8: ("add","r0, r3, #4"),
        0x5326e4dc: ("str","r0, [fp, #-0x3c]"), 0x5326d5e8: ("ldr","r0, [r3]"),
        0x52f0be38: ("bl","#0x52f0bdec"), 0x52f0beec: ("bl","#0x52f0bd6c"),
        0x52f0bf04: ("bl","#0x52f0bd6c"), 0x52f0bd78: ("ldrb","r3, [r0, #0x43]"),
        0x52f0bdb0: ("bl","#0x53106370"), 0x52f0bdb4: ("cmp","r0, r6"),
        0x52f0bdb8: ("bhi","#0x52f0bdd0"), 0x52f0bdbc: ("cmp","r0, r7, lsl #1"),
        0x52f0c09c: ("bl","#0x52f0be18"), 0x52f0d4f4: ("bl","#0x52f0be18"),
        0x52f0d52c: ("bl","#0x52f0be18"), 0x52f0d564: ("bl","#0x52f0be18"),
    }
    for pc, expected in checks.items():
        i, = md.disasm(take(pc,pc+4),pc)
        assert (i.mnemonic,i.op_str) == expected, hex(pc)
    return {
        "schema": 1, "evidence": "static source; no firmware or device execution",
        "original": {"decoded_sha256": DECODED, "rtos_sha256": RTOS, "rtos_base": hex(BASE),
                     "decoded_rtos_offset": hex(OFFSET), "rtos_size": RTOS_SIZE},
        "capstone_version": __version__,
        "spans": {n: [hex(a),hex(b),digest(take(a,b))] for n,(a,b) in SPANS.items()},
        "explicit_byte_writers": writers,
        "table_words": {hex(a): [hex(b) for b in v] for a,v in switches.items()},
        "literal_words": {hex(a):hex(b) for a,b in pointers.items()},
        "checked_instruction_addresses": [hex(pc) for pc in checks],
        "ownership": {"rtti_name": "PafMotor", "field_offset": "0x43",
                      "factory_offset": "0xc", "joint_pointer_offset": "0xdc",
                      "driver_pointer_offset": "0x8", "pulse_pointer_offset": "0x14"},
        "driver_feedback_r1_zero": {"registry_key": "0xd1", "vslot": "0x6c",
                                    "read_pc": "0x5326d5e8", "conditional_address": "0x1e000024",
                                    "return": "low16 of loaded word via 0x53178344",
                                    "runtime_value": None},
        "wrapper_snapshot": {"call_sites": ["0x52f0c09c","0x52f0d4f4","0x52f0d52c","0x52f0d564"],
                             "snapshot_loads": ["0x52f0c08c","0x52f0d424","0x52f0d488","0x52f0d55c"],
                             "reset_before_wrapper_dispatch": "0x52f0be38",
                             "adaptive_read": "0x52f0bd78", "unchanged_value_assumed": False},
        "scope_limit": "explicit [receiver,#0x43] A32 STRB in bounded family only; computed/aliased/bulk stores and other code not enumerated",
    }


def json_bytes(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")


def verify_and_package(record, public_verifier_sha256):
    typed = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if digest(typed) != ORIGINAL_TYPED_SHA256:
        raise ValueError("complete AF83 typed witness SHA-256 mismatch")
    if digest(json_bytes(record)) != ORIGINAL_WITNESS_SHA256:
        raise ValueError("complete AF83 serialized witness SHA-256 mismatch")
    return {
        "schema": "k3iii-af-state-producers-v1",
        "original_research_script_sha256": ORIGINAL_SCRIPT_SHA256,
        "original_full_witness_sha256": ORIGINAL_WITNESS_SHA256,
        "original_typed_witness_sha256": ORIGINAL_TYPED_SHA256,
        "public_verifier_lf_sha256": public_verifier_sha256,
        "counts": {
            "source_spans": len(record["spans"]),
            "explicit_byte_writers": len(record["explicit_byte_writers"]),
            "checked_instruction_addresses": len(record["checked_instruction_addresses"]),
            "jump_tables": len(record["table_words"]),
        },
        "observations": record,
    }


def check_compare(path, expected):
    if not path.is_file():
        raise ValueError("compare regular file required")
    limit = len(expected) + expected.count(b"\n")
    with os.fdopen(os.open(path, OPEN_FLAGS), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("compare file type or size rejected")
        actual = stream.read(limit + 1)
    if len(actual) > limit or actual.replace(b"\r\n", b"\n") != expected:
        raise ValueError("public result differs from --compare")


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("carrier", type=Path, help="original decoded carrier or extracted RTOS")
    cli.add_argument("--output", required=True, type=Path)
    cli.add_argument("--compare", type=Path, help="exact public JSON with LF or CRLF endings")
    args = cli.parse_args(argv)
    if os.path.lexists(args.output) or not args.output.parent.is_dir():
        cli.error("expected a new output in an existing directory")

    image = load(args.carrier)
    public_source = Path(__file__).read_bytes().replace(b"\r\n", b"\n")
    record = verify_and_package(scan(image), digest(public_source))
    payload = json_bytes(record)
    if args.compare is not None:
        check_compare(args.compare, payload)
    if os.path.lexists(args.output):
        cli.error("output already exists")
    with args.output.open("xb") as stream:
        stream.write(payload)
    print(digest(payload))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from error
