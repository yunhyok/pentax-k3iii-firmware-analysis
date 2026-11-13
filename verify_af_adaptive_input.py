"""Verify fixed K-3 III A32 ElapsedTimer input and host integer arithmetic."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from struct import unpack

BASE = 0x52500000
SIZE = 25483200
RTOS_SHA = "342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4"
MASK = 0xffffffff
ORIGINAL_SCRIPT_SHA256 = "09d272575fb12fc4c2f2ff1b878a02e251a0bf38cc46ec0ecb61c3f16e33385e"
ORIGINAL_WITNESS_SHA256 = "de7849fdb05cd5f00524ae4db686e4e63ac04ef63794984cdc918e6a49205643"
ORIGINAL_TYPED_SHA256 = "201c2b5150d00b9d004c0791900d9af4c8fe0dee6e011c9f0739547b623ae405"
CAPSTONE_VERSION = "5.0.7"
OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
SPANS = {
    "utility_factory_init": (0x53102754, 0x5310277c),
    "utility_elapsed_allocation": (0x5310295c, 0x531029a8),
    "utility_cleanup": (0x53102a20, 0x53102a68),
    "utility_singleton": (0x53102ce8, 0x53102d74),
    "utility_vtable": (0x53a6ec30, 0x53a6ec50),
    "utility_typeinfo": (0x53a6ec50, 0x53a6ec58),
    "utility_name": (0x53a6ec1c, 0x53a6ec2d),
    "elapsed_vtable": (0x53a6ee28, 0x53a6ee44),
    "elapsed_typeinfo": (0x53a6ee08, 0x53a6ee10),
    "elapsed_name": (0x53a6ee14, 0x53a6ee23),
    "elapsed_field_name": (0x538f3d64, 0x538f3d73),
    "elapsed_register_binding": (0x5310627c, 0x531062b8),
    "elapsed_constructor_and_snapshot": (0x531062b8, 0x531062e4),
    "adjacent_counter_conversion": (0x531062e4, 0x53106304),
    "elapsed_arithmetic": (0x53106304, 0x53106370),
    "elapsed_virtual_wrapper": (0x53106370, 0x531063b4),
    "elapsed_wait_modes": (0x531063b4, 0x5310643c),
    "registry_singleton": (0x52f137f0, 0x52f13864),
    "registry_insert": (0x52f13864, 0x52f1390c),
    "registry_lookup": (0x52f1390c, 0x52f139a4),
    "distinct_provider_registration_site": (0x531fc9e4, 0x531fc9f4),
    "distinct_provider_insert": (0x52f14044, 0x52f14060),
    "motor_snapshot_zero_initialization": (0x52f0b5cc, 0x52f0b5e0),
    "motor_snapshot_sample_when_feedback_changes": (0x52f0b888, 0x52f0b914),
    "motor_snapshot_after_reset_1": (0x52f0b928, 0x52f0b978),
    "motor_snapshot_after_reset_2": (0x52f0b9f4, 0x52f0ba14),
    "motor_snapshot_pair": (0x52f0bf14, 0x52f0bf5c),
    "motor_adaptive_call_and_threshold": (0x52f0bd6c, 0x52f0bdec),
    "motor_mode3_reference_consumer": (0x52f0b840, 0x52f0b888),
    "motor_mode1_reference_consumer": (0x52f0c1c0, 0x52f0c20c),
}
ANCHORS = {
    0x5310276c: ("ldrls", "pc, [pc, r1, lsl #2]"),
    0x53102968: ("bl", "#0x531062b8"),
    0x5310297c: ("str", "r6, [r4, #0xc]"),
    0x53106294: ("bl", "#0x52f1390c"),
    0x5310629c: ("str", "r0, [r4, #4]"),
    0x531062a0: ("ldr", "r3, [r3, #0x30]"),
    0x531062a8: ("mvn", "r3, #0"),
    0x531062b0: ("str", "r3, [r4, #8]"),
    0x531062dc: ("ldr", "r3, [r3, #0x6c]"),
    0x53106304: ("cmp", "r1, r2"),
    0x5310630c: ("rsbls", "r1, r2, r1"),
    0x53106310: ("rsbhi", "r1, r2, r1"),
    0x53106320: ("addls", "r1, r1, r3"),
    0x53106328: ("umull", "r2, r3, r1, r2"),
    0x53106334: ("lsr", "r0, r1, #4"),
    0x53106364: ("umull", "r0, r1, r0, r3"),
    0x53106390: ("ldr", "r3, [r3, #0x6c]"),
    0x53106394: ("blx", "r3"),
    0x531063b0: ("b", "#0x53106304"),
    0x52f13930: ("mul", "r2, r2, r1"),
    0x52f13944: ("ldr", "r4, [r3, #8]"),
    0x52f14054: ("streq", "r6, [r3, r5, lsl #2]"),
    0x52f0b8fc: ("str", "r0, [r4, #0x80]"),
    0x52f0b974: ("str", "r0, [r4, #0x80]"),
    0x52f0ba10: ("str", "r0, [r4, #0x80]"),
    0x52f0bf48: ("str", "r0, [r4, #0x84]"),
    0x52f0bf54: ("str", "r0, [r4, #0x88]"),
    0x52f0bdac: ("ldr", "r1, [r5, #0x80]"),
    0x52f0bdb0: ("bl", "#0x53106370"),
    0x52f0bdb8: ("bhi", "#0x52f0bdd0"),
    0x52f0c1cc: ("ldr", "r1, [r5, #0x84]"),
}
WORDS = {
    0x53102d70: 0x53a6ec38, 0x53a6ec34: 0x53a6ec50, 0x53a6ec54: 0x53a6ec1c,
    0x53a6ec40: 0x53102754, 0x53102774: 0x531027c0,
    0x531062d0: 0x53a6ee30, 0x53a6ee2c: 0x53a6ee08, 0x53a6ee0c: 0x53a6ee14,
    0x53a6ee3c: 0x5310627c,
}
DIVISORS = (27, 108, 216, 27000)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return sha256(data).hexdigest()


def capture(path):
    require(path.is_file(), "expected a regular extracted RTOS")
    with os.fdopen(os.open(path, OPEN_FLAGS), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size == SIZE, "RTOS length/type")
        data = stream.read(SIZE + 1)
    require(len(data) == SIZE and digest(data) == RTOS_SHA, "RTOS identity")
    return data


def shift_model(old, now, bound, mode):
    delta = (old - now + (bound if old <= now else 0)) & MASK
    high = (delta * 0x2f684bdb) >> 32
    mixed = high + ((delta - high) >> 1)
    if mode == 3:
        result = ((mixed >> 4) * 0x10624dd3) >> 38
    else:
        result = mixed >> (6 if mode == 1 else 7 if mode == 2 else 4)
    return delta, result


def controls():
    bound = MASK
    inputs = [
        (27, 1, bound), (28, 1, bound), (29, 1, bound),
        (1, MASK, bound), (0, MASK, bound), (123, 123, bound),
        (123, 123, 0), (1, 2, bound), (2, 1, bound),
    ]
    inputs += [(1 + threshold * 27 + d, 1, bound)
               for threshold in (2000, 4000, 8000) for d in (-1, 0, 26, 27)]
    rows = []
    for old, now, bound in inputs:
        delta = old-now if old > now else (bound - (now-old)) & MASK
        values = [shift_model(old, now, bound, i) for i in range(4)]
        require(values == [(delta, delta // div) for div in DIVISORS], "division contrast")
        rows.append({"old": old, "now": now, "bound": bound, "delta": delta,
                     "modes_0_1_2_3": [v for _, v in values]})
    for i, threshold in enumerate((2000, 4000, 8000)):
        require([r["modes_0_1_2_3"][0] for r in rows[9+i*4:13+i*4]]
                == [threshold-1, threshold, threshold, threshold+1], "threshold contrast")
    require(shift_model(1, MASK, MASK, 0)[0] == 1, "wrap direction")
    require(shift_model(123, 123, MASK, 0) == (MASK, MASK//27), "strict equality route")
    return rows


def scan(image):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, __version__
    require(__version__ == CAPSTONE_VERSION, f"expected Capstone runtime {CAPSTONE_VERSION}, got {__version__}")
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    def read(start, end):
        require(BASE <= start < end <= BASE + len(image), "span bounds")
        return image[start-BASE:end-BASE]

    for address, expected in ANCHORS.items():
        decoded = list(decoder.disasm(read(address, address+4), address))
        require(len(decoded) == 1 and (decoded[0].mnemonic, decoded[0].op_str) == expected, hex(address))
    for address, value in WORDS.items():
        require(unpack("<I", read(address, address+4))[0] == value, hex(address))
    for address, name in ((0x53a6ec1c, b"14UtilityFactory\0"),
                          (0x53a6ee14, b"12ElapsedTimer\0"),
                          (0x538f3d64, b"m_elapsedTimer\0")):
        require(read(address, address+len(name)) == name, hex(address))
    return {"schema": 1, "scope": "static original A32 and host integer arithmetic only",
            "input_rtos_sha256": RTOS_SHA, "rtos_base": hex(BASE), "capstone_runtime": __version__,
            "source_spans": {name: [hex(a), hex(b), digest(read(a, b))] for name, (a, b) in SPANS.items()},
            "instruction_anchors": [hex(a) for a in ANCHORS],
            "pointer_anchors": {hex(a): hex(v) for a, v in WORDS.items()},
            "provenance": {"factory": "UtilityFactory at 0x547bb080", "elapsed_timer_slot": "factory+0x0c",
                           "old_counter": "PafMotor+0x80 for adaptive mode 0",
                           "current_counter": "ElapsedTimer+4 object from key 0xd9, virtual slot +0x6c",
                           "bound": "ElapsedTimer+8; initialized to 0xffffffff at 0x531062b0",
                           "registry_object_slot": hex(0x54784538 + 12 * 0xd9 + 8),
                           "separate_provider_slot": hex(0x54785994 + 4 * 0xd9),
                           "physical_counter_target": None, "physical_time_scale": None},
            "mode_divisors": dict(enumerate(DIVISORS)), "host_arithmetic_controls": controls()}



def json_bytes(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")


def verify_and_package(record, public_sha256):
    typed = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    require(digest(typed) == ORIGINAL_TYPED_SHA256, "complete typed witness SHA-256 mismatch")
    require(digest(json_bytes(record)) == ORIGINAL_WITNESS_SHA256, "complete serialized witness SHA-256 mismatch")
    return {
        "schema": "k3iii-af-adaptive-input-v1",
        "original_research_script_sha256": ORIGINAL_SCRIPT_SHA256,
        "original_full_witness_sha256": ORIGINAL_WITNESS_SHA256,
        "original_typed_witness_sha256": ORIGINAL_TYPED_SHA256,
        "public_verifier_lf_sha256": public_sha256,
        "observations": record,
    }


def check_compare(path, expected):
    require(path.is_file(), "compare regular file required")
    limit = len(expected) + expected.count(b"\n")
    with os.fdopen(os.open(path, OPEN_FLAGS), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "compare type or size")
        actual = stream.read(limit + 1)
    require(len(actual) == info.st_size and actual.replace(b"\r\n", b"\n") == expected,
            "public result differs from --compare")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rtos", type=Path, help="extracted original RTOS carrier")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compare", type=Path, help="exact public JSON with LF or CRLF endings")
    args = parser.parse_args(argv)
    require(not os.path.lexists(args.output) and args.output.parent.is_dir(), "new output path required")
    image = capture(args.rtos)
    source = Path(__file__).read_bytes().replace(b"\r\n", b"\n")
    payload = json_bytes(verify_and_package(scan(image), digest(source)))
    if args.compare is not None:
        check_compare(args.compare, payload)
    require(not os.path.lexists(args.output), "output already exists")
    with args.output.open("xb") as stream:
        stream.write(payload)
    print(digest(payload))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from error
