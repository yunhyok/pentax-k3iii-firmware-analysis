"""Verify bounded NR research anchors in two pinned decoded images; never patch or execute.

K-3 II is supported here to keep the comparative research reproducible with one tool.
Addresses are static analysis addresses, not instructions to write device memory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from decompile_sample import BASE, RTOS_OFFSET, RTOS_SIZE
from verify_command_analysis import arm_transfer


PROFILES = {
    "k3iii": {
        "version": "2.20", "size": 78683892,
        "sha256": "7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9",
        "offset": RTOS_OFFSET, "length": RTOS_SIZE, "base": BASE,
        "strings": {
            "NoiseReductionCoordinator": (0x53a76458, b"NoiseReductionCoordinator Unknown Project."),
            "NR_ENABLE": (0x53cb31f4, b"NR_ENABLE      , %x\n"),
            "DISABLE_PPU_NR_PARAM": (0x53931a00, b"DISABLE_PPU_NR_PARAM"),
        },
        "words": {
            0x530bc170: 0xe5d610c0, 0x530bc20c: 0xe5d620c1,
            0x52e567cc: 0xe5d10027, 0x52e567dc: 0xe54b0044,
            0x52e567e4: 0xe5d1e026, 0x52e567fc: 0xe54be043,
            0x530bc26c: 0xe3570000, 0x530bc278: 0xe5875000,
        },
        "calls": {0x5258e1b4: 0x530bc14c, 0x52e56830: 0x530bc14c,
                  0x530a3ffc: 0x530bc14c},
        "ranges": {
            "nr_dispatch": (0x530bc14c, 0x530bc42c),
            "caller_flag_transfer": (0x52e567bc, 0x52e56834),
            "workspace_query_call": (0x530a3fb4, 0x530a4000),
            "coordinator_candidate": (0x5313c4c8, 0x5313c5ac),
        },
    },
    "k3ii": {
        "version": "1.12", "size": 16838656,
        "sha256": "1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc",
        "offset": 0, "length": 16838656, "base": 0x02000000,
        "strings": {
            "LNRTRG": (0x024c6c40, b"LNRTRG 0x%08x\n"),
            "LNRCTL": (0x024c6c50, b"LNRCTL 0x%08x\n"),
            "LNRXTH": (0x024c6c60, b"LNRXTH 0x%08x\n"),
        },
        "words": {0x024c6ba8: 0xe59f4060, 0x024c6bb8: 0xe5941304,
                  0x024c6bbc: 0xe28f008c, 0x024c6c10: 0x20000000},
        "calls": {0x024c6bc0: 0x027073ec},
        "ranges": {"lnr_register_dump": (0x024c6b9c, 0x024c6c14)},
    },
}


def inspect(data, profile):
    if len(data) != profile["size"] or hashlib.sha256(data).hexdigest() != profile["sha256"]:
        raise ValueError("decoded image size/SHA-256 mismatch; use the exact reviewed firmware")
    offset, length, base = (profile[key] for key in ("offset", "length", "base"))
    if offset < 0 or length <= 0 or offset + length > len(data):
        raise ValueError("invalid mapped region")
    image = data[offset:offset + length]

    def span(start, end):
        if not base <= start < end <= base + length:
            raise ValueError("anchor outside mapped region")
        return image[start - base:end - base]

    for name, (address, expected) in profile["strings"].items():
        if span(address, address + len(expected) + 1) != expected + b"\0":
            raise ValueError(f"string anchor mismatch: {name}")
    for address, expected in profile["words"].items():
        if address % 4 or struct.unpack("<I", span(address, address + 4))[0] != expected:
            raise ValueError(f"instruction/literal mismatch at {address:#x}")
    for address, target in profile["calls"].items():
        word = struct.unpack("<I", span(address, address + 4))[0]
        if address % 4 or arm_transfer(word, address) != ("call", target):
            raise ValueError(f"direct call mismatch at {address:#x}")
    return {
        "firmware_version": profile["version"], "decoded_sha256": profile["sha256"],
        "scope": "Static anchor verification only; RAW path, pixel arithmetic and hardware unverified.",
        "address_mapping": {"decoded_file_offset": offset, "analysis_base": hex(base), "size": length},
        "strings": {name: hex(value[0]) for name, value in profile["strings"].items()},
        "instruction_and_literal_checks": len(profile["words"]),
        "calls": [{"site": hex(a), "target": hex(b)} for a, b in profile["calls"].items()],
        "ranges": {name: {"start": hex(a), "end_exclusive": hex(b),
                          "sha256": hashlib.sha256(span(a, b)).hexdigest()}
                   for name, (a, b) in profile["ranges"].items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", choices=PROFILES)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path, help="require equality with a published JSON result")
    args = parser.parse_args()
    try:
        with args.decoded.open("rb") as stream:
            data = stream.read(PROFILES[args.model]["size"] + 1)
        result = inspect(data, PROFILES[args.model])
        if args.compare and result != json.loads(args.compare.read_text(encoding="utf-8")):
            raise ValueError("published result mismatch")
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"verification failed: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
