"""Verify the published command inventory, reviewed byte ranges and ARM transfer sites."""

import argparse
from collections import Counter
import csv
import hashlib
from pathlib import Path
import struct

from decompile_sample import BASE, RTOS_OFFSET, RTOS_SIZE
from rtos_catalog import catalog, require

TABLES = Path(__file__).resolve().parent / "analysis"


def rows(filename):
    with (TABLES / filename).open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def arm_transfer(word, site):
    """Decode A32 B/BL immediate or BX/BLX register, including BLX immediate H."""
    tag = word & 0x0ffffff0
    if tag in (0x012fff10, 0x012fff30) and word >> 28 != 15:
        return ("call-reg" if tag == 0x012fff30 else "branch-reg"), None
    if word & 0x0e000000 != 0x0a000000:
        raise ValueError(f"no ARM branch at {site:#x}")
    offset = ((word & 0xffffff) ^ 0x800000) - 0x800000
    dest = site + 8 + 4 * offset
    if word >> 28 == 15:
        return "call-thumb", (dest + ((word >> 23) & 2)) & 0xffffffff
    return ("call" if word & 0x01000000 else "branch"), dest & 0xffffffff


def verify(decoded):
    commands = catalog(decoded)
    with decoded.open("rb") as stream:
        stream.seek(RTOS_OFFSET)
        image = stream.read(RTOS_SIZE)
    entries = rows("command-analysis.tsv")
    require(len(entries) == len(commands), "command count mismatch")
    bounds = {}
    for i, (entry, command) in enumerate(zip(entries, commands)):
        require(int(entry["id"]) == command["id"], "out-of-order command ID")
        for key in ("address", "primary", "also", "topic", "priority"):
            require(entry[key] == command[key], f"command {i+1}: {key} mismatch")
        start = int(entry["address"], 16)
        ceiling = int(entries[i+1]["address"], 16) if i+1 < len(entries) else 0x525b2cd8
        require(0 < int(entry["cfg_bytes"]) <= ceiling-start == int(entry["window_bytes"]),
                f"invalid analysis window at {start:#x}")
        bounds[start] = ceiling
    reviewed = rows("priority-functions.tsv")
    require(len({row["start"] for row in reviewed}) == len(reviewed) and
            Counter(row["method"] for row in reviewed) ==
            {"decompiled": 36, "disassembly-range": 6}, "reviewed range catalog mismatch")
    for row in reviewed:
        start, end = int(row["start"], 16), int(row["end"], 16)
        require(BASE <= start < end <= BASE+len(image), "invalid reviewed range")
        section = image[start-BASE:end-BASE]
        require(hashlib.sha256(section).hexdigest() == row["range_sha256"],
                f"reviewed range hash mismatch at {start:#x}")
        bounds[start] = max(bounds.get(start, start), end)
    seen = set()
    counts = Counter()
    for edge in rows("transfers.tsv"):
        caller, site = int(edge["caller"], 16), int(edge["site"], 16)
        require(edge["evidence"] in ("batch", "review", "both"), "unknown evidence type")
        require(caller in bounds and caller <= site < bounds[caller] and site % 4 == 0,
                f"site outside caller window at {site:#x}")
        require((caller, site) not in seen, f"duplicate edge at {site:#x}")
        seen.add((caller, site))
        kind, dest = arm_transfer(struct.unpack_from("<I", image, site-BASE)[0], site)
        expected = None if edge["target"] == "-" else int(edge["target"], 16)
        require((kind, dest) == (edge["kind"], expected), f"transfer mismatch at {site:#x}")
        if edge["evidence"] in ("batch", "both"):
            counts[caller, kind] += 1
    require(len(seen) == 17_914, "transfer catalog count mismatch")
    for entry in entries:
        a = int(entry["address"], 16)
        require(int(entry["direct_calls"]) == counts[a, "call"] + counts[a, "call-thumb"]
                and int(entry["indirect_calls"]) == counts[a, "call-reg"]
                and int(entry["outside_branches"]) == counts[a, "branch"],
                f"batch site count mismatch at {a:#x}")
    print(f"Verified {len(entries)} commands, {len(reviewed)} reviewed ranges and {len(seen)} transfer sites.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    args = parser.parse_args()
    try:
        verify(args.decoded)
    except (ValueError, OSError, struct.error) as exc:
        parser.exit(1, f"verification failed: {exc}\n")
