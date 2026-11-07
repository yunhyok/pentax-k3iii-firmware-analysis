"""Print angr's raw C-like output for one verified v2.20 RTOS function."""

import argparse
import csv
import hashlib
import io
import json
import sys
from pathlib import Path

RTOS_OFFSET = 0x1c19c
RTOS_SIZE = 25_483_200
RTOS_SHA256 = "342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4"
BASE = 0x52500000
SAMPLES = {"hdmi": (0x8000, 0x8038), "register-write": (0x508, 0x518)}


def analysis_range(decoded, selection):
    if selection in SAMPLES:
        start, end = SAMPLES[selection]
        return BASE + start, BASE + end
    if selection.startswith("0x"):
        address = int(selection, 16)
        table = Path(__file__).with_name("analysis") / "priority-functions.tsv"
        with table.open(encoding="utf-8") as stream:
            for row in csv.DictReader(stream, delimiter="\t"):
                if row["method"] == "decompiled" and int(row["start"], 16) == address:
                    return address, int(row["end"], 16)
        evidence = table.with_name("deep-evidence.json")
        with evidence.open(encoding="utf-8") as stream:
            for row in json.load(stream)["ranges"]:
                if row["method"] == "decompiled-window" and int(row["start"], 16) == address:
                    return address, int(row["end"], 16)
        raise ValueError("Address is outside the reviewed function list.")
    from rtos_catalog import catalog
    index = int(selection)
    rows = catalog(decoded)
    if not 1 <= index <= len(rows):
        raise ValueError("Command ID must be between 1 and 957.")
    # For the last entry, the next ARM prologue follows a terminal guard-failure call.
    end = int(rows[index]["address"], 16) if index < len(rows) else 0x525b2cd8
    return int(rows[index - 1]["address"], 16), end


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path, help="decoded.bin written by inspect_firmware.py")
    parser.add_argument("sample", help="hdmi, register-write, a command ID (1..957), or a reviewed 0x address")
    args = parser.parse_args()
    with args.decoded.open("rb") as stream:
        stream.seek(RTOS_OFFSET)
        image = stream.read(RTOS_SIZE)
    if hashlib.sha256(image).hexdigest() != RTOS_SHA256:
        parser.exit(1, "RTOS hash mismatch. Expected the decoded K-3 Mark III v2.20 image.\n")
    try:
        import angr
    except ImportError:
        parser.exit(1, "This optional analysis needs angr. Tested with angr==10.0.5.\n")

    try:
        start, end = analysis_range(args.decoded, args.sample)
    except ValueError as error:
        parser.exit(1, f"{error}\n")
    project = angr.Project(io.BytesIO(image), auto_load_libs=False, main_opts={
        "backend": "blob", "arch": "ARMEL", "base_addr": BASE, "entry_point": start,
    })
    options = {}
    if args.sample not in SAMPLES:
        # The stack guard's failure routine ends in a self-loop.
        class Terminal(angr.SimProcedure):
            NO_RET = True

            def run(self):
                pass

        project.hook(0x532fb9c8, Terminal())
        options["indirect_calls_always_return"] = True
    cfg = project.analyses.CFGFast(
        regions=[(start, end)], function_starts=[start], normalize=True,
        start_at_entry=False, symbols=False, function_prologues=False,
        force_smart_scan=False, force_complete_scan=False,
        resolve_indirect_jumps=args.sample.startswith("0x"), **options,
    )
    function = cfg.kb.functions.get(start)
    if function is None:
        parser.exit(1, "Function entry was not found.\n")
    pos = start
    blocks = sorted(function.blocks, key=lambda item: item.addr)
    if not blocks or blocks[0].addr != start:
        parser.exit(1, "Entry block missing.\n")
    for block in blocks:
        if block.addr < pos or block.addr + block.size > end:
            parser.exit(1, "Unexpected block overlap or out-of-range block.\n")
        if args.sample in SAMPLES and block.addr != pos:
            parser.exit(1, "Unexpected gap in function coverage.\n")
        pos = block.addr + block.size
    if args.sample in SAMPLES and pos != end:
        parser.exit(1, "Function coverage does not match the measured range.\n")
    result = project.analyses.Decompiler(function, cfg=cfg.model)
    if result.codegen is None:
        parser.exit(1, "Decompiler produced no pseudocode.\n")
    sys.stdout.write(result.codegen.text)


if __name__ == "__main__":
    main()
