"""Print angr's raw C-like output for one verified v2.20 RTOS function."""

import argparse
import hashlib
import io
import sys
from pathlib import Path

RTOS_OFFSET = 0x1c19c
RTOS_SIZE = 25_483_200
RTOS_SHA256 = "342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4"
BASE = 0x52500000
SAMPLES = {"hdmi": (0x8000, 0x8038), "register-write": (0x508, 0x518)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path, help="decoded.bin written by inspect_firmware.py")
    parser.add_argument("sample", choices=SAMPLES)
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

    start, end = (BASE + offset for offset in SAMPLES[args.sample])
    project = angr.Project(io.BytesIO(image), auto_load_libs=False, main_opts={
        "backend": "blob", "arch": "ARMEL", "base_addr": BASE, "entry_point": start,
    })
    cfg = project.analyses.CFGFast(
        regions=[(start, end)], function_starts=[start], normalize=True,
        start_at_entry=False, symbols=False, function_prologues=False,
        force_smart_scan=False, force_complete_scan=False, resolve_indirect_jumps=False,
    )
    function = cfg.kb.functions.get(start)
    if function is None:
        parser.exit(1, "Function entry was not found.\n")
    pos = start
    for block in sorted(function.blocks, key=lambda item: item.addr):
        if block.addr != pos:
            parser.exit(1, "Unexpected gap or overlap in function coverage.\n")
        pos += block.size
    if pos != end:
        parser.exit(1, "Function coverage does not match the measured range.\n")
    result = project.analyses.Decompiler(function, cfg=cfg.model)
    if result.codegen is None:
        parser.exit(1, "Decompiler produced no pseudocode.\n")
    sys.stdout.write(result.codegen.text)


if __name__ == "__main__":
    main()
