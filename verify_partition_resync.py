"""ARM synthetic RAM only. CMD8 data, hardware, clock, and RTOS calls are stubs."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP)

BASE = 0x52500000
SHA = "342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4"
CTRL = 0x520C2100
SHADOW = CTRL + 0x2B3
CACHE = CTRL + 0x4E0
RAM = 0x10000000
HOST = RAM + 0x1000
CARD = RAM + 0x4000
STOP = RAM + 0xF000
RANGES = (
    (0x5335C770, 0x5335CA04), (0x5335D338, 0x5335D4F8),
    (0x5335B778, 0x5335B950), (0x5331FF68, 0x5331FFF8),
    (0x533593A0, 0x5335948C), (0x5335E97C, 0x5335EBEC),
    (0x5335DD78, 0x5335DE60),
)
STUBS = {
    0x5335D230: "host descriptor finalization", 0x5335B51C: "CMD7",
    0x5335BC80: "CMD16", 0x53323684: "destination maintenance",
    0x526AB2A8: "RAM fill", 0x5335A7F0: "CMD8 capture and synthetic receive",
    0x5335AD18: "command wait", 0x533202F0: "entire underlying device initialization",
    0x533244B8: "controller acquire", 0x53324528: "controller release",
    0x53360428: "actual partition switch", 0x5335C190: "diagnostic",
    0x5335D4F8: "host reset wait", 0x53323614: "delay",
}
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)


def run_checks(binary):
    assert hashlib.sha256(binary).hexdigest() == SHA

    def replay(entry, arguments, cache, shadow, init_result=0, switch_result=0):
        machine = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        machine.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        machine.mem_map(BASE, (len(binary) + 4095) & ~4095)
        machine.mem_write(BASE, binary)
        for address, size in ((0x520C2000, 0x2000), (RAM, 0x10000), (0x54565000, 0x1000),
                              (0x547C4000, 0x1000), (0x54C51000, 0x1000)):
            machine.mem_map(address, size)

        def write(address, value, width=4):
            machine.mem_write(address, value.to_bytes(width, "little"))

        def read(address, width=4):
            return int.from_bytes(machine.mem_read(address, width), "little")

        machine.mem_write(CTRL, bytes([0xCC]) * 0x400)
        write(CTRL + 0x410, HOST)
        write(CTRL + 0x414, CARD)
        write(CARD, CTRL)
        write(CTRL + 0x449, 1, 1)
        write(CACHE, cache, 1)
        write(SHADOW, shadow, 1)
        write(HOST + 0xFC, 0x30000)
        write(RAM + 0x6000, HOST)
        write(RAM + 0x6004, 1)
        events = []
        unexpected = []

        def hook(uc, address, size, data):
            if address in STUBS:
                r0, r1, r2 = (uc.reg_read(reg) for reg in REGS)
                result = 0
                if address == 0x526AB2A8:
                    uc.mem_write(r0, bytes([r1]) * r2)
                    result = r0
                elif address == 0x5335A7F0:
                    dest = read(r1 + 4)
                    assert r0 == CTRL and read(r1 + 0x3A, 1) == 8
                    assert (read(r1 + 0x1C), read(r1 + 0x30), read(r1 + 0x38, 2)) == (0, 1, 512)
                    events.append(["cmd8", hex(dest), 512])
                    payload = bytearray([0x36] * 512)
                    payload[0xB3] = 0xA9
                    uc.mem_write(dest, bytes(payload))
                    write(r1 + 0x3B, 0, 1)
                elif address == 0x533202F0:
                    result = init_result
                elif address == 0x53360428:
                    assert r0 == CTRL
                    events.append(["switch", r1, switch_result])
                    result = switch_result
                elif address == 0x5335D4F8:
                    assert r0 == HOST + 0x2C and r1 == 0x06000000 and read(r0) & r1 == r1
                    events.append(["host_reset", hex(r1)])
                    write(r0, read(r0) & ~r1)
                uc.reg_write(UC_ARM_REG_R0, result)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            elif not any(a <= address < z for a, z in RANGES):
                unexpected.append(hex(address))
                uc.emu_stop()

        machine.hook_add(UC_HOOK_CODE, hook)
        for register, value in zip(REGS, arguments):
            machine.reg_write(register, value)
        machine.reg_write(UC_ARM_REG_LR, STOP)
        machine.reg_write(UC_ARM_REG_SP, RAM + 0xE000)
        machine.emu_start(entry, STOP, count=3000)
        assert not unexpected and machine.reg_read(UC_ARM_REG_PC) == STOP, unexpected
        return dict(return_value=machine.reg_read(UC_ARM_REG_R0), cache=read(CACHE, 1),
                    shadow=read(SHADOW, 1), zero_1k=not any(machine.mem_read(CTRL, 0x400)),
                    events=events)

    rows = []
    for label, entry, args, cache, shadow, init_result, switch_result, expected in (
        ("controller_1k_clear", 0x5335C770, (CTRL, RAM + 0x6000), 1, 0xA9, 0, 0, (0, 1, 0, True, [])),
        ("cmd8_refresh_only_shadow", 0x5335D338, (CTRL,), 0, 0xA8, 0, 0,
         (0, 0, 0xA9, False, [["cmd8", "0x520c2300", 512]])),
        ("init_select0_skips_if_cache0", 0x5331FF68, (), 0, 0xA9, 0, 0, (0, 0, 0xA9, False, [])),
        ("init_select0_switch_error", 0x5331FF68, (), 1, 0xA8, 0, 7, (1, 1, 0xA8, False, [["switch", 0, 7]])),
        ("init_failure_skips_select0", 0x5331FF68, (), 1, 0xA9, 8, 0, (1, 1, 0xA9, False, [])),
        ("host_reset_leaves_software_partition_fields", 0x5335E97C, (CTRL, 0x208000), 1, 0xA9, 0, 0,
         (0x24, 1, 0xA9, False, [["host_reset", "0x6000000"], ["host_reset", "0x6000000"]])),
    ):
        got = replay(entry, args, cache, shadow, init_result, switch_result)
        assert tuple(got.values()) == expected, (label, got)
        rows.append(dict(label=label, entry=hex(entry), **got))
    return dict(passed=True, image_sha256=SHA, count=len(rows), cases=rows, scope=__doc__,
                ranges=[dict(start=hex(a), end=hex(z), sha256=hashlib.sha256(binary[a-BASE:z-BASE]).hexdigest())
                        for a, z in RANGES],
                intercepted=[dict(address=hex(a), name=s) for a, s in STUBS.items()])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    decoded = args.decoded.read_bytes()
    assert hashlib.sha256(decoded).hexdigest() == "7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9", "Decoded hash mismatch"
    result = run_checks(decoded[0x1c19c:0x1c19c+25483200])
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"passed": result["passed"], "count": result["count"]}))
