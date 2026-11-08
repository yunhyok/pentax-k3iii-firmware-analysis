"""CPU-only synthetic RAM replay. All media commands and RTOS calls are intercepted."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from rtos_catalog import require

BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_CPSR, UC_ARM_REG_LR,
                               UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP)

CTRL = 0x520C2100
CACHE = 0x520C25E0
SHADOW = CTRL + 0x200 + 0xB3
SCRATCH = 0x10000000
STOP = SCRATCH + 0xF000
RANGES = (
    (0x533593A0, 0x5335948C), (0x53360428, 0x533605D0),
    (0x533601E8, 0x53360428), (0x5335EE8C, 0x5335EF6C),
    (0x53297BC0, 0x53297C40), (0x52FF5AD0, 0x52FF5BAC),
)
STUBS = {
    0x533244B8: "controller semaphore/clock acquire",
    0x53324528: "controller semaphore/clock release",
    0x5335B438: "CMD6 transaction",
    0x5335BB40: "CMD13 transaction",
    0x5335C190: "controller diagnostic",
    0x530FCED4: "update diagnostic",
    0x530F1A68: "Emmc mutex acquire",
    0x530F1BBC: "Emmc mutex release",
    0x532971E4: "wrapper lock",
    0x532971F8: "wrapper unlock",
    0x52FF5708: "wrapper media write",
}


def replay(cache, shadow, cmd6, cmd13, write=1, semaphore=0):
    machine = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    machine.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
    machine.mem_map(BASE, (len(B) + 0xFFF) & ~0xFFF)
    machine.mem_write(BASE, B)
    for address, size in ((CTRL & ~0xFFF, 0x2000), (SCRATCH, 0x10000),
                          (0x547C4000, 0x1000), (0x54C51000, 0x1000)):
        machine.mem_map(address, size)

    def set_word(address, value):
        machine.mem_write(address, struct.pack("<I", value))

    def set_byte(address, value):
        machine.mem_write(address, bytes([value]))

    driver = SCRATCH + 0x1000
    obj = SCRATCH + 0x2000
    vtable = SCRATCH + 0x3000
    card = SCRATCH + 0x4000
    set_word(CTRL + 0x414, card)
    set_word(card, CTRL)
    set_byte(CTRL + 0x449, 1)
    set_byte(CACHE, cache)
    set_byte(SHADOW, shadow)
    set_word(obj + 8, driver)
    set_word(driver, vtable)
    set_word(vtable + 0x6C, 0x532971E4)
    set_word(vtable + 0x70, 0x532971F8)
    switch = iter(cmd6)
    status = iter(cmd13)
    trace = []
    failures = []

    def hook(uc, address, size, data):
        if address in STUBS:
            if address == 0x5335B438:
                assert uc.reg_read(UC_ARM_REG_R0) == CTRL
                index = uc.reg_read(UC_ARM_REG_R1)
                value = uc.reg_read(UC_ARM_REG_R2)
                result = next(switch)
                trace.append(["cmd6", index, value, result])
            elif address == 0x5335BB40:
                assert uc.reg_read(UC_ARM_REG_R0) == CTRL
                result = next(status)
                trace.append(["cmd13", result])
            elif address == 0x533244B8:
                result = semaphore
            elif address in (0x530F1A68, 0x532971E4):
                result = 1
            elif address == 0x52FF5708:
                result = write
                trace.append(["write", result])
            else:
                result = 0
            uc.reg_write(UC_ARM_REG_R0, result)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif not any(start <= address < end for start, end in RANGES):
            failures.append(hex(address))
            uc.emu_stop()

    machine.hook_add(UC_HOOK_CODE, hook)
    machine.reg_write(UC_ARM_REG_CPSR, 0x10)

    def run(entry, *register_args):
        trace.clear()
        for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2), register_args):
            machine.reg_write(register, value)
        machine.reg_write(UC_ARM_REG_SP, SCRATCH + 0xE000)
        machine.reg_write(UC_ARM_REG_LR, STOP)
        machine.emu_start(entry, STOP, count=2000)
        assert not failures and machine.reg_read(UC_ARM_REG_PC) == STOP, failures
        return dict(return_value=machine.reg_read(UC_ARM_REG_R0),
                    cache=machine.mem_read(CACHE, 1)[0], shadow=machine.mem_read(SHADOW, 1)[0],
                    trace=trace.copy())

    return obj, driver, run


def run_checks():
    rows = []
    for label, request, initial, cmd6, cmd13, semaphore, expected, trace in (
        ("restore_cmd6_error", 0, 1, [9], [], 0, (0, 1, 0xA9), [["cmd6", 0xB3, 0xA8, 9]]),
        ("restore_cmd13_error", 0, 1, [0], [4], 0, (0, 1, 0xA9), [["cmd6", 0xB3, 0xA8, 0], ["cmd13", 4]]),
        ("restore_success", 0, 1, [0], [0], 0, (1, 0, 0xA8), [["cmd6", 0xB3, 0xA8, 0], ["cmd13", 0]]),
        ("controller_acquire_error", 0, 1, [], [], 8, (0, 1, 0xA9), []),
        ("cache_already_matches", 1, 1, [], [], 0, (1, 1, 0xA9), []),
    ):
        _, driver, run = replay(initial, 0xA8 | initial, cmd6, cmd13, semaphore=semaphore)
        got = run(0x53297BC0, driver, request)
        assert (got["return_value"], got["cache"], got["shadow"]) == expected and got["trace"] == trace, (label, got)
        rows.append(dict(label=label, requested_partition=request, **got))

    obj, _, run = replay(0, 0xA8, [0, 7, 0], [0, 0])
    first = run(0x52FF5AD0, obj, 0, 512)
    assert first == dict(return_value=1, cache=1, shadow=0xA9,
                         trace=[["cmd6", 0xB3, 0xA9, 0], ["cmd13", 0], ["write", 1], ["cmd6", 0xB3, 0xA8, 7]])
    second = run(0x52FF5AD0, obj, 1, 512)
    assert second == dict(return_value=1, cache=0, shadow=0xA8,
                          trace=[["write", 1], ["cmd6", 0xB3, 0xA8, 0], ["cmd13", 0]])
    rows.extend([dict(label="write_success_masks_restore_error", **first),
                 dict(label="next_boot_write_skips_select1", **second)])
    return dict(passed=True, image_sha256=SHA, count=len(rows), cases=rows,
                scope=__doc__, intercepted=[dict(address=hex(a), name=s) for a, s in STUBS.items()])


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    decoded=args.decoded.read_bytes()
    require(hashlib.sha256(decoded).hexdigest()=='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9','Decoded hash mismatch')
    B=decoded[0x1c19c:0x1c19c+25483200]
    require(hashlib.sha256(B).hexdigest()==SHA,'RTOS hash mismatch')
    result=run_checks()
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print({'passed':result['passed'],'count':result['count']})
