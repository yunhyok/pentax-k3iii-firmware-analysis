"""Run original ARM alias, lock and low-power code with bounded synthetic inputs."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_ARM
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_SP, UC_CPU_ARM_CORTEX_A15,
)

BASE = 0x52500000
SHA = "342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4"
HERE = Path(__file__).resolve().parent
SYSTEM, FWP, EMMC, MUTEX, PM, FILE, ADJUST = range(0x10001000, 0x10008000, 0x1000)
TABLE, TABLE_SIZE = 0x50b70100, 0x10e00
STACK, STOP = 0x1001e000, 0x1001f000
MANAGER, MMIO = 0x54796098, 0x1b110000


def run(blob, evidence):
    assert hashlib.sha256(blob).hexdigest() == SHA
    approved = [(int(r["start"], 16), int(r["end"], 16))
                for r in evidence["functions"] + evidence["fragments"]]
    table_bytes = bytes((n * 17 + 9) & 255 for n in range(TABLE_SIZE))
    results = []
    descriptions = {
        0x530eefc4: "Base task constructor skipped; derived SystemControl constructor executes.",
        0x530fdfc4: "Diagnostic call skipped.",
        0x53103a64: "Return a synthetic SystemControl initialization dependency.",
        0x531592fc: "Return a synthetic SystemControl initialization dependency.",
        0x52f3f764: "Return a synthetic SystemControl initialization dependency.",
        0x53157868: "Return a synthetic SystemControl initialization dependency.",
        0x530feb20: "Mutex diagnostic call skipped.",
        0x525b7358: "Return synthetic kernel lock result for Emmc mutex, or 0 for AdjustManager.",
        0x530f19f0: "Synthetic mutex ownership check succeeds for the two selected handles.",
        0x525b7940: "Record simulated kernel unlock and return 0.",
        0x53272224: "Record power-management hardware entry; no actual hardware access.",
        0x53272260: "Record power-management hardware exit; no actual hardware access.",
        0x52f50f6c: "Record file-factory dependency lookup, returning synthetic object.",
        0x52f5100c: "Record file-factory driver exit as bounded external call.",
        0x52f590b4: "Return synthetic sibling subsystem object.",
        0x52f59158: "Record sibling subsystem exit.",
        0x52f97824: "Return synthetic sibling subsystem object.",
        0x52f97bd8: "Record sibling subsystem no-op.",
        0x52f3f7ec: "Record file-factory driver entry as bounded external call.",
        0x53105564: "Record SystemControl power-management state notification.",
        0x53105c98: "Record SystemControl power-management prerequisite.",
        0x53105678: "Record SystemControl power-management prerequisite.",
        0x525007dc: "Synthetic clock register critical section entry.",
        0x5250082c: "Synthetic clock register critical section exit.",
        0x5250074c: "Synthetic interrupt restore.",
        0x531063b4: "Record delay multiplier and skip timer loop.",
    }

    def case(name, *, entry, args=(), lock=0, count=0, bank=1, disabled=0,
             adjust_busy=0, level3=True, expected=None, expected_mutex_writes=None,
             mock_file_entry=True):
        u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        for start, size in (
            (BASE, (len(blob)+4095)&~4095), (0x10000000, 0x20000),
            (0x54796000, 0x1000), (0x547ba000, 0x1000), (MMIO, 0x1000),
            (TABLE & ~0xfff, 0x12000),
        ):
            u.mem_map(start, size)
        u.mem_write(BASE, blob)
        u.mem_write(TABLE, table_bytes)
        u.mem_write(FWP, b"\xa5" * 0x1c)
        u.mem_write(SYSTEM, b"\x97" * 0xd8)

        def put(address, value):
            u.mem_write(address, struct.pack("<I", value))

        def word(address):
            return struct.unpack("<I", u.mem_read(address, 4))[0]

        for address, value in {
            MANAGER-4: 1, MANAGER+8: FWP, MANAGER+0xc: 0x10009000,
            FWP+8: EMMC, FWP+0x14: TABLE, FWP+0x18: TABLE_SIZE,
            EMMC: 0x53cb1638, EMMC+0x24: MUTEX, EMMC+0x2c: PM,
            MUTEX+4: 0xa1, MUTEX+0x10: count, ADJUST+0x2c+4: 0xa2,
            ADJUST+0x518: 0x10009000, 0x10009000: 0x1000a000,
            SYSTEM+0x40: PM, SYSTEM+0x48: FWP, SYSTEM+0x5c: FILE, SYSTEM+0x6c: ADJUST,
            SYSTEM+0xb0: 0x53cc2c68 if level3 else 0x53cc2a74,
            SYSTEM+0xb4: 0x53cc291c, MMIO+0x40: 0xa5a5a1a5,
        }.items():
            put(address, value)
        u.mem_write(FWP+0x10, bytes([bank]))
        u.mem_write(EMMC+0x44, b"\x01")
        u.mem_write(MUTEX+0xc, b"\x02\x01")
        u.mem_write(ADJUST+0x2c+0xc, b"\x02\x01")
        u.mem_write(0x1000a000+0x26d9, bytes([adjust_busy]))
        u.mem_write(PM+0x4a, b"\x01" if entry != 0x53317920 else b"\x00")
        u.mem_write(FILE+0x20, b"\x01")
        u.mem_write(SYSTEM+0x9a, bytes([disabled]))
        snapshot = bytes(u.mem_read(FWP, 0x1c))
        trace, writes, stubs = [], [], set()

        def hook(uc, pc, size, _):
            r0, r1 = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)
            if pc in descriptions:
                value = 0
                stubs.add(pc)
                if pc == 0x525b7358:
                    assert r0 in (0xa1, 0xa2) and r1 == 0xffffffff
                    trace.append(("lock", r0))
                    value = lock if r0 == 0xa1 else 0
                elif pc == 0x530f19f0:
                    assert r0 in (MUTEX, ADJUST+0x2c)
                    value = 1
                elif pc == 0x525b7940:
                    assert r0 in (0xa1, 0xa2)
                    trace.append(("unlock", r0))
                elif pc in (0x52f5100c, 0x52f3f7ec, 0x53272224, 0x53272260,
                            0x53105564, 0x53105c98, 0x53105678, 0x531063b4):
                    trace.append((hex(pc), r0, r1) if pc in (0x53105564, 0x531063b4) else (hex(pc),))
                elif pc in (0x52f50f6c, 0x52f590b4, 0x52f97824,
                            0x53103a64, 0x531592fc, 0x52f3f764, 0x53157868):
                    value = FILE
                uc.reg_write(UC_ARM_REG_R0, value & 0xffffffff)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                return
            assert any(a <= pc < z for a, z in approved), (name, hex(pc))

        def mem_hook(uc, access, address, size, value, _):
            if FWP <= address < FWP+0x1c or TABLE <= address < TABLE+TABLE_SIZE:
                raise AssertionError((name, "unexpected partition write", hex(address)))
            if address in (MUTEX+0x10, ADJUST+0x2c+0x10, SYSTEM+0x48,
                           SYSTEM+0x9a, SYSTEM+0xb4, PM+0x4a, EMMC+0x44, MMIO+0x40):
                writes.append((address, size, value))

        u.hook_add(UC_HOOK_CODE, hook)
        u.hook_add(UC_HOOK_MEM_WRITE, mem_hook)

        def execute(pc, inputs):
            for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2), inputs):
                u.reg_write(register, value)
            u.reg_write(UC_ARM_REG_CPSR, 0x10)
            u.reg_write(UC_ARM_REG_SP, STACK)
            u.reg_write(UC_ARM_REG_LR, STOP)
            u.emu_start(pc, STOP, count=10000)
            assert u.reg_read(UC_ARM_REG_PC) == STOP, name

        if entry == 0x53315018:
            execute(entry, (SYSTEM,))
            assert word(SYSTEM+0x48) == 0
            execute(0x53314a60, (SYSTEM, 10))
            assert word(SYSTEM+0x48) == FWP
        else:
            execute(entry, args)
        assert bytes(u.mem_read(FWP, 0x1c)) == snapshot
        assert bytes(u.mem_read(TABLE, TABLE_SIZE)) == table_bytes
        if expected is not None:
            assert trace == expected, (name, trace)
        if expected_mutex_writes is not None:
            values = [(size, value) for address, size, value in writes if address == MUTEX+0x10]
            assert values == [(4, n) for n in expected_mutex_writes], (name, values)
        if entry == 0x53317960:
            assert word(SYSTEM+0xb4) == 0x53cc2c54
            assert u.mem_read(SYSTEM+0x9a, 1) == b"\x0a"
        if entry == 0x53317ef0:
            remaining = disabled & ~8
            assert u.mem_read(SYSTEM+0x9a, 1) == bytes([remaining])
            if not remaining:
                assert word(SYSTEM+0xb4) == 0x53cc291c
        if entry in (0x53297408, 0x53297f38):
            on = entry == 0x53297408
            assert word(MMIO+0x40) == ((0xa5a5a1a5 & ~0x400) | (0x400 if on else 0))
            assert u.mem_read(EMMC+0x44, 1) == bytes([on])
        results.append(dict(name=name, bank_input=bank, trace=trace, writes=writes,
                            stubs=[dict(address=hex(p), behavior=descriptions[p]) for p in sorted(stubs)],
                            partition_object_preserved=True, slot2_table_preserved=True))

    case("constructor to Initialize selector 10", entry=0x53315018, bank=0, expected=[])
    case("guard A lock failure", entry=0x53317920, args=(SYSTEM,), lock=-0x320001,
         expected=[("lock", 0xa1)], expected_mutex_writes=[])
    case("guard A lock success", entry=0x53317920, args=(SYSTEM,),
         expected=[("lock", 0xa1), ("0x53272224",), ("0x52f5100c",), ("unlock", 0xa1)],
         expected_mutex_writes=[1, 0, 0])
    case("guard B first state gate rejects", entry=0x53317dfc, args=(SYSTEM,), level3=False,
         expected=[("lock", 0xa1), ("unlock", 0xa1)], expected_mutex_writes=[1, 0, 0])
    case("guard B state matches and adjustment idle", entry=0x53317dfc, args=(SYSTEM,),
         expected=[("lock", 0xa1), ("0x52f3f7ec",), ("lock", 0xa2), ("unlock", 0xa2),
                   ("0x53272260",), ("unlock", 0xa1)], expected_mutex_writes=[1, 0, 0])
    case("guard B state matches and adjustment busy", entry=0x53317dfc, args=(SYSTEM,), adjust_busy=1,
         expected=[("lock", 0xa1), ("0x52f3f7ec",), ("lock", 0xa2), ("unlock", 0xa2),
                   ("unlock", 0xa1)], expected_mutex_writes=[1, 0, 0])
    case("power-save disable tracks requester after failed storage guard", entry=0x53317960,
         args=(SYSTEM, 3), lock=-0x320001, disabled=2,
         expected=[("0x53105564", PM, 0), ("lock", 0xa1)], expected_mutex_writes=[])
    case("power-save enable with another requester still set", entry=0x53317ef0,
         args=(SYSTEM, 1, 3), disabled=10, expected=[], expected_mutex_writes=[])
    case("power-save enable releases last requester", entry=0x53317ef0,
         args=(SYSTEM, 1, 3), disabled=8, lock=-0x320001,
         expected=[("0x53105c98",), ("0x53105678",), ("lock", 0xa1), ("0x53105564", PM, 1)],
         expected_mutex_writes=[])
    for pc, wait in ((0x53297408, 1), (0x53297f38, 2)):
        case(f"Emmc clock callback {wait}", entry=pc, args=(EMMC,),
             expected=[("lock", 0xa1), ("0x531063b4", PM, wait), ("unlock", 0xa1)],
             expected_mutex_writes=[1, 0, 0])
    case("Emmc recursive lock leaves outer owner count", entry=0x53297408, args=(EMMC,),
         lock=-0x1c0000, count=1,
         expected=[("lock", 0xa1), ("0x531063b4", PM, 1)], expected_mutex_writes=[2, 1])
    return dict(passed=True, image_sha256=SHA, cases=len(results), cases_detail=results,
                scope=("Original ARM with vtable bytes, synthetic objects, modeled kernel and dependency stubs. "
                       "MMIO is ordinary mapped RAM. This validates CPU branches and store addresses. "
                       "Bank inputs are synthetic and do not identify a real bank producer."))


if __name__ == "__main__":
    from verify_m0_memory import load_decoded
    cli=argparse.ArgumentParser(description=__doc__);cli.add_argument('decoded',type=Path);cli.add_argument('--output',type=Path,required=True);a=cli.parse_args()
    d=load_decoded(a.decoded);e=json.loads((HERE/'analysis/system-bank-evidence.json').read_text())
    result=run(d[0x1c19c:0x1c19c+25483200],e)
    a.output.write_text(json.dumps(result,indent=2)+'\n');print('Passed',result['cases'],'SystemControl alias cases')
