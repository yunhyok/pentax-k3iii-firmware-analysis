"""Compare the original A32 matrix caller slices with Q forced to 0 and 1."""

if not __debug__:
    raise RuntimeError("Verification requires assertions; run without -O or PYTHONOPTIMIZE")

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

import capstone as cs
from capstone.arm_const import ARM_OP_IMM
import unicorn as uc
from unicorn import arm_const as arm

from verify_recompiled_integration import BASE, RTOS_OFFSET, RTOS_SHA256, RTOS_SIZE, caller_cases
from package_roundtrip import DECODED_SHA

LEAF, PREPARE, PACK, CALC = 0x5312CD40, 0x5312CE30, 0x5312D0AC, 0x5312D344
LOCAL = (LEAF, 0x5312D370)
WINDOWS = {
    "retained_image_tuning_context": (0x5312A8FC, 0x5312C324),
    "original_q13": (LEAF, 0x5312CDB4),
    "signed32_sibling": (0x5312CDB4, PREPARE),
    "prepare": (PREPARE, PACK),
    "pack": (PACK, CALC),
    "calc": (CALC, LOCAL[1]),
}
UPPER = {0x5312AB14: (0x5312AB24, 0x531323C8), 0x5312B518: (0x5312B528, 0x531323C8),
         0x5312B734: (0x5312B744, 0x531323C8), 0x5312BF14: (0x5312BF24, 0x5312CD08)}
STATUS_ACCESS = ("mrs", "msr", "vmrs", "vmsr", "cps", "srs", "rfe", "eret", "svc", "hvc", "smc", "bkpt")
TABLES = ((0x53A7BA9C, 9), (0x53A7BAA8, 34), (0x53A7BACC, 18), (0x53CBB4C0, 4))
PARAMS, STATE, OUT, OBJ, STACK = 0x60000000, 0x61000000, 0x62000000, 0x63000000, 0x70000000
SP, Q = STACK + 0x800, 1 << 27


def digest(value):
    return sha256(value).hexdigest()


def load_image(path):
    if path.stat().st_size not in (RTOS_SIZE, 78_683_892):
        raise ValueError("Expected the verified v2.20 RTOS or decoded image")
    data = path.read_bytes()
    if digest(data) == DECODED_SHA:
        data = data[RTOS_OFFSET:RTOS_OFFSET + RTOS_SIZE]
    if digest(data) != RTOS_SHA256:
        raise ValueError("Expected the verified v2.20 RTOS or decoded image")
    return data


def frag(rtos, start, end):
    assert BASE <= start < end <= BASE + len(rtos)
    return rtos[start - BASE:end - BASE]


def describe(rtos, start, end):
    return {"start": hex(start), "end_exclusive": hex(end), "sha256": digest(frag(rtos, start, end))}


def static_checks(rtos):
    md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
    md.detail = True
    decoded, edges = {}, {}
    targets = {LEAF, PREPARE, PACK, CALC}
    for name, (start, end) in WINDOWS.items():
        hits = []
        for address in range(start, end, 4):
            insn = next(md.disasm(frag(rtos, address, address + 4), address), None)
            if insn is None:
                # The retained context includes literals and padding.
                assert name == "retained_image_tuning_context", hex(address)
                continue
            decoded[address] = insn
            if LOCAL[0] <= address < LOCAL[1]:
                assert not insn.mnemonic.startswith(STATUS_ACCESS), hex(address)
            if (insn.group(cs.CS_GRP_JUMP) or insn.group(cs.CS_GRP_CALL)) and insn.operands:
                op = insn.operands[0]
                if op.type == ARM_OP_IMM and op.imm in targets:
                    hits.append({"site": hex(address), "target": hex(op.imm), "mnemonic": insn.mnemonic})
        edges[name] = hits
    assert {t["site"] for rows in edges.values() for t in rows if t["target"] == hex(LEAF)} == {
        "0x5312ced8", "0x5312cefc", "0x5312d0a0"}
    assert {t["site"] for rows in edges.values() for t in rows if t["target"] == hex(CALC)} == set(map(hex, UPPER))
    resumes = {}
    for site, (stop, next_target) in UPPER.items():
        resume = [decoded[a].mnemonic for a in range(site + 4, stop, 4)]
        assert all(op in ("ldr", "mov", "sub") for op in resume)
        assert decoded[stop].mnemonic == "bl" and decoded[stop].operands[0].imm == next_target
        resumes[hex(site)] = {**describe(rtos, site, stop + 4), "return": hex(site + 4),
                              "next_call_site": hex(stop), "next_target": hex(next_target),
                              "resume_instructions": resume}
    slot, callsite, literal = 0x53A7682C, 0x52E59050, 0x5312B674
    insn = next(md.disasm(frag(rtos, callsite, callsite + 4), callsite))
    assert (insn.mnemonic, insn.op_str) == ("blx", "r3")
    assert struct.unpack("<I", frag(rtos, slot, slot + 4))[0] == 0x5312B310
    assert struct.unpack("<I", frag(rtos, literal, literal + 4))[0] == slot - 0x1C
    return {"range_hashes": {k: describe(rtos, *v) for k, v in WINDOWS.items()}, "direct_edges": edges,
            "explicit_status_access_candidates_in_local_chain": 0, "upper_resumes": resumes,
            "conditional_indirect_entry": {"callsite": hex(callsite), "vtable_slot": hex(slot), "target": "0x5312b310",
                                           "source_ranges": [describe(rtos, a, b) for a, b in (
                                               (0x52E59040, 0x52E59054), (0x5312B650, 0x5312B670),
                                               (literal, literal + 4), (slot, slot + 4))],
                                           "condition": "The derived vtable is installed, selector 3 yields that object, and the branch is reached.",
                                           "reference": "analysis/deep-evidence.json: Develop to derived ImageTuning apply"}}


def fixture(case):
    _, manual, saturation, override, index, rgb, mode, common = case
    data = bytearray(4096)
    struct.pack_into("<I", data, 8, PARAMS + 0x100)
    for offset, value in ((0x52, 1), (0x57, saturation), (0x58, 8), (0x7D, override),
                          (0x7E, manual), (0x86, index)):
        data[offset] = value
    struct.pack_into("<H", data, 0x5A, 256)
    struct.pack_into("<3h", data, 0x80, *rgb)
    struct.pack_into("<5I", data, 0x100, *(PARAMS + offset for offset in (0x180, 0x1A0, 0x1C0, 0x500, 0x510)))
    struct.pack_into("<9h", data, 0x180, *common)
    struct.pack_into("<9h", data, 0x1A0, *mode)
    struct.pack_into("<9I", data, 0x1C0, *(PARAMS + 0x200 + 0x20 * i for i in range(9)))
    for i in range(9):
        coefficients = [v - i if v > 0 else min(v + i, 32767) for v in common]
        struct.pack_into("<9h", data, 0x200 + i * 0x20, *coefficients)
    struct.pack_into("<8H", data, 0x500, *range(0x111, 0x119))
    struct.pack_into("<3I", data, 0x510, 0xDE, 0xAD, 0xBE)
    struct.pack_into("<2H", data, 0x540, 0xABC, 0x123)
    state = bytearray(b"\xa5" * 0x100)
    struct.pack_into("<I", state, 0x44, PARAMS + 0x540)
    return bytes(data), bytes(state)


def run(rtos, case, caller, injection, q):
    stop, _ = UPPER[caller]
    cpu = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    cpu.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A7)
    mapped = set()

    def load(start, end, permissions):
        for page in range(start & -4096, (end + 4095) & -4096, 4096):
            if page not in mapped:
                cpu.mem_map(page, 4096, permissions)
                mapped.add(page)
        cpu.mem_write(start, frag(rtos, start, end))

    rx = uc.UC_PROT_READ | uc.UC_PROT_EXEC
    load(*LOCAL, rx)
    load(caller, stop + 4, rx)
    for addr, size in TABLES:
        load(addr, addr + size, uc.UC_PROT_READ)
    for addr, size in ((PARAMS, 4096), (STATE, 4096), (OUT, 8192), (OBJ, 4096), (STACK, 4096)):
        cpu.mem_map(addr, size)
    data, state = fixture(case)
    cpu.mem_write(PARAMS, data)
    cpu.mem_write(STATE, state)
    cpu.mem_write(OUT, b"\x5a" * 0x1200)
    cpu.mem_write(OBJ + 0x168, struct.pack("<II", STATE, OBJ + 0x800))
    cpu.mem_write(STACK, b"\x79" * 4096)
    cpu.reg_write(arm.UC_ARM_REG_CPSR, cpu.reg_read(arm.UC_ARM_REG_CPSR) & ~Q)
    args = (arm.UC_ARM_REG_R0, arm.UC_ARM_REG_R1, arm.UC_ARM_REG_R2)
    for reg, value in (
        *zip(args, (STATE, PARAMS, OUT)),
        (arm.UC_ARM_REG_R4, OBJ), (arm.UC_ARM_REG_R5, PARAMS if caller == 0x5312B734 else OUT),
        (arm.UC_ARM_REG_R6, OUT), (arm.UC_ARM_REG_R7, OBJ + 0x900),
        (arm.UC_ARM_REG_R11, PARAMS + 0xD0), (arm.UC_ARM_REG_SP, SP),
    ):
        cpu.reg_write(reg, value)
    pcs, stores, calls = [], [], []
    injections = 0

    def trace(emu, pc, size, _):
        nonlocal injections
        assert size == 4 and (LOCAL[0] <= pc < LOCAL[1] or caller <= pc < stop), hex(pc)
        pcs.append(pc)
        if pc == LEAF:
            calls.append(emu.reg_read(arm.UC_ARM_REG_LR) - 4)
        if pc == injection + 4:
            status = emu.reg_read(arm.UC_ARM_REG_CPSR)
            emu.reg_write(arm.UC_ARM_REG_CPSR, (status & ~Q) | (Q if q else 0))
            injections += 1
        if injections:
            assert bool(emu.reg_read(arm.UC_ARM_REG_CPSR) & Q) == q, (hex(pc), "Q overwritten")

    def store(emu, access, addr, size, value, _):
        stores.append((addr, size, value))

    cpu.hook_add(uc.UC_HOOK_CODE, trace)
    cpu.hook_add(uc.UC_HOOK_MEM_WRITE, store)
    cpu.emu_start(caller, stop, timeout=2_000_000, count=20_000)
    assert cpu.reg_read(arm.UC_ARM_REG_PC) == stop and cpu.reg_read(arm.UC_ARM_REG_SP) == SP
    assert injections == 1 and CALC in pcs and PACK in pcs
    assert calls == [0x5312CED8 if case[1] else 0x5312D0A0, 0x5312CEFC]
    q_at_boundary = bool(cpu.reg_read(arm.UC_ARM_REG_CPSR) & Q)
    assert q_at_boundary == q
    return {"instruction_trace_sha256": digest(json.dumps(pcs).encode()),
            "write_trace_sha256": digest(json.dumps(stores).encode()), "instruction_count": len(pcs),
            "prepare_state_sha256": digest(cpu.mem_read(STATE, len(state))),
            "packed_output_sha256": digest(cpu.mem_read(OUT, 0x1200)),
            "next_call_args": [hex(cpu.reg_read(reg)) for reg in args]}, q_at_boundary


def verify(rtos):
    static = static_checks(rtos)
    cases = []
    for caller in UPPER:
        for case in caller_cases():
            for site in (0x5312CED8 if case[1] else 0x5312D0A0, 0x5312CEFC):
                zero, q_zero = run(rtos, case, caller, site, False)
                one, q_one = run(rtos, case, caller, site, True)
                assert zero == one, (hex(caller), case[0], hex(site))
                cases.append({"upper_site": hex(caller), "case": case[0], "injection_return": hex(site + 4),
                              "q_at_next_boundary": [q_zero, q_one], **zero})
    return {"schema_version": 1, "rtos_sha256": RTOS_SHA256, "capstone": cs.__version__, "unicorn": uc.__version__,
            "static": static, "runtime": {"paired_comparisons": len(cases), "executions": 2 * len(cases),
                "color_space": 1, "cpu_model": "Cortex-A7", "firmware_callee_stubs": 0,
                "q_retained_at_every_instruction_after_injection": True, "cases": cases},
            "scope": "Synthetic arguments at four original upper BL sites; original code through matrix prepare and output pack. Force only CPSR.Q once at a selected leaf return and stop before the next processing call.",
            "limits": "Other call sites and indirect targets, ColorSpace-off and exceptional branches, and later consumers are outside the runtime checks. Public AAPCS32 leaves Q undefined; private firmware conventions remain open."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="verified K-3 Mark III v2.20 RTOS or decoded image")
    parser.add_argument("--output", type=Path, required=True, help="new JSON result path")
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise FileExistsError("Output file must not exist")
        report = verify(load_image(args.image))
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    except (OSError, ValueError, AssertionError, uc.UcError) as exc:
        parser.exit(1, f"Q flag verification failed: {exc}\n")
    print(f"Passed {report['runtime']['paired_comparisons']} pairs, {report['runtime']['executions']} A32 executions")


if __name__ == "__main__":
    main()
