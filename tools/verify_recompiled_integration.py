"""Place and verify the Q13 C rebuild in a private, offline RTOS repack."""

import argparse
from io import BytesIO
import json
import os
from pathlib import Path
from random import Random
import struct
import subprocess
from tempfile import mkdtemp

import capstone as cs
from capstone.arm_const import ARM_OP_IMM, ARM_REG_PC
from elftools.elf.elffile import ELFFile
import unicorn as uc
from unicorn import arm_const as arm

from verify_recompiled_kernels import (
    BASE, CC_ARGS, MATRIX, ROOT, RTOS_OFFSET, RTOS_SHA256, RTOS_SIZE, ROUTINES,
    SEED, SOURCE, Sandbox, ZIG_EXE_SHA256, ZIG_VERSION, digest, matrix_cases, require,
)
import package_roundtrip as package
from verify_package_roundtrip import original_arm_checks
from verify_color_math import mat

ENTRY, END, _ = ROUTINES[MATRIX]
CODE_SIZE = 112
TAIL = ENTRY + CODE_SIZE
OBJ_SHA = "b1236d23bce9e4c14ae02e18ba982e83da2a9fc268763ddd5a78d47ec40d17ce"
CODE_SHA = "84d8f005c12abf45bfb40c4410daee4d8bd131e5ccaa74bcedea0c583bb8bea5"
PREPARE, PREPARE_END = 0x5312CE30, 0x5312D0AC
SITES = (0x5312CED8, 0x5312CEFC, 0x5312D0A0)
TABLES = ((0x53A7BA9C, 9), (0x53A7BAA8, 34), (0x53A7BACC, 18), (0x53CBB4C0, 4))
BUF, OUT, STACK, STOP = 0x60000000, 0x61000000, 0x70000000, 0x70002000
SP = STACK + 0x800
ARG_REGS = (arm.UC_ARM_REG_R0, arm.UC_ARM_REG_R1, arm.UC_ARM_REG_R2, arm.UC_ARM_REG_R3)
SAVED_REGS = (*[getattr(arm, f"UC_ARM_REG_R{i}") for i in range(4, 12)],
              *[getattr(arm, f"UC_ARM_REG_D{i}") for i in range(8, 16)])
SAVED_REG_NAMES = "r4-r11, d8-d15"
NESTED_FRAMES = {"original": 28, "candidate": 32}
STAGED_CANDIDATE = "matrix-offline.repacked.unverified.bin"
VERIFIED_CANDIDATE = "matrix-offline.repacked.bin"


def fragment(rtos, start, end):
    return rtos[start - BASE:end - BASE]


def build_matrix(zig, work):
    require(digest(zig.read_bytes()) == ZIG_EXE_SHA256, "Expected the pinned Zig executable")
    obj = work / "numeric_kernels.o"
    env = dict(os.environ, ZIG_LIB_DIR=str(zig.parent / "lib"),
               ZIG_GLOBAL_CACHE_DIR=str(work.parent / "cache-global"),
               ZIG_LOCAL_CACHE_DIR=str(work.parent / "cache-local"))
    version = subprocess.check_output([str(zig), "version"], env=env, text=True).strip()
    require(version == ZIG_VERSION, "Unexpected Zig version")
    subprocess.run([str(zig), *CC_ARGS[:-1], str(obj)], cwd=ROOT, env=env, check=True)
    raw = obj.read_bytes()
    require(digest(raw) == OBJ_SHA, "Built object differs from the verified reference")
    elf = ELFFile(BytesIO(raw))
    text = {name: elf.get_section_by_name(f".text.{name}").data() for name in ROUTINES}
    index = elf.get_section_index(f".text.{MATRIX}")
    require(not any(s["sh_type"] in ("SHT_REL", "SHT_RELA") and s["sh_info"] == index
                    for s in elf.iter_sections()), "Relocation targets matrix code")
    code = text[MATRIX]
    require(len(code) == CODE_SIZE and digest(code) == CODE_SHA, "Unexpected matrix machine code")
    md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM | cs.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    instructions = list(md.disasm(code, ENTRY))
    require(len(instructions) * 4 == CODE_SIZE, "Incomplete A32 instruction coverage")
    targets = []
    for insn in instructions:
        if insn.group(cs.CS_GRP_JUMP):
            (operand,) = insn.operands
            require(operand.type == ARM_OP_IMM and ENTRY <= operand.imm < TAIL,
                    "Branch target outside matrix placement")
            targets.append(hex(operand.imm))
        else:
            require(ARM_REG_PC not in insn.regs_access()[0], "Unexpected PC-relative operand")
        require(not insn.group(cs.CS_GRP_CALL), "Unexpected external call")
    require(instructions[-1].mnemonic == "pop" and ARM_REG_PC in instructions[-1].regs_access()[1],
            "Matrix has no final return before the preserved tail")
    (work / f"{MATRIX}.bin").write_bytes(code)
    return text, {"zig_version": version, "zig_exe_sha256": ZIG_EXE_SHA256, "object_sha256": OBJ_SHA,
                  "source_lf_sha256": digest((ROOT / SOURCE).read_bytes().replace(b"\r\n", b"\n")),
                  "command": ["<zig.exe>", *CC_ARGS[:-1], "<private run>/numeric_kernels.o"],
                  "matrix_sha256": CODE_SHA, "instructions": len(instructions),
                  "direct_branch_targets": targets, "text_relocations": 0, "external_pc_relative_reads": 0,
                  "capstone": cs.__version__}


def direct_calls(original, candidate, text):
    cases = list(matrix_cases(Random(SEED)))
    left_q = [-32768, -32768, 32766, 0, 0, 0, 0, 0, 0]
    right_q = [-32768, 0, 0, -32767, 0, 0, 1, 0, 0]
    result, q_results = {}, {}
    for label, rtos in (("original", original), ("candidate", candidate)):
        sandbox = Sandbox(rtos, text)
        if label == "candidate":
            def forbidden_tail(cpu, address, size, unused):
                raise ValueError("Candidate executed the preserved original instruction")
            sandbox.cpu.hook_add(uc.UC_HOOK_CODE, forbidden_tail, begin=TAIL, end=TAIL)
        depths = []
        for i, (case, left, right) in enumerate(cases):
            out, depth, _, _ = sandbox.run(MATRIX, False, struct.pack("<9h", *left),
                                           struct.pack("<9h", *right), 9, i)
            require(out == struct.pack("<9h", *mat(left, right, "s16")),
                    f"{label} in-place matrix mismatch at {case} {i}")
            depths.append(depth)
        result[label] = max(depths)
        out, _, _, q_flag = sandbox.run(MATRIX, False, struct.pack("<9h", *left_q),
                                         struct.pack("<9h", *right_q), 9, len(cases))
        require(out == bytes(18) and q_flag == (label == "candidate"),
                f"{label} CPSR.Q difference fixture no longer matches")
        q_results[label] = q_flag
    return {"cases_per_image": len(cases), "seed": SEED, "entry": hex(ENTRY),
            "max_stack_write_depth": result, "inputs": "disjoint 18-byte, halfword-aligned arrays",
            "checks": "numeric oracle, preserved registers, SP and CPSR control bits, leaf-only execution, data access, output writes",
            "cpsr_q_difference_fixture": {"left": left_q, "right": right_q, "initial_q": False,
                                          "output_hex_both_images": bytes(18).hex(), "return_q": q_results,
                                          "boundary": "Q is outside the control-bit comparison and is undefined on AAPCS32 public return."}}


def caller_cases():
    rng = Random(SEED + 1)
    identity = [8192, 0, 0, 0, 8192, 0, 0, 0, 8192]
    mixed = [-8192, 4096, 500, 700, 8100, -600, -300, 100, 7900]
    for case, manual in (("manual", True), ("filter", False)):
        yield case + "-identity", manual, 4, 0, 0, [8192, -8192, 4096], identity, identity
        yield case + "-overflow", manual, 255, 0, 0, [-32768] * 3, [-32768] * 9, mixed
        for i in range(3):
            yield (case + f"-random-{i}", manual, i * 4, 1, 8 - i,
                   [rng.randrange(-32768, 32768) for _ in range(3)],
                   [rng.randrange(-32768, 32768) for _ in range(9)],
                   [rng.randrange(-32768, 32768) for _ in range(9)])


def call_prepare(rtos, rebuilt, cases):
    cpu = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    cpu.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A7)
    rx = uc.UC_PROT_READ | uc.UC_PROT_EXEC
    for base in (0x5312C000, 0x5312D000):
        cpu.mem_map(base, 4096, rx)
    cpu.mem_write(ENTRY, fragment(rtos, ENTRY, PREPARE_END))
    for start, size in TABLES:
        base = start & -4096
        if not any(lo == base for lo, _, _ in cpu.mem_regions()):
            cpu.mem_map(base, 4096, uc.UC_PROT_READ)
        cpu.mem_write(start, fragment(rtos, start, start + size))
    cpu.mem_map(BUF, 4096, uc.UC_PROT_READ)
    cpu.mem_map(OUT, 4096, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
    cpu.mem_map(STACK, 4096, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
    # The chosen ColorSpace-on branches need no modeled firmware callees.
    leaf_end = TAIL if rebuilt else END
    frame_bytes = NESTED_FRAMES["candidate" if rebuilt else "original"]
    allowed = ((ENTRY, leaf_end), (END, PREPARE), (PREPARE, PREPARE_END))
    calls, writes = [], set()
    nested = None
    max_stack_depth = 0
    canaries = [0xA2B31753 + 0x01847EAB * i for i in range(8)]
    canaries.extend(0x012356789ABCDEF0 ^ (0x0011223344556677 * i) for i in range(8))

    def saved_registers(emu):
        return [emu.reg_read(reg) for reg in SAVED_REGS]

    def check_code(emu, address, size, unused):
        nonlocal nested
        require(any(lo <= address and address + size <= hi for lo, hi in allowed),
                f"Caller path executed outside measured slices at {address:#x}")
        if address == ENTRY:
            site = emu.reg_read(arm.UC_ARM_REG_LR) - 4
            require(site in SITES and nested is None, "Unexpected matrix call site or recursion")
            _, out, left, right = [emu.reg_read(reg) for reg in ARG_REGS]
            call_sp = emu.reg_read(arm.UC_ARM_REG_SP)
            require(call_sp % 8 == 0 and all(a % 2 == 0 for a in (out, left, right)),
                    "Nested matrix call misaligned")
            require(all(abs(out - a) >= 18 for a in (left, right)), "Matrix output overlaps an input")
            scratch = (call_sp - frame_bytes, call_sp)
            require(all(p + 18 <= scratch[0] or call_sp <= p for p in (out, left, right)),
                    "Matrix operands or output overlap its frame")
            a, b = (struct.unpack("<9h", emu.mem_read(p, 18)) for p in (left, right))
            nested = {"return": site + 4, "out": out, "sp": call_sp, "registers": saved_registers(emu),
                      "expected": struct.pack("<9h", *mat(a, b, "s16")), "scratch": scratch,
                      "reads": (scratch, (left, left + 18), (right, right + 18)), "output_writes": set()}
            calls.append({"site": hex(site), "out": hex(out), "left": hex(left), "right": hex(right),
                          "entry_sp": hex(call_sp)})
        if nested is not None:
            current_sp = emu.reg_read(arm.UC_ARM_REG_SP)
            if address == nested["return"]:
                out = nested["out"]
                actual = bytes(emu.mem_read(out, 18))
                require(actual == nested["expected"] and nested["output_writes"] == set(range(out, out + 18)),
                        "Nested call result or output footprint mismatch")
                require(current_sp == nested["sp"] and saved_registers(emu) == nested["registers"],
                        "Nested call did not restore SP or preserved registers")
                calls[-1]["matrix_output_sha256"] = digest(actual)
                nested = None
            else:
                require(ENTRY <= address < leaf_end and current_sp % 4 == 0
                        and nested["scratch"][0] <= current_sp <= nested["sp"],
                        "Nested call left its code or stack frame")

    def check_read(emu, access, address, size, value, unused):
        if nested is not None:
            require(any(lo <= address and address + size <= hi for lo, hi in nested["reads"]),
                    f"Nested read outside inputs and own frame at {address:#x}")

    def check_write(emu, access, address, size, value, unused):
        nonlocal max_stack_depth
        if nested is not None:
            out, (lo, hi) = nested["out"], nested["scratch"]
            if out <= address and address + size <= out + 18:
                nested["output_writes"].update(range(address, address + size))
            else:
                require(lo <= address and address + size <= hi,
                        f"Nested write outside output and own frame at {address:#x}")
        if STACK <= address and address + size <= SP:
            max_stack_depth = max(max_stack_depth, SP - address)
        else:
            require(OUT <= address and address + size <= OUT + 0x100, "Caller wrote outside output or stack")
            writes.update(range(address - OUT, address - OUT + size))

    cpu.hook_add(uc.UC_HOOK_CODE, check_code)
    cpu.hook_add(uc.UC_HOOK_MEM_READ, check_read)
    cpu.hook_add(uc.UC_HOOK_MEM_WRITE, check_write)
    result = []
    for label, manual, saturation, override, index, rgb, mode, common in cases:
        data = bytearray(4096)
        struct.pack_into("<I", data, 8, BUF + 0x100)
        for offset, value in ((0x52, 1), (0x57, saturation), (0x58, 8), (0x7D, override),
                              (0x7E, manual), (0x86, index)):
            data[offset] = value
        struct.pack_into("<H", data, 0x5A, 256)
        struct.pack_into("<3h", data, 0x80, *rgb)
        struct.pack_into("<5I", data, 0x100, BUF + 0x180, BUF + 0x1A0, BUF + 0x1C0, BUF + 0x500, BUF + 0x510)
        struct.pack_into("<9h", data, 0x180, *common)
        struct.pack_into("<9h", data, 0x1A0, *mode)
        struct.pack_into("<9I", data, 0x1C0, *(BUF + 0x200 + 0x20 * i for i in range(9)))
        for i in range(9):
            coefficients = [v - i if v > 0 else min(v + i, 32767) for v in common]
            struct.pack_into("<9h", data, 0x200 + i * 0x20, *coefficients)
        cpu.mem_write(BUF, bytes(data))
        cpu.mem_write(OUT, b"\xa5" * 0x100)
        cpu.mem_write(STACK, b"\x79" * 4096)
        calls.clear()
        writes.clear()
        max_stack_depth = 0
        for reg, val in zip(SAVED_REGS, canaries):
            cpu.reg_write(reg, val)
        for reg, val in zip((*ARG_REGS, arm.UC_ARM_REG_SP, arm.UC_ARM_REG_LR), (OUT, BUF, 0, 0, SP, STOP)):
            cpu.reg_write(reg, val)
        cpu.emu_start(PREPARE, STOP, timeout=2_000_000, count=20_000)
        expected_sites = (SITES[0] if manual else SITES[2], SITES[1])
        require(nested is None and [c["site"] for c in calls] == list(map(hex, expected_sites)),
                f"{label}: unexpected caller trace")
        require(cpu.reg_read(arm.UC_ARM_REG_PC) == STOP and cpu.reg_read(arm.UC_ARM_REG_SP) == SP
                and saved_registers(cpu) == canaries, f"{label}: caller return state mismatch")
        require(writes == {0, *range(4, 0x30), *range(0x48, 0x5A)}, "Caller output write footprint changed")
        result.append({"case": label, "calls": calls.copy(), "input_sha256": digest(data),
                       "output_sha256": digest(cpu.mem_read(OUT, 0x100)), "max_stack_write_depth": max_stack_depth})
    return result


def placement_diff(before, after, start, code):
    stop = start + len(code)
    require(len(before) == len(after) and before[:start] == after[:start]
            and before[stop:-4] == after[stop:-4], "Unexpected decoded changes outside code/checksum")
    require(after[start:stop] == code, "Patched range does not match compiled bytes")
    old_check = package.u32(before, len(before) - 4)
    new_check = package.u32(after, len(after) - 4)
    expected_check = (old_check + package.sum32(before[start:stop]) - package.sum32(code)) & 0xFFFFFFFF
    require(new_check == expected_check, "Incorrect inner checksum delta")
    return {"decoded_start": hex(start), "decoded_end_exclusive": hex(stop),
            "replacement_bytes": len(code), "different_code_bytes": sum(a != b for a, b in zip(before[start:stop], code)),
            "different_checksum_bytes": sum(a != b for a, b in zip(before[-4:], after[-4:])),
            "original_inner_checksum": hex(old_check), "candidate_inner_checksum": hex(new_check)}


def negative_checks(candidate, info, before, after, start, code):
    rejected = []

    def reject(case, reason, test):
        try:
            test()
        except ValueError as exc:
            require(reason in str(exc), f"{case}: unexpected rejection ({exc})")
            rejected.append({"case": case, "reason": str(exc)})
        else:
            raise ValueError(f"{case}: malformed input accepted")

    malformed = bytearray(after)
    tail = start + len(code)
    old_word = package.u32(malformed, tail)
    malformed[tail] ^= 1
    struct.pack_into("<I", malformed, len(malformed) - 4,
                     (package.u32(after, len(after) - 4) + old_word - package.u32(malformed, tail)) & 0xFFFFFFFF)
    reject("changed_preserved_tail_with_rebalanced_inner_sum", "outside code/checksum",
           lambda: placement_diff(before, malformed, start, code))
    del malformed
    malformed = bytearray(candidate)
    # The stored stream ends with the decoded checksum word followed by a zero envelope.
    inner_word = info["stream_end"] - 6
    require(malformed[inner_word:inner_word + 4] == after[-4:] and malformed[inner_word + 4:inner_word + 6] == b"\0\0",
            "Stored trailer does not contain the decoded checksum")
    malformed[inner_word] ^= 1
    reject("bad_outer_sum", "Outer checksum", lambda: package.parse_package(malformed))
    struct.pack_into("<I", malformed, len(malformed) - 4, 0)
    struct.pack_into("<I", malformed, len(malformed) - 4, (-package.sum32(malformed)) & 0xFFFFFFFF)
    reject("bad_inner_sum_with_rebalanced_outer_sum", "Inner checksum", lambda: package.parse_package(malformed))
    return rejected


def run(original_path, zig, work):
    dependencies = ("package_roundtrip.py", "verify_package_roundtrip.py",
                    "inspect_firmware.py", "verify_update_resources.py")
    tool_hashes = {name: digest((ROOT / name).read_bytes()) for name in dependencies}
    original = package.read_bounded(original_path)
    require(digest(original) == package.ORIGINAL_SHA, "Original package hash mismatch")
    before, original_info = package.parse_package(original)
    require(digest(before) == package.DECODED_SHA, "Original decoded payload hash mismatch")
    index, record = next((i, r) for i, r in enumerate(original_info["named_records"]) if r["name"] == "RTOS")
    require((record["kind"], record["index"], record["size"], record["payload_offset"], record["sha256"])
            == (4, 1, RTOS_SIZE, RTOS_OFFSET, RTOS_SHA256), "Unexpected RTOS record")
    offset = record["payload_offset"]
    original_rtos = before[offset:offset + RTOS_SIZE]
    text, build = build_matrix(zig, work)
    code = text[MATRIX]
    components = work / "components"
    package.unpack(original_path, components)
    record_path = components / "records" / package.filename(index, record)
    require(record_path.read_bytes() == original_rtos, "Extracted RTOS differs")
    patched = original_rtos[:ENTRY - BASE] + code + original_rtos[TAIL - BASE:]
    record_path.write_bytes(patched)
    candidate_path = work / STAGED_CANDIDATE
    packed = package.pack(components, candidate_path)
    candidate = package.read_bounded(candidate_path)
    after, info = package.parse_package(candidate)
    require(packed["package_sha256"] == info["package_sha256"], "Package output identity changed")
    require([r["name"] for r in packed["changed_records"]] == ["RTOS"], "Expected exactly one RTOS replacement")
    require(original[:128] == candidate[:128]
            and original[original_info["version_start"]:original_info["footer_start"]]
            == candidate[info["version_start"]:info["footer_start"]]
            and original[-24:-12] == candidate[-24:-12], "Header, version records or footer identity changed")
    diff = placement_diff(before, after, offset + ENTRY - BASE, code)
    candidate_rtos = after[offset:offset + RTOS_SIZE]
    require(candidate_rtos == patched and fragment(candidate_rtos, TAIL, END) == fragment(original_rtos, TAIL, END),
            "Reopened RTOS or preserved tail differs")
    direct = direct_calls(original_rtos, candidate_rtos, text)
    cases = list(caller_cases())
    baseline_calls = call_prepare(original_rtos, False, cases)
    candidate_calls = call_prepare(candidate_rtos, True, cases)
    require([{k: v for k, v in r.items() if k != "max_stack_write_depth"} for r in baseline_calls]
            == [{k: v for k, v in r.items() if k != "max_stack_write_depth"} for r in candidate_calls],
            "Caller traces or output buffers differ")
    gates = original_arm_checks(original_rtos, original, candidate, before, after)
    rejected = negative_checks(candidate, info, before, after, offset + ENTRY - BASE, code)
    require(all(digest((ROOT / name).read_bytes()) == value for name, value in tool_hashes.items()),
            "A package tool changed during verification; replay the finalized tool")
    keys = ("package_sha256", "package_size", "decoded_sha256", "decoded_size", "blocks", "stored_blocks",
            "outer_checksum", "inner_checksum")
    return {"schema_version": 1, "scope": "One offline Q13 matrix placement and repack. No device or updater execution.",
            "candidate_file_lifecycle": {"during_verification": STAGED_CANDIDATE,
                                         "after_checks_and_evidence": VERIFIED_CANDIDATE},
            "build": build, "package_tools_sha256": tool_hashes, "unicorn": uc.__version__,
            "original": {k: original_info[k] for k in keys}, "candidate": {k: info[k] for k in keys},
            "repack_mode": packed["mode"], "placement": {"rtos_record": packed["changed_records"][0],
            "entry": hex(ENTRY), "preserved_tail_start": hex(TAIL), "end_exclusive": hex(END),
            "original_leaf_sha256": digest(fragment(original_rtos, ENTRY, END)),
            "candidate_leaf_sha256": digest(fragment(candidate_rtos, ENTRY, END)),
            "preserved_tail_sha256": digest(fragment(original_rtos, TAIL, END)), **diff},
            "direct_calls": direct, "caller": {"entry": hex(PREPARE), "end_exclusive": hex(PREPARE_END),
            "caller_bytes_sha256": digest(fragment(original_rtos, PREPARE, PREPARE_END)),
            "call_sites": list(map(hex, SITES)), "cases_per_image": len(cases), "color_space_flag": 1,
            "nested_matrix_calls_per_image": sum(len(r["calls"]) for r in candidate_calls),
            "call_abi": {"checked_preserved_registers": SAVED_REG_NAMES, "sp_restored": True,
                         "scope": "Nested Q13 and outer prepare returns",
                         "nested_memory": {"own_stack_bytes_below_entry_sp": NESTED_FRAMES,
                                           "reads": "two 18-byte operands and own stack frame",
                                           "writes": "exact 18-byte output footprint and own stack frame"}},
            "stubbed_callees": 0, "original_max_stack_write_depth": max(r["max_stack_write_depth"] for r in baseline_calls),
            "candidate_max_stack_write_depth": max(r["max_stack_write_depth"] for r in candidate_calls),
            "candidate_cases": candidate_calls}, "original_arm_gates": gates, "negative_checks": rejected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path, help="verified original v2.20 package or byte-identical copy")
    parser.add_argument("zig", type=Path, help="official Zig 0.15.2 x86-64 Windows zig.exe")
    args = parser.parse_args()
    base = ROOT / ".private/hq-integration"
    base.mkdir(parents=True, exist_ok=True)
    work = Path(mkdtemp(prefix="matrix-", dir=base))
    try:
        report = json.dumps(run(args.original.resolve(), args.zig.resolve(), work), indent=2) + "\n"
        (work / "evidence.json").write_text(report, encoding="utf-8")
        (work / STAGED_CANDIDATE).rename(work / VERIFIED_CANDIDATE)
        print(report, end="")
    except (OSError, ValueError, uc.UcError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Integration verification failed: {exc}\n")


if __name__ == "__main__":
    main()
