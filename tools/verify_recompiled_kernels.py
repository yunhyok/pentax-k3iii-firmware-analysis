"""Build two freestanding ARM routines and compare them with the v2.20 RTOS."""

import argparse
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
from random import Random
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
import elftools
import unicorn as uc
from unicorn import arm_const as arm

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from decompile_sample import BASE, RTOS_OFFSET, RTOS_SHA256, RTOS_SIZE

WORK = Path(".private/hq-compile")
SOURCE = Path("source/reconstructed/numeric_kernels.c")
OBJECT = WORK / "numeric_kernels.o"
ZIG_VERSION = "0.15.2"
ZIG_ARCHIVE = "https://ziglang.org/download/0.15.2/zig-x86_64-windows-0.15.2.zip"
ZIG_ARCHIVE_SHA256 = "3a0ed1e8799a2f8ce2a6e6290a9ff22e6906f8227865911fb7ddedc3cc14cb0c"
ZIG_EXE_SHA256 = "d408dd38eed3e5204af841bcebf70502a4dbbb8399a3a3262be55059370bc018"
CC_ARGS = ("cc", "-target", "arm-freestanding-eabi", "-mcpu=cortex_a7", "-marm",
           "-std=c11", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
           "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-ffunction-sections",
           "-Oz", "-Wall", "-Wextra", "-Werror", "-c", SOURCE.as_posix(), "-o", OBJECT.as_posix())
AF, MATRIX = "sad_ssd_u16", "matrix3_mul_q13"
ROUTINES = {AF: (0x52C73190, 0x52C73268, 0x62000000),
            MATRIX: (0x5312CD40, 0x5312CDB4, 0x62001000)}
MASKS = (0x538853E0, 128)
LEFT, RIGHT, OUT = 0x60000000, 0x60100000, 0x60200000
INPUT_REGION = 0x21000
STACK, SP, RETURN = 0x70000000, 0x70000800, 0x70002000
PAGE = 4096
CPSR_CONTROL = 0x010001FF
SEED = 3220220


def digest(data):
    return sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def build(zig):
    require(digest(zig.read_bytes()) == ZIG_EXE_SHA256, "Expected the pinned Zig for Windows x86-64")
    (ROOT / WORK).mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(ROOT / WORK / "cache-global"),
               ZIG_LOCAL_CACHE_DIR=str(ROOT / WORK / "cache-local"),
               ZIG_LIB_DIR=str(zig.parent / "lib"))
    version = subprocess.check_output([str(zig), "version"], env=env, text=True).strip()
    require(version == ZIG_VERSION, f"Unexpected Zig version: {version}")
    subprocess.run([str(zig), *CC_ARGS], cwd=ROOT, env=env, check=True)
    blob = (ROOT / OBJECT).read_bytes()
    elf = ELFFile(BytesIO(blob))
    require(elf.elfclass == 32 and elf.little_endian and elf["e_machine"] == "EM_ARM"
            and elf["e_type"] == "ET_REL" and elf["e_flags"] >> 24 == 5,
            "Expected a 32-bit little-endian Arm EABI object")
    symbols = elf.get_section_by_name(".symtab")
    require(symbols is not None and not any(s.name and s["st_shndx"] == "SHN_UNDEF"
                                           for s in symbols.iter_symbols()),
            "Unexpected missing symbol table or unresolved imports")
    text = {}
    for name in ROUTINES:
        (symbol,) = symbols.get_symbol_by_name(name) or ()
        index = symbol["st_shndx"]
        section = elf.get_section(index)
        require(symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_value"] == 0
                and section.name == f".text.{name}" and section["sh_flags"] & 4
                and 0 < symbol["st_size"] == section["sh_size"] <= PAGE
                and symbol["st_size"] % 4 == 0
                and any(s.name == "$a" and s["st_shndx"] == index and s["st_value"] == 0
                        for s in symbols.iter_symbols()),
                f"{name}: expected a complete A32 function in its own section")
        require(not any(s["sh_type"] in ("SHT_REL", "SHT_RELA") and s["sh_info"] == index
                        for s in elf.iter_sections()), f"{name}: code has relocations")
        text[name] = section.data()
        (ROOT / WORK / f"{name}.bin").write_bytes(text[name])
    return text, {
        "version": version,
        "llvm_build": elf.get_section_by_name(".comment").data().strip(b"\0").decode("ascii"),
        "official_index": "https://ziglang.org/download/index.json",
        "archive": ZIG_ARCHIVE, "archive_sha256": ZIG_ARCHIVE_SHA256,
        "exe_sha256": ZIG_EXE_SHA256, "command": ["<zig.exe>", *CC_ARGS],
        "source_lf_sha256": digest((ROOT / SOURCE).read_bytes().replace(b"\r\n", b"\n")),
        "object_sha256": digest(blob),
        "elf": {"class": 32, "little_endian": True, "machine": "EM_ARM", "type": "ET_REL",
                "flags": hex(elf["e_flags"]), "text_relocations": 0, "unresolved_imports": 0},
    }


class Sandbox:
    def __init__(self, image, text):
        self.cpu = cpu = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM | uc.UC_MODE_LITTLE_ENDIAN)
        cpu.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A7)
        self.cpsr = cpu.reg_read(arm.UC_ARM_REG_CPSR) & CPSR_CONTROL
        self.saved_regs = [getattr(arm, f"UC_ARM_REG_R{i}") for i in range(4, 12)]
        self.saved_regs.extend(getattr(arm, f"UC_ARM_REG_D{i}") for i in range(8, 16))
        for name, (entry, end, rebuilt) in ROUTINES.items():
            self.map_chunk(entry, image[entry - BASE:end - BASE], uc.UC_PROT_READ | uc.UC_PROT_EXEC)
            self.map_chunk(rebuilt, text[name], uc.UC_PROT_READ | uc.UC_PROT_EXEC)
        mask_addr, mask_size = MASKS
        self.map_chunk(mask_addr, image[mask_addr - BASE:mask_addr - BASE + mask_size], uc.UC_PROT_READ)
        for addr in (LEFT, RIGHT):
            cpu.mem_map(addr, INPUT_REGION, uc.UC_PROT_READ)
        for addr in (OUT, STACK):
            cpu.mem_map(addr, PAGE, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        cpu.hook_add(uc.UC_HOOK_BLOCK, self.check_code)
        cpu.hook_add(uc.UC_HOOK_MEM_READ, self.check_read)
        cpu.hook_add(uc.UC_HOOK_MEM_WRITE, self.check_write)
        self.text = text

    def map_chunk(self, addr, data, perms):
        base = addr & -PAGE
        size = ((addr - base + len(data) + PAGE - 1) // PAGE) * PAGE
        self.cpu.mem_map(base, size, perms)
        self.cpu.mem_write(addr, data)

    def check_code(self, cpu, addr, size, _):
        lo, hi = self.code_bounds
        require(lo <= addr and addr + size <= hi, f"Executed outside the leaf at {addr:#x}")

    def check_read(self, cpu, access, addr, size, value, _):
        if not any(base <= addr and addr + size <= base + length for base, length in self.read_bounds):
            raise ValueError(f"Read outside permitted data at {addr:#x} ({size} bytes)")

    def check_write(self, cpu, access, addr, size, value, _):
        if STACK <= addr and addr + size <= SP:
            self.stack_depth = max(self.stack_depth, SP - addr)
        elif any(base <= addr and addr + size <= base + length for base, length in self.out_bounds):
            self.writes.update(range(addr, addr + size))
            self.write_sizes.add(size)
        else:
            raise ValueError(f"Write outside outputs and scratch stack at {addr:#x} ({size} bytes)")

    def run(self, name, rebuilt, left, right, count, case_no):
        cpu = self.cpu
        entry, end, rebuilt_entry = ROUTINES[name]
        self.code_bounds = (rebuilt_entry, rebuilt_entry + len(self.text[name])) if rebuilt else (entry, end)
        # Offset some operands by one halfword; other arrays end at an unmapped page.
        a = LEFT + INPUT_REGION - len(left) - 2 * (case_no % 2)
        b = RIGHT + INPUT_REGION - len(right) - 2 * ((case_no // 2) % 2)
        cpu.mem_write(a, left)
        cpu.mem_write(b, right)
        cpu.mem_write(OUT, b"\xa5" * PAGE)
        cpu.mem_write(STACK, b"\x79" * PAGE)
        if name == AF:
            sad, ssd = (OUT + 0x74, OUT + 0x28) if case_no % 2 else (OUT + 0x28, OUT + 0x74)
            self.out_bounds = ((sad, 4), (ssd, 4))
            args, stack_args = (a, b, count), struct.pack("<II", sad, ssd)
        else:
            self.out_bounds = ((OUT + 0x102, 18),)
            args, stack_args = (self.out_bounds[0][0], a, b), b""
        if stack_args:
            cpu.mem_write(SP, stack_args)
        self.read_bounds = [(a, len(left)), (b, len(right)), (STACK, SP - STACK + len(stack_args))]
        if name == AF and not rebuilt:
            self.read_bounds.append(MASKS)
        self.writes, self.write_sizes, self.stack_depth = set(), set(), 0
        canaries = [0x517AB0C3 + 0x1B73605 * i for i in range(8)]
        canaries.extend(0xB4258798BA3160EE ^ (0x178EA56026831B1 * i) for i in range(8))
        cpu.reg_write(arm.UC_ARM_REG_CPSR, self.cpsr)
        cpu.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)
        for reg, value in zip(self.saved_regs, canaries):
            cpu.reg_write(reg, value)
        for reg, value in zip((arm.UC_ARM_REG_R0, arm.UC_ARM_REG_R1, arm.UC_ARM_REG_R2,
                               arm.UC_ARM_REG_R3, arm.UC_ARM_REG_SP, arm.UC_ARM_REG_LR),
                              (0xDEAD0000 + 4 * case_no, *args, SP, RETURN)):
            cpu.reg_write(reg, value)
        cpu.emu_start(self.code_bounds[0], RETURN, timeout=10_000_000, count=2_000_000)
        cpsr = cpu.reg_read(arm.UC_ARM_REG_CPSR)
        require(cpu.reg_read(arm.UC_ARM_REG_PC) == RETURN, "Did not return within execution limit")
        require(cpu.reg_read(arm.UC_ARM_REG_SP) == SP and cpsr & CPSR_CONTROL == self.cpsr
                and [cpu.reg_read(reg) for reg in self.saved_regs] == canaries, "Call state changed")
        require(not stack_args or bytes(cpu.mem_read(SP, len(stack_args))) == stack_args,
                "Caller stack arguments changed")
        expected_writes = {i for addr, length in self.out_bounds for i in range(addr, addr + length)}
        require(self.writes == expected_writes, "Output write footprint mismatch")
        out = b"".join(bytes(cpu.mem_read(addr, length)) for addr, length in self.out_bounds)
        return out, self.stack_depth, self.write_sizes, bool(cpsr & (1 << 27))


def af_cases(rng):
    for n in (*range(1, 18), 23, 24, 25, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025):
        yield "equal", [37] * n, [37] * n
        yield "extremes", [65535] * n, [0] * n
        yield "alternating", [65535 * (i % 2) for i in range(n)], [65535 * (1 - i % 2) for i in range(n)]
        yield "random", [rng.randrange(65536) for _ in range(n)], [rng.randrange(65536) for _ in range(n)]
    for n in (65536, 65537, 65538):
        yield "sad-wrap-boundary", [0] * n, [65535] * n


def matrix_cases(rng):
    identity = [8192, 0, 0, 0, 8192, 0, 0, 0, 8192]
    mixed = [-8192, 4096, 500, 700, 8100, -600, -300, 100, 7900]
    yield "identity", identity, identity
    yield "identity-left", identity, mixed
    yield "identity-right", mixed, identity
    yield "zero", [0] * 9, mixed
    yield "positive-32bit-overflow", [-32768] * 9, [-32768] * 9
    yield "negative-32bit-overflow", [32767] * 9, [-32768] * 9
    for sign in (1, -1):
        yield "rounding", [sign, 0, 0] * 3, [4095, 4096, 4097, 0, 0, 0, 0, 0, 0]
    yield "positive-16bit-wrap", [8192, 1, 0] * 3, [32767] * 3 + [4095, 4096, 4097] + [0] * 3
    yield "negative-16bit-wrap", [8192, 1, 0] * 3, [-32768] * 3 + [-4097, -4096, -4095] + [0] * 3
    for _ in range(48):
        yield "random", [rng.randrange(-32768, 32768) for _ in range(9)], [
            rng.randrange(-32768, 32768) for _ in range(9)]
        extremes = (-32768, -32767, -8192, -1, 0, 1, 8192, 32766, 32767)
        yield "random-extremes", rng.choices(extremes, k=9), rng.choices(extremes, k=9)


def verify(image, text):
    sandbox, rng = Sandbox(image, text), Random(SEED)
    report = {}
    for name, cases in ((AF, af_cases(rng)), (MATRIX, matrix_cases(rng))):
        entry, end, rebuilt = ROUTINES[name]
        original = image[entry - BASE:end - BASE]
        runs = {
            "original": {"entry": hex(entry), "end_exclusive": hex(end), "bytes": len(original),
                         "sha256": digest(original)},
            "rebuilt": {"entry": hex(rebuilt), "end_exclusive": hex(rebuilt + len(text[name])),
                        "bytes": len(text[name]), "sha256": digest(text[name])},
        }
        for run in runs.values():
            run.update(max_stack_write_bytes_below_entry_sp=0, output_store_widths_bytes=set(),
                       cpsr_q_set_cases=0)
        rows = []
        for case_no, (label, left, right) in enumerate(cases):
            n = len(left)
            if name == AF:
                a, b = struct.pack(f"<{n}H", *left), struct.pack(f"<{n}H", *right)
                diffs = [abs(a - b) for a, b in zip(left, right)]
                sad, ssd = sum(diffs), sum(d * d for d in diffs)
                expected = struct.pack("<II", sad & 0xFFFFFFFF, ssd & 0xFFFFFFFF)
                padding = (-n) % 8
                padded = (a + b"\x39\x30" * padding, b + b"\x31\xd4" * padding)
                row = {"count": n, "output": struct.unpack("<II", expected),
                       "sad_wrapped": sad > 0xFFFFFFFF, "ssd_wrapped": ssd > 0xFFFFFFFF}
            else:
                a, b = struct.pack("<9h", *left), struct.pack("<9h", *right)
                sums = [sum(left[3 * i + k] * right[3 * k + j] for k in range(3)) + 4096
                        for i in range(3) for j in range(3)]
                rounded = [s // 8192 for s in sums]
                expected = struct.pack("<9H", *(v & 0xFFFF for v in rounded))
                padded = a, b
                row = {"output": struct.unpack("<9h", expected),
                       "biased_sum_outside_int32": any(not -(1 << 31) <= s < 1 << 31 for s in sums),
                       "rounded_result_outside_int16": any(not -32768 <= v <= 32767 for v in rounded)}
            for version, operands in (("original", padded), ("rebuilt", (a, b))):
                try:
                    out, depth, widths, q_set = sandbox.run(name, version == "rebuilt", *operands, n, case_no)
                    require(out == expected, f"Expected {expected.hex()}, got {out.hex()}")
                except (ValueError, uc.UcError) as exc:
                    raise ValueError(f"{name} case {case_no} ({label}, n={n}) {version}: {exc}") from exc
                run = runs[version]
                run["max_stack_write_bytes_below_entry_sp"] = max(run["max_stack_write_bytes_below_entry_sp"], depth)
                run["output_store_widths_bytes"].update(widths)
                run["cpsr_q_set_cases"] += q_set
            rows.append({"case": label, "input_sha256": digest(a + b), **row})
        for run in runs.values():
            run["output_store_widths_bytes"] = sorted(run["output_store_widths_bytes"])
        report[name] = {**runs, "passed": len(rows), "cases": rows}
    mask_addr, mask_size = MASKS
    report[AF]["original_mask_table"] = {"entry": hex(mask_addr), "bytes": mask_size,
                                          "sha256": digest(image[mask_addr - BASE:mask_addr - BASE + mask_size])}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="K-3 Mark III v2.20 decoded.bin or raw RTOS payload")
    parser.add_argument("zig", type=Path, help="official Zig 0.15.2 x86-64 Windows zig.exe")
    args = parser.parse_args()
    try:
        with args.image.open("rb") as stream:
            if args.image.stat().st_size != RTOS_SIZE:
                stream.seek(RTOS_OFFSET)
            image = stream.read(RTOS_SIZE)
        require(len(image) == RTOS_SIZE and digest(image) == RTOS_SHA256, "v2.20 RTOS payload hash mismatch")
        text, compiler = build(args.zig.resolve())
        print(json.dumps({
            "schema_version": 1, "rtos_sha256": RTOS_SHA256, "rtos_base": hex(BASE),
            "compiler": compiler, "engine": {"unicorn": uc.__version__, "pyelftools": elftools.__version__,
                                             "cpu": "Cortex-A7", "state": "A32, little-endian"},
            "seed": SEED, "scope": "Independent synthetic leaf calls only; no camera or firmware integration.",
            "checks_each_call": ["Python mathematical oracle and identical output bytes",
                                 "exact output byte coverage and writes limited to output and scratch stack",
                                 "data reads limited to supplied buffers, stack, and original AF mask table",
                                 "leaf-only instruction fetch and return to sentinel",
                                 "callee-saved r4-r11 and d8-d15, SP, caller stack args and CPSR control bits"],
            "routines": verify(image, text),
        }, indent=2))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Verification failed: {exc}\n")


if __name__ == "__main__":
    main()
