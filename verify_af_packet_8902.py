"""Original A32 producer-to-request replay for two observed 0x8902 callers.

Requires Unicorn 2.1.4 to reproduce the published report. Accepts an original
RTOS or decoded carrier supplied by the caller. No device access or writes.
"""

if not __debug__:
    raise RuntimeError("Replay requires assertions")

import argparse
import hashlib
import json
import os
import stat
import struct
from collections import Counter
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn import __version__ as unicorn_version
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_FP, UC_ARM_REG_LR, UC_ARM_REG_PC,
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R12,
    UC_ARM_REG_SP, UC_CPU_ARM_CORTEX_A7, UC_CPU_ARM_CORTEX_A15,
)


BASE = 0x52500000
RTOS_SHA = "342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4"
DECODED_SHA = "7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9"
RTOS_SIZE = 25483200
DECODED_SIZE = 78683892
RTOS_OFFSET = 0x1C19C
INPUT_SHA = {RTOS_SIZE: RTOS_SHA, DECODED_SIZE: DECODED_SHA}
RANGES = {
    "multiply-caller": (0x52CBDDD8, 0x52CBDE70),
    "multiply-factor": (0x52CBDD88, 0x52CBDDD8),
    "reciprocal-caller": (0x52F05680, 0x52F057FC),
    "reciprocal-value": (0x52F01010, 0x52F0103C),
    "signed-divide": (0x526A8364, 0x526A8374),
    "packet-8902": (0x52EFC858, 0x52EFC918),
    "packet-8900": (0x52EFC7A0, 0x52EFC858),
    "option-to-opcode": (0x52EFF608, 0x52EFF618),
    "bit6-wrapper": (0x52EFF628, 0x52EFF640),
    "bit6-reader": (0x52EFDA40, 0x52EFDA54),
    "separate-byte-bit2": (0x52EFDA70, 0x52EFDA84),
    "factor-gate-reader": (0x52EFDB78, 0x52EFDB88),
    "factor-reader": (0x52EFDC10, 0x52EFDC20),
    "queue-wrapper": (0x52EFF524, 0x52EFF5E0),
    "slot-copy": (0x52EFEEC0, 0x52EFF17C),
    "event-bit-select": (0x52EFEA88, 0x52EFEAF4),
    "queue-submit": (0x52F148FC, 0x52F14A08),
    "option-wait": (0x52EFF444, 0x52EFF524),
    "slot-release": (0x52EFF17C, 0x52EFF2C8),
    "command-metadata": (0x5315A8A0, 0x5315BA7C),
}
ORIGINAL_DATA = {"stack-canary": (0x53CBB4C0, 0x53CBB4C4),
                 "mutex-argument": (0x53A6B110, 0x53A6B114)}
STUBS = {
    0x530F1A68: "mutex lock returns 0",
    0x530F1BBC: "mutex unlock returns 0",
    0x530EDC60: "OS queue push captures request and returns 1",
    0x530ED03C: "event set records arguments and returns 0",
    0x530ED1AC: "event wait writes selected event bits and returns 1",
    0x530ED0F4: "event clear records arguments and returns 0",
    0x530FCED4: "diagnostic returns 0 for all slots busy",
}
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
LENS, COMM, CONTEXT, CALLER, OPTION, META = (
    0x10000000, 0x10010000, 0x10020000, 0x10030000, 0x10040000, 0x10050000
)
BUILDER = LENS + 0x50
STOP, STACK = 0x20000000, 0x20008000
PREFIX_STOPS = {0x52F05740, 0x52EFD3FC}
STUB_EVENT, STUB_MUTEX = OPTION + 0x100, OPTION + 0x200


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_image(path):
    # Check the opened file and bound the read even if it grows after fstat.
    if not path.is_file():
        raise ValueError("expected a regular RTOS or decoded carrier file")
    with path.open("rb") as source:
        info = os.fstat(source.fileno())
        expected = INPUT_SHA.get(info.st_size)
        if not stat.S_ISREG(info.st_mode) or expected is None:
            raise ValueError("unexpected RTOS or decoded carrier size")
        image = source.read(info.st_size + 1)
    if len(image) != info.st_size or sha(image) != expected:
        raise ValueError("unrecognized RTOS or decoded carrier SHA-256")
    if info.st_size == DECODED_SIZE:
        image = image[RTOS_OFFSET:RTOS_OFFSET + RTOS_SIZE]
        if len(image) != RTOS_SIZE or sha(image) != RTOS_SHA:
            raise ValueError("decoded carrier RTOS SHA-256 mismatch")
    return image


def direct_branches(image, targets):
    """Aligned conditional/unconditional A32 B and BL encodings, excluding BLX."""
    matches = {hex(target): [] for target in sorted(targets)}
    for index, (word,) in enumerate(struct.iter_unpack("<I", image)):
        if (word >> 25) & 7 != 5 or word >> 28 == 15:
            continue
        immediate = word & 0xFFFFFF
        if immediate & 0x800000:
            immediate -= 0x1000000
        site = BASE + 4 * index
        target = site + 8 + immediate * 4
        if target in targets:
            matches[hex(target)].append({
                "site": hex(site), "word": f"{word:08x}", "link": bool(word & 0x1000000)
            })
    return matches


class Replay:
    def __init__(self, image, model, clobber=False):
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.cpu.ctl_set_cpu_model(model)
        self.clobber = clobber
        mapped = (len(image) + 0xFFF) & ~0xFFF
        self.cpu.mem_map(BASE, mapped)
        self.cpu.mem_write(BASE, image)
        self.cpu.mem_protect(BASE, mapped, UC_PROT_READ | UC_PROT_EXEC)
        self.cpu.mem_map(LENS, 0x60000)
        self.cpu.mem_map(STOP, 0x10000)
        self.cpu.hook_add(UC_HOOK_CODE, self.hook)

    def read(self, address, size=4):
        return int.from_bytes(self.cpu.mem_read(address, size), "little")

    def write(self, address, value, size=4):
        self.cpu.mem_write(address, value.to_bytes(size, "little"))

    def setup(self, cap, slots=0):
        self.cpu.mem_write(LENS, bytes(0x60000))
        self.write(BUILDER + 4, LENS)
        self.write(BUILDER + 8, COMM)
        self.write(BUILDER + 0x17, 0xA5, 1)
        self.write(BUILDER + 0x8E, 0xBEEF, 2)
        self.write(LENS + 0x1D8, CONTEXT)
        self.write(LENS + 0x1F8, STUB_EVENT)
        self.write(LENS + 0x199C, STUB_MUTEX)
        self.write(COMM + 0x5272, cap, 1)
        for index in range(slots):
            self.write(LENS + 0x20C + index * 0xBC, 1, 1)

    def hook(self, cpu, address, size, _):
        if address in self.stops:
            cpu.emu_stop()
            return
        args = [cpu.reg_read(reg) for reg in REGS]
        if address in STUBS:
            self.stub_counts[hex(address)] += 1
            ret = 0
            if address == 0x530EDC60:
                queue, request, arg2, arg3 = args
                assert (queue, arg2, arg3) == (CONTEXT + 0x74, 0, 0)
                descriptor = self.read(request + 8)
                token = self.read(request + 0x10)
                slot = token & 0xFF
                offset = slot * 0xBC
                payload = self.read(descriptor + 8)
                assert request == LENS + offset + 0x29C
                assert self.read(request + 4) == LENS + 0x1D4
                assert descriptor == LENS + offset + 0x2B0
                assert payload == LENS + offset + 0x212
                assert self.read(descriptor + 0xC) == 0
                assert self.read(LENS + offset + 0x20C, 1) == 1
                length = self.read(descriptor + 0x12, 1)
                assert length == 2
                self.requests.append({
                    "slot": slot, "opcode": hex(self.read(request + 0xC)),
                    "command": hex(self.read(descriptor + 0x14, 2)),
                    "token": f"{token:08x}",
                    "payload": bytes(cpu.mem_read(payload, length)).hex(),
                    "event_bit": self.read(LENS + offset + 0x298),
                })
                ret = 1
            elif address == 0x530ED03C:
                assert args[:2] == [CONTEXT + 0x88, 1]
            elif address == 0x530ED1AC:
                assert self.requests and self.requests[-1]["event_bit"] != 0
                assert args[0] == STUB_EVENT and args[1] == self.requests[-1]["event_bit"]
                assert args[3] == 0x64
                self.write(args[2], args[1])
                ret = 1
            elif address == 0x530ED0F4:
                assert args[:2] == [STUB_EVENT, self.requests[-1]["event_bit"]]
            if self.clobber:
                for register, value in zip(
                    (UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R12),
                    (0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00),
                ):
                    cpu.reg_write(register, value)
                # Invert all four condition flags, preserving CPSR mode and state.
                cpu.reg_write(UC_ARM_REG_CPSR, cpu.reg_read(UC_ARM_REG_CPSR) ^ 0xF0000000)
            cpu.reg_write(UC_ARM_REG_R0, ret)
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
            return
        assert size == 4 and any(
            start <= address and address + size <= end for start, end in RANGES.values()
        ), hex(address)
        self.visited.add(address)
        if address in {0x52EFC858, 0x52EFC7A0}:
            assert args[0] == BUILDER
            self.builders.append({"entry": hex(address), "value": args[1], "flag": args[2],
                                  "option": self.read(args[3], 1)})
        if address == 0x52EFF608:
            desc = bytes(cpu.mem_read(args[2], 16))
            assert desc[0] == 2 and desc[1] == 0 and desc[4:8] == desc[12:16] == bytes(4)
            pointer = int.from_bytes(desc[8:12], "little")
            assert pointer == args[2] - 2
            assert args[0] == LENS and self.read(args[1] + 4) == 0
            self.descriptors.append({"command": hex(int.from_bytes(desc[2:4], "little")),
                                     "payload": bytes(cpu.mem_read(pointer, 2)).hex()})

    def run(self, start, args, stops=(), stack_args=()):
        self.stops = {STOP, *stops}
        self.requests, self.descriptors, self.builders = [], [], []
        self.stub_counts = Counter()
        self.visited = set()
        self.cpu.mem_write(STACK - 0x1000, bytes(0x2000))
        for index, value in enumerate(stack_args):
            self.write(STACK + index * 4, value)
        self.cpu.reg_write(UC_ARM_REG_CPSR, 0x13)
        self.cpu.reg_write(UC_ARM_REG_SP, STACK)
        self.cpu.reg_write(UC_ARM_REG_LR, STOP)
        self.cpu.reg_write(UC_ARM_REG_FP, 0)
        for register, value in zip(REGS, args):
            self.cpu.reg_write(register, value)
        self.cpu.emu_start(start, STOP + 4, count=8000)
        end = self.cpu.reg_read(UC_ARM_REG_PC)
        assert end in self.stops, hex(end)
        return {
            "stop": hex(end), "r0_at_stop": self.cpu.reg_read(UC_ARM_REG_R0),
            "builders": self.builders, "stack_descriptors": self.descriptors,
            "queue_pushes": self.requests, "stub_counts": dict(self.stub_counts),
            "reached_source_ranges": [label for label, (a, z) in RANGES.items()
                                      if any(a <= pc < z for pc in self.visited)],
            "builder_after": {"byte17": self.read(BUILDER + 0x17, 1),
                              "halfword8e": self.read(BUILDER + 0x8E, 2)},
        }


def expect_builder(output, entries, cap, slot, status=None):
    expected_entries = [
        {"entry": hex(entry), "value": value, "flag": flag, "option": option}
        for entry, value, flag, option in entries
    ]
    assert output["builders"] == expected_entries
    if status is not None:
        assert output["r0_at_stop"] == status
    descriptors, pushes = [], []
    state = {"byte17": 0xA5, "halfword8e": 0xBEEF}
    if cap & 0x40:
        for entry, value, flag, option in entries:
            command = 0x8902 if entry == 0x52EFC858 else 0x8900
            word = (value & 0x3FFF) | (0x8000 if flag else 0)
            packet = {"command": hex(command), "payload": f"{word:04x}"}
            descriptors.append(packet)
            if slot < 32:
                pushes.append({
                    **packet, "slot": slot, "opcode": "0x1b",
                    "token": f"{(command << 16) | slot:08x}", "event_bit": int(bool(option)),
                })
            if command == 0x8902:
                state = {"byte17": flag & 0xFF, "halfword8e": value & 0x3FFF}
    assert output["stack_descriptors"] == descriptors
    assert output["queue_pushes"] == pushes
    assert output["builder_after"] == state
    assert output["stub_counts"].get("0x530ed1ac", 0) == sum(bool(row["event_bit"]) for row in pushes)


def run_cases(replay):
    cases = []
    for cap, value, flag, slot in (
        (0, 0x1234, 1, 0), (0xBF, 0x1234, 1, 0),
        (0x40, 0, 0, 0), (0x40, 0x3FFF, 0, 0), (0x40, 0x4000, 0, 1),
        (0x40, 0x12345678, 1, 31), (0xFF, 0xFFFF, 0x100, 0),
        (0x40, 0x1234, 0xFFFFFFFF, 0), (0x40, 0x1234, 0, 32),
    ):
        replay.setup(cap, slot)
        if slot == 32:
            lens_state = bytearray(replay.cpu.mem_read(LENS, 0x2000))
            lens_state[0x67] = flag & 0xFF
            struct.pack_into("<H", lens_state, 0xDE, value & 0x3FFF)
        output = replay.run(0x52EFC858, (BUILDER, value, flag, OPTION))
        expect_builder(output, [(0x52EFC858, value, flag, 0)], cap, slot,
                       slot if cap & 0x40 and slot < 32 else 0xFF)
        if slot == 32:
            assert output["stub_counts"].get("0x530fced4") == 1
            assert replay.cpu.mem_read(LENS, len(lens_state)) == lens_state
            output["all_busy_lens_state_changes"] = ["builder+0x17", "builder+0x8e"]
        cases.append({"group": "direct", "input": [cap, value, flag, slot], **output})

    for cap, factor_gate, factor, value in (
        (0, 2, 19, 47), (0xBF, 2, 19, 47), (0x40, 0, 19, 47),
        (0x40, 2, 19, 47), (0x40, 2, 0, 47), (0x40, 2, 0xFF, 65),
        (0x40, 2, 0xFF, 64), (0x40, 2, 0x80, 0x02000001),
        (0x40, 2, 0xFF, 0xFFFFFFFF), (0xFF, 0xFFFF, 1, 0x3FFF),
    ):
        replay.setup(cap)
        replay.write(CALLER + 4, LENS)
        replay.write(COMM + 0x52AA, factor_gate, 2)
        replay.write(COMM + 0x52B4, factor, 1)
        output = replay.run(0x52CBDDD8, (CALLER, value, 0, 0))
        product = (value * (factor if factor_gate & 2 else 4)) & 0xFFFFFFFF
        entries = [(0x52EFC858, min(product, 0x3FFF), 0, 1)] if cap & 0x40 else []
        expect_builder(output, entries, cap, 0, 0)
        if entries:
            assert replay.read(LENS + 0x20C, 1) == 0
            assert replay.read(LENS + 0x1994) == 0
        cases.append({"group": "multiply-caller", "input": [cap, factor_gate, factor, value], **output})

    for cap, divisor, next_value, next_flag, mode, caps2 in (
        (0, 250, 0x1234, 1, 0, 0), (0x40, 0, 0x1234, 1, 0, 0),
        (0x40, 1, 0xFFFF, 0, 0, 0), (0x40, 2, 0x4000, 1, 0, 0),
        (0x40, 250, 0x1234, 0x80, 0, 0), (0xFF, 0xFFFF, 0x7FFF, 0, 1, 0),
        (0x40, 250, 0x1234, 1, 1, 4), (0, 250, 0x1234, 1, 1, 4),
    ):
        replay.setup(cap)
        replay.write(CALLER + 0x14, LENS)
        replay.write(CALLER + 0x18, next_value, 2)
        replay.write(CALLER + 0x2E, divisor, 2)
        replay.write(CALLER + 0x30, next_flag, 1)
        replay.write(CALLER + 0x35, mode, 1)
        replay.write(COMM + 0x5278, caps2, 1)
        output = replay.run(0x52F05680, (CALLER, 0, 0, 0), PREFIX_STOPS)
        value = ((1_000_000 + divisor // 2) // divisor) & 0xFFFF if divisor else 0
        entries = [(0x52EFC858, value, 0, 1)]
        alternate = bool(mode and caps2 & 4)
        if not alternate:
            entries.append((0x52EFC7A0, next_value, next_flag, 1))
        assert output["stop"] == ("0x52efd3fc" if alternate else "0x52f05740")
        expect_builder(output, entries, cap, 0)
        assert replay.read(LENS + 0x20C, 1) == 0
        cases.append({"group": "reciprocal-caller-prefix",
                      "input": [cap, divisor, next_value, next_flag, mode, caps2], **output})

    for command, index in ((0x8902, 0x4A), (0x8900, 0x49)):
        replay.setup(0)
        output = replay.run(0x5315A8A0, (0x547BC078, command, META, META + 4),
                            stack_args=(META + 8, META + 12))
        expected = {"index": index, "type": 3, "additional_byte": 2, "required_mask": 0}
        actual = {"index": replay.read(META), "type": replay.read(META + 4, 1),
                  "additional_byte": replay.read(META + 8, 1),
                  "required_mask": replay.read(META + 12, 2)}
        assert output["r0_at_stop"] == 1 and actual == expected
        cases.append({"group": "separate-metadata-lookup", "input": [command], "metadata": actual,
                      **output})
    return cases


def check_model(image, model, clobber=False):
    replay = Replay(image, model, clobber)
    cases = run_cases(replay)
    mapped_sha = sha(replay.cpu.mem_read(BASE, len(image)))
    assert mapped_sha == RTOS_SHA
    return cases, mapped_sha


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        raise FileExistsError(args.output)
    image = read_image(args.input)
    branches = direct_branches(image, {0x52EFC858, 0x52EFC7A0, 0x52CBDDD8, 0x52F05680})
    assert [row["site"] for row in branches["0x52efc858"]] == ["0x52cbde64", "0x52f05704"]
    cases, a15_sha = check_model(image, UC_CPU_ARM_CORTEX_A15)
    a15_clobber, a15_clobber_sha = check_model(image, UC_CPU_ARM_CORTEX_A15, clobber=True)
    a7_clobber, a7_clobber_sha = check_model(image, UC_CPU_ARM_CORTEX_A7, clobber=True)
    assert a15_clobber == a7_clobber == cases
    result = {
        "rtos_sha256": RTOS_SHA, "accepted_decoded_sha256": DECODED_SHA,
        "input_bytes": {"rtos": RTOS_SIZE, "decoded": DECODED_SIZE},
        "decoded_rtos_offset": hex(RTOS_OFFSET),
        "cpu": f"Unicorn {unicorn_version}, A32 little-endian",
        "replay_controls": {
            "case_records_equal": True,
            "mapped_original_sha256_after": {
                "Cortex-A15": a15_sha,
                "Cortex-A15-volatile-clobber": a15_clobber_sha,
                "Cortex-A7-volatile-clobber": a7_clobber_sha,
            },
            "clobber": "Overwrite r1-r3 and r12 with sentinels and invert NZCV at each stub return",
        },
        "source_ranges": {
            label: {"start": hex(a), "end_exclusive": hex(z), "sha256": sha(image[a-BASE:z-BASE])}
            for label, (a, z) in {**RANGES, **ORIGINAL_DATA}.items()
        },
        "static_direct_a32_branch_encodings": branches,
        "branch_search_scope": ("Aligned A32 direct B/BL encodings only; excludes Thumb, BLX and "
                                "indirect transfers. The two 0x8902 callsites also ran in replay."),
        "stub_boundaries": {hex(address): desc for address, desc in STUBS.items()},
        "scope": ("Unicorn CPU models, read-only original RTOS mapping, synthetic objects/queue/events. Direct and "
                  "multiply cases return to sentinel, reciprocal caller stops before post-request "
                  "logic or alternate builder; metadata runs separately. No scheduler, actual "
                  "queue drain, completion callback, packet exchange, lens bus or physical test."),
        "passed": True, "case_counts": dict(Counter(case["group"] for case in cases)),
        "cases": cases,
    }
    with args.output.open("x", encoding="utf-8", newline="\n") as file:
        json.dump(result, file, indent=2)
        file.write("\n")
    print(result["case_counts"])


if __name__ == "__main__":
    main()
