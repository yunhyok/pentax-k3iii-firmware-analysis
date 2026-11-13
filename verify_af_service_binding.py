"""Replay the Joint mode-1 binding to its first unmapped register read."""
if not __debug__:
    raise RuntimeError("Replay requires assertions")

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
from struct import pack, unpack
from types import ModuleType

DEPENDENCY = Path(__file__).resolve().with_name("verify_af_packet_8902.py")
DEPENDENCY_SHA = "6796dc7821f84b13ddf2545c569568928eec24a130e27d519d70f75326e0ba12"
source = DEPENDENCY.read_bytes().replace(b"\r\n", b"\n")
if sha256(source).hexdigest() != DEPENDENCY_SHA:
    raise ValueError("Dependency SHA-256 mismatch: verify_af_packet_8902.py")
input_guard = ModuleType("binding_input_guard")
input_guard.__file__ = str(DEPENDENCY)
exec(compile(source, str(DEPENDENCY), "exec"), input_guard.__dict__)
BASE = input_guard.BASE

import unicorn as uc
from unicorn import arm_const as arm

CODE = {
    "registry_get": (0x52F137F0, 0x52F1385C),
    "registry_register_wrapper": (0x52F13774, 0x52F137BC),
    "registry_register": (0x52F13864, 0x52F1390C),
    "registry_lookup": (0x52F1390C, 0x52F139A4),
    "irq_register_wrapper": (0x52F137BC, 0x52F137F0),
    "irq_registry_get": (0x52F13F4C, 0x52F13F58),
    "irq_register": (0x52F13FD8, 0x52F14068),
    "listener_array_ctor": (0x52F13E70, 0x52F13F48),
    "mutex_object_ctor": (0x530F19B4, 0x530F19EC),
    "timer_descriptor_init": (0x5326DD40, 0x5326DD78),
    "reload_factory_get": (0x5326EE34, 0x5326EEAC),
    "timer_d1_factory_slice": (0x5326E458, 0x5326E52C),
    "timer_d2_factory_slice": (0x5326E550, 0x5326E650),
    "timer_ctor": (0x5326DD7C, 0x5326DE20),
    "timer_factory_finish_method": (0x5326D4A0, 0x5326D4A8),
    "device_factory_get": (0x5317757C, 0x53177608),
    "device_factory_service_slice": (0x531777F4, 0x531777FC),
    "service_get": (0x53177D94, 0x53177DF4),
    "service_ctor": (0x53177D14, 0x53177D90),
    "service_bind": (0x531779B0, 0x53177C34),
    "platform_get": (0x530F70B0, 0x530F70BC),
    "platform_map_lookup_non_cc": (0x530F70BC, 0x530F70EC),
    "paf_ctor": (0x52F0B4B0, 0x52F0B5F8),
    "paf_bind_through_primary_service": (0x52F0B380, 0x52F0B40C),
    "lens_factory_get_warm": (0x52F02960, 0x52F0298C),
    "motor_factory_get_warm": (0x52F08D80, 0x52F08DAC),
    "event80_handler_prefix": (0x52F0853C, 0x52F08550),
    "joint_dispatch_prefix": (0x52F083F0, 0x52F0842C),
    "joint_mode1_call": (0x52F08460, 0x52F0847C),
    "mode_lookup_head": (0x52EF877C, 0x52EF8794),
    "mode_lookup_cases": (0x52EF87AC, 0x52EF87D8),
    "paf_mode1_prefix": (0x52F0D83C, 0x52F0D8B0),
    "mode1_singleton_get_warm": (0x53102CE8, 0x53102D14),
    "paf_reset_prefix": (0x52F0BAE4, 0x52F0BB00),
    "adapter_channel0": (0x531784A8, 0x531784C8),
    "timer_target_before_mmio": (0x5326D4EC, 0x5326D4F0),
}
DATA = {
    "registry_cold_literals": (0x52F1385C, 0x52F13864),
    "listener_array_literal": (0x52F13F48, 0x52F13F4C),
    "mutex_object_literal": (0x530F19EC, 0x530F19F0),
    "timer_ctor_literal": (0x5326DE20, 0x5326DE24),
    "timer_d1_d2_literal_words": (0x5326EE08, 0x5326EE10),
    "timer_vtable_header_and_slots_through_target": (0x53CA99F8, 0x53CA9A44),
    "timer_rtti_name": (0x53CA99D8, 0x53CA99E6),
    "timer_factory_and_udc_source_names": (0x53CA79D8, 0x53CA79FE),
    "timer_source_name": (0x53CA78A4, 0x53CA78B8),
    "reload_factory_vptr_literal": (0x5326EEAC, 0x5326EEB0),
    "reload_factory_create_slot": (0x53CA9AA8, 0x53CA9AAC),
    "reload_factory_rtti_name": (0x53CA9AC4, 0x53CA9AD9),
    "device_factory_vptr_literal": (0x53177608, 0x5317760C),
    "device_factory_init_slot": (0x53C710E0, 0x53C710E4),
    "service_base_vptr_literal": (0x53177D90, 0x53177D94),
    "service_bind_slot": (0x53C71148, 0x53C7114C),
    "paf_vptr_literal": (0x52F0B5F8, 0x52F0B5FC),
    "paf_bind_slot": (0x538F25D4, 0x538F25D8),
    "mode_lookup_table": (0x52EF8794, 0x52EF87AC),
    "mutex_init_fixture_readonly_word": (0x53A6B114, 0x53A6B118),
}
STATIC = {
    "reload_factory_frame_and_descriptor_call": (0x5326E230, 0x5326E25C),
    "target_mmio_and_return": (0x5326D4F0, 0x5326D508),
    "null_vptr_load": (0x531784BC, 0x531784C0),
    "image_interrupt_secondary_d1_registration": (0x531FC974, 0x531FC984),
    "paf_reset_rest_unexecuted": (0x52F0BB00, 0x52F0BB38),
}

HEAP = 0x10000000
PAF, JOINT, LENS, PEER = (HEAP + i * 0x1000 for i in range(2, 6))
STACK, RETURN = 0x20008000, 0x20000000
REGISTRY, IRQ_TABLE = 0x54784538, 0x54785994
DEVICE_FACTORY, SERVICE = 0x547BC240, 0x547BC258
RELOAD_FACTORY = 0x547BDE4C
DIAG, ASSERTION = 0x530FEB20, 0x530FDFC4
GUARD_ACQUIRE, GUARD_RELEASE, ATEXIT = 0x533AAEB4, 0x533AAF1C, 0x526AAA50
MALLOC, ARRAY_MALLOC, MUTEX_CREATE = 0x530F25F4, 0x530F2668, 0x530F2258
MMIO_READ, NULL_VPTR = 0x5326D4F0, 0x531784BC
VOLATILE = (arm.UC_ARM_REG_R1, arm.UC_ARM_REG_R2, arm.UC_ARM_REG_R3, arm.UC_ARM_REG_R12)
R0, R1, R2, R3 = (arm.UC_ARM_REG_R0, *VOLATILE[:3])
PC, LR, SP, FP = arm.UC_ARM_REG_PC, arm.UC_ARM_REG_LR, arm.UC_ARM_REG_SP, arm.UC_ARM_REG_R11
REGS = {"r0": R0, "r1": R1, "r4": arm.UC_ARM_REG_R4, "r5": arm.UC_ARM_REG_R5,
        "r7": arm.UC_ARM_REG_R7, "fp": FP, "sp": SP}
STUBS = {
    DIAG: "record diagnostic condition/key and return",
    ASSERTION: "record assertion condition/site; require true and return",
    GUARD_ACQUIRE: "require clear guard in fixture and return acquired",
    GUARD_RELEASE: "publish initialized guard bit in single-thread fixture",
    ATEXIT: "record callback address; no finalization",
    MALLOC: "return fresh poisoned fixture storage for object allocation",
    ARRAY_MALLOC: "return fresh poisoned fixture storage for listener array allocation",
    MUTEX_CREATE: "record constructor's call and return synthetic success; no RTOS mutex",
}


def digest(data):
    return sha256(data).hexdigest()


class Replay:
    def __init__(self, image, model, clobber):
        self.image, self.clobber = image, clobber
        self.cpu = u = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
        u.ctl_set_cpu_model(model)
        mapped = (len(image) + 4095) & ~4095
        u.mem_map(BASE, mapped)
        u.mem_write(BASE, image)
        u.mem_protect(BASE, mapped, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
        for address, size in ((HEAP, 0x10000), (RETURN, 0x10000),
                              (0x54784000, 0x2000), (0x547BA000, 0x4000),
                              (0x54525000, 0x1000)):
            u.mem_map(address, size, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        u.reg_write(arm.UC_ARM_REG_CPSR, 0x13)
        u.reg_write(arm.UC_ARM_REG_C1_C0_2, 0x00F00000)
        u.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)
        u.reg_write(arm.UC_ARM_REG_FPSCR, 0)
        self.next_alloc = HEAP + 0x8000
        self.calls, self.stages, self.visited = [], [], []
        self.counts = Counter()
        self.trace = sha256()
        self.stop_before = ()
        self.stopped = None
        u.hook_add(uc.UC_HOOK_CODE, self.hook)

    def read(self, address, size=4):
        return int.from_bytes(self.cpu.mem_read(address, size), "little")

    def put(self, address, value, size=4):
        self.cpu.mem_write(address, value.to_bytes(size, "little"))

    def hook(self, u, pc, size, _):
        if pc in self.stop_before:
            self.stopped = [pc, u.reg_read(R0), u.reg_read(R2), u.reg_read(R3)]
            u.emu_stop()
            return
        if pc in STUBS:
            r0, r1, r2, r3 = (u.reg_read(reg) for reg in (R0, R1, R2, R3))
            result = 0
            if pc == DIAG:
                detail = [r0, r3, self.read(u.reg_read(SP) + 8)]
            elif pc == ASSERTION:
                assert r0 == 1
                detail = [r0, r3]
            elif pc in (GUARD_ACQUIRE, GUARD_RELEASE):
                assert self.read(r0) == 0
                detail = [r0]
                if pc == GUARD_RELEASE:
                    self.put(r0, 1)
                else:
                    result = 1
            elif pc in (MALLOC, ARRAY_MALLOC):
                assert r0 in ({0x48, 0x14} if pc == MALLOC else {16, 40})
                result = self.next_alloc
                self.next_alloc += 0x100
                u.mem_write(result, b"\xa5" * r0)
                detail = [r0, result]
            elif pc == ATEXIT:
                assert r0 in (0x5317746C, 0x53177470, 0x53268350)
                detail = [r0]
            else:
                assert pc == MUTEX_CREATE and r1 == 0x538F3AC8 and r2 == 0 and r3 == 0x8C
                detail = [r0, r1, r2, r3]
                result = 1
            self.calls.append([pc, u.reg_read(LR), detail])
            if self.clobber:
                for reg, value in zip(VOLATILE, (0xdead11, 0xdead22, 0xdead33, 0xdead44)):
                    u.reg_write(reg, value)
                cpsr = u.reg_read(arm.UC_ARM_REG_CPSR)
                u.reg_write(arm.UC_ARM_REG_CPSR, cpsr ^ 0xF0000000)
            u.reg_write(R0, result)
            u.reg_write(PC, u.reg_read(LR))
            return
        name = next((name for name, (a, z) in CODE.items() if a <= pc and pc + size <= z), None)
        assert size == 4 and name is not None, hex(pc)
        self.counts[name] += 1
        self.trace.update(pack("<I", pc))
        self.trace.update(self.image[pc-BASE:pc-BASE+size])
        if pc in (0x52F08478, 0x52F0BAFC, 0x531784B8, 0x531784C4, 0x5326D4EC):
            self.visited.append([pc, u.reg_read(R0)])

    def stage(self, name, entry, end=RETURN, stop_before=(), **regs):
        u = self.cpu
        self.stopped = None
        self.stop_before = stop_before
        u.mem_write(STACK - 0x400, bytes(0x800))
        u.reg_write(SP, STACK)
        u.reg_write(LR, RETURN)
        for reg, value in regs.items():
            u.reg_write(REGS[reg], value)
        u.emu_start(entry, end, count=12000)
        pc = u.reg_read(PC)
        assert (pc in stop_before and self.stopped is not None) if stop_before else pc == end, (name, hex(pc))
        self.stages.append([name, entry, pc])
        return u.reg_read(R0)

    def primary(self, key):
        p = REGISTRY + 12 * key
        return [self.read(p, 1), self.read(p+4), self.read(p+8)]

    def timer(self, key):
        fp = STACK - 0x500
        # Run the initializer at the same stack address the subsequent factory slice reads.
        self.stage("timer_descriptor_init", 0x5326DD40, r0=fp-0x58)
        start, end, offset, mmio = ((0x5326E458, 0x5326E52C, 0xC, 0x1E000020) if key == 0xD1
                                    else (0x5326E550, 0x5326E650, 0x10, 0x1E000030))
        # Use distinct saved-frame and current-stack positions, as in the original factory.
        self.stage(f"timer_factory_{key:02x}", start, end, fp=fp, sp=fp-0x80,
                   r5=REGISTRY, r7=RELOAD_FACTORY)
        obj = self.read(RELOAD_FACTORY + offset)
        assert obj != 0 and self.read(obj) == 0x53CA9A00
        assert [self.read(obj + 0x34 + i * 4) for i in range(4)] == [mmio + i * 4 for i in range(4)]
        assert self.read(obj + 0x24) == key - 0x79
        return obj

    def one(self, case, keys):
        assert self.stage("primary_registry_cold_init", 0x52F137F0) == REGISTRY
        assert self.primary(0xD1) == self.primary(0xD2) == [0, 0x1B2, 0]
        assert self.stage("reload_factory_cold_get", 0x5326EE34) == RELOAD_FACTORY
        assert self.read(RELOAD_FACTORY) == 0x53CA9AA0
        assert self.read(self.read(RELOAD_FACTORY) + 8) == 0x5326E230
        timers = []
        for key in keys:
            obj = self.timer(key)
            timers.append([key, obj, self.read(obj + 0x10)])
        selected = next((obj for key, obj, _ in timers if key == 0xD1), 0)
        d2 = next((obj for key, obj, _ in timers if key == 0xD2), 0)
        assert self.primary(0xD1) == ([1, 0xD1, selected] if selected else [0, 0x1B2, 0])
        assert self.primary(0xD2) == ([1, 0xD2, d2] if d2 else [0, 0x1B2, 0])
        assert self.read(IRQ_TABLE + 4 * 0x58) == selected
        assert self.read(IRQ_TABLE + 4 * 0x59) == d2
        factory_d1 = self.read(RELOAD_FACTORY + 0xC)
        factory_d2 = self.read(RELOAD_FACTORY + 0x10)
        assert factory_d1 == next((obj for key, obj, _ in reversed(timers) if key == 0xD1), 0)
        assert factory_d2 == d2
        if case == "duplicate_d1":
            assert factory_d1 != selected
        for key, obj, object_id in timers:
            first_obj = selected if key == 0xD1 else d2
            assert object_id == (key if obj == first_obj else 0x1B2)
        assert self.stage("device_factory_cold_get", 0x5317757C) == DEVICE_FACTORY
        assert self.read(DEVICE_FACTORY) == 0x53C710D8 and self.read(DEVICE_FACTORY+4) == 0
        self.stage("device_factory_service_store", 0x531777F4, 0x531777FC, r4=DEVICE_FACTORY)
        assert self.read(DEVICE_FACTORY + 4) == SERVICE
        assert self.read(SERVICE) == 0x53C71140 and self.read(SERVICE + 0x38) == 0
        binder = self.read(self.read(SERVICE) + 8)
        assert binder == 0x531779B0
        assert self.stage("service_vtable_binder", binder, r0=SERVICE) == 1
        assert self.read(SERVICE + 0x38) == selected

        # Only the unrelated lens/pulse dependency pointers and mode input state are fixtures.
        self.put(0x54784440, 1)
        self.put(0x54784444 + 0x10, LENS)
        self.put(0x54784444 + 0x18, LENS + 0x800)
        self.put(0x547844A4, 1)
        self.put(0x547844A8 + 0x10, PEER)
        self.put(0x547BB0A8, 1)
        self.put(0x547BB080 + 0xC, 0x13572468)
        self.stage("paf_ctor", 0x52F0B4B0, r0=PAF)
        binder = self.read(self.read(PAF) + 0xC)
        assert binder == 0x52F0B380
        self.stage("paf_vtable_binder_through_primary_service", binder, 0x52F0B40C, r0=PAF)
        assert self.read(PAF + 8) == SERVICE and self.read(PAF + 0x43, 1) == 0
        self.put(0x5478442C, 1)
        for offset, value in ((0xD0, LENS), (0xDC, PAF), (0xE0, PEER), (0x64, 0x12345678),
                              (0x68, 599), (0x5C, 0x2345), (0x74, 3)):
            self.put(JOINT + offset, value)
        end = MMIO_READ if selected else NULL_VPTR
        self.stage("joint_event80_mode1", 0x52F0853C, stop_before=(end,), r0=JOINT)
        assert self.visited[:3] == [[0x52F08478, PAF], [0x52F0BAFC, SERVICE], [0x531784B8, SERVICE]]
        assert self.read(LENS + 0x19C4) == 0x12345678 and self.read(PEER + 0x2E, 2) == 599
        if selected:
            assert self.visited[3:] == [[0x531784C4, selected], [0x5326D4EC, selected]]
            assert self.stopped[:3] == [MMIO_READ, selected, 0x1E000020]
        else:
            assert self.stopped[:2] == [NULL_VPTR, 0] and len(self.visited) == 3
        mapped_sha = digest(self.cpu.mem_read(BASE, len(self.image)))
        assert mapped_sha == input_guard.RTOS_SHA
        return {"case": case, "timers_key_object_id": timers, "primary_d1": self.primary(0xD1),
                "primary_d2": self.primary(0xD2), "irq_58_59": [selected, d2],
                "reload_factory_c_10": [factory_d1, factory_d2],
                "service_38": selected, "paf_8": SERVICE,
                "boundary": {"pc": end, "r0": self.stopped[1],
                             "first_unread_address": self.stopped[2] if selected else 0},
                "control_points_pc_r0": self.visited, "stages_name_entry_stop": self.stages,
                "stub_calls_pc_lr_args": self.calls, "range_counts": self.counts,
                "executed_pc_and_word_sha256": self.trace.hexdigest(), "mapped_rtos_sha256": mapped_sha}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        parser.error("--output must be a new path")
    image = input_guard.read_image(args.input)
    assert unpack("<I", image[0x53CA9A40-BASE:0x53CA9A44-BASE])[0] == 0x5326D4EC
    cases = (("d1_only", (0xD1,)), ("d2_only", (0xD2,)),
             ("d2_then_d1", (0xD2, 0xD1)), ("duplicate_d1", (0xD1, 0xD1)))
    rows = [Replay(image, arm.UC_CPU_ARM_CORTEX_A7, False).one(*case) for case in cases]
    for model in (arm.UC_CPU_ARM_CORTEX_A7, arm.UC_CPU_ARM_CORTEX_A15):
        assert rows == [Replay(image, model, True).one(*case) for case in cases]
    pins = {kind: {name: {"start": a, "end_exclusive": z, "rtos_offset": a-BASE,
                         "decoded_offset": a-BASE+input_guard.RTOS_OFFSET,
                         "sha256": digest(image[a-BASE:z-BASE])} for name, (a, z) in ranges.items()}
            for kind, ranges in (("code", CODE), ("data", DATA), ("static_only", STATIC))}
    result = {"rtos_sha256": input_guard.RTOS_SHA, "decoded_sha256": input_guard.DECODED_SHA,
              "input_guard_lf_sha256": DEPENDENCY_SHA, "unicorn_version": uc.__version__,
              "cpu_variants_exact": ["Cortex-A7 baseline", "Cortex-A7 volatile/NZCV clobber",
                                     "Cortex-A15 volatile/NZCV clobber"],
              "stub_contracts": {hex(pc): name for pc, name in STUBS.items()},
              "ranges": pins, "cases": rows}
    with args.output.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
