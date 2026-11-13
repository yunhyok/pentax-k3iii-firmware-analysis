"""Replay the native channel-1 reset binding up to the first MMIO instruction."""
if not __debug__:
    raise RuntimeError("Replay requires assertions")

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
from struct import pack
from types import ModuleType

PREVIOUS = Path(__file__).resolve().with_name("verify_af_service_binding.py")
PREVIOUS_SHA = "874a6fb9c38b96a2920751c1d03084d6143ff2b2dc3cd7a9c1ad223e11f0b118"
source = PREVIOUS.read_bytes().replace(b"\r\n", b"\n")
if sha256(source).hexdigest() != PREVIOUS_SHA:
    raise ValueError("Dependency SHA-256 mismatch: verify_af_service_binding.py")
shared = ModuleType("service_binding_fixture")
shared.__file__ = str(PREVIOUS)
exec(compile(source, str(PREVIOUS), "exec"), shared.__dict__)

import unicorn as uc
from unicorn import arm_const as arm

UDC_FACTORY = 0x547BDE98
CHANNEL_COUNTER = 0x547BDE90
FACTORY_VTABLE = 0x53CA9C60
UDC_VTABLE = 0x53CA9C08
REGISTRY, SERVICE, PAF = shared.REGISTRY, shared.SERVICE, shared.PAF
R0, R1, R2, R3, PC = shared.R0, shared.R1, shared.R2, shared.R3, shared.PC
R6 = arm.UC_ARM_REG_R6
COLD_WRITE, RESET_READ, NULL_READ, ASSERTION_ENTRY = 0x5334A26C, 0x5334A3FC, 0x532726E8, shared.ASSERTION

SHARED_CODE = (
    "registry_get", "registry_register_wrapper", "registry_register", "registry_lookup",
    "irq_register_wrapper", "irq_registry_get", "irq_register", "listener_array_ctor",
    "mutex_object_ctor", "service_get", "service_ctor", "service_bind", "platform_get",
    "platform_map_lookup_non_cc", "device_factory_get", "device_factory_service_slice",
    "paf_ctor", "paf_bind_through_primary_service", "lens_factory_get_warm", "motor_factory_get_warm",
    "reload_factory_get", "timer_descriptor_init", "timer_d1_factory_slice",
    "timer_ctor", "timer_factory_finish_method",
)
CODE = {name: shared.CODE[name] for name in SHARED_CODE}
CODE.update({
    "adapter_channels": shared.CODE["adapter_channel0"],
    "udc_factory_get": (0x532734E0, 0x5327355C),
    "udc_descriptor_init": (0x53272508, 0x5327253C),
    "udc_123_factory_slice": (0x53272EF0, 0x53273000),
    "udc_124_factory_slice": (0x53273004, 0x53273110),
    "udc_ctor": (0x53272540, 0x53272620),
    "udc_channel_assignment": (0x53272488, 0x53272508),
    "udc_cold_init_prefix": (0x5334A238, COLD_WRITE),
    "dynamic_cast": (0x533AADA0, 0x533AAEB4),
    "single_inheritance_rtti_cast": (0x533AA14C, 0x533AA224),
    "single_inheritance_rtti_match": (0x533AA224, 0x533AA264),
    "class_rtti_cast": (0x533AB86C, 0x533AB8C8),
    "class_rtti_match": (0x533AB924, 0x533AB950),
    "typeinfo_name_compare": (0x533A9F70, 0x533A9FBC),
    "channel1_callsite": (0x52F0BB00, 0x52F0BB0C),
    "udc_reset_wrapper": (0x532726E8, 0x53272708),
    "udc_reset_prefix": (0x5334A3EC, RESET_READ),
})
THUMB = (0x526AC5E0, 0x526AC5F4)
DATA = {name: shared.DATA[name] for name in (
    "registry_cold_literals", "listener_array_literal", "mutex_object_literal", "timer_ctor_literal",
    "timer_d1_d2_literal_words", "timer_vtable_header_and_slots_through_target", "timer_rtti_name",
    "reload_factory_vptr_literal", "reload_factory_create_slot", "device_factory_vptr_literal",
    "device_factory_init_slot", "service_base_vptr_literal", "service_bind_slot", "paf_vptr_literal",
    "paf_bind_slot", "mutex_init_fixture_readonly_word",
)}
DATA.update({
    "udc_factory_vptr_literal": (0x5327355C, 0x53273560),
    "udc_factory_vtable_create": (0x53CA9C60, 0x53CA9C6C),
    "udc_factory_rtti_name": (0x53CA9C48, 0x53CA9C53),
    "udc_ctor_vptr_literal": (0x53272620, 0x53272624),
    "udc_vtable_and_assignment_slot": (0x53CA9C00, 0x53CA9C28),
    "udc_rtti_record": (0x53CA9BF0, 0x53CA9BFC),
    "udc_rtti_name": (0x53CA9B90, 0x53CA9B95),
    "driver_rtti_record": (0x538F37C0, 0x538F37CC),
    "driver_rtti_name": (0x538F37CC, 0x538F37D4),
    "single_inheritance_rtti_vtable": (0x53CDC1E8, 0x53CDC20C),
})
STATIC = {
    "udc_factory_entry_before_slice": (0x53272EC4, 0x53272EF0),
    "cold_write_unexecuted": (COLD_WRITE, COLD_WRITE + 4),
    "reset_read_write_and_return_unexecuted": (RESET_READ, 0x5334A418),
    "channel0_predecessor_not_run": (0x52F0BAE4, 0x52F0BB00),
}

# Reuse the frozen input/stage helpers. Adjust the live code allowlist only in this module.
shared.CODE = CODE
shared.REGS["r6"] = R6


class Replay(shared.Replay):
    def __init__(self, image, model, clobber):
        super().__init__(image, model, clobber)
        self.observed = []

    def hook(self, u, pc, size, data):
        r0 = u.reg_read(R0)
        result = 0
        if pc == shared.MALLOC and r0 == 0x50:
            result = self.next_alloc
            self.next_alloc += 0x100
            u.mem_write(result, b"\xa5" * 0x50)
            args = [r0, result]
        elif pc == shared.ATEXIT and r0 == 0x53268380:
            args = [r0]
        elif pc == ASSERTION_ENTRY and pc in self.stop_before and r0 == 1:
            args = [r0, u.reg_read(R3)]
        else:
            args = None
        if args is not None:
            self.calls.append([pc, u.reg_read(shared.LR), args])
            if self.clobber:
                for reg, value in zip(shared.VOLATILE, (0xdead11, 0xdead22, 0xdead33, 0xdead44)):
                    u.reg_write(reg, value)
                cpsr = u.reg_read(arm.UC_ARM_REG_CPSR)
                u.reg_write(arm.UC_ARM_REG_CPSR, cpsr ^ 0xF0000000)
            u.reg_write(R0, result)
            u.reg_write(PC, u.reg_read(shared.LR))
            return
        if THUMB[0] <= pc and pc + size <= THUMB[1]:
            assert size in (2, 4) and u.reg_read(arm.UC_ARM_REG_CPSR) & 0x20
            self.counts["rtti_thumb_strcmp_prefix"] += 1
            self.trace.update(pack("<I", pc))
            self.trace.update(self.image[pc-shared.BASE:pc-shared.BASE+size])
            return
        if pc in (0x53177C1C, 0x53177C20, 0x52F0BB08, 0x531784B4, NULL_READ, 0x5334A3EC):
            count = 4 if pc == 0x53177C1C else 2 if pc == 0x52F0BB08 else 1
            self.observed.append([pc, [u.reg_read(reg) for reg in (R0, R1, R2, R3)[:count]]])
        super().hook(u, pc, size, data)

    def udc(self, key, counter):
        assert self.stage("udc_factory_cold_get", 0x532734E0) == UDC_FACTORY
        assert self.read(UDC_FACTORY) == FACTORY_VTABLE
        assert self.read(FACTORY_VTABLE + 8) == 0x53272EC4
        fp = shared.STACK - 0x500
        self.stage("udc_descriptor_init", 0x53272508, r0=fp-0x44)
        self.put(CHANNEL_COUNTER, counter)
        start, end, slot = ((0x53272EF0, 0x53273000, 4) if key == 0x123 else
                            (0x53273004, 0x53273110, 8))
        stop = (COLD_WRITE,) if counter == 0 else (ASSERTION_ENTRY,) if counter == 6 else ()
        result = self.stage(f"udc_{key:x}_factory", start, end, stop_before=stop,
                            fp=fp, sp=fp-0x44, r4=REGISTRY, r6=UDC_FACTORY)
        obj = self.read(UDC_FACTORY + slot)
        assert obj and self.read(obj) == UDC_VTABLE and self.read(obj + 0x10) == key, (
            hex(key), obj, self.primary(key), self.calls[-7:])
        assert self.primary(key) == [1, key, obj]
        assert self.read(shared.IRQ_TABLE + 4 * (key - 0xBC)) == obj
        assert self.read(obj + 0x38) == counter
        assert self.read(CHANNEL_COUNTER) == (counter + 1 if counter else 0)
        if counter == 0:
            assert self.stopped == [COLD_WRITE, 0x1E002000, 0, 0x1E002000]
            assert self.cpu.reg_read(arm.UC_ARM_REG_R5) == 0x8008
        elif counter == 6:
            assert self.stopped == [ASSERTION_ENTRY, 0, 0x53CA79F0, 0x47]
            assert self.cpu.reg_read(shared.LR) == 0x532724F0
        else:
            assert result == 1
        return obj

    def bind(self, expected):
        assert self.stage("device_factory_cold_get", 0x5317757C) == shared.DEVICE_FACTORY
        self.stage("device_factory_service_store", 0x531777F4, 0x531777FC, r4=shared.DEVICE_FACTORY)
        assert self.read(shared.DEVICE_FACTORY+4) == SERVICE
        assert self.read(SERVICE) == 0x53C71140 and self.read(SERVICE + 0x3C) == 0
        binder = self.read(self.read(SERVICE) + 8)
        assert binder == 0x531779B0 and self.stage("service_vtable_binder", binder, r0=SERVICE) == 1
        assert self.read(SERVICE + 0x3C) == expected
        self.put(0x54784440, 1)
        self.put(0x54784444 + 0x10, shared.LENS)
        self.put(0x547844A4, 1)
        self.stage("paf_ctor", 0x52F0B4B0, r0=PAF)
        binder = self.read(self.read(PAF) + 0xC)
        assert binder == 0x52F0B380
        self.stage("paf_vtable_binder_through_primary_service", binder, 0x52F0B40C, r0=PAF)
        assert self.read(PAF + 8) == SERVICE

    def one(self, case, key, counter, wrong_type=False):
        assert self.stage("primary_registry_cold_init", 0x52F137F0) == REGISTRY
        assert self.primary(0x123) == self.primary(0x124) == [0, 0x1B2, 0]
        obj = self.udc(key, counter) if key else 0
        if wrong_type:
            assert self.stage("reload_factory_cold_get", 0x5326EE34) == shared.RELOAD_FACTORY
            obj = self.timer(0xD1)
            assert self.read(obj) == 0x53CA9A00
            # Negative type fixture, using the original primary setter at the correct key.
            assert self.stage("inject_foreign_type_at_123", 0x52F13774, r0=obj, r1=0x123) == 1
            assert self.primary(0x123) == [1, 0x123, obj]
        expected = obj if key == 0x123 and counter in (1, 5) else 0
        if counter not in (0, 6):
            self.bind(expected)
            stop = RESET_READ if expected else NULL_READ
            self.stage("channel1_reset_entry", 0x52F0BB00, stop_before=(stop,), r4=PAF)
            reset_points = [[0x52F0BB08, [SERVICE, 1]], [0x531784B4, [expected]], [NULL_READ, [expected]]]
            if expected:
                reset_points.append([0x5334A3EC, [counter]])
            assert self.observed[-len(reset_points):] == reset_points
            cast_calls = [values for pc, values in self.observed if pc == 0x53177C1C]
            assert cast_calls == ([[obj, 0x538F37C0, 0x53CA9BF0, 0]] if (expected or wrong_type) else [])
            assert self.stopped[:2] == ([RESET_READ, 0x1E002000 + (counter << 5)] if expected else [NULL_READ, 0])
        mapped = shared.digest(self.cpu.mem_read(shared.BASE, len(self.image)))
        assert mapped == shared.input_guard.RTOS_SHA
        pc = self.stopped[0]
        unread = self.stopped[1] + 0xC if pc == RESET_READ else 0 if pc == NULL_READ else None
        return {"case": case, "primary_123": self.primary(0x123), "primary_124": self.primary(0x124),
                "irq_67_68": [self.read(shared.IRQ_TABLE + k*4) for k in (0x67, 0x68)],
                "object": obj, "object_channel_word": self.read(obj + 0x38) if key else None,
                "counter_before_fixture": counter, "counter_after": self.read(CHANNEL_COUNTER),
                "service_3c": self.read(SERVICE + 0x3C), "paf_8": self.read(PAF + 8),
                "boundary": {"pc": pc, "first_unread_address": unread,
                             "first_unwritten_address": self.stopped[1]+0x14 if pc == COLD_WRITE else None,
                             "first_unwritten_u32": 0x8008 if pc == COLD_WRITE else None,
                             "assertion_entry_r0_r2_r3": self.stopped[1:] if pc == ASSERTION_ENTRY else None},
                "observed_pc_args": self.observed, "stages_name_entry_stop": self.stages,
                "stub_calls_pc_lr_args": self.calls, "range_counts": self.counts,
                "executed_pc_and_word_sha256": self.trace.hexdigest(), "mapped_rtos_sha256": mapped}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        parser.error("--output must be a new path")
    image = shared.input_guard.read_image(args.input)
    cases = (("key123_channel1", 0x123, 1), ("key123_channel5", 0x123, 5),
             ("neighbor_key124_only", 0x124, 1), ("no_udc", 0, None),
             ("foreign_rtti_at_key123", 0, None, True),
             ("cold_init_first_write", 0x123, 0), ("channel6_assertion", 0x123, 6))
    rows = [Replay(image, arm.UC_CPU_ARM_CORTEX_A7, False).one(*case) for case in cases]
    for model in (arm.UC_CPU_ARM_CORTEX_A7, arm.UC_CPU_ARM_CORTEX_A15):
        assert rows == [Replay(image, model, True).one(*case) for case in cases]
    pins = {kind: {name: {"start": a, "end_exclusive": z, "rtos_offset": a-shared.BASE,
                         "decoded_offset": a-shared.BASE+shared.input_guard.RTOS_OFFSET,
                         "sha256": shared.digest(image[a-shared.BASE:z-shared.BASE])}
                   for name, (a, z) in spans.items()}
            for kind, spans in (("code", CODE | {"rtti_thumb_strcmp_prefix": THUMB}),
                                ("data", DATA), ("static_only", STATIC))}
    result = {"rtos_sha256": shared.input_guard.RTOS_SHA, "decoded_sha256": shared.input_guard.DECODED_SHA,
              "shared_replay_sha256": PREVIOUS_SHA, "unicorn_version": uc.__version__,
              "cpu_variants_exact": ["Cortex-A7 baseline", "Cortex-A7 volatile/NZCV clobber",
                                     "Cortex-A15 volatile/NZCV clobber"],
              "stub_contracts": {hex(pc): name for pc, name in shared.STUBS.items()},
              "ranges": pins, "cases": rows}
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
