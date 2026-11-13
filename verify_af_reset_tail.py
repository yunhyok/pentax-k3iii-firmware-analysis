"""Original PafMotor reset-tail slices with MMIO left unmapped."""
if not __debug__:
    raise RuntimeError("Run without -O to retain validation")

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
from struct import pack
from types import ModuleType

DEPENDENCY = Path(__file__).resolve().with_name("verify_af_service_binding.py")
DEPENDENCY_SHA = "874a6fb9c38b96a2920751c1d03084d6143ff2b2dc3cd7a9c1ad223e11f0b118"
source = DEPENDENCY.read_bytes().replace(b"\r\n", b"\n")
if sha256(source).hexdigest() != DEPENDENCY_SHA:
    raise ValueError("Dependency SHA-256 mismatch: verify_af_service_binding.py")
shared = ModuleType("reset_tail_binding")
shared.__file__ = str(DEPENDENCY)
exec(compile(source, str(DEPENDENCY), "exec"), shared.__dict__)
arm, uc = shared.arm, shared.uc
R0, R1, R2, R3, PC, SP, FP = shared.R0, shared.R1, shared.R2, shared.R3, shared.PC, shared.SP, shared.FP
IP, R5, R6 = arm.UC_ARM_REG_R12, arm.UC_ARM_REG_R5, arm.UC_ARM_REG_R6
STACK_GUARD, RELOAD_SLOT, APPLY_SLOT, CLEAR_SLOT = 0x53CBB4C0, 0x53CA9A7C, 0x53CA9A54, 0x53CA9A58
RELOAD_READ, APPLY_READ, CLEAR_READ, NULL_VPTR = 0x5326D6C8, 0x5326D8B4, 0x5326D57C, 0x5317850C
ADAPTER, RELOAD_CALL, APPLY_CONTINUATION, CLEAR_CONTINUATION = 0x531784C8, 0x53178534, 0x53178538, 0x5317854C
PAF, SERVICE, REGISTRY = shared.PAF, shared.SERVICE, shared.REGISTRY
EXPECTED_DESCRIPTOR = bytes.fromhex("01000000 00000100 ffff0000 00000000 000003")

CODE = {name: shared.CODE[name] for name in (
    "registry_get", "registry_register_wrapper", "registry_register", "registry_lookup",
    "irq_register_wrapper", "irq_registry_get", "irq_register", "listener_array_ctor",
    "mutex_object_ctor", "timer_descriptor_init", "reload_factory_get", "timer_d1_factory_slice",
    "timer_ctor", "timer_factory_finish_method", "device_factory_get", "device_factory_service_slice",
    "service_get", "service_ctor", "service_bind", "platform_get", "platform_map_lookup_non_cc",
    "paf_ctor", "paf_bind_through_primary_service", "lens_factory_get_warm", "motor_factory_get_warm",
)}
CODE.update({
    "paf_reset_tail": (0x52F0BB0C, 0x52F0BB38),
    "adapter_body_and_stack_check": (ADAPTER, 0x5317857C),
    "descriptor_init": (0x5326DE24, 0x5326DE54),
    "reload_count_before_read": (0x5326D6B0, RELOAD_READ),
    "apply_config_prefix": (0x5326D740, 0x5326D7B8),
    "apply_config_descriptor_mode_3": (0x5326D860, 0x5326D870),
    "apply_config_selector_1": (0x5326D9E4, 0x5326D9F4),
    "apply_config_flags": (0x5326D970, 0x5326D978),
    "apply_config_descriptor_values": (0x5326D894, APPLY_READ),
    "clear_before_read": (0x5326D570, CLEAR_READ),
})
DATA = dict(shared.DATA)
DATA.update({
    "stack_guard": (STACK_GUARD, STACK_GUARD + 4),
    "reloadtimer_slots_54_58": (APPLY_SLOT, CLEAR_SLOT + 4),
    "reloadtimer_slot_7c": (RELOAD_SLOT, RELOAD_SLOT + 4),
    "apply_config_mode_3_table": (0x5326D874, 0x5326D88C),
    "set_reload_count_string": (0x53CA9A88, 0x53CA9A97),
})
STATIC = {
    "reload_count_read_to_return": (RELOAD_READ, 0x5326D740),
    "apply_config_read_to_flag_commit": (APPLY_READ, 0x5326D8FC),
    "clear_read_to_return": (CLEAR_READ, 0x5326D5A4),
    "descriptor_destructor": (0x5326DE54, 0x5326DE58),
    "stack_guard_failure_call": (0x5317857C, 0x53178580),
    "prior_channel_reset_calls_not_executed": (0x52F0BAE4, 0x52F0BB0C),
    "mode1_caller_after_reset": (0x52F0D8AC, 0x52F0D8BC),
}
shared.CODE = CODE


class Replay(shared.Replay):
    def __init__(self, image, model, clobber):
        super().__init__(image, model, clobber)
        self.control_points = []
        self.descriptor = None

    def hook(self, u, pc, size, data):
        if pc == ADAPTER:
            if u.reg_read(R1) == 0:
                self.descriptor = u.reg_read(SP) - 0x38
                u.mem_write(self.descriptor, bytes([0x5A if self.clobber else 0xA5]) * 19)
            self.control_points.append([pc, u.reg_read(R0), u.reg_read(R1)])
        if pc in (RELOAD_CALL, 0x53178548, 0x53178558, 0x5326D6B0, 0x5326D740, 0x5326D570):
            regs = {RELOAD_CALL: (R0, R1, R2, R6), 0x53178548: (R0, R1, R3), 0x53178558: (R0, R3),
                    0x5326D6B0: (R0, R1, R2), 0x5326D740: (R0, R1), 0x5326D570: (R0,)}
            self.control_points.append([pc, *[u.reg_read(reg) for reg in regs[pc]]])
        super().hook(u, pc, size, data)

    def setup(self, registered):
        assert self.stage("primary_registry_cold_init", 0x52F137F0) == REGISTRY
        selected = 0
        if registered:
            assert self.stage("reload_factory_cold_get", 0x5326EE34) == shared.RELOAD_FACTORY
            selected = self.timer(0xD1)
            assert self.primary(0xD1) == [1, 0xD1, selected]
        else:
            assert self.primary(0xD1) == [0, 0x1B2, 0]
        assert self.stage("device_factory_cold_get", 0x5317757C) == shared.DEVICE_FACTORY
        self.stage("device_factory_service_store", 0x531777F4, 0x531777FC, r4=shared.DEVICE_FACTORY)
        assert self.read(shared.DEVICE_FACTORY + 4) == SERVICE
        assert self.read(SERVICE) == 0x53C71140
        binder = self.read(self.read(SERVICE) + 8)
        assert binder == 0x531779B0 and self.stage("service_vtable_binder", binder, r0=SERVICE) == 1
        assert self.read(SERVICE + 0x38) == selected and self.read(SERVICE + 0x3C) == 0
        self.put(0x54784440, 1)
        self.put(0x54784444 + 0x10, shared.LENS)
        self.put(0x547844A4, 1)
        self.stage("paf_ctor", 0x52F0B4B0, r0=PAF)
        binder = self.read(self.read(PAF) + 0xC)
        assert binder == 0x52F0B380
        self.stage("paf_binder_through_service", binder, 0x52F0B40C, r0=PAF)
        assert self.read(PAF + 8) == SERVICE
        return selected

    def independent_callsite(self, name, entry, end):
        # The earlier virtual methods did not return. Reuse only the original
        # caller frame and descriptor, with deliberately undefined volatile state.
        u = self.cpu
        self.stop_before = (end,)
        self.stopped = None
        for reg, value in zip((R0, *shared.VOLATILE), (0xBAD0, 0xBAD1, 0xBAD2, 0xBAD3, 0xBADC)):
            u.reg_write(reg, value)
        cpsr = u.reg_read(arm.UC_ARM_REG_CPSR)
        u.reg_write(arm.UC_ARM_REG_CPSR, cpsr ^ 0xF0000000)
        u.emu_start(entry, shared.RETURN, count=250)
        assert self.stopped is not None and u.reg_read(PC) == end
        self.stages.append([name, entry, end])

    def one(self, case):
        selected = self.setup(case in ("reload_count", "apply_config", "clear_config"))
        descriptor, unread, returned = None, None, None
        if case in ("reload_count", "apply_config", "clear_config", "missing_d1"):
            before = bytes(self.cpu.mem_read(selected, 0x48)) if selected else b""
            end = (NULL_VPTR if not selected else RELOAD_READ if case == "reload_count" else RELOAD_CALL)
            self.stage("paf_channel0_post_reset_call", 0x52F0BB0C, stop_before=(end,), r4=PAF)
            assert self.control_points[0] == [ADAPTER, SERVICE, 0]
            if selected:
                actual = bytes(self.cpu.mem_read(self.descriptor, 19))
                assert actual[7] == (0x5A if self.clobber else 0xA5)
                descriptor = actual[:7] + b"\0" + actual[8:]
                assert descriptor == EXPECTED_DESCRIPTOR, actual.hex()
                assert self.control_points[1] == [RELOAD_CALL, selected, 0xFFFF, 1, 0x5326D6B0]
                if case == "reload_count":
                    assert self.control_points[2] == [0x5326D6B0, selected, 0xFFFF, 1]
                    assert self.cpu.reg_read(R3) == 0x1E000020
                    unread = self.cpu.reg_read(R3)
                elif case == "apply_config":
                    self.independent_callsite("apply_callsite_without_prior_virtual_return", APPLY_CONTINUATION, APPLY_READ)
                    assert self.control_points[2:] == [
                        [0x53178548, selected, self.descriptor, 0x5326D740],
                        [0x5326D740, selected, self.descriptor],
                    ]
                    assert self.cpu.reg_read(R2) == 0x1E000020
                    assert self.cpu.reg_read(R5) == 0xC80 and self.cpu.reg_read(R0) == 0xFFFF
                    assert self.cpu.reg_read(IP) == 0 and self.cpu.reg_read(R1) == 0
                    assert self.read(selected + 0x30) == 0
                    before = before[:0x30] + bytes(4) + before[0x34:]
                    unread = self.cpu.reg_read(R2)
                else:
                    self.independent_callsite("clear_callsite_without_prior_virtual_returns", CLEAR_CONTINUATION, CLEAR_READ)
                    assert self.control_points[2:] == [[0x53178558, selected, 0x5326D570], [0x5326D570, selected]]
                    assert self.cpu.reg_read(R1) == 0x1E000020
                    assert self.cpu.reg_read(IP) == 0x1E000028 and self.cpu.reg_read(R2) == 0
                    unread = self.cpu.reg_read(R1)
                assert bytes(self.cpu.mem_read(selected, 0x48)) == before
            else:
                assert self.stopped[0:2] == [NULL_VPTR, 0]
                unread = 0
        else:
            # Supply a Paf tail frame only for the independent channel-1 entry.
            # The original outer epilogue restores r3/r4/fp/sp/pc from this frame.
            frame = shared.STACK - 0x500
            original_paf = bytes(self.cpu.mem_read(PAF, 0xA4))
            for offset in (0x20, 0x21, 0x32):
                self.put(PAF+offset, 0xA5, 1)
            self.cpu.mem_write(frame, pack("<6I", 0x3333, 0x4444, 0x5555,
                                           shared.STACK, shared.RETURN, 0))
            returned = self.stage("paf_channel1_post_reset_call_and_epilogue", 0x52F0BB18, r4=PAF, sp=frame)
            assert returned == SERVICE and self.control_points == [[ADAPTER, SERVICE, 1]]
            assert self.descriptor is None and bytes(self.cpu.mem_read(PAF, 0xA4)) == original_paf
        mapped = shared.digest(self.cpu.mem_read(shared.BASE, len(self.image)))
        assert mapped == shared.input_guard.RTOS_SHA
        return {"case": case, "service_38": selected, "service_3c": 0, "paf_8": SERVICE,
                "boundary_pc": self.cpu.reg_read(PC), "first_unread_address": unread, "returned_r0": returned,
                "descriptor_19_bytes": (descriptor[:7].hex() + "??" + descriptor[8:].hex())
                if descriptor is not None else None,
                "config_prefix_inputs": {"control": 0xC80, "reload_0": 0xFFFF, "reload_1": 0}
                if case == "apply_config" else None,
                "control_points_pc_args": self.control_points, "stages_name_entry_stop": self.stages,
                "stub_calls_pc_lr_args": self.calls, "range_counts": self.counts,
                "executed_pc_and_word_sha256": self.trace.hexdigest(), "mapped_rtos_sha256": mapped}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        parser.error("--output must be a new path")
    image = shared.input_guard.read_image(args.input)
    for slot, target in ((RELOAD_SLOT, 0x5326D6B0), (APPLY_SLOT, 0x5326D740), (CLEAR_SLOT, 0x5326D570)):
        assert int.from_bytes(image[slot-shared.BASE:slot-shared.BASE+4], "little") == target
    cases = ("reload_count", "apply_config", "clear_config", "missing_d1", "channel1_noop")
    rows = [Replay(image, arm.UC_CPU_ARM_CORTEX_A7, False).one(case) for case in cases]
    for model in (arm.UC_CPU_ARM_CORTEX_A7, arm.UC_CPU_ARM_CORTEX_A15):
        assert rows == [Replay(image, model, True).one(case) for case in cases]
    pins = {kind: {name: {"start": a, "end_exclusive": z, "rtos_offset": a-shared.BASE,
                         "decoded_offset": a-shared.BASE+shared.input_guard.RTOS_OFFSET,
                         "sha256": shared.digest(image[a-shared.BASE:z-shared.BASE])}
                   for name, (a, z) in spans.items()}
            for kind, spans in (("code", CODE), ("data", DATA), ("static_only", STATIC))}
    result = {"rtos_sha256": shared.input_guard.RTOS_SHA, "decoded_sha256": shared.input_guard.DECODED_SHA,
              "binding_dependency_sha256_lf": DEPENDENCY_SHA,
              "input_guard_dependency_sha256_lf": shared.DEPENDENCY_SHA,
              "unicorn_version": uc.__version__,
              "cpu_variants_exact": ["Cortex-A7 baseline, descriptor stack fill A5",
                                     "Cortex-A7 volatile/NZCV clobber, descriptor stack fill 5A",
                                     "Cortex-A15 volatile/NZCV clobber, descriptor stack fill 5A"],
              "descriptor_unknown_byte": "?? marks +7, which retained the prefill in both controls",
              "stub_contracts": {hex(pc): name for pc, name in shared.STUBS.items()},
              "ranges": pins, "cases": rows}
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
