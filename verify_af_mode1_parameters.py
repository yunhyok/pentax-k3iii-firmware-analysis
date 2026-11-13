"""Original mode-1 parameter slices with separate pre-reset and post-reset entries."""
if not __debug__:
    raise RuntimeError("Run without -O to retain validation")

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
from types import ModuleType

DEPENDENCY = Path(__file__).resolve().with_name("verify_af_udc_binding.py")
PIN = "87b2eef778027e9067eeb46973dd3a44cb462173c7338f192d2fa74104f8319e"
source = DEPENDENCY.read_bytes().replace(b"\r\n", b"\n")
if sha256(source).hexdigest() != PIN:
    raise ValueError("Dependency SHA-256 mismatch: verify_af_udc_binding.py")
udc = ModuleType("mode1_udc_fixture")
udc.__file__ = str(DEPENDENCY)
exec(compile(source, str(DEPENDENCY), "exec"), udc.__dict__)
shared, arm, uc = udc.shared, udc.arm, udc.uc
R0, R1, R2, R3, PC = udc.R0, udc.R1, udc.R2, udc.R3, udc.PC
R4, R5, R6, SB = arm.UC_ARM_REG_R4, arm.UC_ARM_REG_R5, arm.UC_ARM_REG_R6, arm.UC_ARM_REG_R9
R = (R0, R1, R2, R3)
JOINT, PAF, LENS, PEER, SERVICE = shared.JOINT, shared.PAF, shared.LENS, shared.PEER, shared.SERVICE
RESOURCE, READ_0, READ_1, COUNT_READ = 0x52F06B24, 0x5326D4F0, 0x5334A3FC, 0x5326D5E8
TABLE = 0x538F25E0
CODE = dict(udc.CODE)
# udc swaps the shared allowlist on import; recover only the required native source ranges.
CODE.update({
    "paf_bind_through_primary_service": (0x52F0B380, 0x52F0B490),
    "event80_handler_prefix": (0x52F0853C, 0x52F08550),
    "joint_dispatch_prefix": (0x52F083F0, 0x52F0842C),
    "joint_mode1_call": (0x52F08460, 0x52F0847C),
    "mode_lookup_head": (0x52EF877C, 0x52EF8794),
    "mode_lookup_cases": (0x52EF87AC, 0x52EF87D8),
    "mode1_singleton_get_warm": (0x53102CE8, 0x53102D14),
    "paf_mode1_to_reset": (0x52F0D83C, 0x52F0D8B0),
    "paf_request_dispatch": (0x52F0D8B0, 0x52F0D8BC),
    "paf_default_and_polarity_call": (0x52F0D8E4, 0x52F0D920),
    "paf_drive_arguments": (0x52F0D920, 0x52F0D934),
    "paf_request_7_5_6_9_1_2_8": (0x52F0DAD8, 0x52F0DC20),
    "paf_request_1_alternate_prefix": (0x52F0DC6C, 0x52F0DC78),
    "paf_polarity": (0x52F0BD1C, 0x52F0BD6C),
    "lens_byte_reader": (0x52F02E04, 0x52F02E0C),
    "drive_parameter_builder": (0x52F0C78C, 0x52F0C868),
    "drive_parameter_builder_alternate": (0x52F0C868, 0x52F0C96C),
    "drive_service_argument_builder": (0x52F0C5D8, 0x52F0C644),
    "drive_service_wrapper": (0x531785F8, 0x53178620),
    "drive_service_prefix": (0x5317834C, 0x5317838C),
    "drive_service_timer_dispatch": (0x53178400, 0x53178410),
    "timer_before_read": (0x5326D4EC, READ_0),
    "paf_count_reader_wrapper": (0x52F0B490, 0x52F0B498),
    "count_service_prefix": (0x53178310, 0x5317834C),
    "count_register_prefix": (0x5326D5E4, COUNT_READ),
})
DATA = dict(udc.DATA)
DATA.update({
    "request_mode_jump_table": (0x52F0D8BC, 0x52F0D8E4),
    "joint_client_jump_table": (0x52EF8794, 0x52EF87AC),
    "parameter_pairs_and_defaults": (TABLE, TABLE + 0x74),
    "stack_guard": (0x53CBB4C0, 0x53CBB4C4),
    "reloadtimer_count_slot": (0x53CA9A6C, 0x53CA9A70),
})
STATIC = {
    "request_producer": (0x52EF82B8, 0x52EF8368),
    "facade_command6_caller": (0x52EF8C68, 0x52EF8CA0),
    "reset_entry_not_executed": (0x52F0BAE4, 0x52F0BB38),
    "resource_callback_not_executed": (RESOURCE, RESOURCE + 4),
    "request_1_alternate_not_executed": (0x52F0D0C0, 0x52F0D0C4),
    "request_8_alternate_not_executed": (0x52F0D000, 0x52F0D004),
    "timer_first_read": (READ_0, READ_0 + 4),
    "udc_first_read": (READ_1, READ_1 + 4),
    "count_first_read": (COUNT_READ, COUNT_READ + 4),
}
shared.CODE = CODE
MARKS = {
    0x52F08478: R, 0x52F0D904: R[:2], 0x52F0D930: R,
    0x52F0C87C: R[:3], 0x52F0C940: R[:3], 0x531785F8: R,
    0x5326D4EC: R[:1], 0x532726E8: R[:1], 0x5334A3EC: R[:1],
}
AF_FIELDS = ((0x2C, 1), (0x2D, 1), (0x2E, 1), (0x30, 1), (0x35, 1), (0x40, 1),
             (0x41, 1), (0x42, 1), (0x43, 1), (0x48, 4), (0x4C, 4),
             (0x5A, 2), (0x5C, 2), (0x98, 4))


def polarity(lens_flag, argument):
    return int(argument != (0 if lens_flag else 1))


class Replay(udc.Replay):
    def __init__(self, image, model, clobber):
        super().__init__(image, model, clobber)
        self.points = {}

    def hook(self, u, pc, size, data):
        if pc in MARKS:
            assert pc not in self.points
            self.points[pc] = [u.reg_read(reg) for reg in MARKS[pc]]
        super().hook(u, pc, size, data)

    def setup(self):
        assert self.stage("primary_registry_init", 0x52F137F0) == shared.REGISTRY
        assert self.stage("reload_factory_init", 0x5326EE34) == shared.RELOAD_FACTORY
        timer = self.timer(0xD1)
        device = self.udc(0x123, 1)
        self.bind(device)
        assert self.read(SERVICE + 0x38) == timer
        self.put(0x54784444 + 0x18, LENS + 0x1000)
        self.put(0x547844A8 + 0x10, PEER)
        # Other sibling factories are out of scope; provide the nonzero dependency
        # copied by their original binder. The memory is never used by this replay.
        self.put(shared.DEVICE_FACTORY + 8, LENS + 0x2000)
        assert self.stage("paf_full_binder", 0x52F0B380, r0=PAF) == 1
        assert [self.read(PAF + x) for x in (4, 8, 0x10, 0x14)] == [LENS, SERVICE, LENS+0x1000, PEER]
        self.put(0x547BB0A8, 1)
        self.put(0x547BB080 + 0xC, 0x13572468)
        return timer, device

    def resume_slice(self, label, entry, end):
        # Preserve the original caller frame and live callee-saved registers.
        # This separate entry supplies no previous service or MMIO return value.
        u = self.cpu
        self.stopped, self.stop_before = None, (end,)
        for reg, val in zip((R0, *shared.VOLATILE), (0xA0A0, 0xA1A1, 0xA2A2, 0xA3A3, 0xACAC)):
            u.reg_write(reg, val)
        cpsr = u.reg_read(arm.UC_ARM_REG_CPSR)
        u.reg_write(arm.UC_ARM_REG_CPSR, cpsr ^ 0xF0000000)
        u.emu_start(entry, shared.RETURN, count=1000)
        assert self.stopped is not None and u.reg_read(PC) == end, (label, hex(u.reg_read(PC)), hex(end))
        self.stages.append([label, entry, end])

    def one(self, case, request, direction, lens_flag, sample, calibration, old_direction, pulse_flag,
            first_parameter, forwarded_word, boundary, service_args=None, lut=None, band=None):
        timer, device = self.setup()
        self.put(0x5478442C, 1)
        self.put(LENS + 0x134, lens_flag, 1)
        self.put(PAF + 0x48, old_direction)
        self.put(PAF + 0x41, 0xA5, 1)
        self.put(PEER + 0xEC, calibration, 2)
        self.put(PEER + 0x15, pulse_flag, 1)
        for offset, value, size in ((0xD0, LENS, 4), (0xDC, PAF, 4), (0xE0, PEER, 4),
                                    (0x64, 0x12345678, 4), (0x68, sample, 2),
                                    (0x5C, direction, 4), (0x74, request, 4)):
            self.put(JOINT + offset, value, size)
        self.stage("joint_mode1_to_prior_reset_entry", 0x52F0853C,
                   stop_before=(0x52F0BAE4,), r0=JOINT)
        assert self.points[0x52F08478] == [PAF, request, direction, JOINT+0x58]
        assert self.read(PEER + 0x2E, 2) == sample and self.read(LENS + 0x19C4) == 0x12345678
        assert [self.cpu.reg_read(r) for r in (R4, R6, SB)] == [PAF, request, direction]
        assert self.read(PAF + 0x38) == request
        self.resume_slice("post_reset_dispatch_without_reset_return", 0x52F0D8B0,
                          boundary if first_parameter is None else RESOURCE)
        if first_parameter is not None:
            assert self.points[0x52F0D904] == [PAF, forwarded_word]
            sign = polarity(lens_flag, forwarded_word)
            assert self.read(PAF + 0x42, 1) == sign
            assert self.cpu.reg_read(R5) == first_parameter and self.cpu.reg_read(SB) == sign
            assert self.cpu.reg_read(R1) == first_parameter and self.cpu.reg_read(R0) == LENS+0x1000
            if band is not None:
                assert self.read(PAF+0x41, 1) == band
            if boundary != RESOURCE:
                self.resume_slice("drive_builder_without_resource_return", 0x52F0D920, boundary)
                assert self.points[0x52F0D930] == [PAF, first_parameter, sign, request]
        if service_args is not None:
            assert self.points[0x531785F8] == [SERVICE, *service_args]
        if lut is not None:
            actual = [self.read(PAF+x, 2) for x in (0x5A, 0x5C)]
            assert actual == lut, (case, actual, lut)
        address = None
        if boundary == READ_0:
            assert self.points[0x5326D4EC] == [timer] and self.cpu.reg_read(R2) == 0x1E000020
            address = 0x1E000020
        elif boundary == READ_1:
            assert self.points[0x532726E8] == [device] and self.points[0x5334A3EC] == [1]
            assert self.cpu.reg_read(R0) == 0x1E002020
            address = 0x1E00202C
        elif boundary == COUNT_READ:
            address = self.cpu.reg_read(R3)
            assert address == 0x1E000024
        return self.result(case, boundary, address,
                           {"request_word": request, "direction_word": direction, "lens_byte": lens_flag,
                            "request_sample_u16": sample, "pulse_ec_u16": calibration,
                            "initial_paf_48": old_direction, "pulse_15_byte": pulse_flag})

    def direct_polarity_service(self, case, lens_flag, direction, value, expected):
        _, device = self.setup()
        self.put(LENS + 0x134, lens_flag, 1)
        self.put(PAF+0x42, 0xA5, 1)
        sign = self.stage("original_polarity", 0x52F0BD1C, r0=PAF, r1=direction)
        assert sign == polarity(lens_flag, direction) == self.read(PAF+0x42, 1)
        # Separately exercise the channel-1 numeric interface with a caller-supplied
        # word. This does not model the motion/count code which can produce it.
        shared.REGS["r2"] = R2
        self.stage("direct_numeric_channel1_interface", 0x52F0C5D8, stop_before=(READ_1,),
                   r0=PAF, r1=1, r2=value)
        assert self.points[0x531785F8] == [SERVICE, 1, expected, 0]
        assert self.points[0x532726E8] == [device] and self.points[0x5334A3EC] == [1]
        assert self.cpu.reg_read(R0) == 0x1E002020
        return self.result(case, READ_1, 0x1E00202C,
                           {"lens_byte": lens_flag, "direction_word": direction, "numeric_interface_word": value})

    def result(self, case, boundary, address, inputs):
        mapped = shared.digest(self.cpu.mem_read(shared.BASE, len(self.image)))
        assert mapped == shared.input_guard.RTOS_SHA
        return {"case": case, "fixtures": inputs, "boundary_pc": boundary, "first_unread_address": address,
                "control_points_pc_args": {hex(pc): args for pc, args in self.points.items()},
                "paf_fields": {hex(offset): self.read(PAF+offset, size) for offset, size in AF_FIELDS},
                "stages_name_entry_stop": self.stages, "stub_calls_pc_lr_args": self.calls,
                "range_counts": self.counts, "executed_pc_and_word_sha256": self.trace.hexdigest(),
                "mapped_rtos_sha256": mapped}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        parser.error("--output must be a new path")
    image = shared.input_guard.read_image(args.input)
    routes = (
        # name, request, direction, lens byte, request sample, pulse+ec, Paf+48,
        # pulse+15, first parameter, forwarded polarity word, stop, service args, LUT, band.
        ("request0_polarity0", 0, 1, 0, 120, 4, 0, 0, 120, 1, READ_0, [0, 120, 1], None, None),
        ("request0_polarity1", 0, 1, 2, 120, 4, 0, 0, 120, 1, READ_0, [0, 120, 1], None, None),
        ("request1_sum_wrap", 1, 0, 0, 0xFFFF, 2, 0, 0, 1, 0, READ_0, [0, 1, 1], None, None),
        ("request1_pulse_flag", 1, 0, 0, 0xFFFF, 2, 0, 1, None, None, 0x52F0D0C0),
        ("request2_sum_wrap_zero", 2, 0, 1, 0xFFFF, 1, 0, 1, 0, 0, READ_0, [0, 0, 1], None, None),
        ("request3_feedback_boundary", 3, 1, 0, 120, 4, 0, 0, 120, 1, COUNT_READ),
        ("request5_prior_zero", 5, 0xFFFFFFFF, 0, 120, 24, 0, 0, 24, 1, READ_0, [0, 24, 1], [300, 300]),
        ("request5_prior_nonzero", 5, 0, 0, 120, 24, 3, 0, 24, 0, READ_0, [0, 24, 1], [300, 300]),
        ("request6_fixed", 6, 0, 0, 120, 24, 1, 0, 0xFFFE, 1, READ_0, [0, 0xFFFE, 1], [0xFFFF, 0]),
        ("request7_prior_direction", 7, 0, 0, 120, 24, 1, 0, 120, 1, READ_0, [0, 120, 1], [0xFFFF, 0]),
        ("request8_alternate", 8, 0, 0, 120, 24, 1, 0, None, None, 0x52F0D000),
        ("request9_at214_default", 9, 1, 0, 214, 0, 0, 0, 214, 1, READ_0, [0, 214, 1], [0xFFFF, 0], 0xA5),
        ("request9_at215_band0", 9, 0, 0, 215, 0, 0, 0, 215, 0, READ_0, [0, 215, 1], [200, 300], 0),
        ("request9_at408_band1", 9, 1, 0, 408, 0, 0, 0, 408, 1, READ_0, [0, 408, 1], [200, 300], 1),
        ("request9_at540_band1", 9, 1, 0, 540, 0, 0, 0, 540, 1, READ_0, [0, 540, 1], [300, 300], 1),
        ("request9_at541_band2", 9, 0, 0, 541, 0, 0, 0, 541, 0, READ_0, [0, 541, 1], [300, 300], 2),
        ("request_ff_bucket_floor", 0xFF, 0, 1, 101, 0, 0, 0, 101, 0, READ_0, [0, 101, 1], [200, 300]),
        ("request_ff_bucket_cap", 0xFF, 0, 1, 0xFFFF, 0, 0, 0, 0xFFFF, 0, READ_0, [0, 0xFFFF, 1], [300, 300]),
        ("request_u32_default", 0xFFFFFFFF, 0xFFFFFFFF, 0xFF, 120, 0, 0, 0, 120, 0xFFFFFFFF,
         READ_0, [0, 120, 1], [300, 300]),
    )
    numeric = (
        ("channel1_unsigned_keep", 0, 1, 0x12348001, 0x8001),
        ("channel1_unsigned_negate", 2, 1, 0x12348001, 0x7FFF),
        ("channel1_negate_8000", 1, 0xFFFFFFFF, 0x8000, 0x8000),
        ("channel1_negate_ffff", 0, 0, 0xFFFF, 1),
    )
    def run(model, clobber):
        return ([Replay(image, model, clobber).one(*route) for route in routes]
                + [Replay(image, model, clobber).direct_polarity_service(*case) for case in numeric])
    rows = run(arm.UC_CPU_ARM_CORTEX_A7, False)
    for model in (arm.UC_CPU_ARM_CORTEX_A7, arm.UC_CPU_ARM_CORTEX_A15):
        assert rows == run(model, True)
    assert {k for row in rows for k in row["range_counts"]} <= CODE.keys() | {"rtti_thumb_strcmp_prefix"}
    pins = {kind: {name: {"start": a, "end_exclusive": z, "rtos_offset": a-shared.BASE,
                         "decoded_offset": a-shared.BASE+shared.input_guard.RTOS_OFFSET,
                         "sha256": shared.digest(image[a-shared.BASE:z-shared.BASE])}
                   for name, (a, z) in spans.items()}
            for kind, spans in (("code", CODE | {"rtti_thumb_strcmp_prefix": udc.THUMB}),
                                ("data", DATA), ("static_only", STATIC))}
    output = {"rtos_sha256": shared.input_guard.RTOS_SHA, "decoded_sha256": shared.input_guard.DECODED_SHA,
              "dependencies_sha256_lf": {DEPENDENCY.name: PIN, "verify_af_service_binding.py": udc.PREVIOUS_SHA,
                                         "verify_af_packet_8902.py": shared.DEPENDENCY_SHA},
              "unicorn_version": uc.__version__,
              "cpu_variants_exact": ["Cortex-A7 baseline", "Cortex-A7 volatile/NZCV clobber",
                                     "Cortex-A15 volatile/NZCV clobber"],
              "stub_contracts": {hex(pc): contract for pc, contract in shared.STUBS.items()},
              "ranges": pins, "cases": rows}
    with args.output.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(output, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
