"""Original request-3 feedback arithmetic with explicit numeric inputs, no MMIO read."""
if not __debug__:
    raise RuntimeError("Run without -O to retain validation")

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
from types import ModuleType

PREVIOUS = Path(__file__).resolve().with_name("verify_af_mode1_parameters.py")
PREVIOUS_SHA = "41059460e76ec67cf66c1c95814a26e9319e025692706c78d3fa1a95bb31c50e"
source = PREVIOUS.read_bytes().replace(b"\r\n", b"\n")
if sha256(source).hexdigest() != PREVIOUS_SHA:
    raise ValueError("Dependency SHA-256 mismatch: verify_af_mode1_parameters.py")
previous = ModuleType("request3_fixture")
previous.__file__ = str(PREVIOUS)
exec(compile(source, str(PREVIOUS), "exec"), previous.__dict__)
shared, arm, uc = previous.shared, previous.arm, previous.uc
R0, R1, R2, R3, PC = previous.R0, previous.R1, previous.R2, previous.R3, previous.PC
R4, R5, R6 = previous.R4, previous.R5, previous.R6
R7 = arm.UC_ARM_REG_R7
PAF, PEER, SERVICE = previous.PAF, previous.PEER, previous.SERVICE
COUNT_READ, READ_0, READ_1, TABLE = previous.COUNT_READ, previous.READ_0, previous.READ_1, previous.TABLE
FEEDBACK_ENTRY = 0x52F0C7D8
CALLER_ENTRY = 0x52F0C9F0
CALLER_ALTERNATE = 0x52F0CAC4
CALLER_COMPLETE = 0x52F0CA70
REQUEST3_ENTRY = 0x52F0C78C

CODE = dict(previous.CODE)
CODE.update({
    "request3_lut_store": (0x52F0C96C, 0x52F0C9B0),
    "request3_local_caller": (0x52F0C9B0, 0x52F0CA48),
})
DATA = dict(previous.DATA)
STATIC = dict(previous.STATIC)
STATIC.update({
    "local_caller_else_and_followup_not_executed": (0x52F0CA48, 0x52F0CB34),
    "paf_ctor_feedback_fields": (0x52F0B574, 0x52F0B5A4),
    "mode1_later_resets_accumulator": (0x52F0D938, 0x52F0D958),
    "pulse_ctor_a88_initialization": (0x52F0E074, 0x52F0E094),
    "feedback_reader_uxth_return": (0x53178344, 0x5317834C),
    "other_class_halfword_56_store_excluded": (0x52F0E3EC, 0x52F0E3F8),
})
shared.CODE = CODE
shared.REGS.update(r2=R2, r3=R3, r5=R5, r6=R6)


def u16(n):
    return n & 0xFFFF


def s16(n):
    return (u16(n) ^ 0x8000) - 0x8000


class Replay(previous.Replay):
    def __init__(self, image, model, clobber):
        super().__init__(image, model, clobber)
        self.after_sxth = None
        self.bucket_input = None
        self.table_reads = []

    def hook(self, u, pc, size, data):
        if pc == 0x52F0C7E0:
            self.after_sxth = s16(u.reg_read(R0))
            assert u.reg_read(R0) == (self.after_sxth & 0xFFFFFFFF)
        if pc == 0x52F0C81C:
            self.bucket_input = u.reg_read(R3)
        if pc in (0x52F0C850, 0x52F0C980, 0x52F0C984, 0x52F0C9A8):
            r7 = u.reg_read(R7)
            address = u.reg_read(R1) + u.reg_read(R3) if pc == 0x52F0C984 else r7 + 0x70
            assert TABLE <= address < TABLE + 0x74
            self.table_reads.append([pc, address, self.read(address, 2)])
        super().hook(u, pc, size, data)

    def numeric_entry(self, label, entry, numeric_input, end):
        # At this explicit seam r0 is a test number, not an emulated load or return.
        # Preserve the original frame and callee-saved registers from the first slice.
        u = self.cpu
        self.stopped, self.stop_before = None, (end,)
        u.reg_write(R0, numeric_input)
        for reg, value in zip(shared.VOLATILE, (0xAA11, 0xAA22, 0xAA33, 0xAA44)):
            u.reg_write(reg, value)
        cpsr = u.reg_read(arm.UC_ARM_REG_CPSR)
        u.reg_write(arm.UC_ARM_REG_CPSR, cpsr ^ 0xF0000000)
        u.emu_start(entry, shared.RETURN, count=500)
        assert self.stopped is not None and u.reg_read(PC) == end, (label, hex(u.reg_read(PC)))
        self.stages.append([label, entry, end])

    def feedback(self, case, raw, old, previous_sample, parameter,
                 offset=0, override=0, phase=0, polarity=0):
        assert 0 <= raw <= 0xFFFF and polarity in (0, 1)
        timer, device = self.setup()
        for field, value in ((0x52, old), (0x58, previous_sample), (0x56, offset),
                             (0x68, override), (0x5A, 0xA55A), (0x5C, 0xA55C)):
            self.put(PAF + field, value, 2)
        self.put(PAF+0x42, polarity, 1)
        self.put(PAF+0x43, phase, 1)
        self.stage("original_request3_to_pre_feedback_read", REQUEST3_ENTRY,
                   stop_before=(COUNT_READ,), r0=PAF, r1=parameter, r2=polarity, r3=3)
        assert self.stopped[1] == timer and self.cpu.reg_read(R3) == 0x1E000024
        assert self.cpu.reg_read(R4) == PAF and self.cpu.reg_read(R5) == parameter
        assert self.cpu.reg_read(R6) == previous_sample
        end = READ_1 if phase else READ_0
        self.numeric_entry("independent_post_feedback_numeric_slice", FEEDBACK_ENTRY, raw, end)
        signed = s16(raw)
        accumulator = u16(old + previous_sample - signed)
        assert self.after_sxth == signed and self.read(PAF + 0x52, 2) == accumulator
        assert self.read(PAF + 0x58, 2) == previous_sample
        observed = self.points[0x531785F8]
        if phase:
            doubled = u16(2 * parameter)
            emitted = u16(-doubled if polarity else doubled)
            assert self.points[0x52F0C940] == [PAF, 1, doubled]
            assert observed == [SERVICE, 1, emitted, 0]
            assert self.points[0x532726E8] == [device]
            assert self.cpu.reg_read(R0) == 0x1E002020
            assert self.bucket_input is None and not self.table_reads
            assert [self.read(PAF+x, 2) for x in (0x5A, 0x5C)] == [0xA55A, 0xA55C]
            bucket = None
            address = 0x1E00202C
        else:
            gate_input = u16((0 if accumulator & 0x8000 else accumulator) + parameter)
            bucket = max(0, (gate_input - 1) // 100)
            default_addr = TABLE + 0x70 + 2 * polarity
            table_addr = TABLE + 4 * bucket + 2 * polarity
            if override or bucket > 28:
                assert self.bucket_input is None if override else self.bucket_input == gate_input
                expected_reads = [default_addr]
                base = override if override else 300
            else:
                assert self.bucket_input == gate_input
                expected_reads = [default_addr, table_addr]
                base = 100 if bucket == 0 else 200 if bucket <= 4 else 300
            assert [address for _, address, _ in self.table_reads] == expected_reads
            assert self.read(PAF+0x5A, 2) == u16(base + offset) and self.read(PAF+0x5C, 2) == 300, (
                case, self.read(PAF+0x5A, 2), self.read(PAF+0x5C, 2), base, offset, self.table_reads)
            assert self.points[0x52F0C87C] == [PAF, 0, parameter] and observed == [SERVICE, 0, parameter, 1]
            assert self.points[0x5326D4EC] == [timer] and self.cpu.reg_read(R2) == 0x1E000020
            address = 0x1E000020
        return self.finish(case, {"input_u16": raw, "old_accumulator_u16": old, "previous_sample_u16": previous_sample,
                                  "parameter_u16": parameter, "offset_u16": offset, "override_u16": override,
                                  "phase_byte": phase, "polarity": polarity},
                           {"signed_feedback": signed, "accumulator_u16": accumulator,
                            "temporary_clamped_u16": 0 if accumulator & 0x8000 else accumulator,
                            "observed_bucket_input_u16": self.bucket_input,
                            "calculated_bucket_before_fallback": bucket,
                            "output_5a_u16": self.read(PAF+0x5A, 2), "output_5c_u16": self.read(PAF+0x5C, 2),
                            "table_reads_pc_address_u16": self.table_reads, "first_service_args": observed,
                            "first_unread_address": address})

    def local_caller(self, case, raw, baseline, target, busy=0, phase=0, polarity=0):
        timer, _ = self.setup()
        self.put(PEER+0xA88, baseline)
        self.put(PEER+0x2E, target, 2)
        self.put(PAF+0x1A, busy, 1)
        self.put(PAF+0x42, polarity, 1)
        self.put(PAF+0x43, phase, 1)
        self.stage("original_local_caller_pre_feedback", 0x52F0C9B0, stop_before=(COUNT_READ,) if not phase else
                   (0x53178788,), r0=PAF)
        if phase:
            # Establish a separate local frame at the common count site; do not return from the optional service.
            self.numeric_entry("count_prefix_after_optional_service_not_run", 0x52F0C9E4, 0, COUNT_READ)
        assert self.stopped[1] == timer and self.cpu.reg_read(R3) == 0x1E000024
        assert self.cpu.reg_read(R4) == PAF
        reduced = u16(baseline - raw)
        remainder = s16(target - reduced)
        end = (CALLER_COMPLETE if busy else CALLER_ALTERNATE if phase not in (0, 4)
               else REQUEST3_ENTRY if remainder > 0 else CALLER_COMPLETE)
        self.numeric_entry("independent_local_caller_numeric_slice", CALLER_ENTRY, raw, end)
        assert self.read(PEER+0xF8) == (remainder & 0xFFFFFFFF)
        request_args = None
        if end == REQUEST3_ENTRY:
            request_args = [self.cpu.reg_read(reg) for reg in (R0, R1, R2, R3)]
            assert request_args == [PAF, remainder, polarity, 3]
        return self.finish(case, {"input_u16": raw, "pulse_baseline_a88_u32": baseline, "target_2e_u16": target,
                                  "paf_1a_byte": busy, "phase_byte": phase, "polarity": polarity},
                           {"difference_u16": reduced, "remainder_s16": remainder,
                            "stored_pulse_f8_u32": self.read(PEER+0xF8), "request3_args": request_args})

    def finish(self, case, fixtures, measurements):
        mapped = shared.digest(self.cpu.mem_read(shared.BASE, len(self.image)))
        assert mapped == shared.input_guard.RTOS_SHA
        return {"case": case, "numeric_fixtures": fixtures, "measured_or_validated": measurements,
                "boundary_pc": self.cpu.reg_read(PC), "stages_name_entry_stop": self.stages,
                "control_points_pc_args": {hex(pc): args for pc, args in self.points.items()},
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
    feedback = (
        # name, numeric u16, old accumulator, previous sample, parameter, optional fields
        ("negative_counter_ffff", 0xFFFF, 99, 0, 1),
        ("positive_counter_0001", 1, 99, 0, 1),
        ("signed_counter_7fff", 0x7FFF, 0, 0, 101),
        ("signed_counter_8000", 0x8000, 0, 0, 101),
        ("wrap_negative_to_zero", 0xFFFF, 0xFFFF, 0, 0),
        ("accumulator_7fff_unclamped", 0, 0, 0x7FFF, 0),
        ("accumulator_8000_clamp_temporary", 0, 0, 0x8000, 0),
        ("parameter_sum_wraps", 0, 0x7FFF, 0, 0x8001),
        ("bucket_last_2900", 0, 2800, 0, 100, 4),
        ("bucket_overflow_2901", 0, 2800, 0, 101, 4),
        ("lookup_offset_wraps", 0, 100, 0, 1, 0xFFFF),
        ("override_bypasses_lut", 0, 100, 0, 1, 4, 1),
        ("phase1_double_wrap", 1, 0, 0, 0x8001, 0, 0, 1),
        ("phase4_double_and_negate", 1, 0, 0, 0xFFFF, 0, 0, 4, 1),
    )
    callers = (
        ("caller_remainder_positive", 100, 120, 21),
        ("caller_remainder_zero", 100, 120, 20),
        ("caller_remainder_negative", 100, 120, 19),
        ("caller_baseline_wrap", 0xFFFF, 0x00010000, 2),
        ("caller_7fff_positive", 0, 0, 0x7FFF),
        ("caller_8000_negative", 0, 0, 0x8000),
        ("caller_busy_bypasses_positive", 100, 120, 21, 1),
        ("caller_phase4_accepts_positive", 100, 120, 21, 0, 4, 1),
        ("caller_phase1_alternate", 100, 120, 21, 0, 1, 1),
    )
    def run(model, clobber):
        return ([Replay(image, model, clobber).feedback(*case) for case in feedback]
                + [Replay(image, model, clobber).local_caller(*case) for case in callers])
    rows = run(arm.UC_CPU_ARM_CORTEX_A7, False)
    for model in (arm.UC_CPU_ARM_CORTEX_A7, arm.UC_CPU_ARM_CORTEX_A15):
        assert rows == run(model, True)
    ranges = {kind: {name: {"start": a, "end_exclusive": z, "rtos_offset": a-shared.BASE,
                           "decoded_offset": a-shared.BASE+shared.input_guard.RTOS_OFFSET,
                           "sha256": shared.digest(image[a-shared.BASE:z-shared.BASE])} for name, (a, z) in spans.items()}
              for kind, spans in (("code", CODE | {"rtti_thumb_strcmp_prefix": previous.udc.THUMB}),
                                  ("data", DATA), ("static_only", STATIC))}
    result = {"rtos_sha256": shared.input_guard.RTOS_SHA, "decoded_sha256": shared.input_guard.DECODED_SHA,
              "dependency_lf_sha256": PREVIOUS_SHA, "unicorn_version": uc.__version__,
              "cpu_variants_exact": ["Cortex-A7 baseline", "Cortex-A7 volatile/NZCV clobber",
                                     "Cortex-A15 volatile/NZCV clobber"],
              "ranges": ranges, "cases": rows}
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
