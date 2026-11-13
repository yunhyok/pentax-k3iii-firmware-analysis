"""Replay bounded K-3 III Motor/Pulse field observations on original RTOS instructions."""

if not __debug__:
    raise SystemExit("Run without -O: replay requires assertions")

import argparse
import json
import os
import types
from hashlib import sha256
from pathlib import Path

from unicorn import (
    Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
    UC_MODE_ARM, UC_PROT_EXEC, UC_PROT_READ, __version__,
)
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
    UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
    UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10,
    UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_SP,
    UC_CPU_ARM_CORTEX_A7, UC_CPU_ARM_CORTEX_A15,
)

ROOT = Path(__file__).resolve().parent
INPUT_HELPER = "6796dc7821f84b13ddf2545c569568928eec24a130e27d519d70f75326e0ba12"
NATIVE_SHA256 = "7b338c7f1abd6314aae7b6324799f65105dec8fd4029e9c207b334de1491af24"
FLAG_SHA256 = "5180258f9a0990f8e9bd168cb90890a6cf022170bcdab8c2a2b4beedd122091d"
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
        UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
        UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12)
FACTORY, MOTOR, PULSE, DEBUG, INFO, PARAM, LENS, STACK, STOP = (
    0x10000100, 0x10000200, 0x10001000, 0x10002100, 0x10002300, 0x10002500,
    0x10003000, 0x10006000, 0x20000000,
)
RAM = 0x10000000
RAM_SIZE = 0x7000
ACCESSOR, CONFIG, CONFIG_SOURCE = 0x10005000, 0x10005100, 0x10005300
VIEWS = {
    "factory": (FACTORY, 0x14), "motor": (MOTOR, 0xec), "pulse": (PULSE, 0xab4),
    "debug": (DEBUG, 0xb8), "lens_info": (INFO, 0x38), "parameter": (PARAM, 0x36),
    "lens": (LENS, 0x1990), "stack": (STACK - 0x100, 0x108),
    "sensor_accessor": (ACCESSOR, 0xc8), "integral_config": (CONFIG, 0x118),
    "config_source": (CONFIG_SOURCE, 0x13f + 1),
}
CODE = {
    "motor_ctor": (0x52F0B4B0, 0x52F0B5F8),
    "pulse_ctor": (0x52F0DEC8, 0x52F0E0E0),
    "debug_ctor": (0x52CB4714, 0x52CB4810),
    "info_ctor": (0x52F061E4, 0x52F0625C),
    "motor_bind_pulse": (0x52F0B45C, 0x52F0B480),
    "debug_bind_motor": (0x52CB4600, 0x52CB4624),
    "info_bind_motor": (0x52F06184, 0x52F061A8),
    "info_bind_pulse": (0x52F061B0, 0x52F061D4),
    "reset_prefix": (0x52F0B674, 0x52F0B6C0),
    "debug_route": (0x52CB4C28, 0x52CB4CD8),
    "debug_motor_parameters": (0x52F0DC88, 0x52F0DCB0),
    "debug_motor_clear": (0x52F0DCBC, 0x52F0DCF4),
    "pulse_unsigned_min_store": (0x52F0E3D0, 0x52F0E408),
    "pulse_lens_adjustment": (0x52F0E2F4, 0x52F0E34C),
    "masked_lens_word": (0x52EFF640, 0x52EFF65C),
    "lens_parameter_byte": (0x52F02EE4, 0x52F02EEC),
    "lens_info_pulse_use": (0x52F0671C, 0x52F0675C),
    "pulse_ratio": (0x52F0E1C4, 0x52F0E200),
    "unsigned_division_nonzero": (0x526A8330, 0x526A8340),
    "integral_config_copy_field": (0x52CEAC04, 0x52CEAC14),
    "integral_config_read_field": (0x52CAAD00, 0x52CAAD0C),
}
ROM_DATA = {
    "motor_vptr_literal": (0x52F0B5F8, 0x52F0B5FC),
    "pulse_vptr_literal": (0x52F0E0E0, 0x52F0E0E4),
    "debug_vptr_literal": (0x52CB4810, 0x52CB4814),
    "info_vptr_literal": (0x52F0625C, 0x52F06260),
    "stack_canary": (0x53CBB4C0, 0x53CBB4C4),
}
STATIC = {
    "factory_allocates_and_stores_objects": (0x52F08C74, 0x52F08CD0),
    "factory_getter": (0x52F08D80, 0x52F08DF4),
    "debug_factory_object": (0x52CA4290, 0x52CA42B4),
    "debug_request_forwarder": (0x52C7802C, 0x52C78054),
    "debug_bind_warm_getter": (0x52CB45FC, 0x52CB4600),
    "debug_readback": (0x52CB4814, 0x52CB4840),
    "lens_info_factory_object": (0x52F02898, 0x52F028A8),
    "pulse_lens_and_parameter_binder": (0x52F0DDFC, 0x52F0DE80),
    "lens_info_binders": (0x52F06180, 0x52F061D8),
    "lens_info_motor_call": (0x52F06514, 0x52F06564),
    "motor_reset_preceding_service_and_tail": (0x52F0BA34, 0x52F0BA7C),
    "motor_reset_first_unexecuted_call": (0x52F0B6C0, 0x52F0B6C4),
    "debug_first_unexecuted_call": (0x52F0DCB0, 0x52F0DCB4),
    "pulse_gate_and_prior_calls": (0x52F0E34C, 0x52F0E3D0),
    "pulse_alternate_path": (0x52F0E408, 0x52F0E430),
    "pulse_caller_a": (0x52CB19C4, 0x52CB19F8),
    "pulse_caller_b": (0x52CB31F8, 0x52CB3244),
    "pulse_caller_config_read": (0x52CAAD00, 0x52CAAD0C),
    "control_pulse_binder": (0x52CAD930, 0x52CAD94C),
    "control_config_binder": (0x52CAD8D8, 0x52CAD904),
    "control_config_factory_slot": (0x52CA41E8, 0x52CA420C),
    "sensor_accessor_constructor": (0x52CAA6A0, 0x52CAA748),
    "sensor_accessor_rtti": (0x53889308, 0x53889310),
    "sensor_accessor_name": (0x538892F4, 0x53889308),
    "sensor_accessor_typeinfo_pointer": (0x5388932C, 0x53889330),
    "sensor_accessor_bind_integral_config": (0x52CAA280, 0x52CAA2E4),
    "integral_config_factory_array": (0x52CA4524, 0x52CA4588),
    "integral_config_constructor": (0x52CEA838, 0x52CEA988),
    "integral_config_typeinfo_pointer": (0x5389C454, 0x5389C458),
    "integral_config_rtti": (0x5389C490, 0x5389C498),
    "integral_config_name": (0x5389C47C, 0x5389C490),
    "integral_config_full_copy": (0x52CEAB3C, 0x52CEAC34),
    "integral_config_call_site": (0x52CF1850, 0x52CF1878),
    "possible_source_98_producer": (0x52CF0248, 0x52CF0258),
    "motor_request3_test": (0x52F0C808, 0x52F0C81C),
    "motor_request3_read": (0x52F0C988, 0x52F0C9B0),
    "motor_vtable": (0x538F25C4, 0x538F25E0),
    "motor_rtti_name": (0x538F2668, 0x538F2671),
    "motor_rtti": (0x538F2674, 0x538F267C),
    "pulse_vtable": (0x538F26B4, 0x538F26CC),
    "pulse_rtti": (0x538F26A4, 0x538F26AC),
    "pulse_rtti_name": (0x538F26D0, 0x538F26D9),
    "debug_vtable": (0x5388B3EC, 0x5388B404),
    "debug_rtti_name": (0x5388B408, 0x5388B41A),
    "debug_rtti": (0x5388B41C, 0x5388B424),
    "info_vtable": (0x538F1FB4, 0x538F1FCC),
    "info_rtti_name": (0x538F1F74, 0x538F1F82),
    "info_rtti": (0x538F1F84, 0x538F1F8C),
}


def read_helper():
    path = ROOT / "verify_af_packet_8902.py"
    code = path.read_bytes().replace(b"\r\n", b"\n")
    if sha256(code).hexdigest() != INPUT_HELPER:
        raise ValueError("verify_af_packet_8902.py SHA-256 mismatch")
    helper = types.ModuleType("verified_carrier")
    exec(compile(code, str(path), "exec", dont_inherit=True), vars(helper))
    return helper


def json_bytes(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")


def verify_witness(value, expected, label):
    if sha256(json_bytes(value)).hexdigest() != expected:
        raise ValueError(f"{label} SHA-256 mismatch")


def interval(start, size, lower, end):
    return lower <= start and start + size <= end


class Replay:
    def __init__(self, image, base, model, poison):
        self.image = image
        self.base = base
        self.poison = poison
        self.cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.cpu.ctl_set_cpu_model(model)
        mapped = (len(image) + 0xfff) & ~0xfff
        self.cpu.mem_map(base, mapped)
        self.cpu.mem_write(base, image)
        self.cpu.mem_protect(base, mapped, UC_PROT_READ | UC_PROT_EXEC)
        self.cpu.mem_map(RAM, RAM_SIZE)
        self.cpu.hook_add(UC_HOOK_CODE, self.on_code)
        self.cpu.hook_add(UC_HOOK_MEM_READ, self.on_read)
        self.cpu.hook_add(UC_HOOK_MEM_WRITE, self.on_write)

    def view(self, address, size):
        for name, (start, length) in VIEWS.items():
            if interval(address, size, start, start + length):
                return name, address - start
        raise AssertionError(f"unexpected RAM access {address:#x}/{size}")

    def on_code(self, cpu, address, size, _):
        assert size == 4 and any(interval(address, size, *CODE[k]) for k in self.allowed), hex(address)
        offset = address - self.base
        instruction = bytes(cpu.mem_read(address, size))
        assert instruction == self.image[offset:offset + size]
        self.trace.update(address.to_bytes(4, "little") + instruction)
        self.steps += 1

    def on_read(self, cpu, _access, address, size, _value, _):
        if any(interval(address, size, *span) for span in ROM_DATA.values()):
            return
        name, offset = self.view(address, size)
        if name != "stack":
            self.reads.append([hex(cpu.reg_read(UC_ARM_REG_PC)), name, hex(offset), size])

    def on_write(self, cpu, _access, address, size, value, _):
        name, offset = self.view(address, size)
        assert name in self.writable, (name, hex(offset))
        if name != "stack":
            self.writes.append([hex(cpu.reg_read(UC_ARM_REG_PC)), name, hex(offset), size, value])

    def word(self, address, size=4):
        return int.from_bytes(self.cpu.mem_read(address, size), "little")

    def put(self, address, value, size=4):
        self.cpu.mem_write(address, value.to_bytes(size, "little"))

    def run(self, code, *, stop=STOP, stack=STACK, writable=(), **regs):
        self.allowed = code
        self.writable = set(writable) | {"stack"}
        self.trace = sha256()
        self.steps = 0
        self.writes = []
        self.reads = []
        for index, reg in enumerate(REGS):
            self.cpu.reg_write(reg, (0xA1B2C3D4 ^ index * 0x01010101) if self.poison else 0)
        self.cpu.reg_write(UC_ARM_REG_CPSR, 0xa0000013 if self.poison else 0x13)
        self.cpu.reg_write(UC_ARM_REG_SP, stack)
        self.cpu.reg_write(UC_ARM_REG_LR, STOP)
        for name, value in regs.items():
            self.cpu.reg_write(REGS[int(name[1:])], value)
        start = CODE[code[0]][0]
        self.cpu.emu_start(start, stop, count=8192)
        assert self.cpu.reg_read(UC_ARM_REG_PC) == stop
        return {"entry": hex(start), "stop_before": hex(stop), "instructions": self.steps,
                "pc_and_original_instruction_sha256": self.trace.hexdigest(),
                "writes": self.writes}

    def setup(self):
        self.cpu.mem_write(RAM, b"\xa5" * RAM_SIZE)
        ctor = self.run(("motor_ctor",), writable=("motor",), r0=MOTOR)
        self.run(("pulse_ctor",), writable=("pulse",), r0=PULSE)
        self.run(("debug_ctor",), writable=("debug",), r0=DEBUG)
        self.run(("info_ctor",), writable=("lens_info",), r0=INFO)
        assert [self.word(address) for address in (MOTOR, PULSE, DEBUG, INFO)] == [
            0x538F25C8, 0x538F26B8, 0x5388B3F0, 0x538F1FB8,
        ]
        assert [self.word(MOTOR + offset, 2) for offset in (0x56, 0x68)] == [0, 0]
        self.put(FACTORY + 0xc, MOTOR)
        self.put(FACTORY + 0x10, PULSE)
        for name, receiver, source_reg, stop, write_view, offset, expected in (
            ("motor_bind_pulse", MOTOR, "r9", 0x52F0B480, "motor", 0x14, PULSE),
            ("debug_bind_motor", DEBUG, "r0", 0x52CB4624, "debug", 0x1c, MOTOR),
            ("info_bind_motor", INFO, "r0", 0x52F061A8, "lens_info", 0x18, MOTOR),
            ("info_bind_pulse", INFO, "r0", 0x52F061D4, "lens_info", 0x1c, PULSE),
        ):
            self.run((name,), stop=stop, writable=(write_view,), r6=receiver, **{source_reg: FACTORY})
            assert self.word(receiver + offset) == expected
        return ctor

    def motor_fields(self):
        return [self.word(MOTOR + offset, 2) for offset in (0x56, 0x68)]

    def set_motor_sentinels(self):
        self.put(MOTOR + 0x56, 0xc345, 2)
        self.put(MOTOR + 0x68, 0x8137, 2)

    def check_motor_sentinels(self):
        assert self.motor_fields() == [0xc345, 0x8137]
        return self.motor_fields()

    def cases(self):
        ctor = self.setup()
        assert [row for row in ctor["writes"] if row[2] in ("0x56", "0x68")] == [
            ["0x52f0b57c", "motor", "0x56", 2, 0], ["0x52f0b5a0", "motor", "0x68", 2, 0],
        ]
        ctor["writes"] = [row for row in ctor["writes"] if row[2] in ("0x56", "0x68")]
        ctor.update(case="constructor_dirty_allocation", fill_byte=0xa5, motor_56_68=self.motor_fields())
        result = [ctor]
        self.set_motor_sentinels()
        self.put(MOTOR + 0x08, 0x19000000)  # deliberately unmapped service object
        self.put(MOTOR + 0x25, 0x91, 1)
        self.put(MOTOR + 0x54, 0xeeee, 2)
        self.put(PULSE + 0x2e, 0xbbee, 2)
        row = self.run(("reset_prefix",), stop=0x52F0B6C0, writable=("motor", "pulse"), r0=MOTOR)
        args = [self.cpu.reg_read(reg) for reg in REGS[:3]]
        assert args == [0x19000000, 1, 0x91]
        assert self.word(MOTOR + 0x54, 2) == self.word(PULSE + 0x2e, 2) == 0
        row.update(case="reset_prefix", motor_56_68=self.check_motor_sentinels(), unexecuted_call_args=args)
        result.append(row)

        for name, packet, active, expected in (
            ("debug_packed_set", 0x9abc1232, False, (0x9abc, 0x123)),
            ("debug_bit1_clear_inactive", 0x9abc1230, False, (0x1111, 0x2222)),
            ("debug_bit1_clear_active_no_handle", 0x9abc1230, True, (0, 0)),
        ):
            self.setup()
            self.set_motor_sentinels()
            self.put(MOTOR + 0x33, int(active), 1)
            self.put(MOTOR + 0x78, 0x1111, 2)
            self.put(MOTOR + 0x7a, 0x2222, 2)
            assert self.word(DEBUG + 0x2c, 1) == 0
            assert self.word(MOTOR + 0x74) == 0
            row = self.run(
                ("debug_route", "debug_motor_parameters", "debug_motor_clear"),
                stop=0x52F0DCB0 if packet & 2 else STOP,
                writable=("debug", "motor"), r0=DEBUG, r1=packet,
            )
            observed = [self.word(MOTOR + offset, 2) for offset in (0x78, 0x7a)]
            assert observed == list(expected)
            assert self.word(MOTOR + 0x33, 1) == int(bool(packet & 2))
            row.update(case=name, input_request_word=packet, initial_motor_active=active,
                       motor_78_7a=observed, motor_56_68=self.check_motor_sentinels())
            result.append(row)

        for name, caller, limit, lens_word, lens_byte, expected, request in (
            ("pulse_caller_smaller", 320, 1024, 0, 0xf0, 320, 400),
            ("pulse_limit_smaller_wrong_byte", 1024, 320, 0x000dafc0, 0xef, 320, 600),
            ("pulse_masked_match_and_f0", 1024, 320, 0xffcdafea, 0xf0, 310, 1000),
            ("pulse_zero_limit", 320, 0, 0x000dafc0, 0xf0, 0, 1000),
            ("pulse_ratio_saturates", 2, 1, 0, 0, 1, 1000),
        ):
            self.setup()
            self.set_motor_sentinels()
            self.put(PULSE + 4, LENS)
            self.put(PULSE + 0xc, PARAM)
            self.put(PULSE + 0x40, 600, 2)
            self.put(PULSE + 0x56, 0x7777, 2)
            self.put(PARAM + 0x34, limit, 2)
            self.put(LENS + 0x198c, lens_word)
            self.put(LENS + 0x167, lens_byte, 1)
            self.put(STACK - 0x30, self.word(0x53CBB4C0))
            self.put(ACCESSOR + 0x10, CONFIG)
            self.put(CONFIG_SOURCE + 0x98, caller, 2)
            copy = self.run(("integral_config_copy_field",), stop=0x52CEAC14,
                            writable=("integral_config",), r4=CONFIG, r5=CONFIG_SOURCE, r8=0)
            assert copy["writes"] == [
                ["0x52ceac08", "integral_config", "0xf0", 4, 0],
                ["0x52ceac10", "integral_config", "0xec", 2, caller],
            ]
            accessor = self.run(("integral_config_read_field",), r0=ACCESSOR)
            assert ["0x52caad04", "integral_config", "0xec", 2] in self.reads
            argument = self.cpu.reg_read(UC_ARM_REG_R0)
            assert argument == caller
            row = self.run(
                ("pulse_unsigned_min_store", "pulse_lens_adjustment", "masked_lens_word",
                 "lens_parameter_byte"),
                stop=0x52F0E3F8, stack=STACK - 0x80, writable=("pulse",),
                r4=PULSE, r5=0x53CBB4C0, r6=argument, r11=STACK,
            )
            assert self.word(PULSE + 0x56, 2) == expected
            assert row["writes"] == [["0x52f0e3f4", "pulse", "0x56", 2, expected]]
            row.update(case=name, staged_caller_u16=caller, staged_parameter_limit_u16=limit,
                       staged_lens_word=lens_word, staged_lens_byte=lens_byte, pulse_56=expected,
                       motor_56_68=self.check_motor_sentinels())
            row["separate_config_copy_and_read"] = {
                "supplied_source_98": caller, "native_copy_prefix": copy, "native_accessor": accessor,
                "transferred_argument": argument,
            }
            self.put(MOTOR + 0x1a, int(bool(lens_word)), 1)
            consumer = self.run(
                ("lens_info_pulse_use", "pulse_ratio", "unsigned_division_nonzero"),
                stop=0x52F0675C, r5=INFO, r7=request,
            )
            assert ["0x52f06734", "pulse", "0x56", 2] in self.reads
            assert all(not (read[1] == "motor" and read[2] == "0x56") for read in self.reads)
            numerator_u16 = (600 - request) & 0xffff
            ratio = min(0xffff, (numerator_u16 << 8) // expected) if expected else 0
            assert self.cpu.reg_read(UC_ARM_REG_R0) == ratio, (name, ratio)
            consumer.update(staged_request=request, staged_pulse_40=600,
                            motor_1a=int(bool(lens_word)), reads=self.reads,
                            numerator_u16=numerator_u16, divisor=expected, ratio=ratio)
            row["separate_lens_info_consumer"] = consumer
            result.append(row)
        return result

    def flag_controls(self, model, poison):
        """Reproduce the independent paired witness without changing the ten native fixtures."""
        self.setup()
        self.put(PULSE + 0x40, 600, 2)
        self.put(PULSE + 0x56, 1024, 2)
        rows = []
        for request in (0x8123, 0x12348123, 0xffff, 0x12340001):
            pair = []
            for flag, branch_pc in ((0, "0x52f06744"), (1, "0x52f06748")):
                self.put(MOTOR + 0x1a, flag, 1)
                trace = self.run(("lens_info_pulse_use", "pulse_ratio", "unsigned_division_nonzero"),
                                 stop=0x52F0675C, r5=INFO, r7=request)
                assert trace["writes"] == []
                assert [branch_pc, "pulse", "0x40", 2] in self.reads
                result = self.cpu.reg_read(UC_ARM_REG_R0)
                assert result == (((600 - request) & 0xffff) << 8) // 1024
                pair.append({"flag": flag, "ratio": result, "reads": self.reads})
            rows.append({"cpu": model, "poison": poison, "request": request,
                         "pulse_40": 600, "pulse_56": 1024, "pair": pair})
        return rows

    def mapped_sha(self):
        return sha256(self.cpu.mem_read(self.base, len(self.image))).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("carrier", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--compare", type=Path, help="require exact public JSON bytes before creating output")
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        parser.error("output already exists")
    helper = read_helper()
    image = helper.read_image(args.carrier)
    if __version__ != "2.1.4":
        raise ValueError("expected Unicorn 2.1.4")
    original_sha = sha256(image).hexdigest()
    for vptr, name in (
        (0x538F25C8, b"8PafMotor"), (0x538F26B8, b"8PafPulse"),
        (0x5388B3F0, b"15PafControlDebug"), (0x538F1FB8, b"11PafLensInfo"),
        (0x53889330, b"17PafSensorAccessor"),
        (0x5389C458, b"17PafIntegralConfig"),
    ):
        typeinfo = int.from_bytes(image[vptr - helper.BASE - 4:vptr - helper.BASE], "little")
        name_pointer = int.from_bytes(image[typeinfo + 4 - helper.BASE:typeinfo + 8 - helper.BASE], "little")
        start = name_pointer - helper.BASE
        assert image[start:start + len(name) + 1] == name + b"\0"
    records = None
    flags = []
    for model, poison in (
        (UC_CPU_ARM_CORTEX_A7, False), (UC_CPU_ARM_CORTEX_A7, True),
        (UC_CPU_ARM_CORTEX_A15, True),
    ):
        replay = Replay(image, helper.BASE, model, poison)
        current = replay.cases()
        assert replay.mapped_sha() == original_sha
        if records is None:
            records = current
        else:
            assert json_bytes(records) == json_bytes(current)
        flags.extend(replay.flag_controls(model, poison))
        assert replay.mapped_sha() == original_sha
    spans = {**CODE, **ROM_DATA, **STATIC}
    assert all(helper.BASE <= start < end <= helper.BASE + len(image) for start, end in spans.values())
    pins = {name: {"start": hex(start), "end_exclusive": hex(end),
                   "sha256": sha256(image[start - helper.BASE:end - helper.BASE]).hexdigest()}
            for name, (start, end) in spans.items()}
    result = {
        "rtos_sha256": original_sha, "decoded_sha256": helper.DECODED_SHA,
        "rtos_offset_in_decoded": hex(helper.RTOS_OFFSET), "rtos_base": hex(helper.BASE),
        "verified_input_helper_lf_sha256": INPUT_HELPER,
        "unicorn_version": __version__, "cpu_controls": ["A7", "A7 poisoned registers/NZCV", "A15 poisoned registers/NZCV"],
        "case_count": len(records), "service_stubs": 0, "mapped_original_unchanged": True,
        "motor_56_68_nonzero_writer_identified": False,
        "scope": {
            "carrier": "K-3 III 2.20, decoded RTOS, little-endian original A32",
            "fixtures": "object allocations, factory slots, binder entry register/stack state, reset service pointer, request word, handle-free clear state, config source halfword and accessor pointer, parameter/lens memory, separate Pulse and LensInfo arithmetic entries",
            "native": "four constructors, four binder prefixes, local reset, debug request set/clear prefix, staged config copy/accessor, selected Pulse store path and distinct LensInfo ratio",
            "stops": "before the reset service call and debug handle creation; selected Pulse write ends before canary comparison; no earlier Pulse branch/service execution",
            "unresolved": "PafMotor+0x56/+0x68 nonzero producer, persistence, physical interpretation",
        },
        "source_ranges": pins, "cases": records,
    }
    verify_witness(result, NATIVE_SHA256, "Complete native witness")
    flag_control = {
        "frozen_replay_sha256": NATIVE_SHA256,
        "checked_original_ranges": len(pins),
        "separate_control": "Same request with Motor+0x1a 0/1 in original LensInfo consumer, no service calls or writes to object RAM",
        "pairs": flags,
    }
    verify_witness(flag_control, FLAG_SHA256, "Complete LensInfo flag witness")
    result["native_witness_sha256"] = NATIVE_SHA256
    result["lens_info_flag_witness_sha256"] = FLAG_SHA256
    result["lens_info_flag_control"] = flag_control
    payload = json_bytes(result)
    if args.compare is not None and args.compare.read_bytes() != payload:
        raise ValueError("public result differs from --compare")
    with args.output.open("xb") as output:
        output.write(payload)
    print(sha256(payload).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
