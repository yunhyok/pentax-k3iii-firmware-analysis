"""Verify K-3 III PWM request dispatch and record packing on original A32 code."""
if not __debug__:
    raise SystemExit("Run without -O: replay requires assertions")

import argparse
import json
import os
import stat
import struct
import types
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HELPERS = {
    "verify_af_packet_8902.py": "6796dc7821f84b13ddf2545c569568928eec24a130e27d519d70f75326e0ba12",
    "verify_af_motor_fields.py": "d5fd3ffdb3dcf4f90a8bd5c49a7d6478c679253f7e00854046cd6117d1ac1cf8",
}
SPANS = {
    "motor_router": (0x52F0BBD4, 0x52F0BCB4),
    "caller_a": (0x52F0BCB4, 0x52F0BD1C),
    "caller_a_constant_source": (0x52F0C03C, 0x52F0C068),
    "caller_a_state_source": (0x52F0C454, 0x52F0C4E8),
    "caller_a_adaptive_source": (0x52F0C0D4, 0x52F0C210),
    "caller_b": (0x52F0BE18, 0x52F0BF14),
    "caller_b_scale": (0x52F0BD6C, 0x52F0BDEC),
    "caller_b_upstream_a": (0x52F0C080, 0x52F0C0A4),
    "caller_b_upstream_b": (0x52F0D40C, 0x52F0D590),
    "local_reset_service_wrapper": (0x52F0BDEC, 0x52F0BE18),
    "first_prior_service": (0x53179018, 0x53179058),
    "single_pack": (0x531780B8, 0x5317817C),
    "pair_pack": (0x5317912C, 0x53179264),
    "pair_apply_start": (0x53178CA4, 0x53178D00),
    "pair_apply_first_mmio_code": (0x5326C2C4, 0x5326C35C),
    "scratch_init": (0x5326C0F4, 0x5326C128),
    "overlay_merge": (0x5326CA24, 0x5326CB14),
    "derived_16_byte_record": (0x5326C7C4, 0x5326CA24),
    "motor_56_to_threshold": (0x52F0C988, 0x52F0C9B0),
    "motor_68_to_threshold": (0x52F0CDE4, 0x52F0CE3C),
    "threshold_branch_a": (0x52F0BF5C, 0x52F0BFA4),
    "threshold_branch_b": (0x52F0C4BC, 0x52F0C4E8),
}
CODE = {
    "motor_router": SPANS["motor_router"],
    "single_pack": (0x531780B8, 0x53178154),
    "pair_pack": (0x5317912C, 0x53179224),
    "scratch_init": SPANS["scratch_init"],
    "caller_a": (0x52F0BCB4, 0x52F0BCF0),
    "caller_b_after_reset": (0x52F0BE3C, 0x52F0BF14),
}


def load_helpers():
    captured = {name: (ROOT / name).read_bytes().replace(b"\r\n", b"\n") for name in HELPERS}
    for name, data in captured.items():
        if sha256(data).hexdigest() != HELPERS[name]:
            raise ValueError(f"{name} SHA-256 mismatch")
    modules = []
    for name, data in captured.items():
        module = types.ModuleType(Path(name).stem)
        module.__file__ = str(ROOT / name)
        exec(compile(data, module.__file__, "exec", dont_inherit=True), vars(module))
        modules.append(module)
    return modules


def signed32(value):
    return ((value + 0x80000000) & 0xffffffff) - 0x80000000


def expected_record(x, y, byte_a=0xff):
    def converted(value):
        wrapped = signed32(843 * value)
        q = abs(wrapped) // 1000
        return ((-q if wrapped < 0 else q) - 1) & 0xffff

    first, second = converted(x), converted(y)
    clipped = min(second, 0xffff - first)
    return [first + clipped, clipped], struct.pack("<HH8B", first + clipped, clipped,
                                                   *([0xff] * 6), byte_a, 0xff)


def read_regs(replay, motor, count=4):
    return [replay.cpu.reg_read(reg) for reg in motor.REGS[:count]]


def dispatch_cases(replay, motor, driver):
    results = []
    for motor_18, request, flag0, flag1, selected, stop in (
        (0, 0, 0, 1, 0, 0x531780B8),
        (0, 1, 0, 1, 1, 0x531780B8),
        (1, 0, 0, 1, 1, 0x531780B8),
        (1, 1, 0, 1, 0, 0x531780B8),
        (0, 2, 0, 0x100, 0, 0x52F0BC88),
        (1, 2, 0x101, 1, 1, 0x52F0BC54),
    ):
        replay.put(motor.MOTOR + 0x18, motor_18, 1)
        replay.put(motor.STACK, flag0)
        replay.put(motor.STACK + 4, flag1)
        # Unicorn 2.1.4 can reuse a translated target block across changing stop PCs.
        replay.cpu.ctl_flush_tb()
        observed = replay.run(("motor_router",), stop=stop, r0=motor.MOTOR, r1=request, r2=1000, r3=500)
        if stop == 0x531780B8:
            assert read_regs(replay, motor) == [driver, selected, 1000, 500]
        else:
            expected_start_flag = int(stop == 0x52F0BC54)
            assert read_regs(replay, motor, 3) == [driver, expected_start_flag, 0x6a]
            assert replay.cpu.reg_read(motor.REGS[5]) == selected
            assert [replay.cpu.reg_read(motor.REGS[i]) for i in (7, 6)] == [1000, 500]
        observed.update(motor_18_fixture=motor_18, request_fixture=request, stack_words=[flag0, flag1],
                        computed_selector=selected)
        assert not observed["writes"]
        results.append(observed)
    return results


def producer_cases(replay, motor):
    results = []
    for motor_42, incoming, selector in ((0, 20000, 1), (1, 308, 0)):
        replay.put(motor.MOTOR + 0x42, motor_42, 1)
        observed = replay.run(("caller_a",), stop=0x52F0BCF0,
                              r0=motor.MOTOR, r1=500, r2=incoming)
        assert read_regs(replay, motor) == [motor.MOTOR, selector, 3, incoming]
        sp = replay.cpu.reg_read(motor.UC_ARM_REG_SP)
        assert [replay.word(sp), replay.word(sp + 4)] == [1, 0]
        observed.update(caller="bcf0", motor_42_fixture=motor_42,
                        router_r1_r2_r3=[selector, 3, incoming], router_stack_words=[1, 0])
        results.append(observed)

    for byte_2c, word_54, state, expected, stop in (
        (1, 1000, 3, (1000, 500), 0x52F0BEA8),
        (1, 1001, 3, (500, 1000), 0x52F0BEA8),
        (1, 2000, 3, (500, 1000), 0x52F0BEA8),
        (1, 2001, 3, (500, 2000), 0x52F0BEA8),
        (0, 0, 1, (1000, 500), 0x52F0BEA8),
        (0, 0, 2, None, 0x52F0BEEC),
        (0, 0, 3, None, 0x52F0BF04),
        (0, 0, 5, (1000, 500), 0x52F0BE68),
    ):
        replay.put(motor.MOTOR + 0x2c, byte_2c, 1)
        replay.put(motor.MOTOR + 0x54, word_54, 2)
        observed = replay.run(("caller_b_after_reset",), stop=stop, r4=motor.MOTOR, r5=state,
                              r7=1, r8=0x101)
        observed.update(caller="bea8_post_reset_slice", motor_2c_fixture=byte_2c,
                        motor_54_fixture=word_54, state_fixture=state, selector_fixture=1,
                        second_stack_word_fixture=0x101)
        assert not observed["writes"]
        if stop == 0x52F0BEA8:
            assert read_regs(replay, motor) == [motor.MOTOR, 1, *expected]
            sp = replay.cpu.reg_read(motor.UC_ARM_REG_SP)
            assert [replay.word(sp), replay.word(sp + 4)] == [0, 0x101]
            observed.update(router_r1_r2_r3=[1, *expected], router_stack_words=[0, 0x101])
        elif expected is None:
            assert read_regs(replay, motor, 2) == [motor.MOTOR, 500]
            observed["adaptive_input_r1"] = 500
        else:
            assert tuple(replay.cpu.reg_read(motor.REGS[i]) for i in (5, 6)) == expected
            observed["local_store_pair_r5_r6"] = list(expected)
        results.append(observed)
    return results


def pack_cases(replay, motor, driver, slots):
    results = []
    for selector, x, y, pair in (
        (1, 3, 20000, False),
        (0, 1000, 500, False),
        (2, 1000, 500, False),
        (0, 0, 0, False),
        (1, 1, 2, False),
        (0, -3, -2, False),
        (1, 1000, 76742, False),
        (1, 1000, 76743, False),
        (1, 1000, 76744, False),
        (1, 0x7fffffff, -0x80000000, False),
        (1, 2547430, 2547431, False),
        (1, 3, 20000, True),
        (0, 3, 20000, True),
        (2, 1000, 76744, True),
        (1, 0, 1, True),
    ):
        code, stop = ("pair_pack", 0x53179224) if pair else ("single_pack", 0x53178154)
        observed = replay.run((code, "scratch_init"), stop=stop, r0=driver,
                              r1=selector, r2=x & 0xffffffff, r3=y & 0xffffffff)
        r0, r1, r2, r3 = read_regs(replay, motor)
        assert not observed["writes"]
        if pair:
            sp = replay.cpu.reg_read(motor.UC_ARM_REG_SP)
            second = replay.word(sp)
            assert (r0, r1, r2) == (driver, *(slots[::-1] if selector == 1 else slots))
            first_bytes = bytes(replay.cpu.mem_read(r3, 12))
            second_bytes = bytes(replay.cpu.mem_read(second, 12))
            halves, expected = expected_record(x, y, 1)
            assert first_bytes == bytes(4) + bytes([0xff]) * 6 + b"\x03\xff"
            assert second_bytes == expected
            observed.update(slot_order=["+0x30", "+0x2c"] if selector == 1 else ["+0x2c", "+0x30"],
                            records_hex=[first_bytes.hex(), second_bytes.hex()], value_halfwords=halves)
        else:
            assert r0 == slots[0 if selector == 1 else 1]
            actual = bytes(replay.cpu.mem_read(r1, 12))
            halves, expected = expected_record(x, y)
            assert actual == expected
            observed.update(selected_slot="+0x2c" if selector == 1 else "+0x30",
                            records_hex=[actual.hex()], value_halfwords=halves)
        observed.update(selector_fixture=selector, numeric_fixtures=[x, y])
        results.append(observed)
    return results


def replay_all(carrier, motor, image):
    base = carrier.BASE
    motor.CODE.update(CODE)
    runs = []
    for model, poison, driver, slots in (
        (motor.UC_CPU_ARM_CORTEX_A7, False, 0x10005500, (0x10005600, 0x10005700)),
        (motor.UC_CPU_ARM_CORTEX_A7, True, 0x10005780, (0x100056c0, 0x10005500)),
        (motor.UC_CPU_ARM_CORTEX_A15, True, 0x10005800, (0x10005580, 0x10005640)),
    ):
        motor.VIEWS["driver"] = (driver, 0x48)
        replay = motor.Replay(image, base, model, poison)
        replay.cpu.mem_write(motor.RAM, b"\xa5" * motor.RAM_SIZE)
        replay.put(motor.MOTOR + 8, driver)
        replay.put(motor.MOTOR + 0x25, 0x6a, 1)
        for offset, slot in zip((0x2c, 0x30), slots):
            replay.put(driver + offset, slot)
        driver_before = bytes(replay.cpu.mem_read(driver, 0x48))
        packs = pack_cases(replay, motor, driver, slots)
        routes = dispatch_cases(replay, motor, driver)
        producers = producer_cases(replay, motor)
        assert bytes(replay.cpu.mem_read(driver, 0x48)) == driver_before
        assert replay.mapped_sha() == carrier.RTOS_SHA
        runs.append({"cpu": "A7" if model == motor.UC_CPU_ARM_CORTEX_A7 else "A15",
                     "poison": poison, "driver_ram": hex(driver), "slot_pointer_fixtures": list(map(hex, slots)),
                     "routes": routes, "producers": producers, "packs": packs})
    assert all(all(run[key] == runs[0][key] for key in ("routes", "producers", "packs"))
               for run in runs)
    return {
        "rtos_sha256": carrier.RTOS_SHA, "decoded_sha256": carrier.DECODED_SHA,
        "rtos_offset": hex(carrier.RTOS_OFFSET), "helper_lf_sha256": HELPERS,
        "unicorn": motor.__version__, "scope": "Explicit fixture RAM. Stop before all service/apply calls.",
        "source_spans": {key: [hex(a), hex(b), sha256(image[a-base:b-base]).hexdigest()]
                         for key, (a, b) in SPANS.items()},
        "runs": runs,
    }


ORIGINAL_SCRIPT_SHA256 = "ea914781ad1fffaba2e2259cd03c68c7ef7c377e3f90141e790bbdd81fdf6f01"
ORIGINAL_WITNESS_SHA256 = "894bd3bc5a684e89063a031dcba466107e41ca6005f1c0584e2ad961876aa89b"
ORIGINAL_TYPED_SHA256 = "6f427c2cbd1d148600b25f3d0b3dd296059c4eff91c9eb620a42eadc6ac4db0f"


def json_bytes(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")


def verify_and_package(record, public_script_lf_sha256):
    typed = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if sha256(typed).hexdigest() != ORIGINAL_TYPED_SHA256:
        raise ValueError("complete AF63 typed witness SHA-256 mismatch")
    if sha256(json_bytes(record)).hexdigest() != ORIGINAL_WITNESS_SHA256:
        raise ValueError("complete AF63 serialized witness SHA-256 mismatch")

    return {
        "schema": "k3iii-af-pwm-parameters-v1",
        "original_research_script_sha256": ORIGINAL_SCRIPT_SHA256,
        "original_full_witness_sha256": ORIGINAL_WITNESS_SHA256,
        "original_typed_witness_sha256": ORIGINAL_TYPED_SHA256,
        "public_verifier_lf_sha256": public_script_lf_sha256,
        "case_counts": {"cpu_and_ram_conditions": 3, "pack_per_condition": 15,
                        "route_per_condition": 6, "caller_per_condition": 10, "total": 93},
        "observations": record,
    }


def check_compare(path, expected):
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("compare regular file required")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    limit = len(expected) + expected.count(b"\n")
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("compare regular file required")
        if info.st_size > limit:
            raise ValueError("compare exceeds LF/CRLF result size")
        actual = stream.read(limit + 1)
    if len(actual) > limit:
        raise ValueError("compare exceeds LF/CRLF result size")
    if actual.replace(b"\r\n", b"\n") != expected:
        raise ValueError("public result differs from --compare")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("carrier", type=Path, help="original decoded carrier or extracted RTOS")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compare", type=Path, help="compare an exact public JSON file with LF or CRLF endings")
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        parser.error("output already exists")
    carrier, motor = load_helpers()
    if motor.__version__ != "2.1.4":
        raise ValueError("expected Unicorn 2.1.4")
    image = carrier.read_image(args.carrier)
    public_script = Path(__file__).read_bytes().replace(b"\r\n", b"\n")
    record = verify_and_package(replay_all(carrier, motor, image), sha256(public_script).hexdigest())
    payload = json_bytes(record)
    if args.compare is not None:
        check_compare(args.compare, payload)
    with args.output.open("xb") as output:
        output.write(payload)
    print(sha256(payload).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from error
