"""Verify K-3 III PafMotor aliases, AfMotorDriver/Pwm bindings and local callbacks."""
if not __debug__:
    raise SystemExit("Run without -O: replay requires assertions")

import argparse
import json
import os
import struct
import types
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HELPERS = {
    "verify_af_packet_8902.py": "6796dc7821f84b13ddf2545c569568928eec24a130e27d519d70f75326e0ba12",
    "verify_af_motor_fields.py": "d5fd3ffdb3dcf4f90a8bd5c49a7d6478c679253f7e00854046cd6117d1ac1cf8",
}
ALIAS_WITNESS = "fabd4354eb29fa5e5e38b933dfe99d63296e2790ae8b57c6e0fcfc324a246918"
SERVICE_WITNESS = "ea296258aa16282ef210406ad553c6849d0827af2f30d692a3280e382a3d963d"

MOTOR_TEXT = (0x52F0B354, 0x52F0DDB4)
SOURCE = {
    "allocation": (0x52F08C74, 0x52F08CD0),
    "factory_teardown": (0x52F08B18, 0x52F08B5C),
    "getter": (0x52F08D80, 0x52F08DF4),
    "initial_probe_dispatch": (0x52F08D04, 0x52F08D2C),
    "binder_dispatch": (0x52F08AA8, 0x52F08AD0),
    "motor_vtable": (0x538F25C8, 0x538F25E0),
    "pulse_vtable": (0x538F26B8, 0x538F26D0),
    "motor_code_window": MOTOR_TEXT,
    "motor_binding": (0x52F0B380, 0x52F0B490),
    "pulse_motor_backlink": (0x52F0DE94, 0x52F0DEB8),
    "pulse_flag_reader": (0x52F0FA14, 0x52F0FA28),
    "debug_alias": (0x52CB45FC, 0x52CB4624),
    "debug_usage_window": (0x52CB44D0, 0x52CB4E64),
    "lens_info_alias": (0x52F06180, 0x52F061A8),
    "lens_info_usage_window": (0x52F06020, 0x52F06A30),
    "movable_alias": (0x52CBE580, 0x52CBE598),
    "movable_usage_window": (0x52CBE4AC, 0x52CBF478),
    "movable_rtti_name": (0x5388B734, 0x5388B747),
    "warm_flag_store_wrapper": (0x52C76E8C, 0x52C76EE0),
    "warm_flag_store_getter": (0x52C76F70, 0x52C76F88),
    "warm_flag_read_wrapper": (0x52C77000, 0x52C77064),
    "warm_flag_read_getter": (0x52C77150, 0x52C77168),
    "joint_getter": (0x52F07AFC, 0x52F07B1C),
    "joint_subobject": (0x52F07B7C, 0x52F07B84),
    "joint_motor_alias": (0x52F07BAC, 0x52F07BD4),
    "joint_usage_window": (0x52F07B00, 0x52F08828),
    "joint_rtti_name": (0x538F20EC, 0x538F2101),
    "joint_readback": (0x52F07F3C, 0x52F07F64),
    "motor_state_predicate": (0x52F0B914, 0x52F0B928),
    "joint_reset_entry": (0x52F08210, 0x52F08218),
    "reset_predecessor": (0x52F0BA34, 0x52F0BA7C),
    "reset_first_call": (0x52F0B988, 0x52F0B9A8),
    "reset_next_call": (0x52F0B674, 0x52F0B6C4),
    "first_service_prefix": (0x5317817C, 0x531781D0),
}


# Each stop is exclusive. Code and literal/RTTI material are distinguished.
SERVICE_CODE = {
    "device_factory_getter": (0x5317757C, 0x53177608),
    "device_factory_slot_4": (0x531777A4, 0x531778B4),
    "motor_driver_getter": (0x53177D94, 0x53177DF4),
    "motor_driver_constructor": (0x53177D14, 0x53177D90),
    "motor_driver_bind_slots": (0x53177B6C, 0x53177BD4),
    "motor_binder_driver_link": (0x52F0B380, 0x52F0B40C),
    "joint_driver_and_motor_links": (0x52F07AFC, 0x52F07BD4),
    "joint_reset_site": (0x52F08210, 0x52F08218),
    "pafmotor_reset_first": (0x52F0BA34, 0x52F0BA7C),
    "pafmotor_reset_service_link": (0x52F0B988, 0x52F0B9A8),
    "driver_reset": (0x5317817C, 0x5317821C),
    "driver_pwm_parameter_pack": (0x531780B8, 0x5317817C),
    "motor_parameter_to_pwm": (0x52F0BC00, 0x52F0BCB4),
    "pwm_factory_getter": (0x5326D424, 0x5326D49C),
    "pwm_factory_virtual_initialize": (0x5327ECD0, 0x5327ECE4),
    "pwm_factory_0xe0_e1": (0x5326CE14, 0x5326CF04),
    "pwm_constructor": (0x5326C03C, 0x5326C0F0),
    "pwm_slot_1c": (0x5326BFA8, 0x5326C010),
    "registry_put_wrapper": (0x52F13774, 0x52F137BC),
    "registry_put": (0x52F13864, 0x52F1390C),
    "registry_get": (0x52F1390C, 0x52F139A4),
    "pwm_overlay_init": (0x5326C0F4, 0x5326C128),
    "pwm_overlay_merge": (0x5326CA24, 0x5326CB14),
    "pwm_record_apply": (0x5326C7C4, 0x5326CA24),
    "pwm_record_mmio_first": (0x533495C8, 0x53349648),
    "pwm_record_mmio_alternate_address": (0x533497F4, 0x5334980C),
    "pwm_initial_stop": (0x5326C190, 0x5326C1B0),
    "pwm_initial_stop_mmio": (0x53349B7C, 0x53349BA0),
    "pwm_driver_setup_entry": (0x53177EE4, 0x53177F14),
    "pwm_listener_dispatch_entry": (0x5326BF4C, 0x5326BF50),
    "pwm_register_driver_callback": (0x53177F9C, 0x53177FCC),
    "pwm_unregister_driver_callback": (0x53177C34, 0x53177C70),
    "listener_register": (0x52F13B24, 0x52F13C68),
    "listener_select_and_deliver": (0x52F13A18, 0x52F13AAC),
    "driver_event": (0x531778B4, 0x53177930),
    "joint_register_driver_events": (0x52F07C24, 0x52F07C94),
    "joint_event": (0x52F07CC8, 0x52F07DEC),
    "joint_pafmotor_update": (0x52F0B5FC, 0x52F0B674),
    "joint_debug_pafmotor_update": (0x52F0DCF4, 0x52F0DDB4),
}
SERVICE_DATA = {
    "device_factory_vptr_literal": (0x53177608, 0x5317760C),
    "device_factory_vtable": (0x53C710D0, 0x53C710EC),
    "device_factory_rtti": (0x53C70B38, 0x53C70B40),
    "device_factory_rtti_name": (0x53C710F0, 0x53C71102),
    "driver_ctor_vptr_literal": (0x53177D90, 0x53177D94),
    "driver_vtables": (0x53C71138, 0x53C7117C),
    "driver_rtti": (0x53C71118, 0x53C71138),
    "driver_rtti_name": (0x53C71180, 0x53C71190),
    "pafmotor_driver_member_name": (0x538EFE8C, 0x538EFE9C),
    "pwm_factory_vptr_literal": (0x5326D49C, 0x5326D4A0),
    "pwm_factory_vtable": (0x53CA9980, 0x53CA999C),
    "pwm_factory_rtti": (0x53CA99A0, 0x53CA99AC),
    "pwm_factory_rtti_name": (0x53CA996C, 0x53CA9979),
    "pwm_vptr_literal": (0x5326C0F0, 0x5326C0F4),
    "pwm_vtable": (0x53CA9800, 0x53CA9830),
    "pwm_rtti": (0x53CA9940, 0x53CA994C),
    "pwm_rtti_name": (0x53CA98A0, 0x53CA98A5),
    "joint_listener_vtable": (0x538F24EC, 0x538F2510),
}


def source_checks(image, base):
    from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
    from capstone import __version__ as capstone_version
    from capstone.arm import ARM_OP_MEM
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    arm.detail = True
    arm.skipdata = True

    def insns(start, end):
        return list(arm.disasm(image[start - base:end - base], start))

    def summary(instruction):
        return [hex(instruction.address), instruction.mnemonic, instruction.op_str]

    widths = {"str": 4, "strb": 1, "strh": 2}
    scalar_count = 0
    overlaps = []
    indexed = []
    writebacks = []
    other_stores = []
    start, end = MOTOR_TEXT
    for i in insns(start, end):
        name = arm.insn_name(i.id) if i.id else ""
        if name not in widths:
            if name.startswith(("str", "stm", "vst", "swp", "stc")):
                other_stores.append(summary(i))
            continue
        scalar_count += 1
        mem = next(op.mem for op in i.operands if op.type == ARM_OP_MEM)
        if mem.index:
            indexed.append(summary(i))
        if i.writeback:
            writebacks.append(summary(i))
        if any(mem.disp < field + 2 and field < mem.disp + widths[name] for field in (0x56, 0x68)):
            overlaps.append(summary(i))
    assert scalar_count == 328
    assert [row[0] for row in overlaps] == ["0x52f0b57c", "0x52f0b5a0"]
    assert [row[0] for row in indexed] == ["0x52f0ca9c", "0x52f0d0f0"]
    assert [row[0] for row in writebacks] == ["0x52f0d36c"]
    assert not other_stores

    def loads(window, offset):
        return [summary(i) for i in insns(*SOURCE[window])
                if i.id and arm.insn_name(i.id) == "ldr"
                and any(op.type == ARM_OP_MEM and op.mem.disp == offset for op in i.operands)]

    getter_calls, external_motor_targets, aligned_motor_words = [], [], []
    for index, (word,) in enumerate(struct.iter_unpack("<I", image)):
        pc = base + index * 4
        if start <= word < end and word % 4 == 0 and not start <= pc < end:
            aligned_motor_words.append([hex(pc), hex(word)])
        if (word >> 25) & 7 != 5 or word >> 28 == 15:
            continue
        imm = word & 0xffffff
        if imm & 0x800000:
            imm -= 0x1000000
        target = pc + 8 + imm * 4
        if target == 0x52F08D80 and pc < 0x533C0000:
            getter_calls.append(hex(pc))
        if start <= target < end and not start <= pc < end:
            external_motor_targets.append([hex(pc), hex(target)])
    assert len(getter_calls) == 27
    assert len(external_motor_targets) == 40
    assert len(aligned_motor_words) == 7
    assert not loads("movable_usage_window", 0x14)
    return {
        "capstone": capstone_version,
        "scalar_store_count": scalar_count,
        "scalar_immediate_overlap_candidates": overlaps,
        "indexed_stores": indexed,
        "writeback_stores": writebacks,
        "other_decoded_store_candidates_except_stack_push": other_stores,
        "raw_aligned_getter_direct_B_BL_candidates_before_0x533c0000": getter_calls,
        "raw_aligned_external_motor_direct_B_BL_candidates": external_motor_targets,
        "raw_aligned_external_motor_code_address_words": aligned_motor_words,
        "bounded_alias_loads": {
            "debug_1c": loads("debug_usage_window", 0x1c),
            "lens_info_18": loads("lens_info_usage_window", 0x18),
            "movable_14": loads("movable_usage_window", 0x14),
            "joint_dc": loads("joint_usage_window", 0xdc),
        },
    }


def run_native(motor, image, base):
    joint = 0x10005500
    motor.VIEWS["joint"] = (joint, 0xe4)
    motor.CODE.update({
        "factory_probe": (0x52F08D04, 0x52F08D18),
        "probe_leaf": (0x52F0B358, 0x52F0B360),
        "factory_binder": (0x52F08AA8, 0x52F08ABC),
        "binder_prefix": (0x52F0B380, 0x52F0B394),
        "joint_add": (0x52F07B7C, 0x52F07B80),
        "joint_bind": (0x52F07BAC, 0x52F07BD0),
        "joint_readback": SOURCE["joint_readback"],
        "motor_predicate": SOURCE["motor_state_predicate"],
    })
    motor.ROM_DATA["motor_vtable"] = SOURCE["motor_vtable"]
    results = []
    for model, poison in ((motor.UC_CPU_ARM_CORTEX_A7, False), (motor.UC_CPU_ARM_CORTEX_A7, True),
                          (motor.UC_CPU_ARM_CORTEX_A15, True)):
        replay = motor.Replay(image, base, model, poison)
        replay.setup()
        replay.set_motor_sentinels()
        baseline_motor = bytes(replay.cpu.mem_read(motor.MOTOR, 0xec))
        probe = replay.run(("factory_probe", "probe_leaf"), stop=0x52F08D18, r4=motor.FACTORY)
        assert replay.cpu.reg_read(motor.UC_ARM_REG_R0) == 1
        assert not probe["writes"]
        binder = replay.run(("factory_binder", "binder_prefix"), stop=0x52F0B394, r4=motor.FACTORY)
        assert replay.cpu.reg_read(motor.UC_ARM_REG_R6) == motor.MOTOR
        assert replay.cpu.reg_read(motor.UC_ARM_REG_R1) == 0
        assert not binder["writes"]
        add = replay.run(("joint_add",), stop=0x52F07B80, r4=joint)
        subobject = replay.cpu.reg_read(motor.UC_ARM_REG_R4)
        assert subobject == joint + 0xc0
        bind = replay.run(("joint_bind",), stop=0x52F07BD0, writable=("joint",),
                          r4=subobject, r7=motor.FACTORY, r5=0, r6=0)
        assert bind["writes"] == [["0x52f07bbc", "joint", "0xdc", 4, motor.MOTOR]]
        assert replay.word(joint + 0xdc) == motor.MOTOR
        assert bytes(replay.cpu.mem_read(motor.MOTOR, 0xec)) == baseline_motor
        checks = []
        for state, flag, predicate in ((3, 0xa6, 1), (4, 0x53, 0)):
            replay.put(motor.MOTOR + 0x3c, state)
            replay.put(motor.MOTOR + 0x44, flag, 1)
            before = bytes(replay.cpu.mem_read(motor.MOTOR, 0xec))
            observed = replay.run(("joint_readback", "motor_predicate"), writable=("joint",), r0=joint)
            assert observed["writes"] == [
                ["0x52f07f54", "joint", "0x90", 4, flag],
                ["0x52f07f5c", "joint", "0x94", 1, predicate],
            ]
            assert replay.reads == [
                ["0x52f07f48", "joint", "0xdc", 4],
                ["0x52f07f50", "motor", "0x44", 1],
                ["0x52f0b914", "motor", "0x3c", 4],
            ]
            assert bytes(replay.cpu.mem_read(motor.MOTOR, 0xec)) == before
            assert replay.check_motor_sentinels() == [0xc345, 0x8137]
            observed.update(motor_3c_fixture=state, motor_44_fixture=flag, reads=replay.reads)
            checks.append(observed)
        assert sha256(bytes(replay.cpu.mem_read(base, len(image)))).digest() == sha256(image).digest()
        results.append({
            "cpu": "Cortex-A7" if model == motor.UC_CPU_ARM_CORTEX_A7 else "Cortex-A15",
            "poisoned_registers_nzcv_at_entry": poison,
            "factory_probe": probe,
            "factory_probe_r0": 1,
            "factory_binder": binder,
            "factory_binder_r6": hex(motor.MOTOR),
            "joint_add_separate_entry": add,
            "joint_bind_separate_entry": bind,
            "joint_readback_cases": checks,
            "untouched_motor_56_68_sentinels": replay.motor_fields(),
        })
    assert all({k: v for k, v in row.items() if k not in ("cpu", "poisoned_registers_nzcv_at_entry")}
               == {k: v for k, v in results[0].items() if k not in ("cpu", "poisoned_registers_nzcv_at_entry")}
               for row in results[1:])
    return results


def source_record(image, base):
    from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    arm.skipdata = True

    def capture(start, end):
        assert base <= start < end <= base + len(image)
        return image[start - base:end - base]

    spans = {}
    for label, (start, end) in (SERVICE_CODE | SERVICE_DATA).items():
        raw = capture(start, end)
        row = {"va": [hex(start), hex(end)], "sha256": sha256(raw).hexdigest()}
        if label in SERVICE_CODE:
            row["a32_disassembly"] = [[hex(i.address), i.mnemonic, i.op_str]
                                      for i in arm.disasm(raw, start) if i.id]
        spans[label] = row

    def word(va):
        return struct.unpack("<I", capture(va, va + 4))[0]

    # Derive each virtual target from the actual literal/ROM slot.
    for literal, vptr, slots in [
        (0x53177608, 0x53C710D8, {8: 0x531777A4, 0xc: 0x531774C4}),
        (0x5326D49C, 0x53CA9988, {8: 0x5326CC0C}),
        (0x5326C0F0, 0x53CA9808, {0xc: 0x52F13B24, 0x10: 0x52F13C68, 0x1c: 0x5326BFA8}),
    ]:
        assert word(literal) == vptr
        assert all(word(vptr + slot) == target for slot, target in slots.items())
    assert [word(0x53C71140 + slot) for slot in (8, 0xc, 0x10, 0x14)] == [
        0x531779B0, 0x53177EE4, 0x53177C34, 0x531778B4,
    ]
    assert word(0x53C71160 + 8) == 0x53177928
    assert word(0x53C71160 + 0xc) == 0x52F13B24
    assert word(0x53C71160 + 0x18) == 0x52F13A18
    assert word(0x538F24F4 + 8) == 0x52F07DE4
    assert word(0x53CA9944) == 0x53CA98A0

    # A32 direct branch candidates over aligned words, including possible data.
    targets = {address: [] for address in (0x5317757C, 0x53177D94, 0x5317817C,
                                          0x5326D424, 0x5326C03C, 0x5326CA24)}
    for index, (word_value,) in enumerate(struct.iter_unpack("<I", image)):
        if word_value >> 28 == 15 or (word_value >> 25) & 7 != 5:
            continue
        immediate = word_value & 0xffffff
        if immediate & 0x800000:
            immediate -= 1 << 24
        pc = base + 4 * index
        target = pc + 8 + 4 * immediate
        if target in targets:
            targets[target].append(hex(pc))
    assert [len(calls) for calls in targets.values()] == [12, 5, 4, 3, 16, 9]
    return spans, {hex(target): calls for target, calls in targets.items()}


def callback_checks(motor, image, base):
    driver = 0x547BC258
    motor.VIEWS["driver"] = (driver, 0x48)
    motor.ROM_DATA["driver_vtables"] = SERVICE_DATA["driver_vtables"]
    motor.CODE.update({
        "driver_ctor_tail": (0x53177D34, 0x53177D8C),
        "driver_callback_thunk": (0x53177928, 0x53177930),
        "driver_callback_handler": (0x531778B4, 0x5317790C),
        "driver_callback_forward_prefix": (0x5317790C, 0x5317791C),
    })
    cases = []
    for model, poison in ((motor.UC_CPU_ARM_CORTEX_A7, False),
                          (motor.UC_CPU_ARM_CORTEX_A7, True),
                          (motor.UC_CPU_ARM_CORTEX_A15, True)):
        replay = motor.Replay(image, base, model, poison)
        replay.cpu.mem_map(driver & ~0xfff, 0x1000)
        replay.cpu.mem_write(driver, b"\xa5" * 0x48)
        # Enter after the original listener allocation. The suffix itself
        # supplies both vptrs and clears the slots/flags used by these cases.
        constructor = replay.run(("driver_ctor_tail",), stop=0x53177D8C, r4=driver, writable=("driver",))
        assert [replay.word(driver + o) for o in (0, 4, 0x2c, 0x30)] == [0x53C71140, 0x53C71160, 0, 0]
        assert replay.word(driver + 0x44, 2) == 0
        target = replay.word(replay.word(driver + 4) + 8)
        assert target == motor.CODE["driver_callback_thunk"][0]
        observations = []
        for event, expected in [(0x12f, 0x0001), (0x130, 0x0100), (0x131, 0x0000)]:
            replay.put(driver + 0x44, 0, 2)
            old = bytearray(replay.cpu.mem_read(driver, 0x48))
            observed = replay.run(("driver_callback_thunk", "driver_callback_handler"),
                                  r0=driver + 4, r1=event, writable=("driver",))
            old[0x44:0x46] = expected.to_bytes(2, "little")
            assert bytes(replay.cpu.mem_read(driver, 0x48)) == old
            assert replay.cpu.reg_read(motor.UC_ARM_REG_R0) == 0
            assert observed["writes"] == {
                0x12f: [["0x531778f0", "driver", "0x44", 1, 1]],
                0x130: [["0x53177900", "driver", "0x45", 1, 1]],
                0x131: [],
            }[event]
            observed.update(event=hex(event), flags=[expected & 0xff, expected >> 8])
            observations.append(observed)
        # No listener object is fabricated. Stop before the virtual BLX
        # that would need the live subscription list and downstream state.
        for event in (0x3d, 0x58, 0x5f, 0x67):
            forward = replay.run(("driver_callback_thunk", "driver_callback_handler",
                                  "driver_callback_forward_prefix"), stop=0x5317791C,
                                 r0=driver + 4, r1=event)
            assert [replay.cpu.reg_read(r) for r in motor.REGS[:4]] == [
                driver + 4, event, 0, 0x52F13A18,
            ]
            assert not forward["writes"]
            forward.update(event=hex(event), listener_r0=hex(driver + 4), event_r1=hex(event),
                           payload_r2=0, virtual_target_r3="0x52f13a18")
            observations.append(forward)
        assert sha256(bytes(replay.cpu.mem_read(base, len(image)))).digest() == sha256(image).digest()
        cases.append({"cpu": "A7" if model == motor.UC_CPU_ARM_CORTEX_A7 else "A15",
                      "poisoned_initial_registers_nzcv": poison,
                      "constructor_suffix": constructor, "events": observations})
    assert all(row["events"] == cases[0]["events"] for row in cases)
    return cases


def capture_helpers(root):
    captured = {name: (root / name).read_bytes().replace(b"\r\n", b"\n") for name in HELPERS}
    for name, code in captured.items():
        if sha256(code).hexdigest() != HELPERS[name]:
            raise ValueError(f"{name} SHA-256 mismatch")
    return captured


def load_helper(root, name, source):
    module = types.ModuleType(Path(name).stem)
    module.__file__ = str(root / name)
    exec(compile(source, module.__file__, "exec", dont_inherit=True), vars(module))
    return module


def json_bytes(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")


def verify_and_project(alias, service):
    for label, record, expected in (
        ("Motor alias", alias, ALIAS_WITNESS), ("Driver/Pwm", service, SERVICE_WITNESS),
    ):
        if sha256(json_bytes(record)).hexdigest() != expected:
            raise ValueError(f"{label} complete witness SHA-256 mismatch")

    # Static disassembly text is only used to verify the full source witness.
    # The public record retains address/range hashes and exact native results.
    alias_static = dict(alias["static"])
    for key in ("scalar_immediate_overlap_candidates", "indexed_stores", "writeback_stores",
                "other_decoded_store_candidates_except_stack_push"):
        alias_static[key] = [entry[0] for entry in alias_static[key]]
    alias_static["bounded_alias_loads"] = {
        label: [entry[0] for entry in entries] for label, entries in alias_static["bounded_alias_loads"].items()
    }
    return {
        "source": {
            "rtos_sha256": alias["rtos_sha256"],
            "rtos_bytes": alias["rtos_bytes"],
            "rtos_va": alias["rtos_va"],
            "decoded_sha256": "7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9",
            "rtos_offset_in_decoded": "0x1c19c",
            "capstone": alias["static"]["capstone"],
            "unicorn": alias["unicorn"],
            "helper_lf_sha256": alias["helper_lf_sha256"],
        },
        "complete_witness_sha256": {"motor_alias": ALIAS_WITNESS, "driver_pwm": SERVICE_WITNESS},
        "motor_alias": {
            "source_spans": alias["source_spans"], "static": alias_static, "native": alias["native"],
        },
        "driver_pwm": {
            "source_spans": {label: {key: row[key] for key in ("va", "sha256")}
                             for label, row in service["source_spans"].items()},
            "raw_a32_direct_branch_candidates": service["raw_a32_direct_branch_candidates"],
            "native_local_driver_callback": service["native_local_driver_callback"],
        },
    }


def run(carrier, image, motor, service_motor):
    from capstone import __version__ as capstone_version

    if capstone_version != "5.0.7" or motor.__version__ != "2.1.4":
        raise ValueError("expected Capstone 5.0.7 and Unicorn 2.1.4")
    base = carrier.BASE
    image_sha = sha256(image).hexdigest()
    alias = {
        "rtos_sha256": image_sha,
        "rtos_bytes": len(image),
        "rtos_va": [hex(base), hex(base + len(image))],
        "helper_lf_sha256": HELPERS,
        "source_spans": {key: [hex(a), hex(b), sha256(image[a-base:b-base]).hexdigest()]
                         for key, (a, b) in SOURCE.items()},
        "static": source_checks(image, base),
        "unicorn": motor.__version__,
        "native": run_native(motor, image, base),
    }
    spans, calls = source_record(image, base)
    service = {
        "rtos_sha256": image_sha,
        "rtos_bytes": len(image),
        "helper_lf_sha256": HELPERS,
        "capstone": capstone_version,
        "unicorn": service_motor.__version__,
        "source_spans": spans,
        "raw_a32_direct_branch_candidates": calls,
        "native_local_driver_callback": callback_checks(service_motor, image, base),
    }
    return verify_and_project(alias, service)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("carrier", type=Path, help="original decoded carrier or extracted RTOS")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compare", type=Path, help="require exact public result bytes before creating output")
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        parser.error("output already exists")

    captured = capture_helpers(ROOT)
    packet, motor_fields = HELPERS
    carrier = load_helper(ROOT, packet, captured[packet])
    image = carrier.read_image(args.carrier)
    # Each accepted witness uses independent replay address/permission tables.
    motor = load_helper(ROOT, motor_fields, captured[motor_fields])
    service_motor = load_helper(ROOT, motor_fields, captured[motor_fields])
    data = json_bytes(run(carrier, image, motor, service_motor))
    if args.compare is not None:
        with args.compare.open("rb") as expected:
            if expected.read(len(data) + 1) != data:
                raise ValueError("public result differs from --compare")
    with args.output.open("xb") as output:
        output.write(data)
    print(sha256(data).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
