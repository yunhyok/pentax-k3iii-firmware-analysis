"""Replay six bounded Stubby ROMFS cases from a SHA-pinned user-supplied image.

Original Thumb code and ROMFS bytes run on Unicorn's Cortex-A7 model. All RAM
placement and call arguments are synthetic; no device or selected image runs.
"""
if not __debug__:
    raise RuntimeError("Assertions required; -O unsupported")

import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import unicorn
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                     UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID, UC_PROT_READ, UC_PROT_EXEC)
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A7, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
    UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

# Reuse the published size/SHA-pinned reader; its historical six stub tests stay unchanged.
from verify_stubby_load_auth import load, H, SHA, SIZE, KERNEL, DTB, INITRD

BASE, STOP, STACK = 0x41000000, 0x70000f00, 0x7000f000
KERNEL_DEST, DTB_DEST = 0x40008000, 0x42800000
INSTRUCTION_LIMIT = 400000
SOURCE_RANGES = (
    ("wrapper", 0x9fc, 0xa52, "4d53bb01ff17b65beb27ec8ad03c917e00df92cb318548869626c55c499a9833"),
    ("mount", 0xedc, 0xf1e, "0badb2b3dc276715c774150e14d7ce8c718d9140ab79961b69e9c99e916e2ff2"),
    ("pic_dereference", 0x1080, 0x1098, "bcfd9bf5283cbbf9c36a73dbee49c4bc63bd3a994fcbf8ca8395d0ff47fbbaf1"),
    ("get_address", 0xea4, 0xed4, "e52cd97db37f46f1c5946c95e5406bf3d6e41f4fd206e52d6365adfdf5a2f78b"),
    ("lookup", 0xd30, 0xe52, "08a34d703f3e2cbe5f0f49114ee81dd03874e4bf5363041b2ca746afd5ae02f3"),
    ("read_bigendian", 0xd04, 0xd1a, "a1565b2a1f1bf2f6b1f9b7a0f119e18a7cbb0b65774c610c92d825a45945af39"),
    ("pad_name", 0xd1a, 0xd30, "7fdc41564e6519496c10e585a668108b9d3fbbf95743e4ff0e3bdb26433ef8d3"),
    ("read", 0xe5c, 0xe9c, "8fa42ad5be0f8963f5e18b1aba5dde6f7a4b13abec438e8261b8814eb7a338e8"),
    ("copy_bytes", 0x122e, 0x1244, "42b747a73d135264005691f2d3906e30649f57450a499a463b7e5c82daa5db17"),
)
CASES = (
    dict(label="missing_bootloader", entry=0x9fc, path_offset=0x2b43, source=0,
         destination=KERNEL_DEST, maxsize=0x100000, result=0xffffffff,
         kernel_pointer=KERNEL_DEST, copy_offset=0, copy_size=0),
    dict(label="kernel_xip", entry=0x9fc, path_offset=0x2b53, source=0,
         destination=KERNEL_DEST, maxsize=0x27f8000, result=2993056,
         kernel_pointer=BASE + 0x9000, copy_offset=0, copy_size=0),
    dict(label="dtb_copy", entry=0x9fc, path_offset=0x2b76, source=0,
         destination=DTB_DEST, maxsize=0xc800, result=32694,
         kernel_pointer=KERNEL_DEST, copy_offset=0x2e3be0, copy_size=32694),
    dict(label="bounded_direct_copy", entry=0xe5c, path_offset=0x2b76, source=None,
         destination=DTB_DEST, maxsize=17, result=17,
         kernel_pointer=KERNEL_DEST, copy_offset=0x2e3be0, copy_size=17),
    dict(label="kernel_maxsize17_xip", entry=0x9fc, path_offset=0x2b53, source=0,
         destination=KERNEL_DEST, maxsize=17, result=2993056,
         kernel_pointer=BASE + 0x9000, copy_offset=0, copy_size=0),
    dict(label="kernel_maxsize17_copy", entry=0x9fc, path_offset=0x2b53, source=1,
         destination=KERNEL_DEST, maxsize=17, result=17,
         kernel_pointer=KERNEL_DEST, copy_offset=0x9000, copy_size=17),
)
ARGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
SAVED = (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
         UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11)
POINTS = {0x9fc, 0xa08, 0xa0e, 0xa20, 0xa28, 0xa36, 0xa3a, 0xa46,
          0xe5c, 0xe7c, 0xe84, 0xe92, 0xea4, 0xec2, 0xedc}
MAPS = ((BASE, 0x310000), (0x40004000, 0x1000), (KERNEL_DEST - 0x1000, 0x2000),
        (DTB_DEST - 0x1000, 0x11000), (0x70000000, 0x10000))


def run_one(b, case):
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    for address, size in MAPS:
        u.mem_map(address, size)
    u.mem_write(BASE, b)
    u.mem_protect(BASE, 0x310000, UC_PROT_READ | UC_PROT_EXEC)
    for address, value in ((KERNEL, KERNEL_DEST), (DTB, DTB_DEST), (INITRD, 0x43000000)):
        u.mem_write(address, value.to_bytes(4, "little"))
    buffers = {KERNEL_DEST: b"\xa5" * 0x1000, DTB_DEST: b"\xa5" * 0x9000}
    for address, data in buffers.items():
        u.mem_write(address, data)
        u.mem_write(address - 16, b"\xa5" * 16)
    u.reg_write(UC_ARM_REG_SP, STACK)
    for n, reg in enumerate(SAVED):
        u.reg_write(reg, 0xcafe0000 + n)
    dest, count = case["destination"], case["copy_size"]
    result = dict(label=case["label"], calls=[], critical_trace=[], destination_write_events=0)
    phase = dict(name="mount", instructions=0, ranges={})

    def code(uc, address, size, unused):
        if address == STOP:
            uc.emu_stop()
            return
        off = address - BASE
        matched = next((name for name, a, z, _ in SOURCE_RANGES if a <= off and off + size <= z), None)
        assert matched is not None, f"Unexpected instruction {address:#x}"
        phase["pc_offset"] = off
        phase["instructions"] += 1
        phase["ranges"][matched] = phase["ranges"].get(matched, 0) + 1
        if off in POINTS:
            result["critical_trace"].append(dict(phase=phase["name"], offset=hex(off)))

    def write(uc, access, address, size, value, unused):
        n = result["destination_write_events"]
        assert phase["name"] == "operation" and n < count
        assert address == dest + n and size == 1 and phase["pc_offset"] == 0x123c
        result["destination_write_events"] += 1

    def invalid(uc, access, address, size, value, unused):
        result["invalid_access"] = dict(access=access, address=hex(address), size=size)
        return False

    u.hook_add(UC_HOOK_CODE, code)
    # The write observer is confined to the destination. Globals are checked after return.
    u.hook_add(UC_HOOK_MEM_WRITE, write, begin=dest, end=dest + len(buffers[dest]) - 1)
    u.hook_add(UC_HOOK_MEM_INVALID, invalid)

    def call(name, offset, args):
        phase.update(name=name, instructions=0, ranges={})
        for reg, value in zip(ARGS, args):
            u.reg_write(reg, value)
        u.reg_write(UC_ARM_REG_LR, STOP | 1)
        try:
            u.emu_start((BASE + offset) | 1, STOP, count=INSTRUCTION_LIMIT)
        except Exception as exc:
            raise RuntimeError(f"{case['label']}/{name}: pc={u.reg_read(UC_ARM_REG_PC):#x}, "
                               f"invalid={result.get('invalid_access')}") from exc
        assert u.reg_read(UC_ARM_REG_PC) == STOP, "No sentinel return within instruction limit"
        assert u.reg_read(UC_ARM_REG_SP) == STACK
        assert [u.reg_read(r) for r in SAVED] == [0xcafe0000 + n for n in range(8)]
        rv = u.reg_read(UC_ARM_REG_R0)
        result["calls"].append(dict(phase=name, entry_offset=hex(offset), arguments=[hex(x) for x in args],
            result=rv, instruction_count=phase["instructions"], executed_ranges=phase["ranges"].copy(),
            stop_pc=hex(STOP), sp_and_r4_r11_preserved=True))
        return rv

    rd = lambda a: int.from_bytes(u.mem_read(a, 4), "little")
    assert call("mount", 0xedc, [BASE + 0x8000]) == 0
    assert rd(0x40004004) == BASE + 0x8000 and rd(0x4000441c) == BASE + 0xe5d
    args = [BASE + case["path_offset"], dest, case["maxsize"]]
    if case["source"] is not None:
        args.insert(0, case["source"])
    rv = call("operation", case["entry"], args)
    assert rv == case["result"]
    assert rd(KERNEL) == case["kernel_pointer"]
    assert rd(DTB) == DTB_DEST and rd(INITRD) == 0x43000000
    assert rd(0x40004004) == BASE + 0x8000 and rd(0x4000441c) == BASE + 0xe5d
    assert result["destination_write_events"] == count
    expected_bytes = b[case["copy_offset"]:case["copy_offset"] + count]
    after = bytes(u.mem_read(dest, len(buffers[dest])))
    assert after == expected_bytes + buffers[dest][count:]
    for address, data in buffers.items():
        assert bytes(u.mem_read(address - 16, 16)) == b"\xa5" * 16
        if address != dest:
            assert bytes(u.mem_read(address, len(data))) == data
    mapped = bytes(u.mem_read(BASE, len(b)))
    assert mapped == b
    result.update(passed=True, result=rv, source_argument=case["source"], maxsize=case["maxsize"],
        kernel_pointer=hex(rd(KERNEL)), dtb_pointer=hex(rd(DTB)), initrd_pointer=hex(rd(INITRD)),
        mount_pointer=hex(rd(0x40004004)), read_callback=hex(rd(0x4000441c)),
        destination=hex(dest), destination_bytes_checked=len(after), destination_sha256=H(after),
        copied_bytes=count, copied_bytes_equal_original=True, copied_bytes_sha256=H(after[:count]),
        original_copy_offset=hex(case["copy_offset"]) if count else None,
        ordered_one_byte_stores_verified=True, copy_store_offset="0x123c" if count else None,
        head_canary_bytes=16, head_canary_preserved=True, tail_canary_bytes=len(after) - count,
        tail_canary_preserved=True, other_destination_preserved=True,
        mapped_image_sha256=H(mapped), original_payload_bytes_checked=len(b), entire_original_payload_unchanged=True)
    return result


def run_checks(b, input_sha):
    assert len(b) == SIZE and H(b) == SHA, "Unknown LINUX image"
    for name, start, end, digest in SOURCE_RANGES:
        assert H(b[start:end]) == digest, f"Changed source range: {name}"
    cases = [run_one(b, case) for case in CASES]
    return dict(passed=True, input_sha256=input_sha, linux_sha256=SHA, case_count=len(cases),
        engine=dict(name="Unicorn", version=unicorn.__version__, cpu="Cortex-A7", mode="ARM Thumb little endian"),
        synthetic=dict(base=hex(BASE), stack=hex(STACK), return_sentinel=hex(STOP),
                       maps=[dict(base=hex(a), size=z) for a, z in MAPS]),
        instruction_limit_per_call=INSTRUCTION_LIMIT, original_mapping_permissions="read+execute",
        source_ranges=[dict(name=n, start=hex(a), end=hex(z), sha256=h) for n, a, z, h in SOURCE_RANGES],
        explicit_stubs=[], cases=cases,
        hooks=["Code: count executed instructions, enforce nine original ranges, record selected offsets.",
               "Write: destination buffer only; assert ordered one-byte stores at offset0x123c. Globals and head canaries are checked after return.",
               "Invalid/protection access: stop with an error. No hook supplies return values or patches instructions."],
        scope=["User-supplied original LINUX code and ROMFS; full guest image bytes checked after each case. No ROMFS mutation.",
               "Base0x41000000, stack, destination, globals and call arguments are synthetic, not measured physical placement.",
               "source1 is a synthetic wrapper input; selected loader984 uses source0. Source1 caller reachability remains unverified.",
               "Each native mount and operation returns to a synthetic sentinel; no selected kernel/image entry executes.",
               "No ROMFS checksum, complete loader, Boot ROM authentication, modified-image acceptance or camera-device behavior is proven.",
               "Earlier all-address write-observer attempts failed at a2c. Observer scope and RX protection changed together before success; cause remains unisolated."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        raise FileExistsError("output exists: " + str(args.output))
    b, input_sha = load(args.input)
    result = run_checks(b, input_sha)
    after, after_sha = load(args.input)
    assert after_sha == input_sha and after == b, "Disk input changed during replay"
    result["disk_input_sha256_after"] = after_sha
    result["disk_input_unchanged"] = True
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(dict(passed=True, cases=len(result["cases"]), cpu=result["engine"]["cpu"])))


if __name__ == "__main__":
    main()
