"""Replay original Stubby source 0 through ROMFS to two unmapped-read boundaries.

The user supplies the SHA-pinned decoded carrier. Guest RAM placement is
synthetic and only diagnostic functions are stubbed. No selected image runs.
"""
if not __debug__:
    raise RuntimeError("Assertions required; -O unsupported")
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parent
DEPENDENCIES = {
    "verify_stubby_romfs.py": "80060110e7573ef3e87f560454caf2c39e50d0fa7db407429e7e7538b4d8c70d",
    "verify_stubby_load_auth.py": "a64e6a2473a60e0cf08ea234e9d0159ecafd4324e79451a9689261eed9674664",
}


def load_dependencies():
    sources = {}
    for name, expected in DEPENDENCIES.items():
        path = ROOT / name
        source = path.read_bytes().replace(b"\r\n", b"\n")
        if hashlib.sha256(source).hexdigest() != expected:
            raise ValueError(f"Dependency SHA-256 mismatch: {name}")
        sources[path] = source

    # Load auth before ROMFS, executing the checked bytes without using cached bytecode.
    for path in reversed(sources):
        module = ModuleType(path.stem)
        module.__file__ = str(path)
        exec(compile(sources[path], module.__file__, "exec"), module.__dict__)
        sys.modules[path.stem] = module


INITFS_OFFSET, INITFS_SIZE = 32855436, 14452736
INITFS_SHA = "0f230006ec83cf48567977081ac2446072dec58aa5c9c7ddc2d38009a44650a0"
EXTRA_RANGES = (
    ("loader", 0x984, 0x9be, "1d2cefc031380c84133490e18673fadcbd802c89e520c28fdb871d1e7e869211"),
    ("select_source", 0x928, 0x930, "a68d0a87d69f408f7c7657f63089e233c7df9e43ea0edc88577219a3dfdfb214"),
    ("try_source", 0x930, 0x976, "f5925fd9de716d34ea00c0fb1454c8aa13060807b2eff361e1fdc7b43f367df9"),
    ("load_files", 0xa68, 0xc00, "9408ab441cfe68231e29c05278dc1a4e8e3b044e7fdda3185fb00a5d01493f80"),
    ("config_head", 0x2616, 0x263e, "a0ea26f8a4554adbce12ebdde14718e61295e583757b317e1e2b0c2ce26d8634"),
    ("config_return", 0x2940, 0x2948, "d0c92af6ea94c366484612ea240cae0d23a943c5fa231087e393da3ac2cfa7ad"),
    ("fdt_path_head", 0x24dc, 0x250e, "9875a6af78eb502273a888b5598ab52b08e52d75ebe30a922e4b089771336141"),
    ("fdt_path_body", 0x2512, 0x25ca, "0e9cb0657437b5dea8c9c9d93e232978f0ec033a8ff0ef10b7bc2117fbe079fa"),
    ("read_be32", 0x1218, 0x122e, "956864b43b6f0bd77745941173ca664fb08c2e30f654135a6f3d49bde5f00929"),
    ("write_be32", 0x1208, 0x1218, "560c9c56074aeb247459e1653a222c5c49f35f7ba2ab26bc1f97a6a7daf48476"),
)
STUBS = {0x894: "print_info including CP15 MPIDR read; entire diagnostic function skipped",
         0x8bc: "describe boot source; entire diagnostic function skipped",
         0xc84: "puts; output suppressed"}
POINTS = {0x984, 0x98c, 0x99a, 0x930, 0x95a, 0xedc, 0xa68, 0x9fc,
          0xaa4, 0xaba, 0xad4, 0xae4, 0xae8, 0xb02, 0xb10, 0x2616,
          0x2638, 0x2940, 0x24dc, 0xb36, 0xb56, 0xb6e}
RETURNS = {0xaa4: "bootloader", 0xaba: "kernel", 0xad4: "dtb", 0xb02: "dtb_config"}


def replay(b, initfs, map_initfs, ranges):
    from verify_stubby_romfs import ARGS, SAVED, BASE, STACK, STOP, KERNEL_DEST, DTB_DEST
    from verify_stubby_load_auth import H, KERNEL, DTB, INITRD
    from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
                         UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID,
                         UC_PROT_READ, UC_PROT_EXEC, UC_MEM_READ_UNMAPPED, UC_ERR_READ_UNMAPPED)
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A7, UC_ARM_REG_R0, UC_ARM_REG_R5,
                                   UC_ARM_REG_R8, UC_ARM_REG_R12, UC_ARM_REG_SP,
                                   UC_ARM_REG_LR, UC_ARM_REG_PC)

    tracked = (KERNEL, DTB, INITRD, 0x40004004, 0x4000441c, 0x40004000)
    clobbered = (*ARGS[1:], UC_ARM_REG_R12)
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    maps = [(BASE, 0x310000), (0x40004000, 0x2000), (KERNEL_DEST - 0x1000, 0x2000),
            (DTB_DEST - 0x1000, 0x11000), (0x70000000, 0x10000)]
    if map_initfs:
        maps.append((0x43000000, (len(initfs) + 0xfff) & ~0xfff))
    for address, length in maps:
        u.mem_map(address, length)
    u.mem_write(BASE, b)
    u.mem_protect(BASE, 0x310000, UC_PROT_READ | UC_PROT_EXEC)
    if map_initfs:
        u.mem_write(0x43000000, initfs)
        u.mem_protect(0x43000000, maps[-1][1], UC_PROT_READ)
    initial_globals = {hex(a): 0xdeaf0000 + i for i, a in enumerate(tracked)}
    for address, value in zip(tracked, initial_globals.values()):
        u.mem_write(address, value.to_bytes(4, "little"))
    u.mem_write(KERNEL_DEST - 16, b"\xa5" * (0x1000 + 16))
    u.mem_write(DTB_DEST - 16, b"\xa5" * (0x10000 + 16))
    u.reg_write(UC_ARM_REG_SP, STACK)
    u.reg_write(UC_ARM_REG_LR, 0x70000f01)
    for n, reg in enumerate(ARGS):
        u.reg_write(reg, 0xdead1000 + n)
    for n, reg in enumerate(SAVED):
        u.reg_write(reg, 0xcafe0000 + n)
    result = dict(label="original_initfs_at_assumed_base" if map_initfs else "initfs_unmapped",
        entry=hex(BASE + 0x984), initial_globals=initial_globals, maps=[dict(base=hex(a), size=z) for a, z in maps],
        events=[], stub_calls=[], wrapper_returns=[], instruction_count=0,
        executed_ranges={}, dtb_copy_stores=0, dtb_property_stores=[])
    executed = {}
    last_offset = None
    stub_return = None
    accesses = {}
    regions = [("linux", BASE, len(b)), ("globals", 0x40004000, 0x2000),
               ("dtb", DTB_DEST, 32694), ("stack", 0x70000000, 0x10000)]
    if map_initfs:
        regions.append(("initfs", 0x43000000, len(initfs)))

    def rd(address):
        return int.from_bytes(u.mem_read(address, 4), "little")

    def code(uc, address, size, unused):
        nonlocal last_offset, stub_return
        off = address - BASE
        last_offset = off
        if stub_return is not None:
            lr, sp, saved = stub_return
            assert address == (lr & ~1)
            assert uc.reg_read(UC_ARM_REG_SP) == sp
            assert tuple(uc.reg_read(reg) for reg in SAVED) == saved
            assert uc.reg_read(UC_ARM_REG_R0) == 0
            assert all(uc.reg_read(reg) == 0xdeadc000 + reg for reg in clobbered)
            stub_return = None
        if off in STUBS:
            lr = uc.reg_read(UC_ARM_REG_LR)
            result["stub_calls"].append(dict(offset=hex(off), role=STUBS[off],
                arguments=[hex(uc.reg_read(r)) for r in ARGS], return_address=hex(lr), return_value=0))
            stub_return = (lr, uc.reg_read(UC_ARM_REG_SP), tuple(uc.reg_read(reg) for reg in SAVED))
            for reg in clobbered:
                uc.reg_write(reg, 0xdeadc000 + reg)
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, lr)
            return
        name = next((n for n, a, z, _ in ranges if a <= off and off + size <= z), None)
        assert name is not None, f"Uncovered original code edge {address:#x}"
        if off == 0x9bc:
            raise AssertionError("Original loader entered failure loop")
        result["instruction_count"] += 1
        result["executed_ranges"][name] = result["executed_ranges"].get(name, 0) + 1
        executed[off] = size
        if off in POINTS:
            result["events"].append(dict(offset=hex(off), args=[hex(uc.reg_read(r)) for r in ARGS],
                sp=hex(uc.reg_read(UC_ARM_REG_SP)), r5=hex(uc.reg_read(UC_ARM_REG_R5)), r8=hex(uc.reg_read(UC_ARM_REG_R8))))
        if off in RETURNS:
            result["wrapper_returns"].append(dict(role=RETURNS[off], result=uc.reg_read(UC_ARM_REG_R0),
                kernel_pointer=hex(rd(KERNEL)), dtb_pointer=hex(rd(DTB))))

    def memory(uc, access, address, size, value, kind):
        region = next((name for name, start, length in regions if start <= address
                       and address + size <= start + length), None)
        assert region is not None, f"Unexpected {kind} at {address:#x}"
        key = f"{kind}_{region}"
        accesses[key] = accesses.get(key, 0) + 1
        if region == "initfs":
            assert (kind, last_offset, address, size) == ("read", 0xae4, 0x43000068, 4)
        if kind == "read":
            return
        assert region in {"stack", "globals", "dtb"}
        if region != "dtb":
            return
        if last_offset == 0x123c:
            assert size == 1 and address == DTB_DEST + result["dtb_copy_stores"]
            result["dtb_copy_stores"] += 1
        else:
            result["dtb_property_stores"].append(dict(offset=hex(last_offset), address=hex(address), size=size, value=value))

    def invalid(uc, access, address, size, value, unused):
        result["missing_input"] = dict(access=access, address=hex(address), size=size,
                                       instruction_offset=hex(last_offset))
        return False

    u.hook_add(UC_HOOK_CODE, code)
    u.hook_add(UC_HOOK_MEM_READ, memory, user_data="read")
    u.hook_add(UC_HOOK_MEM_WRITE, memory, user_data="write")
    u.hook_add(UC_HOOK_MEM_INVALID, invalid)
    try:
        u.emu_start((BASE + 0x984) | 1, STOP, count=400000)
    except UcError as exc:
        assert exc.errno == UC_ERR_READ_UNMAPPED, str(exc)
        result["execution_error"] = dict(type=type(exc).__name__, message=str(exc), code=exc.errno)
    else:
        raise AssertionError("Loader did not reach the expected unmapped read")
    result["stop_pc"] = hex(u.reg_read(UC_ARM_REG_PC))
    result["stop_sp"] = hex(u.reg_read(UC_ARM_REG_SP))
    result["final_globals"] = {hex(a): hex(rd(a)) for a in tracked}
    result["original_linux_guest_unchanged"] = bytes(u.mem_read(BASE, len(b))) == b
    result["original_initfs_guest_unchanged"] = bytes(u.mem_read(0x43000000, len(initfs))) == initfs if map_initfs else None
    result["kernel_buffer_unchanged"] = bytes(u.mem_read(KERNEL_DEST - 16, 0x1010)) == b"\xa5" * 0x1010
    dtb_original = b[0x2e3be0:0x2e3be0 + 32694]
    dtb_after = bytes(u.mem_read(DTB_DEST, 32694))
    result["dtb_before_sha256"] = H(dtb_original)
    result["dtb_after_sha256"] = H(dtb_after)
    result["dtb_changed_offsets"] = [i for i, (a, z) in enumerate(zip(dtb_original, dtb_after)) if a != z]
    result["dtb_head_canary_preserved"] = bytes(u.mem_read(DTB_DEST - 16, 16)) == b"\xa5" * 16
    result["dtb_tail_canary_preserved"] = bytes(u.mem_read(DTB_DEST + 32694, 0x10000 - 32694)) == b"\xa5" * (0x10000 - 32694)
    result["initrd_start_property"] = hex(int.from_bytes(dtb_after[0x150:0x154], "big"))
    result["initrd_end_property"] = hex(int.from_bytes(dtb_after[0x160:0x164], "big"))
    spans = []
    for off in sorted(executed):
        end = off + executed[off]
        if spans and spans[-1][1] == off:
            spans[-1][1] = end
        else:
            spans.append([off, end])
    result["observed_instruction_spans"] = [dict(start=hex(a), end=hex(z), sha256=H(b[a:z])) for a, z in spans]
    expected_address, expected_pc = (0x1800003c, 0xb6e) if map_initfs else (0x43000068, 0xae4)
    boundary = result.get("missing_input", {})
    result["expected_boundary_observed"] = (boundary.get("address") == hex(expected_address)
        and boundary.get("instruction_offset") == hex(expected_pc) and boundary.get("size") == 4
        and boundary.get("access") == UC_MEM_READ_UNMAPPED
        and result["execution_error"] is not None and result["execution_error"]["type"] == "UcError"
        and result["stop_pc"] == hex(BASE + expected_pc))
    assert result["expected_boundary_observed"], boundary
    assert stub_return is None
    expected_stubs = [("0x894", "0x4100098b"), ("0x8bc", "0x41000969")]
    if map_initfs:
        expected_stubs.append(("0xc84", "0x41000b0d"))
    assert [(s["offset"], s["return_address"]) for s in result["stub_calls"]] == expected_stubs
    assert accesses.get("read_initfs", 0) == int(map_initfs)
    assert result["instruction_count"] == (167633 if map_initfs else 165570)
    result["memory_access_counts"] = accesses
    result["stub_return_registers_verified"] = True
    assert result["original_linux_guest_unchanged"] and result["kernel_buffer_unchanged"]
    assert result["dtb_copy_stores"] == 32694 and result["dtb_head_canary_preserved"] and result["dtb_tail_canary_preserved"]
    assert rd(KERNEL) == BASE + 0x9000 and rd(DTB) == DTB_DEST and rd(0x4000441c) == BASE + 0xe5d
    assert rd(0x40004000) == 0 and rd(0x40004004) == BASE + 0x8000
    assert u.reg_read(UC_ARM_REG_SP) == STACK - 56
    expected_returns = [0xffffffff, 2993056, 32694] + ([0xffffffff] if map_initfs else [])
    assert [r["result"] for r in result["wrapper_returns"]] == expected_returns
    calls = [e for e in result["events"] if e["offset"] == "0x9fc"]
    assert all(e["args"][0] == "0x0" for e in calls)
    assert next(e for e in result["events"] if e["offset"] == "0x99a")["args"][:3] == ["0x0", "0x0", "0x0"]
    assert next(e for e in result["events"] if e["offset"] == "0xa68")["args"][:3] == ["0x0", "0x1", "0x0"]
    assert next(e for e in result["events"] if e["offset"] == "0x95a")["r5"] == "0x40004000"
    expected = bytearray(dtb_original)
    if map_initfs:
        length = int.from_bytes(initfs[0x68:0x6c], "big")
        assert length == 14451829 and result["original_initfs_guest_unchanged"]
        assert rd(INITRD) == 0x43000080
        expected[0x150:0x154] = (0x43000080).to_bytes(4, "big")
        expected[0x160:0x164] = (0x43000080 + length).to_bytes(4, "big")
        expected_stores = []
        for address, value in [(DTB_DEST + 0x150, 0x43000080), (DTB_DEST + 0x160, 0x43000080 + length)]:
            for n, (off, byte) in enumerate(zip([0x120a, 0x120e, 0x1212, 0x1214], value.to_bytes(4, "big"))):
                expected_stores.append(dict(offset=hex(off), address=hex(address + n), size=1, value=byte))
        assert result["dtb_property_stores"] == expected_stores
    else:
        assert rd(INITRD) == 0x43000000 and result["dtb_property_stores"] == []
    assert dtb_after == expected
    result["verified"] = True
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("decoded", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if os.path.lexists(args.output):
        raise FileExistsError(args.output)
    if not args.decoded.is_file():
        raise ValueError("Input must be a decoded firmware file")
    sys.dont_write_bytecode = True
    load_dependencies()
    from verify_stubby_romfs import SOURCE_RANGES
    from verify_stubby_load_auth import load, H, SHA, DSHA
    import unicorn

    b, input_sha = load(args.decoded)
    assert input_sha == DSHA, "Original decoded carrier is required, including INITFS"
    decoded = args.decoded.read_bytes()
    assert H(decoded) == DSHA, "Decoded input changed while reading INITFS"
    initfs = decoded[INITFS_OFFSET:INITFS_OFFSET + INITFS_SIZE]
    del decoded
    assert len(initfs) == INITFS_SIZE and H(initfs) == INITFS_SHA, "Unexpected INITFS record"
    ranges = SOURCE_RANGES + EXTRA_RANGES
    for name, start, end, digest in ranges:
        assert H(b[start:end]) == digest, f"Source range SHA-256 mismatch: {name}"
    rows = [replay(b, initfs, False, ranges), replay(b, initfs, True, ranges)]
    assert H(args.decoded.read_bytes()) == DSHA, "Decoded input changed during replay"
    report = dict(verified=True, input_sha256=input_sha, linux_sha256=SHA, initfs_sha256=INITFS_SHA,
        initfs_decoded_offset=INITFS_OFFSET, initfs_size=INITFS_SIZE,
        engine=dict(name="Unicorn", version=unicorn.__version__, cpu="Cortex-A7"),
        public_dependencies_sha256_lf=DEPENDENCIES,
        source_ranges=[dict(name=n, start=hex(a), end=hex(z), sha256=h) for n, a, z, h in ranges],
        stubs={hex(k): v for k, v in STUBS.items()},
        stub_abi="Return via LR with r0=0 and r1/r2/r3/r12 poisoned. Preserve SP and r4–r11 across each diagnostic stub.",
        instruction_count_semantics="CODE callbacks before instructions, including the faulting instruction and excluding stub bodies.",
        memory_count_semantics="Guest data read/write callbacks by region. Invalid reads are recorded separately. Host snapshots and instruction fetches are excluded.",
        cases=rows, disk_input_unchanged=True,
        limits=["LINUX and optional INITFS are mapped by the replay. Runtime placement is unverified.",
                "Starts at original Thumb loader 0x984. Reset and the listed diagnostic bodies are outside the trace.",
                "The stops are unmapped reads. The loader does not return and neither kernel entry nor initrd consumption executes.",
                "No hardware access, ROM authentication, modified-image acceptance or flash was tested."])
    with args.output.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(json.dumps({"verified": True, "boundaries": [r["missing_input"] for r in rows]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
