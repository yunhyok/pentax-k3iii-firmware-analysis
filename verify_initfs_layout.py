"""Replay original PARTPARA layout and BOOT INITFS request with modeled media.

The user supplies the decoded carrier. Host setup joins six original ARM
fragments and supplies object bindings, the BOOT selector and table LBA.
"""

if not __debug__:
    raise RuntimeError("Assertions required; -O unsupported")

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from types import ModuleType


DEPENDENCY = "verify_update_bank_selection.py"
DEPENDENCY_SHA = "0618f4a8160f66f93c5ab385739a6f149a5cf9eda71c982f0502ca538a37650d"
DECODED_SIZE = 78683892
PART_HEADER_OFFSET, PART_END = 0x294, 0x4A8
INITFS_HEADER_OFFSET = 0x1F5557C


def load_dependency():
    path = Path(__file__).resolve().with_name(DEPENDENCY)
    source = path.read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(source).hexdigest() != DEPENDENCY_SHA:
        raise ValueError(f"Dependency SHA-256 mismatch: {DEPENDENCY}")
    # Execute the checked source directly, bypassing any cached bytecode.
    module = ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


TABLE, N = 0x50B70100, 0x10E00
OBJ, CTX, DRIVER, VT, RECORD = [
    0x10000000 + x for x in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000)
]
SOURCE, DEST, STACK, STOP = 0x11000000, 0x43000000, 0x1003E000, 0x1003F000
INITFS_OFFSET, INITFS_SIZE = 0x1F5558C, 0xDC8800
INITFS_SHA = "0f230006ec83cf48567977081ac2446072dec58aa5c9c7ddc2d38009a44650a0"
PART_SHA = "2c202527871d2ef6677c2daf52a12f9c701c29296727fb5d4ee9d05e298e44bb"
RANGES = (
    (
        "ctor",
        0x52FF52D4,
        0x52FF5300,
        "b0e80c520adae7747671efe8dbed5319add25fccf75913fe70d7a7c826581794",
    ),
    (
        "kind_dispatch",
        0x52FF2A24,
        0x52FF2A3C,
        "730ab5355fa02cc98d899cd9d1a7f8c682a72388f5eecb3883b5705924daaa2c",
    ),
    (
        "kind2_handler",
        0x52FF2BBC,
        0x52FF2BDC,
        "5db1ffa0bce7bc736bef109e1e06989225dfa7319ec111ddb206968c821fd49e",
    ),
    (
        "layout",
        0x52FF1EA8,
        0x52FF2060,
        "8e1c52e6e4e5f204f510505af51c93251b78d1c725a996f768abef61df19c776",
    ),
    (
        "indexed_write_success",
        0x52FF586C,
        0x52FF5918,
        "0ebc56b421325b6305d6ff95a07fe951e98e889f1dde3983870a35162c67ac64",
    ),
    (
        "transfer_head",
        0x52FF5708,
        0x52FF5760,
        "09569bcdac0e6f60d695457461f7f1eed4a2321e94902c55af3ca1db93f49eff",
    ),
    (
        "transfer_aligned_tail",
        0x52FF57F8,
        0x52FF5818,
        "f47a0e0b90f71b21278b763c29e9fb0ac9da0949d2ad65a907fe9a9ef7b70fe9",
    ),
    (
        "commit_head",
        0x52FF5818,
        0x52FF5840,
        "6390465a13b15d02a776a38b91c454a08372d05b8a6175de11ee97a0bdebddbd",
    ),
    (
        "commit_return",
        0x52FF5860,
        0x52FF586C,
        "1a372dc9c38bfcd3f44d2eff1ed28c4d4b0758a525b7f5e6419eacd42802b594",
    ),
    (
        "block_count",
        0x532974A8,
        0x53297510,
        "b38b49549511613e40b475af6ce7e8c9c205010468b95671340817c52eda4f98",
    ),
    (
        "block_size",
        0x532971DC,
        0x532971E4,
        "732254e783751fcde0d42a21270c5e4b8f2ea029fe41215bd85bfbcc79455a7f",
    ),
    (
        "unsigned_divide",
        0x526A8330,
        0x526A8340,
        "c7d1d71906329593ec9d2ef2fb65b89c950fa0a162d8de5e82d55f31f97647fe",
    ),
    (
        "unsigned_divmod",
        0x526A834C,
        0x526A8364,
        "291288c08bc3f1d5e5d7ae7c91d8c9a98f7a0c6fe05db03457343303e3afc288",
    ),
    (
        "boot_table_setup",
        0x50B00C0C,
        0x50B00C70,
        "56728487f3ad1b8460add6d1997493e5d6559322d2f4c11e5c7cd20c20ae32ab",
    ),
    (
        "boot_index6_gate",
        0x50B00F58,
        0x50B00F68,
        "35806db4f120d10cbfe12ce01583e7daa3f0b9018917e627c03556f79a24c986",
    ),
    (
        "boot_index6_read",
        0x50B01050,
        0x50B01094,
        "468253f0eb0509b9fb8662e3c40dc04ad0e77b8f84058f183201709131bc3c5e",
    ),
)

EXPECTED_VALUE_FLOW = (
    ("read", 0x52FF200C, 0x10005078, 0x43000000),
    ("write", 0x52FF2020, 0x50B733A8, 0x43000000),
    ("write", 0x52FF5908, 0x50B733B4, 0xDC8800),
    ("write", 0x52FF590C, 0x50B733B8, 0x6E44),
    ("read", 0x50B00F58, 0x50B011C0, 0x50B73100),
    ("read", 0x50B00F5C, 0x50B733A0, 0x8000000),
    ("read", 0x50B01050, 0x50B733A4, 0x0),
    ("read", 0x50B01068, 0x50B733B8, 0x6E44),
    ("read", 0x50B0106C, 0x50B733B0, 0x72A00),
    ("read", 0x50B01070, 0x50B733A8, 0x43000000),
)

EXPECTED_STUB_RETURNS = (
    (0x530FCED4, 0x52FF1F14),
    (0x530FCED4, 0x52FF1F38),
    (0x53297A84, 0x52FF58EC),
    (0x53297A84, 0x52FF5838),
    (0x50B03F04, 0x50B00C68),
    (0x50B03F04, 0x50B01094),
)


def run(rtos, boot, part_record, initfs, bank):
    import unicorn
    from unicorn import (
        Uc,
        UC_ARCH_ARM,
        UC_MODE_ARM,
        UC_HOOK_CODE,
        UC_HOOK_MEM_READ,
        UC_HOOK_MEM_WRITE,
        UC_PROT_READ,
        UC_PROT_EXEC,
    )
    from unicorn.arm_const import (
        UC_CPU_ARM_CORTEX_A7,
        UC_ARM_REG_CPSR,
        UC_ARM_REG_R0,
        UC_ARM_REG_R1,
        UC_ARM_REG_R2,
        UC_ARM_REG_R3,
        UC_ARM_REG_R4,
        UC_ARM_REG_R5,
        UC_ARM_REG_R6,
        UC_ARM_REG_R7,
        UC_ARM_REG_R8,
        UC_ARM_REG_R9,
        UC_ARM_REG_R10,
        UC_ARM_REG_R11,
        UC_ARM_REG_R12,
        UC_ARM_REG_LR,
        UC_ARM_REG_PC,
        UC_ARM_REG_SP,
    )

    sha, BASE, BOOT_BASE = bank.sha, bank.BASE, bank.BOOT_BASE
    R = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
    clobbered = (*R[1:], UC_ARM_REG_R12)
    saved = (
        UC_ARM_REG_R4,
        UC_ARM_REG_R5,
        UC_ARM_REG_R6,
        UC_ARM_REG_R7,
        UC_ARM_REG_R8,
        UC_ARM_REG_R9,
        UC_ARM_REG_R10,
        UC_ARM_REG_R11,
        UC_ARM_REG_SP,
    )
    assert sha(rtos) == bank.SHA and sha(boot) == bank.BOOT_SHA
    assert sha(part_record[16:]) == PART_SHA and sha(initfs) == INITFS_SHA
    assert struct.unpack_from("<8sHHI", part_record) == (b"PARTPARA", 2, 65535, 516)
    for name, start, end, digest in RANGES:
        data, base = (boot, BOOT_BASE) if start < BASE else (rtos, BASE)
        assert (
            sha(data[start - base : end - base]) == digest
        ), f"Source range SHA-256 mismatch: {name}"
    u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    rounded = lambda n: (n + 4095) & ~4095
    for a, n in [
        (BASE, rounded(len(rtos))),
        (BOOT_BASE, 0x10000),
        (0x50B70000, 0x20000),
        (0x10000000, 0x40000),
        (SOURCE, rounded(len(initfs))),
        (DEST, rounded(len(initfs)) + 0x1000),
    ]:
        u.mem_map(a, n)
    u.mem_write(BASE, rtos)
    u.mem_write(BOOT_BASE, boot)
    u.mem_write(RECORD, part_record)
    u.mem_write(SOURCE, initfs)
    for a, n in [(BASE, rounded(len(rtos))), (BOOT_BASE, 0x10000)]:
        u.mem_protect(a, n, UC_PROT_READ | UC_PROT_EXEC)
    u.mem_protect(RECORD, 0x1000, UC_PROT_READ)
    u.mem_protect(SOURCE, rounded(len(initfs)), UC_PROT_READ)
    u.mem_write(DEST, b"\xa5" * (rounded(len(initfs)) + 0x1000))
    p = lambda a, v: u.mem_write(a, struct.pack("<I", v & 0xFFFFFFFF))
    w = lambda a: int.from_bytes(u.mem_read(a, 4), "little")
    args = lambda: [u.reg_read(r) for r in R]
    u.reg_write(UC_ARM_REG_CPSR, 0x10)
    stage = "setup"
    end = STOP
    events = []
    writes = []
    media = {}
    instructions = {}
    last_pc = None
    value_flow, stub_returns = [], []
    watched = {(kind, pc, address) for kind, pc, address, _ in EXPECTED_VALUE_FLOW}
    pending_return = None

    def ret(value):
        nonlocal pending_return
        assert pending_return is None
        lr = u.reg_read(UC_ARM_REG_LR)
        pending_return = (last_pc, lr, value, tuple(u.reg_read(reg) for reg in saved))
        for reg in clobbered:
            u.reg_write(reg, 0xDEADC000 + reg)
        u.reg_write(UC_ARM_REG_R0, value)
        u.reg_write(UC_ARM_REG_PC, lr)

    def hook(uc, a, size, _):
        nonlocal last_pc, pending_return
        last_pc = a
        if pending_return is not None:
            entry, lr, value, registers = pending_return
            assert a == lr and uc.reg_read(UC_ARM_REG_R0) == value
            assert tuple(uc.reg_read(reg) for reg in saved) == registers
            assert all(uc.reg_read(reg) == 0xDEADC000 + reg for reg in clobbered)
            stub_returns.append((entry, a))
            pending_return = None
        if a == end:
            uc.emu_stop()
            return
        if a == 0x530FCED4:
            events.append(dict(stage=stage, model="diagnostic", pc=hex(a), returned=0))
            ret(0)
            return
        if a == 0x53297A84:
            av = args()
            assert stage in ("initfs_write", "table_commit") and av[0] == DRIVER
            data = bytes(u.mem_read(av[3], av[2] * 512))
            media[av[1]] = data
            events.append(
                dict(
                    stage=stage,
                    model="media_write",
                    arguments=[hex(x) for x in av],
                    bytes=len(data),
                    sha256=sha(data),
                    returned=1,
                )
            )
            ret(1)
            return
        if a == 0x50B03F04:
            av = args()[:3]
            assert stage in ("boot_table_reload", "boot_initfs_read")
            data = media[av[0]]
            assert len(data) == av[1] * 512
            u.mem_write(av[2], data)
            events.append(
                dict(
                    stage=stage,
                    model="media_read",
                    arguments=[hex(x) for x in av],
                    bytes=len(data),
                    sha256=sha(data),
                    returned=0,
                )
            )
            ret(0)
            return
        assert any(x <= a and a + size <= z for _, x, z, _ in RANGES), (
            stage,
            hex(a),
            "uncovered original code",
        )
        instructions.setdefault(stage, []).append(a)

    def observe_value(uc, access, address, size, value, kind):
        if (kind, last_pc, address) in watched:
            assert size == 4
            value_flow.append(
                (kind, last_pc, address, w(address) if kind == "read" else value)
            )
        if kind == "write" and address < TABLE + N and TABLE < address + size:
            assert TABLE <= address and address + size <= TABLE + N
            writes.append(
                dict(
                    stage=stage,
                    pc=hex(last_pc),
                    address=hex(address),
                    size=size,
                    value=value,
                )
            )

    u.hook_add(UC_HOOK_CODE, hook)
    u.hook_add(UC_HOOK_MEM_READ, observe_value, user_data="read")
    u.hook_add(UC_HOOK_MEM_WRITE, observe_value, user_data="write")

    def execute(label, start, stop=STOP, regs=None):
        nonlocal stage, end
        stage, end = label, stop
        u.reg_write(UC_ARM_REG_SP, STACK)
        u.reg_write(UC_ARM_REG_LR, STOP)
        for reg, value in (regs or {}).items():
            u.reg_write(reg, value)
        u.emu_start(start, STOP, count=20000)
        assert u.reg_read(UC_ARM_REG_PC) == stop, (
            stage,
            hex(u.reg_read(UC_ARM_REG_PC)),
        )
        assert u.reg_read(UC_ARM_REG_SP) == STACK
        return u.reg_read(UC_ARM_REG_R0)

    u.mem_write(OBJ, b"\xa7" * 0x1C)
    execute("constructor", 0x52FF52D4, regs={R[0]: OBJ})
    assert bytes(u.mem_read(OBJ + 0x10, 1)) == b"\0" and w(OBJ + 0x18) == N
    # The replay supplies object bindings and common +4 selector words.
    for a, v in [
        (OBJ + 8, DRIVER),
        (OBJ + 0x14, TABLE),
        (CTX + 8, DRIVER),
        (CTX + 0x4C, OBJ),
        (DRIVER, VT),
        (VT + 0x4C, 0x532971DC),
        (VT + 0x2C, 0x53297A84),
    ]:
        p(a, v)
    u.mem_write(TABLE - 16, b"\xa5" * (N + 32))
    for i in range(32):
        p(TABLE + 0x870 * i + 4, 0 if i == 6 else 0xA5A50000 + i)
    before = bytes(u.mem_read(TABLE, N))
    selectors = [w(TABLE + i * 0x870 + 4) for i in range(32)]
    execute(
        "kind2_layout",
        0x52FF2A24,
        0x52FF2BDC,
        {
            UC_ARM_REG_R4: len(part_record),
            UC_ARM_REG_R5: RECORD,
            UC_ARM_REG_R6: CTX,
            UC_ARM_REG_R9: 1,
        },
    )
    assert w(CTX + 0x40) == RECORD + 16 and w(CTX + 0x48) == 32
    expected = bytearray(before)
    part = part_record[16:]
    lba = int.from_bytes(part[:4], "little")
    rows = []
    for i in range(32):
        cap, dest, count, entry = struct.unpack_from("<4I", part, 4 + 16 * i)
        for off, value in [
            (0, cap),
            (8, dest),
            (12, entry),
            (16, lba),
            (20, count * 512),
            (24, count),
        ]:
            struct.pack_into("<I", expected, 0x870 * i + off, value)
        rows.append(
            dict(
                index=i,
                capacity=cap,
                destination=hex(dest),
                lba=hex(lba),
                initial_count=count,
            )
        )
        lba = (lba + (cap + 511) // 512) & 0xFFFFFFFF
    assert bytes(u.mem_read(TABLE, N)) == expected
    assert rows[6]["lba"] == "0x72a00" and rows[6]["destination"] == "0x43000000"
    layout_hash = sha(bytes(expected))
    assert (
        execute(
            "initfs_write",
            0x52FF586C,
            regs={R[0]: OBJ, R[1]: 6, R[2]: len(initfs), R[3]: SOURCE},
        )
        == 1
    )
    struct.pack_into("<II", expected, 6 * 0x870 + 0x14, len(initfs), len(initfs) // 512)
    assert bytes(u.mem_read(TABLE, N)) == expected
    assert execute("table_commit", 0x52FF5818, regs={R[0]: OBJ}) == 1
    assert media[0] == expected and media[0x72A00] == initfs
    assert [w(TABLE + i * 0x870 + 4) for i in range(32)] == selectors
    assert all(
        not any(
            TABLE + i * 0x870 + 4 <= int(x["address"], 16) < TABLE + i * 0x870 + 8
            for i in range(32)
        )
        for x in writes
    )
    assert len(writes) == 194 and all(x["size"] == 4 for x in writes)
    for st, pc, off, value in [
        ("kind2_layout", 0x52FF2020, 8, DEST),
        ("initfs_write", 0x52FF5908, 0x14, len(initfs)),
        ("initfs_write", 0x52FF590C, 0x18, len(initfs) // 512),
    ]:
        assert (
            dict(
                stage=st,
                pc=hex(pc),
                address=hex(TABLE + 6 * 0x870 + off),
                size=4,
                value=value,
            )
            in writes
        )
    committed_hash = sha(bytes(expected))
    # Poison table RAM, then explicitly pass table LBA 0 to the BOOT fragment.
    u.mem_write(TABLE, b"\x5b" * N)
    execute("boot_table_reload", 0x50B00C0C, 0x50B00C70, {R[0]: 0})
    assert (
        u.reg_read(UC_ARM_REG_R5) == TABLE and bytes(u.mem_read(TABLE, N)) == expected
    )
    execute("boot_initfs_read", 0x50B00F58, 0x50B01094)
    assert (
        bytes(u.mem_read(TABLE, N)) == expected
        and bytes(u.mem_read(DEST, len(initfs))) == initfs
    )
    assert bytes(
        u.mem_read(DEST + len(initfs), rounded(len(initfs)) + 0x1000 - len(initfs))
    ) == b"\xa5" * (rounded(len(initfs)) + 0x1000 - len(initfs))
    assert (
        bytes(u.mem_read(TABLE - 16, 16)) == b"\xa5" * 16
        and bytes(u.mem_read(TABLE + N, 16)) == b"\xa5" * 16
    )
    assert (
        bytes(u.mem_read(BASE, len(rtos))) == rtos
        and bytes(u.mem_read(BOOT_BASE, len(boot))) == boot
    )
    assert (
        bytes(u.mem_read(RECORD, len(part_record))) == part_record
        and bytes(u.mem_read(SOURCE, len(initfs))) == initfs
    )
    io = [x for x in events if x["model"] != "diagnostic"]
    assert [(x["stage"], x["arguments"]) for x in io] == [
        ("initfs_write", [hex(DRIVER), "0x72a00", "0x6e44", hex(SOURCE)]),
        ("table_commit", [hex(DRIVER), "0x0", "0x87", hex(TABLE)]),
        ("boot_table_reload", ["0x0", "0x87", hex(TABLE)]),
        ("boot_initfs_read", ["0x72a00", "0x6e44", "0x43000000"]),
    ]
    assert pending_return is None and tuple(stub_returns) == EXPECTED_STUB_RETURNS
    assert tuple(value_flow) == EXPECTED_VALUE_FLOW
    counts = {label: len(addresses) for label, addresses in instructions.items()}
    assert list(counts.values()) == [11, 2727, 141, 81, 25, 16]
    ranges = [
        dict(name=name, start=hex(start), end=hex(end), sha256=digest)
        for name, start, end, digest in RANGES
    ]
    return dict(
        verified=True,
        engine=dict(
            name="Unicorn", version=unicorn.__version__, cpu="Cortex-A7", mode="ARM"
        ),
        inputs=dict(
            rtos_sha256=bank.SHA,
            boot_sha256=bank.BOOT_SHA,
            partpara_sha256=PART_SHA,
            initfs_sha256=INITFS_SHA,
        ),
        source_ranges=ranges,
        stage_instruction_callbacks=counts,
        observed_instruction_addresses={
            k: [hex(a) for a in sorted(set(v))] for k, v in instructions.items()
        },
        events=events,
        native_table_stores=writes,
        layout_rows=rows,
        writer_bank_from_original_constructor=0,
        observed_value_flow=[
            dict(access=kind, pc=hex(pc), address=hex(address), value=hex(value))
            for kind, pc, address, value in value_flow
        ],
        checked_stub_returns=[
            dict(entry=hex(entry), return_pc=hex(pc)) for entry, pc in stub_returns
        ],
        stub_abi="Return via LR with the modeled r0 result and r1/r2/r3/r12 poisoned. SP and r4–r11 preserved.",
        source_record=dict(
            address=hex(RECORD),
            decoded_header_offset="0x294",
            size=len(part_record),
            kind=2,
            index=65535,
            payload_pointer=hex(RECORD + 16),
            entry_count=32,
        ),
        consumer_selector_supplied=0,
        boot_table_lba_supplied=0,
        all_native_selector_fields_preserved=True,
        layout_table_sha256=layout_hash,
        committed_and_reloaded_table_sha256=committed_hash,
        loaded_initfs_sha256=sha(bytes(u.mem_read(DEST, len(initfs)))),
        loaded_initfs_bytes=len(initfs),
        destination_tail_and_table_canaries_preserved=True,
        all_original_guest_inputs_unchanged=True,
        final_stop_pc=hex(u.reg_read(UC_ARM_REG_PC)),
        limits=[
            "The replay supplies object/table binding and record 6 selector 0. The writer's separate bank byte is initialized by its original constructor.",
            "The host joins six original fragments, bypassing the full package walker, reset, BOOT prologue and preceding resource loads.",
            "The host passes table LBA 0 to BOOT. Header generation and table selection are outside the trace.",
            "The model stores bytes keyed by start LBA and returns success by construction. Partition switching, device I/O and DMA are outside the trace.",
            "The final stop is after the modeled INITFS read return and before the original BOOT comparison at 0x50b01094.",
            "Diagnostic 0x530fced4, driver write 0x53297a84 and BOOT read 0x50b03f04 are modeled. Physical placement, authentication and boot are unverified.",
        ],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        raise FileExistsError(args.output)
    if not args.decoded.is_file() or args.decoded.stat().st_size != DECODED_SIZE:
        raise ValueError("Original decoded carrier of 78,683,892 bytes is required")

    sys.dont_write_bytecode = True
    bank = load_dependency()
    data = args.decoded.read_bytes()
    assert bank.sha(data) == bank.DECODED_SHA, "Unknown decoded input SHA-256"
    assert struct.unpack_from("<8sHHI", data, INITFS_HEADER_OFFSET) == (
        b"INITFS\0\0", 4, 6, INITFS_SIZE
    )
    rtos, boot = bank.load(args.decoded)
    part_record = data[PART_HEADER_OFFSET:PART_END]
    initfs = data[INITFS_OFFSET : INITFS_OFFSET + INITFS_SIZE]
    del data
    report = run(rtos, boot, part_record, initfs, bank)
    assert (
        bank.sha(args.decoded.read_bytes()) == bank.DECODED_SHA
    ), "Decoded input changed during replay"
    report.update(
        decoded_sha256=bank.DECODED_SHA,
        disk_input_unchanged=True,
        public_dependencies_sha256_lf={DEPENDENCY: DEPENDENCY_SHA},
        initfs_record=dict(
            decoded_header_offset=hex(INITFS_HEADER_OFFSET),
            decoded_payload_offset=hex(INITFS_OFFSET),
            kind=4,
            index=6,
            payload_size=INITFS_SIZE,
            header_parsed_by_host=True,
        ),
    )
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            dict(
                verified=True,
                loaded_bytes=report["loaded_initfs_bytes"],
                native_table_stores=len(report["native_table_stores"]),
                stop=report["final_stop_pc"],
            )
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
