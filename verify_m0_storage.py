"""Check original M0 Thumb read code with a synthetic controller and RAM."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_THUMB
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
)

BASE = 0x3ffe0300
EXPECTED_SHA = "63dd8f3b2668ef68f3ab0f8ecd0f4cda8c46a78c5388646fc9e1fe85e39a070e"
HERE = Path(__file__).resolve().parent
CONTROLLER, CARD, HOST, DEST, ADMA = (
    0x3fff74c0, 0x10001000, 0x10002000, 0x10004000, 0x10008000,
)
STACK, STOP = 0x1000e000, 0x1000f000


def run(blob):
    assert hashlib.sha256(blob).hexdigest() == EXPECTED_SHA
    evidence = json.loads((HERE / "analysis/m0-storage-evidence.json").read_text(encoding="utf-8"))
    allowed = [(int(r["start"], 16), int(r["end"], 16)) for r in
               evidence["functions"] + evidence["fragments"]]
    allowed.append((0x3fff04e2, 0x3fff04f2))  # original byte fill
    rows = []

    def test(name, *, count=1, lba=10, strategy=0xff, ready=1, response=0,
             timeout=False, address_mode=2, salt=0x2468ace0, chunk_mock=None,
             expected_result=0, expected_status=None, expected_commands=()):
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.mem_map(0x3ffe0000, 0x20000)
        u.mem_map(0x10000000, 0x10000)
        u.mem_write(BASE, blob)
        commands, statuses, fifo, chunks = [], [], [], []

        def put32(address, value):
            u.mem_write(address, struct.pack("<I", value))

        def word(address):
            return struct.unpack("<I", u.mem_read(address, 4))[0]

        for address, value in {
            CONTROLLER+0x414: CARD, CONTROLLER+0x410: HOST, CONTROLLER+0x41c: CONTROLLER,
            CONTROLLER+0x420: ADMA, CONTROLLER+0x428: strategy, CARD: CONTROLLER,
            CARD+4: 64, HOST+0x10: response,
        }.items():
            put32(address, value)
        u.mem_write(CONTROLLER+0x449, bytes([ready]))
        u.mem_write(CONTROLLER+0x450, b"\x01")
        u.mem_write(CARD+0xc, struct.pack("<H", 512))
        u.mem_write(CARD+0x10, struct.pack("<HB", 3, address_mode))
        u.mem_write(CARD+0x15, b"\x01")
        u.mem_write(DEST, b"\x5a" * 2048)

        def hook(_u, address, size, _data):
            if address == 0x3fff2090:  # Synthetic monotonic ticks, bounded to the read wait.
                now = 16002 if timeout and u.reg_read(UC_ARM_REG_LR) == 0x3ffe6313 else 1
                u.reg_write(UC_ARM_REG_R0, now)
                u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
                return
            if address == 0x3fff0384:  # AAPCS unsigned division helper.
                quotient = u.reg_read(UC_ARM_REG_R0) // u.reg_read(UC_ARM_REG_R1)
                u.reg_write(UC_ARM_REG_R0, quotient)
                u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
                return
            if address == 0x3ffe71d4 and chunk_mock is not None:
                chunks.append((
                    u.reg_read(UC_ARM_REG_R1), u.reg_read(UC_ARM_REG_R2),
                    u.reg_read(UC_ARM_REG_R3), word(u.reg_read(UC_ARM_REG_SP)),
                ))
                u.reg_write(UC_ARM_REG_R0, chunk_mock[len(chunks)-1])
                u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
                return
            assert any(start <= address < end for start, end in allowed), hex(address)
            if address == 0x3ffe5a12:
                commands.append((word(HOST+0xc) >> 24, word(HOST+8), word(HOST+4) >> 16))
                put32(HOST+0x30, 0x23 if strategy == 0xff else 0x3)
            elif address == 0x3ffe632a:
                put32(HOST+0x30, 0)  # Host write-one-to-clear behavior in synthetic RAM.
            elif address == 0x3ffe6392:
                value = (salt + len(fifo)*0x10203) & 0xffffffff
                fifo.append(value)
                put32(HOST+0x20, value)
            elif address == 0x3ffe6046:
                statuses.append(u.mem_read(u.reg_read(UC_ARM_REG_R2)+0x3b, 1)[0])

        u.hook_add(UC_HOOK_CODE, hook)
        for register, value in (
            (UC_ARM_REG_CPSR, 0x30), (UC_ARM_REG_SP, STACK), (UC_ARM_REG_LR, STOP|1),
            (UC_ARM_REG_R0, lba), (UC_ARM_REG_R1, count), (UC_ARM_REG_R2, DEST),
        ):
            u.reg_write(register, value)
        u.emu_start(0x3ffe6fa9, STOP, count=50000)
        assert u.reg_read(UC_ARM_REG_PC) == STOP, name
        assert u.reg_read(UC_ARM_REG_R0) == expected_result, name
        assert statuses == ([] if expected_status is None else [expected_status]), name
        assert commands == list(expected_commands), (name, commands)
        if fifo:
            assert len(fifo) == count * 128
            assert u.mem_read(DEST, count*512) == struct.pack(f"<{len(fifo)}I", *fifo)
        elif count <= 4:
            assert u.mem_read(DEST, 2048) == b"\x5a" * 2048
        dma = []
        if commands and strategy == 2:
            dma = [word(HOST+0x58), word(ADMA), word(ADMA+4)]
            assert dma == [ADMA, (count*512 << 16) | 0x23, DEST], name
        if chunk_mock is not None:
            expected_chunks = [(lba, DEST, 0x01fffe00, 2)]
            if len(chunk_mock) == 2:
                expected_chunks.append((lba+0xffff, DEST+0x01fffe00, 512, 2))
            assert chunks == expected_chunks, (name, chunks)
        rows.append(dict(name=name, result=expected_result, descriptor_status=statuses,
                         commands=commands, pio_words=len(fifo), dma=dma, chunk_calls=chunks))

    test("zero count", count=0)
    test("bounds rejection", count=2, lba=(64 << 11)-1, expected_result=4)
    test("controller unready", ready=0, expected_result=1)
    test("CMD17 block address PIO", expected_commands=[(17, 10, 1)], expected_status=0)
    test("CMD18 byte address PIO", count=2, address_mode=1, salt=0x9a012345,
         expected_commands=[(18, 10 << 9, 2)], expected_status=0)
    test("card response bit masked as error", response=0x80,
         expected_commands=[(17, 10, 1)], expected_status=1, expected_result=1)
    test("card response bit outside mask", response=0x100,
         expected_commands=[(17, 10, 1)], expected_status=0)
    test("CMD18 DMA descriptor", count=2, strategy=2,
         expected_commands=[(18, 10, 2)], expected_status=0)
    test("poll timeout with pending status", timeout=True,
         expected_commands=[(17, 10, 1)], expected_status=0xff, expected_result=1)
    test("65535 plus one sector chunking", count=65536, chunk_mock=(0, 0))
    test("first chunk error stops next chunk", count=65536, chunk_mock=(1,), expected_result=1)
    return dict(passed=True, image_sha256=EXPECTED_SHA, cases=len(rows), cases_detail=rows,
                scope=("Original Thumb read wrappers and transport driver paths in synthetic RAM. "
                       "Clock, divide helper, host register behavior and chunk-only leaf calls are modeled. "
                       "DMA descriptors are inspected without emulating a DMA engine, card or hardware authentication."))


if __name__ == "__main__":
    from verify_m0_memory import load_decoded, verify_metadata
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('decoded',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    data=load_decoded(a.decoded);blob=data[1208:1208+92164]
    evidence=json.loads((HERE/'analysis/m0-storage-evidence.json').read_text())
    metadata=verify_metadata(blob,evidence);result=run(blob);result['metadata']=metadata
    a.output.write_text(json.dumps(result,indent=2)+'\n');print('Passed',result['cases'],'M0 storage cases and source metadata')
