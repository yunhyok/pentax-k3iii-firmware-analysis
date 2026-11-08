"""Check packaged M0 metadata and execute bounded Thumb fragments in synthetic RAM."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from capstone.arm import ARM_OP_IMM
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
from inspect_firmware import named_records
from rtos_catalog import require

BASE = 0x3ffe0300
SHA = '63dd8f3b2668ef68f3ab0f8ecd0f4cda8c46a78c5388646fc9e1fe85e39a070e'


def run(blob, evidence):
    require(hashlib.sha256(blob).hexdigest() == SHA, 'M0 hash mismatch')
    ranges = evidence['functions'] + evidence['fragments']
    for row in ranges:
        a, z = int(row['start'], 16), int(row['end'], 16)
        require(BASE <= a < z <= BASE + len(blob), 'Invalid M0 range')
        require(hashlib.sha256(blob[a-BASE:z-BASE]).hexdigest() == row['sha256'], 'M0 range mismatch')
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    for row in evidence['transfers']:
        a = int(row['site'], 16)
        require(any(int(r['start'], 16) <= a < int(r['end'], 16) for r in ranges), 'Uncovered M0 transfer')
        i = next(md.disasm(blob[a-BASE:a-BASE+4], a))
        require(i.mnemonic == row['kind'] and i.size == row['size'] and
                i.operands[0].type == ARM_OP_IMM and i.operands[0].imm == int(row['target'], 16), 'M0 transfer mismatch')
    for row in evidence['pointer_words']:
        a = int(row['address'], 16)
        require(BASE <= a <= BASE + len(blob) - 4, 'Invalid M0 literal')
        require(struct.unpack_from('<I', blob, a-BASE)[0] == int(row['value'], 16), 'M0 literal mismatch')

    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for a, n in [(0x3ffe0000, 0x20000), (0x20000000, 0x10000),
                 (0x4d021000, 0x1000), (0x70b70000, 0x20000), (0x10000000, 0x10000)]:
        u.mem_map(a, n)
    u.mem_write(BASE, blob)
    stops, allowed, writes = set(), [], []

    def put(a, v):
        u.mem_write(a, struct.pack('<I', v))

    def word(a):
        return struct.unpack('<I', u.mem_read(a, 4))[0]

    def code(uc, a, size, data):
        if a in stops:
            uc.emu_stop()
        else:
            require(any(x <= a < z for x, z in allowed), 'Execution left declared M0 fragment')

    u.hook_add(UC_HOOK_CODE, code)
    u.hook_add(UC_HOOK_MEM_WRITE, lambda uc, access, a, size, v, data: writes.append((a, size, v)))

    def execute(start, end, targets, registers):
        stops.clear()
        stops.update(targets)
        allowed[:] = [(start, end)]
        writes.clear()
        for r in range(UC_ARM_REG_R0, UC_ARM_REG_R12 + 1):
            u.reg_write(r, 0)
        u.reg_write(UC_ARM_REG_CPSR, 0x30)
        u.reg_write(UC_ARM_REG_SP, 0x1000e000)
        u.reg_write(UC_ARM_REG_LR, 0x1000f001)
        for r, v in registers.items():
            u.reg_write(r, v)
        u.emu_start(start | 1, 0x1000f000, count=200)
        pc = u.reg_read(UC_ARM_REG_PC)
        require(pc in stops, 'M0 fragment failed to reach declared stop')
        return pc

    rows = []
    for mode in (1, 2):
        for entry in (0, 0x50b00000, 0x50b0003c):
            put(0x3fffa800, entry)
            for a in (0x20000000, 0x20000020, 0x2000fffc, 0x4d021090):
                put(a, 0xa5a5a5a5)
            if mode == 1:
                execute(0x3ffe4db4, 0x3ffe4ddc, [0x1000f000], {})
            else:
                # shortcut: warm prelude is hardware-dependent; test only the source-backed release tail.
                execute(0x3fff01a8, 0x3fff01e8, [0x3fff01e8], {})
            expected = [] if mode == 1 and entry == 0 else [(0x20000000, 4, 0xe59ff018)]
            if expected:
                if mode == 2:
                    expected += [(a, 4, 0xeafffffe) for a in range(0x20000004, 0x20000020, 4)]
                expected += [(0x20000020, 4, entry), (0x2000fffc, 4, mode), (0x4d021090, 4, 0xf3f)]
            require(writes == expected, 'M0 release write sequence mismatch')
            rows.append(dict(group='release_tail', mode=mode, entry=hex(entry), writes=[dict(address=hex(a), value=hex(v)) for a, _, v in writes]))
    for bank in (0, 1):
        for entry in (0, 0x50b00000):
            put(0x70b70100 + bank * 0x434 + 0xc, entry)
            put(0x3fffa800, 0xa5a5a5a5)
            execute(0x3ffe492a, 0x3ffe4938, [0x3ffe4938], {UC_ARM_REG_R9: bank, UC_ARM_REG_R7: 0x70b70100})
            require(word(0x3fffa800) == entry, 'M0 selected entry copy mismatch')
            rows.append(dict(group='record0_entry_after_read_success', bank=bank, entry=hex(entry)))
    for block in (0, 0x1234, 0xffff):
        pc = execute(0x3ffe4896, 0x3ffe48aa, [0x3ffe48aa, 0x3ffe4918], {UC_ARM_REG_R0: block})
        require(pc == (0x3ffe4918 if block == 0xffff else 0x3ffe48aa), 'M0 table candidate guard mismatch')
        if block != 0xffff:
            require([u.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)] == [block, 0x87, 0x50b70100], 'M0 table DMA arguments mismatch')
        rows.append(dict(group='table_read_arguments', block=block, stop=hex(pc)))
    return dict(passed=True, image_sha256=SHA, ranges=len(ranges), transfers=len(evidence['transfers']),
                literal_words=len(evidence['pointer_words']), cases=len(rows), cases_detail=rows,
                scope='Original Thumb release, successful-read entry-copy tail and pre-read arguments in synthetic RAM. MMIO is ordinary mapped RAM; no real processor release, storage, ROM, authentication or cross-core address alias tested.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('decoded', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    decoded = a.decoded.read_bytes()
    require(hashlib.sha256(decoded).hexdigest() == '7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9', 'Decoded hash mismatch')
    records, _ = named_records(decoded)
    record = next(r for r in records if r['name'] == 'M0')
    evidence = json.loads((Path(__file__).resolve().parent / 'analysis/preboot-mode-evidence.json').read_text())
    bp = evidence['bootpara']
    para = decoded[bp['payload_offset']:bp['payload_offset']+bp['size']]
    require(hashlib.sha256(para).hexdigest() == bp['sha256'], 'BOOTPARA mismatch')
    require(struct.unpack_from('<II', para, 4) == (BASE, BASE), 'M0 base fields mismatch')
    blob = decoded[record['payload_offset']:record['payload_offset']+record['size']]
    require(record['payload_offset'] == evidence['image']['payload_offset'] and len(blob) == evidence['image']['size'], 'M0 record mismatch')
    result = run(blob, evidence)
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('passed', 'ranges', 'transfers', 'literal_words', 'cases')}))


if __name__ == '__main__':
    main()
