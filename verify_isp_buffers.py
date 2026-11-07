"""Execute two original ARM descriptor builders with synthetic buffers, not pixels."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from decompile_sample import BASE, RTOS_OFFSET, RTOS_SIZE, RTOS_SHA256

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('decoded', type=Path)
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
with args.decoded.open('rb') as stream:
    stream.seek(RTOS_OFFSET)
    data = stream.read(RTOS_SIZE)
if hashlib.sha256(data).hexdigest() != RTOS_SHA256:
    p.exit(1, 'RTOS hash mismatch\n')
import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import *

u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
size = (len(data) + 4095) & ~4095
u.mem_map(BASE, size)
u.mem_write(BASE, data)
u.mem_protect(BASE, size, UC_PROT_READ | UC_PROT_EXEC)
D = 0x10000000
u.mem_map(D, 0x100000)
M, P, PLAN = D + 0x10000, D + 0x20000, D + 0x21000
B2R, R2Y = D + 0x22000, D + 0x23000
BDIN, BDOUT, RDIN = D + 0x24000, D + 0x25000, D + 0x26000
STATE, PTR, ROWS, CONTROL = D + 0x27000, D + 0x28000, D + 0x29000, D + 0x2a000
SP, RET = D + 0xf0000, D + 0x100

def w(a, v):
    u.mem_write(a, struct.pack('<I', v))

def h(a, v):
    u.mem_write(a, struct.pack('<H', v))

def read(a, fmt):
    return struct.unpack(fmt, u.mem_read(a, struct.calcsize(fmt)))

def run(a, extra):
    for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                UC_ARM_REG_R12):
        u.reg_write(reg, 0)
    for reg, value in ((UC_ARM_REG_SP, SP), (UC_ARM_REG_LR, RET),
                       (UC_ARM_REG_R0, M), (UC_ARM_REG_R1, P),
                       (UC_ARM_REG_R2, index), (UC_ARM_REG_R3, PLAN)):
        u.reg_write(reg, value)
    u.mem_write(SP, struct.pack('<' + 'I' * len(extra), *extra))
    u.emu_start(a, RET, count=10000)
    assert u.reg_read(UC_ARM_REG_PC) == RET

cases = []
for mode in (0, 1):
    for bfmt in (0, 8):
        for rfmt in (0, 8):
            for index in range(4):
                u.mem_write(M, bytes(0x20000))
                for address, value in ((PLAN+0x14, B2R), (PLAN+0x18, R2Y),
                        (B2R+0x10, BDIN), (B2R+0x14, BDOUT),
                        (R2Y+0xc, CONTROL), (R2Y+0xa0, RDIN),
                        (M+0xa030, STATE), (STATE+0xc4, PTR), (PTR, ROWS),
                        (P+8, 0x20000000), (P+0x18, 123), (P+0x1c, 456)):
                    w(address, value)
                bases = (0x21000000, 0x22000000, 0x23000000)
                for off, value in zip((0x60, 0x64, 0x68), bases):
                    w(P+off, value)
                h(ROWS+0xc+2*index, 37+index)
                h(STATE+0x152+2*index, 11+index)
                u.mem_write(BDIN, bytes([bfmt]))
                u.mem_write(BDOUT, bytes([bfmt]))
                u.mem_write(RDIN, bytes([rfmt]))
                run(0x52e5a500, [mode])
                run(0x52e5a62c, [PLAN, mode])
                step = struct.unpack_from('<I', data, 0x538e2b68-BASE+4*index)[0] + 0x26
                rows = struct.unpack_from('<I', data, 0x538e2cac-BASE+4*index)[0] & 0xffff
                bout = read(BDOUT+4, '<3I')
                rin = read(RDIN+4, '<3I')
                for actual, fmt in ((bout, bfmt), (rin, rfmt)):
                    expected = tuple(v+step*(1 if fmt==0 else 2) for v in bases) if mode else (0,0,0)
                    assert actual == expected
                assert read(BDIN+4, '<I')[0] == (0x20000000+step*(1 if bfmt==0 else 2) if mode else 0)
                assert read(BDIN+8, '<H')[0] == (rows if mode else 37+index)
                assert read(BDOUT+0x10, '<H')[0] == read(RDIN+0x10, '<H')[0] == (rows if mode else 0)
                assert read(BDIN+0x10, '<H')[0] == read(BDOUT+0x18, '<H')[0] == read(RDIN+0x18, '<H')[0] == 0
                assert read(R2Y+0x18, '<2I') == (134+index, 467+index)
                if bfmt == rfmt:
                    assert bout == rin
                cases.append({'mode':mode, 'b2r_format':bfmt, 'r2y_format':rfmt,
                    'index':index, 'address_triples_equal':bout==rin,
                    'output_sha256':hashlib.sha256(bytes(u.mem_read(BDIN,0x20))+bytes(u.mem_read(BDOUT,0x20))+bytes(u.mem_read(RDIN,0x20))).hexdigest()})
result = {'rtos_sha256':RTOS_SHA256, 'unicorn_version':unicorn.__version__,
    'passed':True, 'case_count':len(cases),
    'scope':'Full ARM functions 52e5a500 and 52e5a62c, formats 0/8, four indices, mode 0/1; synthetic objects, original ROM offset tables. No hooks. No queues, hardware, buffer pixel contents or internal ISP order executed.',
    'cases':cases}
args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
print({k:v for k,v in result.items() if k!='cases'})
