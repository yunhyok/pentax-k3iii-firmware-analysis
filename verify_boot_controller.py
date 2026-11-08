"""Check BOOT transport status branches in synthetic RAM, without device I/O."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import *
from inspect_firmware import named_records
from rtos_catalog import require
from verify_deep_analysis import verify_code
from verify_boot_path import BASE, SHA


def run(blob):
    require(hashlib.sha256(blob).hexdigest() == SHA, 'BOOT hash mismatch')
    u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
    u.mem_map(BASE, 0x10000)
    u.mem_map(0x10000000, 0x10000)
    u.mem_write(BASE, blob)
    host, command, registers, device = 0x10000000, 0x10002000, 0x10004000, 0x10005000
    stop = BASE + 0xff00
    calls = []

    def put(a, v): u.mem_write(a, struct.pack('<I', v))
    def word(a): return struct.unpack('<I', u.mem_read(a, 4))[0]
    def byte(a): return u.mem_read(a, 1)[0]

    def hook(uc, address, size, data):
        if address == stop:
            uc.emu_stop()
        elif address == 0x50b02204:
            # shortcut: DMA teardown is stubbed; these cases test status decoding only.
            calls.append(hex(address))
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == 0x50b028c0:
            raise ValueError('Unexpected recovery path outside test scope')

    u.hook_add(UC_HOOK_CODE, hook)

    def reset():
        u.mem_write(host, bytes(0x6000))
        put(host + 0x410, registers)
        put(host + 0x414, device)
        put(host + 0x418, command)
        u.mem_write(host + 0x44c, b'\x01')
        u.mem_write(command + 0x3b, b'\xff')
        calls.clear()

    def execute(status):
        for reg in range(UC_ARM_REG_R0, UC_ARM_REG_R12 + 1): u.reg_write(reg, 0)
        u.reg_write(UC_ARM_REG_CPSR, 0x10)
        u.reg_write(UC_ARM_REG_SP, 0x1000f000)
        u.reg_write(UC_ARM_REG_LR, stop)
        u.reg_write(UC_ARM_REG_R0, host)
        u.reg_write(UC_ARM_REG_R1, status)
        u.emu_start(0x50b0306c, stop + 4, count=500)
        require(u.reg_read(UC_ARM_REG_PC) == stop, 'Status handler did not return')

    rows = []
    error_cases = [(0x2000000, 0x21), (0x1000000, 0x2b), (0x800000, 0x22),
                   (0x400000, 0x23), (0x200000, 0x24), (0x100000, 0x25),
                   (0x80000, 0x26), (0x40000, 0x2a), (0x20000, 0x29),
                   (0x10000, 0x28), (0x30000, 0x27), (0, 9), (0x2010000, 0x21)]
    for bits, expected in error_cases:
        reset()
        put(registers + 0x30, bits | 0x8000)
        execute(0x8000)
        require(byte(command + 0x3b) == expected, 'Error priority/code mismatch')
        require(calls == ['0x50b02204'], 'Unexpected teardown call count')
        rows.append(dict(group='transport_error', status=hex(bits | 0x8000), code=expected))
    for response in [0, 0x80, 0x100, 0x80000000]:
        reset()
        u.mem_write(device + 0x10, b'\x01\x00')
        u.mem_write(command + 0x15, b'\x01')
        u.mem_write(command + 0x17, b'\x01')
        u.mem_write(command + 0x3d, b'\x04')
        put(registers + 0x10, response)
        execute(1)
        expected = 1 if response & 0xfdfc8080 else 0xff
        require(byte(command + 0x3b) == expected, 'Response status mask mismatch')
        require(word(command + 0x20) == response, 'Response register copy mismatch')
        require(not calls, 'Unexpected teardown in response-only case')
        rows.append(dict(group='response_mask', response=hex(response), code=expected))
    return dict(passed=True, image_sha256=SHA, cases=len(rows), cases_detail=rows,
                stubbed_calls=['0x50b02204'],
                scope='Original status handler0x50b0306c..0x50b03438, synthetic host/command/register RAM; DMA teardown stubbed, recovery suppressed by host+0x44c=1. No MMIO semantics, media, full command, authentication or boot execution.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('decoded', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    data = a.decoded.read_bytes()
    require(hashlib.sha256(data).hexdigest() == '7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9', 'Decoded hash mismatch')
    records, _ = named_records(data)
    record = next(r for r in records if r['name'] == 'BOOT')
    blob = data[record['payload_offset']:record['payload_offset'] + record['size']]
    evidence = json.loads((Path(__file__).resolve().parent / 'analysis/boot-controller-evidence.json').read_text(encoding='utf-8'))
    counts = verify_code(blob, evidence['code'], base=BASE)
    result = run(blob)
    result['source_verification'] = dict(zip(('ranges', 'transfers', 'words'), counts))
    a.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print({'passed': True, 'cases': result['cases']})


if __name__ == '__main__': main()
