"""Check offline repacks, malformed inputs and original ARM header/checksum code.

The hardware decompressor, updater state machine, storage writes and boot never run.
"""
import argparse
import json
import struct
from pathlib import Path

from inspect_firmware import decode, sha256
from package_roundtrip import parse_package, encode_stored, read_bounded, ORIGINAL_SHA
from verify_update_resources import sum32, require


def compare_outer(original, edited, original_info, edited_info):
    require(original[:128] == edited[:128], 'Outer header changed')
    a, b = original_info['version_start'], edited_info['version_start']
    require(original[a:a+256] == edited[b:b+256], 'Version table changed')
    a, b = original_info['footer_start'], edited_info['footer_start']
    require(original[a:a+12] == edited[b:b+12] and
            original[a+16:a+20] == edited[b+16:b+20], 'Invariant footer fields changed')


def original_arm_checks(rtos, original, edited, original_decoded, edited_decoded):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
    base = 0x52500000
    require(sha256(rtos) == '342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4', 'RTOS hash mismatch')
    code_start, code_end = 0x52ff4d08, 0x52ff4f88
    rows = []
    for label, package, decoded in [('original', original, original_decoded), ('edited', edited, edited_decoded)]:
        u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        u.mem_map(0x52ff4000, 0x1000)
        u.mem_write(code_start, rtos[code_start-base:code_end-base])
        buffer, context, stop = 0x10000000, 0x20000000, 0x2000f000
        u.mem_map(buffer, (max(len(package), len(decoded))+4095)&~4095)
        u.mem_map(context, 0x10000)
        # Logging on rejected header branches is the only replaced callee.
        logs = []
        def diagnostic(uc, address, size, data):
            logs.append(address)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        u.mem_map(0x530fc000, 0x1000)
        u.hook_add(UC_HOOK_CODE, diagnostic, begin=0x530fced4, end=0x530fced4)
        def run(entry, expected):
            u.reg_write(UC_ARM_REG_R0, context);u.reg_write(UC_ARM_REG_R1, context+0x80)
            u.reg_write(UC_ARM_REG_SP, context+0xe000);u.reg_write(UC_ARM_REG_LR, stop)
            u.emu_start(entry, stop, timeout=60000000)
            require(u.reg_read(UC_ARM_REG_PC) == stop, 'ARM execution did not terminate')
            result = u.reg_read(UC_ARM_REG_R0)
            require(result == expected, 'Original ARM predicate disagreed')
            return result
        u.mem_write(buffer, package)
        u.mem_write(context+8, struct.pack('<II', buffer, len(package)))
        u.mem_write(context+0x18, struct.pack('<II', 0x246, 2))
        result = run(0x52ff4d80, 1)
        require(not logs, 'Unexpected diagnostic on valid header')
        rows.append(dict(image=label, function='header_and_full_outer_checksum', result=result,
                         bytes_summed=len(package), checksum_stubbed=False))
        for field, wrong in [(0x30, 0x245), (0x7c, 0)]:
            saved = bytes(u.mem_read(buffer+field, 4));u.mem_write(buffer+field, struct.pack('<I', wrong))
            rows.append(dict(image=label, function='rejected_header_field', changed_offset=hex(field), result=run(0x52ff4d80, 0)))
            u.mem_write(buffer+field, saved)
        u.mem_write(buffer, decoded)
        u.mem_write(context+0x10, struct.pack('<II', buffer, len(decoded)))
        rows.append(dict(image=label, function='full_inner_checksum', result=run(0x52ff4ee8, 1),
                         bytes_summed=len(decoded), checksum_stubbed=False))
    return dict(cases=len(rows), results=rows, source_range=dict(start=hex(code_start), end=hex(code_end),
                sha256=sha256(rtos[code_start-base:code_end-base])),
                limits='Original ARM header and additive checksum loops run over complete buffers. Error diagnostics only are skipped. Hardware transform, decode wrapper, updater, storage and boot are not executed.')


def run(original, noop, edited, rtos):
    require(sha256(original) == ORIGINAL_SHA, 'Original package hash mismatch')
    before, original_info = parse_package(original)
    after, edited_info = parse_package(edited)
    require(noop == original, 'Unchanged repack differs from original bytes')
    compare_outer(original, edited, original_info, edited_info)
    changes = []
    for a, b in zip(original_info['named_records'], edited_info['named_records']):
        require({k:a[k] for k in ('name','kind','index','payload_offset','size')} ==
                {k:b[k] for k in ('name','kind','index','payload_offset','size')}, 'Record shape changed')
        if a['sha256'] != b['sha256']:changes.append(a['name'])
    require(changes == ['ICONBIN'], 'Expected one ICONBIN edit')
    icon = next(r for r in original_info['named_records'] if r['name'] == 'ICONBIN')
    start, end = icon['payload_offset'], icon['payload_offset']+icon['size']
    require(before[:start] == after[:start] and before[end:-4] == after[end:-4], 'Unexpected decoded changes outside selected payload/checksum')
    changed_pixels_bytes = sum(a != b for a, b in zip(before[start:end], after[start:end]))
    encoder_cases = []
    for size in [4, 16, 32764, 32768, 65528, 65532, 98300]:
        source = bytes((i*23+11)&255 for i in range(size));stream = encode_stored(source)
        result, last, blocks = decode(stream, 0, size)
        require(result == source and last == len(stream) and len(stream)%4 == 0, 'Stored encoding mismatch')
        require(all(b['kind']=='stored' and 0 < b['output_end']-b['output_start'] <= 32767 for b in blocks), 'Stored block bounds mismatch')
        encoder_cases.append(dict(size=size, blocks=len(blocks), stream_size=len(stream)))
    rejected = []
    def reject(label, value, expected):
        try:parse_package(value)
        except ValueError as error:
            require(expected in str(error), 'Unexpected rejection reason: '+str(error))
            rejected.append(dict(case=label, reason=str(error)))
        else:raise AssertionError('Malformed input accepted: '+label)
    reject('truncated_header', original[:100], 'Package size')
    reject('unaligned_package', original[:-1], 'Package size')
    for label, offset, value, error in [
        ('camera_identity',0,0,'camera header'), ('project',0x30,0x245,'project'),
        ('version_count',0x3c,0xffffffff,'record count'), ('magic',0x7c,0,'magic'),
        ('project_repeat',0x78,0,'repeat'), ('footer_type',len(original)-16,3,'type'),
        ('compressed_length',len(original)-12,0xffffffff,'Compressed length'),
        ('decoded_length',len(original)-8,0xffffffff,'decoded length'),
        ('outer_sum',100,1,'Outer checksum'),
        ('outer_bypass',len(original)-4,0xffffffff,'bypass sentinel')]:
        malformed = bytearray(original);struct.pack_into('<I', malformed, offset, value)
        reject(label, malformed, error)
    bad_streams = [b'', b'\0', b'\x80\x03ab', b'\0\5\0\0A\0\1\0\0',
                   b'\0\6\x80\0\0\1\0\0\0\0', b'\0\7\x40\0A\7\1\0\0\0\0']
    for i, stream in enumerate(bad_streams):
        try:decode(stream,0,100)
        except ValueError as error:rejected.append(dict(case='malformed_lz_'+str(i),reason=str(error)))
        else:raise AssertionError('Malformed stream accepted')
    try:decode(encode_stored(b'abcdefgh'),0,7)
    except ValueError as error:rejected.append(dict(case='decompression_output_bound',reason=str(error)))
    else:raise AssertionError('Output bound ignored')
    arm = original_arm_checks(rtos, original, edited, before, after)
    return dict(passed=True, original=original_info, unchanged_byte_identical=True,
                edited=edited_info, changed_records=changes, changed_payload_bytes=changed_pixels_bytes,
                unchanged_outer_header=True, unchanged_version_table=True,
                unchanged_footer_identity_type_and_decoded_length=True,
                unchanged_other_decoded_bytes=True, stored_encoder_cases=encoder_cases,
                malformed_rejections=rejected, original_arm=arm,
                scope='Lossless repack and same-size single-record stored-block reencoding only. No compiler/linker reconstruction, hardware decoder, updater acceptance, device storage or camera boot.')


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','noop','edited','rtos'):p.add_argument(name,type=Path)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(), 'Report output already exists')
    result=run(*(read_bounded(getattr(a,n)) for n in ('original','noop','edited','rtos')))
    with a.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2);output.write('\n')
    print(json.dumps(dict(passed=True,malformed_rejections=len(result['malformed_rejections']),encoder_cases=len(result['stored_encoder_cases']),original_arm_cases=result['original_arm']['cases'])))
