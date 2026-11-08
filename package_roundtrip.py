"""Offline K-3 III 2.20 container repack; never performs device I/O.

Unchanged records reuse the original compressed bytes for byte-identical output.
One same-size kind-4 record may be edited; that image is encoded with stored
blocks and both additive checksums are recalculated. This is not a source build,
signature generator, hardware decoder test, or proof of updater acceptance.
"""
import argparse
import json
import struct
from pathlib import Path

from inspect_firmware import decode, named_records, sha256
from verify_update_resources import require, sum32, u32

ORIGINAL_SHA = '3c9d466b8160689867af2f58ff2cf0bf3363bc3b42daff43685a33171b91eb1a'
DECODED_SHA = '7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
MAX_SIZE = 128 * 1024 * 1024
RECORDS = (
    ('BOOTPARA', 5, 65535, 72), ('DRAMPARA', 1, 65535, 556),
    ('PARTPARA', 2, 65535, 516), ('M0', 3, 0, 92164),
    ('BOOT', 4, 0, 21696), ('RTOS', 4, 1, 25483200),
    ('DSP', 4, 2, 4194304), ('LINUX', 4, 5, 3062784),
    ('INITFS', 4, 6, 14452736), ('SRIC', 9, 0, 122880),
    ('CPU', 7, 0, 131072), ('SHELLCMD', 4, 3, 61312),
    ('ICONBIN', 4, 4, 26219192), ('FDRVPARA', 8, 65535, 36),
    ('RES', 6, 65535, 36),
)


def read_bounded(path, limit=MAX_SIZE):
    require(path.is_file() and path.stat().st_size <= limit, 'Missing or oversized input')
    return path.read_bytes()


def parse_package(data):
    """Strict observed layout, narrower than the unproven camera parser."""
    require(408 <= len(data) <= MAX_SIZE and len(data) % 4 == 0,
            'Package size or alignment invalid')
    require(data.startswith(b'PENTAX\0K-3 Mark III\0'), 'Unsupported camera header')
    require(u32(data, 0x30) == 0x246 and u32(data, 0x3c) == 2,
            'Unsupported project or version record count')
    require((u32(data, 0x78), u32(data, 0x7c)) == (0x02460246, 0xa55a5aa5),
            'Header project repeat or magic invalid')
    footer = len(data) - 24
    require(struct.unpack_from('<III', data, footer) == (0x02460246, 0xa55a5aa5, 2),
            'Footer identity or type invalid')
    stream_length, decoded_length = struct.unpack_from('<II', data, footer + 12)
    table = footer - 256
    require(stream_length == table - 128 and stream_length > 2,
            'Compressed length or version table boundary invalid')
    require(decoded_length == 78683892, 'Unsupported decoded length')
    require(u32(data, footer + 20) != 0xffffffff and sum32(data) == 0,
            'Outer checksum invalid or bypass sentinel')
    payload, end, blocks = decode(data[:table], 128, decoded_length)
    require(end == table and len(payload) == decoded_length, 'Decoded length or stream end invalid')
    require(all(b['output_end'] > b['output_start'] for b in blocks), 'Empty blocks unsupported')
    require(u32(payload, len(payload) - 4) not in (0, 0xffffffff) and sum32(payload) == 0,
            'Inner checksum invalid or bypass sentinel')
    records, tail = named_records(payload)
    require([(r['name'], r['kind'], r['index'], r['size']) for r in records] == list(RECORDS),
            'Unsupported or malformed named-record layout')
    require(tail == 73842796 and payload[tail:tail+4] == b'LELR', 'Opaque resource-tail boundary invalid')
    require([u32(data, table + i * 128) for i in range(2)] == [0x246, 0x26e],
            'Version record selectors invalid')
    return payload, dict(package_sha256=sha256(data), package_size=len(data),
                        decoded_sha256=sha256(payload), decoded_size=len(payload),
                        stream_start=128, stream_end=end, version_start=table,
                        footer_start=footer, blocks=len(blocks),
                        stored_blocks=sum(b['kind'] == 'stored' for b in blocks),
                        named_records=records, opaque_tail_offset=tail,
                        outer_checksum=u32(data, footer + 20),
                        inner_checksum=u32(payload, len(payload) - 4),
                        structural_checks_passed=True, updater_acceptance=False,
                        hardware_decode_tested=False, camera_boot_tested=False)


def encode_stored(payload):
    """Emit nonempty stored blocks. Odd block count preserves 4-byte alignment."""
    require(len(payload) >= 4 and len(payload) % 4 == 0, 'Stored payload needs aligned words')
    # The verified original's 742 stored blocks all contain 0x6000 output bytes.
    sizes = [min(0x6000, len(payload) - p) for p in range(0, len(payload), 0x6000)]
    if len(sizes) % 2 == 0:
        split = next(i for i in reversed(range(len(sizes))) if sizes[i] >= 8)
        sizes[split:split+1] = [sizes[split] - 4, 4]
    parts, cursor = [], 0
    for size in sizes:
        require(0 < size <= 0x7fff, 'Stored block size invalid')
        parts.append(struct.pack('>H', 0x8000 | size) + payload[cursor:cursor+size])
        cursor += size
    stream = b''.join(parts) + b'\0\0'
    require(len(stream) % 4 == 0 and cursor == len(payload), 'Stored stream alignment invalid')
    return stream


def filename(index, record):
    return f"{index:02d}_{record['name']}.bin"


def unpack(source, directory):
    data = read_bounded(source)
    require(sha256(data) == ORIGINAL_SHA, 'Unpack requires the verified original package')
    payload, info = parse_package(data)
    require(sha256(payload) == DECODED_SHA, 'Original decoded identity mismatch')
    require(not directory.exists(), 'Output directory must not exist')
    directory.mkdir(parents=True)
    (directory / 'records').mkdir()
    components = {'header.bin': data[:128], 'stream.bin': data[128:info['stream_end']],
                  'versions.bin': data[info['version_start']:info['footer_start']],
                  'footer.bin': data[info['footer_start']:],
                  'opaque-tail.bin': payload[info['opaque_tail_offset']:]}
    for name, value in components.items():
        (directory / name).write_bytes(value)
    for index, record in enumerate(info['named_records']):
        p = record['payload_offset']
        (directory / 'records' / filename(index, record)).write_bytes(payload[p:p+record['size']])
    info['mode'] = 'lossless original compressed-stream preservation'
    (directory / 'manifest.json').write_text(json.dumps(info, indent=2)+'\n', encoding='utf-8')
    return info


def pack(directory, output):
    require(not output.exists(), 'Output file must not exist')
    parts = [read_bounded(directory / name, limit) for name, limit in
             [('header.bin',128), ('stream.bin',35106308), ('versions.bin',256), ('footer.bin',24)]]
    original = b''.join(parts)
    require(sha256(original) == ORIGINAL_SHA, 'Original carrier components changed')
    baseline, info = parse_package(original)
    require(read_bounded(directory / 'opaque-tail.bin', 4841096) == baseline[info['opaque_tail_offset']:],
            'Opaque resource tail edits are unsupported')
    expected = {filename(i, r) for i, r in enumerate(info['named_records'])}
    require({p.name for p in (directory / 'records').iterdir()} == expected,
            'Missing or extra record files')
    decoded = bytearray(baseline)
    changes = []
    for index, record in enumerate(info['named_records']):
        replacement = read_bounded(directory / 'records' / filename(index, record), record['size'])
        require(len(replacement) == record['size'], 'Record resizing is unsupported')
        if sha256(replacement) != record['sha256']:
            require(record['kind'] == 4, 'Only same-size kind-4 payload edits are supported')
            p = record['payload_offset'];decoded[p:p+record['size']] = replacement
            changes.append(dict(name=record['name'], index=record['index'], payload_offset=p,
                                size=len(replacement), before_sha256=record['sha256'],
                                after_sha256=sha256(replacement)))
    require(len(changes) <= 1, 'Only one record may change per experiment')
    mode = 'preserved-stream'
    result = original
    if changes:
        struct.pack_into('<I', decoded, len(decoded)-4, 0)
        checksum = (-sum32(decoded)) & 0xffffffff
        require(checksum not in (0, 0xffffffff), 'Recomputed inner checksum collides with bypass sentinel')
        struct.pack_into('<I', decoded, len(decoded)-4, checksum)
        stream = encode_stored(decoded)
        footer = bytearray(parts[3])
        struct.pack_into('<III', footer, 12, len(stream), len(decoded), 0)
        result = bytearray(parts[0] + stream + parts[2] + footer)
        checksum = (-sum32(result)) & 0xffffffff
        require(checksum != 0xffffffff, 'Recomputed outer checksum collides with bypass sentinel')
        struct.pack_into('<I', result, len(result)-4, checksum)
        mode = 'stored-block-reencoding'
    decoded_again, verified = parse_package(result)
    require(decoded_again == bytes(decoded), 'Repack decode mismatch')
    if not changes:
        require(bytes(result) == original, 'Unchanged repack was not byte-identical')
    with output.open('xb') as f:
        f.write(result)
    verified.update(mode=mode, changed_records=changes,
                    byte_identical_to_original=not changes,
                    source_compilation=False, linker_reconstruction=False,
                    genuine_compressor_recovered=False)
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('unpack');p.add_argument('input', type=Path);p.add_argument('directory', type=Path)
    p = sub.add_parser('pack');p.add_argument('directory', type=Path);p.add_argument('output', type=Path)
    p = sub.add_parser('verify');p.add_argument('input', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        if args.report:
            require(not args.report.exists(), 'Report file must not exist')
            if args.command == 'pack':
                require(args.report.resolve() != args.output.resolve(), 'Report and binary paths must differ')
        if args.command == 'unpack':info = unpack(args.input, args.directory)
        elif args.command == 'pack':info = pack(args.directory, args.output)
        else:_, info = parse_package(read_bounded(args.input))
        if args.report:
            with args.report.open('x', encoding='utf-8') as f:f.write(json.dumps(info, indent=2)+'\n')
        print(json.dumps({k:info[k] for k in ('package_sha256','decoded_sha256','structural_checks_passed','updater_acceptance','camera_boot_tested')}, indent=2))
    except (OSError, ValueError, struct.error) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
