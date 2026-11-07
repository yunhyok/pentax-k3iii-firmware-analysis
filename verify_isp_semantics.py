"""Reproduce bounded ISP reference searches; does not simulate silicon pixels."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from decompile_sample import BASE, RTOS_OFFSET, RTOS_SIZE, RTOS_SHA256
from rtos_catalog import require


def direct_references(image, targets, base=BASE):
    found = {target: [] for target in targets}
    for offset, (word,) in enumerate(struct.iter_unpack('<I', image[:len(image)//4*4])):
        if word & 0x0e000000 != 0x0a000000 or word >> 28 == 15:
            continue
        displacement = word & 0xffffff
        if displacement & 0x800000:
            displacement -= 1 << 24
        site = base + offset * 4
        target = (site + 8 + 4 * displacement) & 0xffffffff
        if target in found:
            found[target].append(hex(site))
    return {hex(target): sites for target, sites in found.items()}


def literal_references(image, targets):
    found = {}
    for target in targets:
        needle = struct.pack('<I', target)
        locations = []
        offset = image.find(needle)
        while offset >= 0:
            locations.append(hex(BASE + offset))
            offset = image.find(needle, offset + 1)
        found[hex(target)] = locations
    return found


def verify(image, evidence):
    require(hashlib.sha256(image).hexdigest() == RTOS_SHA256 == evidence['rtos_sha256'], 'RTOS hash mismatch')
    targets = {int(k, 16) for scan in evidence['reference_searches'] for k in scan['expected'] if scan['kind'] == 'a32-b-bl'}
    calls = direct_references(image, targets)
    results = []
    for scan in evidence['reference_searches']:
        expected = scan['expected']
        if scan['kind'] == 'a32-b-bl':
            start, end = int(scan['start'], 16), int(scan['end'], 16)
            require(BASE <= start < end <= BASE+len(image) and start % 4 == end % 4 == 0, 'Invalid search range')
            actual = {key: [site for site in calls[key] if start <= int(site, 16) < end] for key in expected}
        elif scan['kind'] == 'literal-u32':
            actual = literal_references(image, [int(key, 16) for key in expected])
        else:
            raise ValueError('Unknown reference search kind')
        require(actual == expected, f"Reference search mismatch: {scan['label']}")
        results.append({'label': scan['label'], 'targets': len(expected), 'matches': sum(map(len, actual.values()))})
    for row in evidence['diagnostic_strings']:
        start = int(row['address'], 16) - BASE
        require(0 <= start and 0 < row['size'] <= len(image)-start, 'Invalid string range')
        require(hashlib.sha256(image[start:start+row['size']]).hexdigest() == row['sha256'], 'Diagnostic string hash mismatch')
    return {'passed': True, 'rtos_sha256': RTOS_SHA256, 'reference_searches': results,
            'diagnostic_strings': len(evidence['diagnostic_strings']), 'pixel_comparator_or_order_verified': False,
            'scope': 'Aligned immediate A32 B/BL and exact pointer words only. Candidate references do not establish live reachability; negative results do not exclude computed/Thumb references or other implementations.'}


def self_test():
    # Includes backward branch, conditional branch, BL, BLX exclusion, and unaligned pointer.
    data = struct.pack('<4I', 0xeb000002, 0x0a000001, 0xeafffffe, 0xfa000000)
    require(direct_references(data, {0x1010, 0x1008, 0x1014}, 0x1000) ==
            {'0x1010':['0x1000','0x1004'], '0x1008':['0x1008'], '0x1014':[]}, 'Branch scanner self-test failed')
    require(literal_references(b'x'+struct.pack('<I', 0x12345678), [0x12345678]) ==
            {'0x12345678':[hex(BASE+1)]}, 'Pointer scanner self-test failed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded', type=Path, nargs='?')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print('ISP reference scanner self-test passed')
        else:
            if args.decoded is None:
                parser.error('decoded is required unless --self-test is used')
            with args.decoded.open('rb') as stream:
                stream.seek(RTOS_OFFSET)
                image = stream.read(RTOS_SIZE)
            evidence = json.loads((Path(__file__).parent/'analysis/isp-semantics-evidence.json').read_text(encoding='utf-8'))
            result = verify(image, evidence)
            serialized = json.dumps(result, indent=2)+'\n'
            if args.output:
                args.output.write_text(serialized, encoding='utf-8')
            print(serialized, end='')
    except (OSError, ValueError, KeyError, struct.error) as error:
        parser.exit(1, f'ISP reference verification failed: {error}\n')
