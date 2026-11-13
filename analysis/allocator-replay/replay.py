"""Replay accepted K-3 III allocator evidence from the caller's exact decoded image.

No firmware is bundled. This is a bounded offline experiment, not a boot test.
"""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
INPUT_SIZE = 78683892
PINS = {
    'decoded': '7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9',
    'rtos': '342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4',
    'boot': '0a9c086818b9d6e7531b93710c2cab2782c7f2c32bb5b1c26e3b5b5b69695900',
    'm0': '63dd8f3b2668ef68f3ab0f8ecd0f4cda8c46a78c5388646fc9e1fe85e39a070e',
}
HELPERS = {
    'native.py.inc': 'd39e81571dcf05c747aabbf24f3c50e55f2a3805a733049a78bde390c6b78196',
    'proof.py.inc': '43b30c6184c17d42df3025a5c9be13fd51f2e65f0e717cf462e0d57520d2b7d4',
}
WITNESSES = {
    'native': ('9c950214e40cd5d8c527884db9d9bf2c4f39a1cc9cc47761f70c62c13074624d', 9463180),
    'proof': ('5e11102009550884e0bd128fd08c865d072fc432a61a8e31b96da8d313ec7f0f', 3577),
}
RANGES_SHA = '650e8a9d3a7a5e1e29295a6585548ae633ddc9daf7297360bc2b6da2e17dfcc1'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_input(path):
    require(path.is_file() and path.stat().st_size == INPUT_SIZE, 'decoded input size mismatch')
    with path.open('rb') as stream:
        data = stream.read(INPUT_SIZE + 1)
    require(len(data) == INPUT_SIZE and sha(data) == PINS['decoded'], 'decoded input hash mismatch')
    return data


def guard_output(output, decoded):
    protected = [decoded, Path(__file__), HERE / 'source-ranges.json']
    protected += [HERE / 'helpers' / name for name in HELPERS]
    require(output.resolve() not in [p.resolve() for p in protected], 'output aliases an input or package source')
    require(not os.path.lexists(output), 'output already exists (including aliases or dangling links)')
    require(output.parent.is_dir(), 'output parent must already exist')


def capture_helpers():
    captured = {}
    for name, digest in HELPERS.items():
        raw = (HERE / 'helpers' / name).read_bytes()
        require(sha(raw) == digest, 'helper hash mismatch: ' + name)
        captured[name] = raw
    return captured


def load_captured(captured):
    # Execute the exact bytes already checked, never reopen a helper after checking.
    modules = {}
    for name, raw in captured.items():
        namespace = {'__name__': 'captured_allocator_helper', '__file__': str(HERE / 'helpers' / name)}
        exec(compile(raw, namespace['__file__'], 'exec'), namespace)
        modules[name] = namespace
    return modules


def object_digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    return {'sha256': sha(raw), 'serialized_bytes': len(raw)}


def check_witness(kind, value):
    raw = (json.dumps(value, indent=2) + '\n').encode('utf-8')
    digest, size = WITNESSES[kind]
    require(len(raw) == size and sha(raw) == digest, kind + ' reference-witness/toolchain mismatch; no result published')
    return {'sha256': digest, 'bytes': size, 'byte_identical_to_accepted_27': True}


def project_case(case):
    fields = ('kind', 'raw_byte_pattern', 'host_control_addresses', 'host_control_bytes',
              'outcomes', 'boundary', 'parsed_task_config', 'page_initializer_final_pairs',
              'task_table_pairs', 'creator_stack_request', 'creator_stack_route', 'native_stack_pointer',
              'after_stack_pairs', 'creator_returned', 'task_table_bytes_and_queue_unchanged',
              'list_entry_preconditions', 'allocator_entry_preconditions', 'native_task_pointer',
              'remaining_pages', 'pool_table_pointer', 'per_core_zero_words', 'region',
              'native_ranges', 'original_code_unchanged', 'hardware_or_SVC_executed')
    result = {key: case[key] for key in fields}
    result['omitted_records'] = {
        key: {'count': len(case[key]), **object_digest(case[key])}
        for key in ('task_nodes', 'writes', 'reads', 'faults')
    }
    result['code_hook_stages'] = {
        key: {'count': len(sequence), **object_digest(sequence)}
        for key, sequence in case['code_hook_addresses'].items()
    }
    result['code_hook_all_stages'] = object_digest(case['code_hook_addresses'])
    result['raw_read_events'] = sum(bool(row['raw_control_bytes']) for row in case['reads'])
    result['creator_raw_read_events'] = sum(
        row['stage'].startswith('creator_') and bool(row['raw_control_bytes']) for row in case['reads'])
    return result


def run(decoded, output):
    guard_output(output, decoded)
    captured = capture_helpers()
    data = read_input(decoded)
    images = {'rtos': data[0x1c19c:0x1c19c + 25483200],
              'boot': data[0x16ccc:0x16ccc + 21696], 'm0': data[1208:1208 + 92164]}
    for name, raw in images.items():
        require(sha(raw) == PINS[name], name + ' segment hash mismatch')
    ranges_raw = (HERE / 'source-ranges.json').read_bytes()
    require(sha(ranges_raw) == RANGES_SHA, 'source range manifest hash mismatch')
    ranges = json.loads(ranges_raw)
    rtos = images['rtos']
    for item in ranges['named_ranges'] + ranges['executed_hook_ranges']:
        start, end = int(item['start'], 16) - 0x52500000, int(item['end'], 16) - 0x52500000
        require(0 <= start < end <= len(rtos) and sha(rtos[start:end]) == item['sha256'], 'code range mismatch')
    for item in ranges['data_ranges']:
        start = int(item['address'], 16) - 0x52500000
        require(0 <= start < start + item['size'] <= len(rtos) and
                sha(rtos[start:start + item['size']]) == item['sha256'], 'data range mismatch')
    modules = load_captured(captured)
    native = modules['native.py.inc']['replay'](rtos)
    require(read_input(decoded) == data, 'disk input changed during native replay')
    native.update(inputs=PINS, script_sha256=HELPERS['native.py.inc'], disk_input_unchanged=True)
    native_match = check_witness('native', native)
    proof = modules['proof.py.inc']['prove']()
    proof.update(allocator_source_sha256=sha(rtos[0xd8678:0xd880c]),
                 source_range={'start': '0x525d850c', 'end': '0x525d8668', 'sha256': sha(rtos[0xd850c:0xd8668])},
                 script_sha256=HELPERS['proof.py.inc'], disk_input_unchanged=read_input(decoded) == data)
    require(proof['disk_input_unchanged'], 'disk input changed during proof')
    proof_match = check_witness('proof', proof)
    result = {
        'schema': 1, 'marker': 'III-ALLOCATOR-PUBLIC-28', 'verified': True,
        'input': {'size': INPUT_SIZE, 'sha256': PINS['decoded']}, 'segments': PINS,
        'canonical_witnesses': {'native': native_match, 'proof': proof_match},
        'helper_sha256': HELPERS, 'source_ranges_sha256': RANGES_SHA,
        'native_engine': native['engine'], 'proof': proof,
        'cases': [project_case(case) for case in native['cases']],
        'projection': {'digest_encoding': 'UTF-8 JSON, sort_keys=True, separators=(comma,colon), ensure_ascii=True',
                       'full_witness_encoding': 'UTF-8 json.dumps(indent=2) plus one LF; exact accepted helper metadata',
                       'omitted': ['per-record task nodes', 'individual writes', 'individual dynamic reads',
                                   'individual fault records', 'repeated code-hook addresses'],
                       'firmware_bytes_or_disassembly_exported': False},
        'comparison': native['comparison'], 'trace_semantics': native['trace_semantics'],
        'limits': native['limits'], 'disk_input_unchanged': True,
    }
    guard_output(output, decoded)
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded', type=Path, help='Caller-supplied exact decoded image; never downloaded')
    parser.add_argument('--output', type=Path, required=True, help='New JSON file; existing paths are rejected')
    args = parser.parse_args()
    result = run(args.decoded, args.output)
    print(json.dumps({'verified': result['verified'], 'native_cases': len(result['cases']),
                      'proof_cases': len(result['proof']['cases']) + len(result['proof']['allocated_tails']),
                      'stop': result['cases'][-1]['boundary']['pc']}))


if __name__ == '__main__':
    main()
