"""Verify the decoded image and an authored 15-instruction block model; no native replay."""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SIZE = 78683892
INPUT_SHA = '7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RTOS_SHA = '342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
BLOCK_SHA = '86e67a1d1ddcb8baa1ca1863685ada9ede289648b3cc2353109896d4da0cba8c'
ORIGINAL_SCRIPT = '895f14ae328b0b93bcfa1bd0f3b84ea43e3a17697d7ee001b0fa4fc21cb191e2'
ORIGINAL_RESULT = '765c7ae01b3b20b8fda19219eecac269132960b9b1476eb49580d101f7245ebd'
PINS = {'helpers/model.py.inc': '9396b221c7756a234e67259dd42d78667afa379a6be99c1f98a49d28cc685959',
        'source.json': '87fb583052f647352721390f58e011f1cad5563b211aca0ffd8daa325f5ed05c'}
sha = lambda data: hashlib.sha256(data).hexdigest()

def require(ok, message):
    if not ok:
        raise ValueError(message)

def validate_manifest(m):
    require(type(m) is dict and set(m) == {'schema','decoded_size','decoded_sha256','rtos','block','provenance','premises','limits'}, 'manifest fields')
    require(type(m['schema']) is int and m['schema'] == 1, 'schema type')
    require(type(m['decoded_size']) is int and m['decoded_size'] == SIZE and m['decoded_sha256'] == INPUT_SHA, 'input identity')
    r = m['rtos']; b = m['block']; p = m['provenance']; limits = m['limits']
    require(type(r) is dict and set(r) == {'offset','size','base','sha256'}, 'RTOS fields')
    require(type(r['offset']) is int and r['offset'] == 0x1c19c and type(r['size']) is int and r['size'] == 25483200 and r['base'] == '0x52500000' and r['sha256'] == RTOS_SHA, 'RTOS identity')
    require(type(b) is dict and set(b) == {'start','end_exclusive','bytes','instruction_count','mode','sha256'}, 'block fields')
    require(b['start'] == '0x525d8594' and b['end_exclusive'] == '0x525d85d0' and b['sha256'] == BLOCK_SHA and b['mode'] == 'A32 little-endian', 'block bounds/identity')
    require(type(b['bytes']) is int and b['bytes'] == 60 and type(b['instruction_count']) is int and b['instruction_count'] == 15, 'block numeric types')
    require(type(p) is dict and set(p) == {'original33_script_sha256','original33_result_sha256','public_helper_sha256','transformation'}, 'provenance fields')
    require(p['original33_script_sha256'] == ORIGINAL_SCRIPT and p['original33_result_sha256'] == ORIGINAL_RESULT and p['public_helper_sha256'] == PINS['helpers/model.py.inc'] and type(p['transformation']) is str, 'provenance identity')
    require(type(m['premises']) is list and len(m['premises']) == 3 and all(type(x) is str for x in m['premises']), 'premises types')
    require(type(limits) is dict and set(limits) == {'raw_RMW_allowlist_bytes_unchanged','other_RMW_bytes_not_proved','physical_initial_producer_known','native_replay','proves_no_reads','proves_concurrency','private31_trace_required','scope_note'}, 'limits fields')
    require(type(limits['raw_RMW_allowlist_bytes_unchanged']) is int and limits['raw_RMW_allowlist_bytes_unchanged'] == 56 and type(limits['other_RMW_bytes_not_proved']) is int and limits['other_RMW_bytes_not_proved'] == 48, 'allowlist scope')
    require(all(limits[k] is False for k in ('physical_initial_producer_known','native_replay','proves_no_reads','proves_concurrency','private31_trace_required')) and type(limits['scope_note']) is str, 'limits types')

def capture_package():
    raw = {name: (HERE/name).read_bytes() for name in PINS}
    for name, pin in PINS.items():
        require(sha(raw[name]) == pin, 'package hash mismatch: '+name)
    manifest = json.loads(raw['source.json'])
    validate_manifest(manifest)
    return raw, manifest

def guard_output(path, decoded):
    require(path.resolve() not in [p.resolve() for p in (decoded, Path(__file__), *(HERE/name for name in PINS))], 'output alias')
    require(not os.path.lexists(path), 'output exists')
    require(path.parent.is_dir(), 'output parent must exist')

def read_input(path):
    require(path.is_file() and path.stat().st_size == SIZE, 'input size mismatch')
    with path.open('rb') as f:
        data = f.read(SIZE+1)
    require(len(data) == SIZE and sha(data) == INPUT_SHA, 'input digest mismatch')
    return data

def verify_sources(data):
    rtos = data[0x1c19c:0x1c19c+25483200]
    require(len(rtos) == 25483200 and sha(rtos) == RTOS_SHA, 'RTOS digest mismatch')
    block = rtos[0xd8594:0xd85d0]
    require(len(block) == 60 and sha(block) == BLOCK_SHA, 'block digest mismatch')
    import capstone
    rows = list(capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM).disasm(block, 0x525d8594))
    require(len(rows) == 15 and all(i.address == 0x525d8594+4*n and i.size == 4 for n,i in enumerate(rows)), 'decode coverage mismatch')
    return {'block_sha256': BLOCK_SHA, 'decoded_instruction_count': len(rows),
            'Capstone_module': capstone.__version__, 'Capstone_distribution': importlib.metadata.version('capstone'),
            'instruction_text_or_bytes_emitted': False}

def run(decoded, output):
    guard_output(output, decoded)
    captured, manifest = capture_package()
    data = read_input(decoded)
    source = verify_sources(data)
    scope = {'__name__': 'captured_public_manual_model', '__file__': str(HERE/'helpers/model.py.inc')}
    exec(compile(captured['helpers/model.py.inc'], scope['__file__'], 'exec'), scope)
    proof = scope['prove']()
    require(proof['counterexample_result'] == 'unsat' and len(proof['negative_controls']) == 2 and all(x['result'] == 'sat' for x in proof['negative_controls']), 'proof result mismatch')
    require(read_input(decoded) == data, 'input changed during proof')
    result = {'schema':1, 'marker':'III-RMW-PUBLIC-34', 'source_bound_manual_model_proved':True,
              'input_sha256':INPUT_SHA, 'source':source, 'source_manifest_sha256':PINS['source.json'],
              'original33_script_sha256':ORIGINAL_SCRIPT, 'original33_result_sha256':ORIGINAL_RESULT,
              'public_helper_sha256':PINS['helpers/model.py.inc'], 'Z3_distribution':importlib.metadata.version('z3-solver'),
              'proof':proof, 'premises':manifest['premises'], 'limits':manifest['limits'],
              'historical31_observation_reverified':False, 'firmware_bytes_or_disassembly_bundled':False}
    guard_output(output, decoded)
    with output.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(result, f, ensure_ascii=False, indent=2); f.write('\n')
    return result

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('decoded', type=Path); ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args(); result = run(args.decoded, args.output)
    print(json.dumps({'source_bound_model_proved':True, 'counterexample':result['proof']['counterexample_result'], 'native_replay':False, 'historical_trace_reverified':False}))

if __name__ == '__main__':
    main()
