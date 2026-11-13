"""Standard-library package/guard checks; --decoded additionally runs the actual proof."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--work-dir', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--decoded', type=Path)
    args = ap.parse_args()
    if not args.work_dir.is_dir() or os.path.lexists(args.output) or not args.output.parent.is_dir():
        raise ValueError('existing work directory and fresh output path required')
    checks = []
    namespace = runpy.run_path(str(HERE/'verify.py'), run_name='package_test')
    captured, source = namespace['capture_package']()
    checks.append({'test':'package_bytes_and_typed_manifest','status':'passed'})
    with tempfile.TemporaryDirectory(prefix='rmw34-', dir=args.work_dir.resolve()) as temporary:
        root = Path(temporary).resolve()
        assert root.parent == args.work_dir.resolve()
        package = root/'relocated package with spaces'
        package.mkdir(); (package/'helpers').mkdir()
        for name in ('verify.py', *namespace['PINS']):
            shutil.copyfile(HERE/name, package/name)
        invalid = root/'invalid.bin'; invalid.write_bytes(b'x')
        def reject(label, argv, expected, existing=None):
            before = sha(existing) if existing else None
            p = subprocess.run([sys.executable, '-S', *argv], capture_output=True, text=True)
            assert p.returncode != 0 and expected in p.stderr, (label,p.stdout,p.stderr)
            if existing: assert sha(existing) == before
            checks.append({'test':label,'status':'passed','expected_error':expected})
        script = str(package/'verify.py')
        out = root/'never-created.json'
        reject('wrong_size_before_optional_imports', [script,str(invalid),'--output',str(out)], 'input size mismatch')
        reject('optimized_mode_before_imports', ['-O',script], 'Assertions required')
        reject('existing_output_preserved', [script,str(invalid),'--output',str(invalid)], 'output alias', invalid)
        existing = root/'existing.json'; existing.write_text('keep', encoding='utf-8')
        reject('existing_unrelated_output_preserved', [script,str(invalid),'--output',str(existing)], 'output exists', existing)
        reject('package_output_alias', [script,str(invalid),'--output',str(package/'helpers/model.py.inc')], 'output alias', package/'helpers/model.py.inc')
        for name in namespace['PINS']:
            p = package/name; original = p.read_bytes(); p.write_bytes(original+b'\nraise RuntimeError("must_not_execute")\n')
            reject('tampered_'+name, [script,str(invalid),'--output',str(out)], 'package hash mismatch')
            p.write_bytes(original)
        sparse = root/'wrong-digest.bin'
        with sparse.open('wb') as f: f.truncate(namespace['SIZE'])
        reject('right_size_wrong_digest', [script,str(sparse),'--output',str(out)], 'input digest mismatch')
        for label, kind in [('hardlink_output','hard'),('dangling_symlink_output','symbolic')]:
            link = root/(label+'.json')
            try:
                if kind == 'hard':os.link(existing,link)
                else:link.symlink_to(root/'absent-target.json')
            except OSError as error:
                checks.append({'test':label,'status':'unsupported','reason':type(error).__name__})
            else:
                reject(label,[script,str(invalid),'--output',str(link)],'output exists')
        mutations = [
            ('bool_instruction_count',lambda m:m['block'].__setitem__('instruction_count',True),'block numeric types'),
            ('wrong_block_end',lambda m:m['block'].__setitem__('end_exclusive','0x525d85d4'),'block bounds/identity'),
            ('extra_disassembly_field',lambda m:m['block'].__setitem__('instructions',[]),'block fields'),
            ('bool_RMW_allowlist',lambda m:m['limits'].__setitem__('raw_RMW_allowlist_bytes_unchanged',True),'allowlist scope'),
            ('false_as_integer',lambda m:m['limits'].__setitem__('native_replay',0),'limits types'),
            ('source_provenance_not_helper_hash',lambda m:m['provenance'].__setitem__('original33_script_sha256',m['provenance']['public_helper_sha256']),'provenance identity'),
        ]
        for label, mutate, expected in mutations:
            m = copy.deepcopy(source); mutate(m)
            try:namespace['validate_manifest'](m)
            except ValueError as error: assert expected in str(error)
            else:raise AssertionError(label)
            checks.append({'test':label,'status':'passed'})
        assert not out.exists() and 'z3' not in sys.modules and 'capstone' not in sys.modules
        checks.append({'test':'format_guard_checks_do_not_import_optional_packages','status':'passed'})
        if args.decoded:
            before = sha(args.decoded)
            results=[]
            for i in range(2):
                output=root/f'proof-{i}.json'
                p=subprocess.run([sys.executable,script,str(args.decoded.resolve()),'--output',str(output)],capture_output=True,text=True)
                assert p.returncode==0,(p.stdout,p.stderr)
                v=json.loads(output.read_text(encoding='utf-8'))
                assert v['source_bound_manual_model_proved'] is True and v['proof']['counterexample_result']=='unsat'
                assert v['historical31_observation_reverified'] is False and v['limits']['native_replay'] is False
                results.append(output.read_bytes())
            assert results[0]==results[1] and sha(args.decoded)==before
            assert results[0]==(HERE/'verified.json').read_bytes()
            checks.append({'test':'two_relocated_actual_proofs_equal_published_result','status':'passed','result_sha256':hashlib.sha256(results[0]).hexdigest(),'input_preserved':True})
    result={'schema':1,'mode':'actual_proof_plus_guards' if args.decoded else 'asset_free_format_and_guards_only',
            'actual_firmware_bound_proof_run':bool(args.decoded),'private31_trace_required':False,
            'fixtures_in_exclusive_temporary_scope':True,'checks':checks,
            'all_supported_checks_passed':True,'unsupported_count':sum(x['status']=='unsupported' for x in checks),
            'cli_sha256':sha(HERE/'verify.py'),'test_script_sha256':sha(Path(__file__))}
    with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'mode':result['mode'],'passed':sum(x['status']=='passed' for x in checks),'unsupported':result['unsupported_count']}))

if __name__=='__main__':main()
