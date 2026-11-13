"""Package guards and optional relocated replay; all fixtures stay in exclusive temp dirs."""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
HERE=Path(__file__).resolve().parent
SIZE=78683892
digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--work-dir',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--decoded',type=Path);a=ap.parse_args()
    if os.path.lexists(a.output):raise FileExistsError(a.output)
    if not a.work_dir.is_dir():raise NotADirectoryError(a.work_dir)
    results=[];env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    with tempfile.TemporaryDirectory(prefix='registry-tests-',dir=a.work_dir.resolve()) as tmp:
        work=Path(tmp);assert work.resolve().parent==a.work_dir.resolve()
        package=work/'relocated package with spaces';(package/'helpers').mkdir(parents=True)
        for name in ('replay.py','source-ranges.json','provenance.json','helpers/native.py.inc'):shutil.copyfile(HERE/name,package/name)
        cli=package/'replay.py';wrong=work/'wrong.bin';wrong.write_bytes(b'wrong')
        def rejected(name,image,output,error,flags=('-I','-S')):
            before=digest(output) if output.is_file() else None
            cp=subprocess.run([sys.executable,*flags,str(cli),str(image),'--output',str(output)],cwd=work,env=env,text=True,capture_output=True,timeout=120)
            assert cp.returncode!=0 and error in cp.stderr,(name,cp.stdout,cp.stderr)
            if before is not None:assert digest(output)==before
            else:assert not output.exists()
            results.append({'test':name,'passed':True,'expected_error':error,'existing_output_preserved':before is not None})
        rejected('wrong_size',wrong,work/'wrong.json','decoded input size mismatch')
        for name,size in [('truncated',SIZE-1),('oversized',SIZE+1),('wrong_digest',SIZE)]:
            fixture=work/(name+'.bin')
            with fixture.open('xb') as f:f.truncate(size)
            rejected(name,fixture,work/(name+'.json'),'decoded input hash mismatch' if size==SIZE else 'decoded input size mismatch');fixture.unlink()
        rejected('optimized_before_optional_imports',wrong,work/'optimized.json','Assertions required',('-O','-I','-S'))
        existing=work/'existing.json';existing.write_bytes(b'preserve existing output\n')
        rejected('existing_output',wrong,existing,'output already exists')
        rejected('input_alias',wrong,wrong,'output aliases')
        rejected('normalized_input_alias',wrong,work/'.'/'wrong.bin','output aliases')
        rejected('helper_output_alias',wrong,package/'helpers/native.py.inc','output aliases')
        hard=work/'hardlink.json';os.link(existing,hard);rejected('hardlink_output',wrong,hard,'output already exists');assert digest(hard)==digest(existing)
        dangling=work/'dangling.json'
        try:dangling.symlink_to(work/'absent.json')
        except OSError as error:results.append({'test':'dangling_symlink','passed':None,'status':'unsupported','winerror':getattr(error,'winerror',None)})
        else:
            rejected('dangling_symlink',wrong,dangling,'output already exists');assert dangling.is_symlink() and not (work/'absent.json').exists()
        for name in ('helpers/native.py.inc','source-ranges.json','provenance.json'):
            file=package/name;original=file.read_bytes();sentinel=work/'must-not-execute.txt'
            injected=('from pathlib import Path\nPath('+repr(str(sentinel))+').write_text("bad")\n').encode()+original if name.endswith('.inc') else original+b' '
            file.write_bytes(injected);rejected('tampered_'+name,wrong,work/(file.name+'.out.json'),'package hash mismatch: '+name);assert not sentinel.exists();file.write_bytes(original)
        namespace={'__name__':'registry_guard_tests','__file__':str(cli)};exec(compile(cli.read_bytes(),str(cli),'exec'),namespace)
        captured,manifest,provenance=namespace['capture_package']()
        def fails(name,fn,message):
            try:fn()
            except ValueError as e:assert message in str(e),(name,str(e));results.append({'test':name,'passed':True,'expected_error':message})
            else:raise AssertionError('accepted invalid '+name)
        clone=lambda x:json.loads(json.dumps(x))
        bad=clone(manifest);bad['data_ranges'][0]['size']=True;fails('bool_is_not_data_size',lambda:namespace['validate_manifest'](bad),'data size type')
        bad=clone(manifest);bad['named_ranges'][0]['start']='0x525d5bb9';fails('unaligned_code',lambda:namespace['validate_manifest'](bad),'code alignment')
        bad=clone(manifest);bad['data_ranges'][0]['address']='0xffffffff';fails('out_of_bounds_data',lambda:namespace['validate_manifest'](bad),'source range bounds')
        bad=clone(manifest);bad['named_ranges'][0]['instructions']=[];fails('no_disassembly_fields',lambda:namespace['validate_manifest'](bad),'source record fields')
        bad=clone(manifest);bad['executed_hook_ranges'].pop();fails('wrong_hook_range_count',lambda:namespace['validate_manifest'](bad),'manifest record count')
        bad=clone(provenance);bad['full_witness_bytes']=True;fails('bool_is_not_witness_size',lambda:namespace['validate_provenance'](bad),'provenance witness')
        if a.decoded:
            image=a.decoded.resolve();before=digest(image);outputs=[]
            for i in range(2):
                output=work/f'positive-{i}.json';cp=subprocess.run([sys.executable,str(cli),str(image),'--output',str(output)],cwd=work,env=env,text=True,capture_output=True,timeout=120)
                assert cp.returncode==0,(cp.stdout,cp.stderr);outputs.append(output.read_bytes())
            assert outputs[0]==outputs[1]==(HERE/'verified.json').read_bytes() and digest(image)==before
            results.append({'test':'two_relocated_replays_equal_published_projection','passed':True,'projection_sha256':hashlib.sha256(outputs[0]).hexdigest(),'input_preserved':True})
            data=namespace['read_input'](image);rtos=data[0x1c19c:0x1c19c+25483200]
            bad=clone(manifest);bad['named_ranges'][0]['sha256']='0'*64;fails('wrong_source_range_hash',lambda:namespace['verify_sources'](rtos,bad),'source code range mismatch')
            full=namespace['observe'](rtos,captured,provenance);namespace['validate_observation'](full,manifest);namespace['check_witness'](full)
            original=full['cases'][0]['hash_zero_stores'];full['cases'][0]['hash_zero_stores']=True
            fails('bool_is_not_native_store_count',lambda:namespace['validate_observation'](full,manifest),'case integer');full['cases'][0]['hash_zero_stores']=original
            original=full['cases'][0]['writes'][-1]['value'];full['cases'][0]['writes'][-1]['value']=original[:-1]+('1' if original[-1]=='0' else '0')
            assert len((json.dumps(full,indent=2)+'\n').encode('utf-8'))==namespace['WITNESS_SIZE']
            fails('omitted_guest_store_still_checked',lambda:namespace['check_witness'](full),'complete observation witness mismatch');full['cases'][0]['writes'][-1]['value']=original
            full['script_sha256']=namespace['FILES']['helpers/native.py.inc']
            fails('public_helper_hash_is_not_original_provenance',lambda:namespace['check_witness'](full),'complete observation witness mismatch');full['script_sha256']=namespace['ORIGINAL_SCRIPT']
            namespace['check_witness'](full);assert digest(image)==before
    result={'schema':1,'all_supported_tests_passed':True,'positive_replay_tested':a.decoded is not None,'fixtures_in_exclusive_temporary_scope':True,'private_guard_runner_bundled':False,'tests':results,'test_script_sha256':digest(Path(__file__)),'cli_sha256':digest(HERE/'replay.py')}
    with a.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'passed':sum(x['passed'] is True for x in results),'unsupported':sum(x['passed'] is None for x in results)}))
if __name__=='__main__':main()
