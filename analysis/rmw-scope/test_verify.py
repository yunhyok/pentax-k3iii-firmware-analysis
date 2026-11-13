"""Firmware-free stdlib guards; two supplied inputs opt in to full record reproduction."""
if not __debug__:raise RuntimeError('Assertions required; -O unsupported')
import argparse,copy,hashlib,json,os,runpy,shutil,subprocess,sys,tempfile
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--work-dir',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--decoded',type=Path);ap.add_argument('--accepted31',type=Path)
    a=ap.parse_args()
    if bool(a.decoded)!=bool(a.accepted31):raise ValueError('both supplied inputs required')
    if not a.work_dir.is_dir() or os.path.lexists(a.output) or not a.output.parent.is_dir():raise ValueError('existing work directory and fresh output required')
    checks=[];ns=runpy.run_path(str(HERE/'verify.py'),run_name='guard_test')
    captured,manifest=ns['capture_package']()
    def passed(name):checks.append({'test':name,'status':'passed'})
    passed('bounded_captured_package_pins')
    with tempfile.TemporaryDirectory(prefix='rmw36-',dir=a.work_dir.resolve()) as temp:
        root=Path(temp).resolve();assert root.parent==a.work_dir.resolve()
        package=root/'relocated package with spaces';(package/'helpers').mkdir(parents=True)
        for name in ('verify.py',*ns['PINS']):shutil.copyfile(HERE/name,package/name)
        script=str(package/'verify.py');invalid=root/'invalid.bin';invalid.write_bytes(b'x');out=root/'never-created.json'
        def reject(label,argv,expected,preserve=None):
            before=sha(preserve) if preserve else None
            result=subprocess.run([sys.executable,'-S',*argv],capture_output=True,text=True,timeout=30)
            assert result.returncode!=0 and expected in result.stderr,(label,result.stdout,result.stderr)
            if preserve:assert sha(preserve)==before
            passed(label)
        args=[script,str(invalid),str(invalid),'--output',str(out)]
        reject('wrong_size_before_optional_imports',args,'decoded size/type mismatch')
        reject('optimized_mode_before_imports',['-O',script],'Assertions required')
        reject('decoded_output_alias',[script,str(invalid),str(invalid),'--output',str(invalid)],'output alias',invalid)
        second=root/'accepted31.json';second.write_text('preserve')
        reject('accepted31_output_alias',[script,str(invalid),str(second),'--output',str(second)],'output alias',second)
        reject('unrelated_existing_output',[script,str(invalid),str(invalid),'--output',str(second)],'output exists',second)
        reject('package_output_alias',[script,str(invalid),str(invalid),'--output',str(package/'helpers/scope_model.py.inc')],'output alias',package/'helpers/scope_model.py.inc')
        reject('missing_output_parent',[script,str(invalid),str(invalid),'--output',str(root/'absent/out.json')],'output parent must exist')
        for name in ns['PINS']:
            path=package/name;raw=path.read_bytes();tampered=bytearray(raw);tampered[0]^=1;path.write_bytes(tampered)
            reject('same_size_tampered_'+name,args,'package '+name+' digest mismatch');path.write_bytes(raw)
        for label,size,pin in [('decoded',manifest['inputs']['decoded']['bytes'],manifest['inputs']['decoded']),('accepted31',manifest['inputs']['accepted31']['bytes'],manifest['inputs']['accepted31'])]:
            sparse=root/(label+'-wrong.bin')
            with sparse.open('wb') as stream:stream.truncate(size)
            try:ns['capture'](sparse,(size,pin['sha256']),label)
            except ValueError as error:assert label+' digest mismatch' in str(error)
            else:raise AssertionError('wrong digest accepted')
            passed(label+'_right_size_wrong_digest')
        try:ns['capture'](root,(0,'unused'),'directory')
        except ValueError as error:assert 'size/type mismatch' in str(error)
        else:raise AssertionError('directory accepted')
        passed('nonregular_input_rejected')
        for label,kind in [('hardlink_output','hard'),('dangling_symlink_output','symlink')]:
            link=root/(label+'.json')
            try:
                if kind=='hard':os.link(second,link)
                else:link.symlink_to(root/'absent-target')
            except OSError as error:checks.append({'test':label,'status':'unsupported','reason':type(error).__name__})
            else:reject(label,[script,str(invalid),str(invalid),'--output',str(link)],'output exists',second)
        assert ns['typed_digest']({'x':False})!=ns['typed_digest']({'x':0})
        assert ns['typed_digest']({'x':True})!=ns['typed_digest']({'x':1})
        passed('bool_integer_distinction')
        for label,record in [('float',{'x':1.0}),('null',{'x':None}),('integer_key',{1:'x'}),('tuple',{'x':(1,)})]:
            try:ns['typed_digest'](record)
            except ValueError:passed('unsupported_record_type_'+label)
            else:raise AssertionError(label)
        projected=json.loads((HERE/'verified.json').read_text(encoding='utf-8'))
        try:ns['project_record'](projected['projection'])
        except ValueError as error:assert 'whole original35 typed record mismatch' in str(error)
        else:raise AssertionError('projection accepted as full record')
        passed('projection_cannot_bypass_whole_record_gate')
        assert not out.exists() and 'z3' not in sys.modules and 'capstone' not in sys.modules
        passed('guards_do_not_import_optional_packages_or_run_firmware')
        if a.decoded:
            before=[sha(a.decoded),sha(a.accepted31)];results=[]
            for n in range(2):
                target=root/f'proof-{n}.json'
                result=subprocess.run([sys.executable,script,str(a.decoded.resolve()),str(a.accepted31.resolve()),'--output',str(target)],capture_output=True,text=True,timeout=60)
                assert result.returncode==0,(result.stdout,result.stderr)
                results.append(target.read_bytes())
            assert results[0]==results[1]==(HERE/'verified.json').read_bytes()
            assert before==[sha(a.decoded),sha(a.accepted31)]
            passed('two_relocated_full_proofs_equal_published_result_inputs_preserved')
            scope={'__name__':'whole_record_mutation_test'}
            exec(compile(captured['helpers/scope_model.py.inc'],'captured scope helper','exec'),scope)
            record=scope['reconstruct'](a.decoded.read_bytes(),a.accepted31.read_bytes());ns['gate_record'](record)
            mutations=[
                ('numeric_bool',lambda x:x.__setitem__('classified_bytes',True)),
                ('bool_integer',lambda x:x['cases'][0]['pairs'][0].__setitem__('physical_initialization_producer_known',0)),
                ('omitted_source_list',lambda x:x.pop('source_instructions')),
                ('unprojected_source_operand',lambda x:x['source_instructions'][-1].__setitem__('operands','changed')),
                ('unprojected_source_hash',lambda x:x['source_instructions'][0].__setitem__('sha256','0'*64)),
                ('extra_top_field',lambda x:x.__setitem__('extra',True)),
                ('prior_trace_order',lambda x:x['cases'][0]['pairs'][0]['byte_provenance'][0]['first_read'].__setitem__('trace_index',0)),
                ('historical_script_identity',lambda x:x.__setitem__('script_sha256',sha(HERE/'verify.py'))),
                ('historical_limit',lambda x:x['limits'].pop()),
                ('proof_formula',lambda x:x['manual_word_proof'].__setitem__('final_word','changed'))]
            for label,mutate in mutations:
                wrong=copy.deepcopy(record);mutate(wrong)
                try:ns['project_record'](wrong)
                except ValueError as error:assert 'whole original35 typed record mismatch' in str(error)
                else:raise AssertionError(label)
                passed('full_record_mutation_'+label)
    result={'schema':1,'mode':'full_source_and_trace_proof_plus_guards' if a.decoded else 'firmware_free_guards_only',
            'actual_source_bound_manual_proof_run':bool(a.decoded),'new_original_CPU_execution':False,
            'checks':checks,'all_supported_checks_passed':True,'unsupported_count':sum(x['status']=='unsupported' for x in checks),
            'cli_sha256':sha(HERE/'verify.py'),'test_script_sha256':sha(Path(__file__))}
    with a.output.open('x',encoding='utf-8',newline='\n') as target:json.dump(result,target,indent=2);target.write('\n')
    print(json.dumps({'mode':result['mode'],'passed':sum(x['status']=='passed' for x in checks),'unsupported':result['unsupported_count']}))

if __name__=='__main__':main()
