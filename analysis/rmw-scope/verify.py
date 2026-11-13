"""Reconstruct frozen35 from two supplied inputs, gate the whole record, then project."""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import stat
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PINS={'helpers/scope_model.py.inc':(10700,'a0f0c1d8f9f6eef0fdc13fa5279b5715c6647dad15f264a3e2ce779080355fe2'),
      'source.json':(2451,'12f9ea9907f7b8ccb449feaeba5bf4e8558260546f49b56abdceaf2ef31e22d4')}
CANONICAL='6081eafffc91064d03f08e0d10648a64ff5a5b0ade374c752164d6053a446ddd'
sha=lambda data:hashlib.sha256(data).hexdigest()

def require(ok,message):
    if not ok:raise ValueError(message)

def typed_digest(value):
    def walk(x):
        if type(x) is dict:
            require(all(type(k) is str for k in x),'record key type')
            for item in x.values():walk(item)
        elif type(x) is list:
            for item in x:walk(item)
        else:require(type(x) in (str,int,bool),'record value type')
    walk(value)
    return sha(json.dumps(value,ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(',',':')).encode())

def gate_record(record):
    require(type(record) is dict and typed_digest(record)==CANONICAL,'whole original35 typed record mismatch')

def capture(path,pin,label):
    size,digest=pin
    require(path.is_file() and path.stat().st_size==size,label+' size/type mismatch')
    with path.open('rb') as source:
        info=os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size==size,label+' changed before capture')
        data=source.read(size+1)
        end=os.fstat(source.fileno())
        require(end.st_size==size,label+' size changed during capture')
    require(len(data)==size and sha(data)==digest,label+' digest mismatch')
    return data

def capture_package():
    captured={name:capture(HERE/name,pin,'package '+name) for name,pin in PINS.items()}
    manifest=json.loads(captured['source.json'])
    require(type(manifest['schema']) is int and manifest['schema']==1,'manifest schema')
    require(manifest['historical35']['whole_typed_record_canonical_sha256']==CANONICAL,'manifest record identity')
    require(manifest['public_helper_sha256']==PINS['helpers/scope_model.py.inc'][1],'helper identity')
    return captured,manifest

def guard_output(output,inputs):
    protected=[*inputs,Path(__file__),*(HERE/name for name in PINS)]
    require(output.resolve() not in [x.resolve() for x in protected],'output alias')
    require(not os.path.lexists(output),'output exists')
    require(output.parent.is_dir(),'output parent must exist')

def project_record(record):
    # Full gate precedes every field projection, including calls outside the CLI.
    gate_record(record)
    cases=[]
    for case in record['cases']:
        pairs=[]
        for pair in case['pairs']:
            row={k:pair[k] for k in ('index','start','end_exclusive','bytes','role_inference','first_raw_read','guest_writes_before_first_raw_read','byte_provenance','subsequent_store_count','final_words_in_selected31_trace','all8_bytes_guest_produced_at_end','physical_initialization_producer_known')}
            row['events']=[{k:event[k] for k in ('kind','stage','pc','address','size','value','raw_control_bytes','trace_index','unproduced_byte_addresses') if k in event} for event in pair['events']]
            pairs.append(row)
        cases.append({'pattern':case['pattern'],'all_guest_writes_scanned':case['all_guest_writes_scanned'],'pairs':pairs})
    return {'contiguous_ranges':record['contiguous_ranges'],'classified_bytes':48,'cases':cases,
            'manual_word_proof':record['manual_word_proof'],'page_count_derivation':record['page_count_derivation'],
            'ordering_method':record['ordering_method'],'historical_limits':record['limits']}

def run(decoded,accepted31,output):
    guard_output(output,[decoded,accepted31])
    own_source=Path(__file__).read_bytes()
    captured,manifest=capture_package()
    inputs=manifest['inputs']
    decoded_pin=(inputs['decoded']['bytes'],inputs['decoded']['sha256'])
    trace_pin=(inputs['accepted31']['bytes'],inputs['accepted31']['sha256'])
    data=capture(decoded,decoded_pin,'decoded')
    trace=capture(accepted31,trace_pin,'accepted31')
    scope={'__name__':'captured_scope36_model','__file__':str(HERE/'helpers/scope_model.py.inc')}
    exec(compile(captured['helpers/scope_model.py.inc'],scope['__file__'],'exec'),scope)
    record=scope['reconstruct'](data,trace)
    projection=project_record(record)
    import capstone,z3
    current={'python':sys.version.split()[0],'Capstone_distribution':importlib.metadata.version('capstone'),
             'Capstone_module':capstone.__version__,'Z3_distribution':importlib.metadata.version('z3-solver'),'Z3_engine':z3.get_version_string(),
             'cli_sha256':sha(own_source),'helper_sha256':PINS['helpers/scope_model.py.inc'][1]}
    result={'schema':1,'marker':'III-RMW-SCOPE-PUBLIC-36','whole_original35_typed_record_verified':True,
            'whole_original35_canonical_sha256':CANONICAL,'source_manifest_sha256':PINS['source.json'][1],
            'historical35':manifest['historical35'],'current_execution':current,'inputs':inputs,
            'source_block':manifest['model_block'],'source_instruction_hashes_reconstructed_and_gated':len(record['source_instructions']),
            'source_instructions_or_bytes_emitted':False,'historical31_observation_reverified':True,
            'new_original_CPU_execution':False,'projection':projection,'limits':manifest['limits']}
    require(capture(decoded,decoded_pin,'decoded')==data and capture(accepted31,trace_pin,'accepted31')==trace,'inputs changed')
    require(Path(__file__).read_bytes()==own_source,'CLI changed')
    guard_output(output,[decoded,accepted31])
    with output.open('x',encoding='utf-8',newline='\n') as target:
        json.dump(result,target,ensure_ascii=False,indent=2);target.write('\n')
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('decoded',type=Path);ap.add_argument('accepted31',type=Path);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();run(args.decoded,args.accepted31,args.output)
    print(json.dumps({'whole_original35_verified':True,'classified_bytes':48,'proved_bytes':4,'native_execution':False}))

if __name__=='__main__':main()
