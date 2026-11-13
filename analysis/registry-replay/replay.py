"""Verify the full frozen registry witness, then emit a firmware-free summary."""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
SIZE=78683892
DECODED='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RTOS='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
ORIGINAL_SCRIPT='7dd968d21c8510bb629b43918d7c9e24b36b819650ebdcc9dd0d006c0e6da2a0'
WITNESS_SHA='95a5ce68c95bcc4391894983e0650cf8098ae6f2c56878667b0a64cb01ef7b98'
WITNESS_SIZE=7200103
FILES={'helpers/native.py.inc':'072d660f7abeb63b959848392545f411fb0e1a56a178d21f1f8d3a38bcc6cd3a',
       'source-ranges.json':'293b9ef7243e0a6ccb45cdc917a457d3dfd32f9a16a53c2bd789e70e7636b2a5',
       'provenance.json':'1be9be77c0c4c9a680e6ee62a795d8d544ffa42037ac29b614b9cb9ecff0b6cc'}
sha=lambda b:hashlib.sha256(b).hexdigest()

def require(ok,message):
    if not ok:raise ValueError(message)

def address(value):
    require(type(value) is str and re.fullmatch(r'0x[0-9a-f]{8}',value) is not None,'invalid address type or format')
    return int(value,16)

def validate_manifest(m):
    require(type(m) is dict and set(m)=={'schema','base_address','rtos_size','rtos_sha256','named_ranges','executed_hook_ranges','data_ranges'},'manifest fields')
    require(type(m['schema']) is int and m['schema']==1,'manifest schema type')
    require(type(m['rtos_size']) is int and m['rtos_size']==25483200,'manifest size type')
    base=address(m['base_address']);require(base==0x52500000 and m['rtos_sha256']==RTOS,'manifest identity')
    for key,count in [('named_ranges',14),('executed_hook_ranges',46),('data_ranges',6)]:
        rows=m[key];require(type(rows) is list and len(rows)==count,'manifest record count: '+key)
        names=[];previous=base
        for row in rows:
            expected={'name','address','size','sha256'} if key=='data_ranges' else {'start','end','sha256'}|({'name'} if key=='named_ranges' else set())
            require(type(row) is dict and set(row)==expected,'source record fields')
            require(type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}',row['sha256']) is not None,'source digest format')
            if 'name' in row:
                require(type(row['name']) is str and re.fullmatch(r'[A-Za-z0-9_]+',row['name']) is not None,'source name type')
                names.append(row['name'])
            if key=='data_ranges':
                start=address(row['address']);require(type(row['size']) is int and row['size']>0,'data size type');end=start+row['size']
            else:
                start,end=address(row['start']),address(row['end']);require(start%4==0 and end%4==0,'code alignment')
            require(base<=start<end<=base+m['rtos_size'],'source range bounds')
            if key=='executed_hook_ranges':require(start>=previous,'hook ranges overlap or unsorted');previous=end
        require(len(names)==len(set(names)),'duplicate source names')

def validate_provenance(p):
    fields={'schema','source_marker','original_source_script_sha256','public_helper_sha256','helper_transformation','full_witness_sha256','full_witness_bytes','witness_encoding','original_envelope'}
    require(type(p) is dict and set(p)==fields,'provenance fields')
    require(type(p['schema']) is int and p['schema']==1,'provenance schema type')
    require(type(p['full_witness_bytes']) is int and p['full_witness_bytes']==WITNESS_SIZE and p['full_witness_sha256']==WITNESS_SHA,'provenance witness')
    require(p['source_marker']=='III-REGISTRY-RAM-31' and p['original_source_script_sha256']==ORIGINAL_SCRIPT and p['public_helper_sha256']==FILES['helpers/native.py.inc'],'provenance source/helper identity')
    e=p['original_envelope'];require(type(e) is dict and list(e)==['marker','decoded_sha256','rtos_sha256','script_sha256','cases','limits'],'original envelope fields/order')
    require(e['marker']=='III-REGISTRY-RAM-31' and e['decoded_sha256']==DECODED and e['rtos_sha256']==RTOS and e['script_sha256']==ORIGINAL_SCRIPT,'original envelope identity')
    require(type(e['cases']) is list and not e['cases'] and type(e['limits']) is list and len(e['limits'])==6 and all(type(x) is str for x in e['limits']),'original envelope types')

def capture_package():
    captured={name:(HERE/name).read_bytes() for name in FILES}
    for name,pin in FILES.items():require(sha(captured[name])==pin,'package hash mismatch: '+name)
    manifest=json.loads(captured['source-ranges.json']);provenance=json.loads(captured['provenance.json'])
    validate_manifest(manifest);validate_provenance(provenance)
    return captured,manifest,provenance

def read_input(path):
    require(path.is_file() and path.stat().st_size==SIZE,'decoded input size mismatch')
    with path.open('rb') as f:data=f.read(SIZE+1)
    require(len(data)==SIZE and sha(data)==DECODED,'decoded input hash mismatch')
    return data

def guard_output(output,decoded):
    protected=[decoded,Path(__file__),*(HERE/name for name in FILES)]
    require(output.resolve() not in [p.resolve() for p in protected],'output aliases input or package source')
    require(not os.path.lexists(output),'output already exists')
    require(output.parent.is_dir(),'output parent must exist')

def verify_sources(rtos,manifest):
    require(len(rtos)==manifest['rtos_size'] and sha(rtos)==RTOS,'RTOS identity mismatch')
    base=address(manifest['base_address'])
    for row in manifest['named_ranges']+manifest['executed_hook_ranges']:
        a,z=address(row['start'])-base,address(row['end'])-base
        require(sha(rtos[a:z])==row['sha256'],'source code range mismatch')
    for row in manifest['data_ranges']:
        a=address(row['address'])-base;require(sha(rtos[a:a+row['size']])==row['sha256'],'source data range mismatch')

def observe(rtos,captured,provenance):
    namespace={'__name__':'captured_public_registry_helper','__file__':str(HERE/'helpers/native.py.inc')}
    exec(compile(captured['helpers/native.py.inc'],namespace['__file__'],'exec'),namespace)
    # Source SHA identifies the frozen original probe; captured executable has its own checked hash.
    full=dict(provenance['original_envelope'])
    full['cases']=[namespace['replay'](rtos,pattern) for pattern in (0,0xa5)]
    return full

def validate_observation(full,manifest):
    require(type(full) is dict and list(full)==['marker','decoded_sha256','rtos_sha256','script_sha256','cases','limits'],'witness fields/order')
    require(type(full['cases']) is list and len(full['cases'])==2,'case count')
    for case,pattern in zip(full['cases'],('0x0','0xa5')):
        require(type(case) is dict and case['backing_ram_pattern']==pattern,'case identity')
        for key,expected in [('raw_read_control_bytes',56),('hash_zero_stores',300),('hash_reads',300),('task_name_reads',0)]:
            require(type(case[key]) is int and case[key]==expected,'case integer: '+key)
        require(case['executed_ranges']==manifest['executed_hook_ranges'],'observed hook/source ranges disagree')
        require(type(case['outcomes']) is list and len(case['outcomes'])==11,'entry count')
        require(type(case['exclusive_status']) is list and len(case['exclusive_status'])==10,'exclusive outcome count')
        for x in case['exclusive_status']:require(type(x['status']) is int and x['status']==0,'exclusive status type/value')
        for key in ('writes','reads','trace','exclusive_events'):
            require(type(case[key]) is list and all(type(x) is dict for x in case[key]),'record list type: '+key)
        for x in case['writes']+case['reads']:
            require(type(x['size']) is int and x['size']>0,'memory access size type')
        require(type(case['fill']['bytes']) is int and case['fill']['bytes']==1200,'fill size type')

def check_witness(full):
    raw=(json.dumps(full,indent=2)+'\n').encode('utf-8')
    require(len(raw)==WITNESS_SIZE and sha(raw)==WITNESS_SHA,'complete observation witness mismatch; no projection emitted')
    return {'sha256':WITNESS_SHA,'bytes':WITNESS_SIZE,'byte_identical_to_accepted31':True}

def record_digest(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('utf-8')
    return {'count':len(value),'sha256':sha(raw),'serialized_bytes':len(raw)}

def project_case(case):
    keys=('backing_ram_pattern','raw_read_control_bytes','raw_control_addresses','logical_heap','outcomes','native_hash_pointer','native_task_pointer','hash_zero_stores','hash_reads','task_name_reads','lookup_returns','empty_name_original_ROM','exclusive_status','task_records_and_queue_unchanged','no_forced_exclusive_status','MPIDR_CP15_SVC_executed','original_code_unchanged')
    projected={k:case[k] for k in keys}
    projected['registry_count_reads']=sum(x['stage']=='original_first_name_lookup' and x['pc'] in ('0x525d5398','0x525d53c8') for x in case['reads'])
    projected['registry_pointer_reads']=sum(x['stage']=='original_first_name_lookup' and x['pc']=='0x525d53dc' for x in case['reads'])
    projected['fill']={k:v for k,v in case['fill'].items() if k not in ('guard_left_before','guard_right_before')}
    projected['fill']['neighbor_guard_bytes_each_side']=8
    projected['omitted_records']={k:record_digest(case[k]) for k in ('writes','reads','trace','exclusive_events')}
    projected['exclusive_RAM_targets']=sorted({x['address'] for x in case['exclusive_events']})
    return projected

def run(decoded,output):
    guard_output(output,decoded)
    captured,manifest,provenance=capture_package()
    data=read_input(decoded);rtos=data[0x1c19c:0x1c19c+25483200];verify_sources(rtos,manifest)
    full=observe(rtos,captured,provenance);validate_observation(full,manifest)
    witness=check_witness(full)  # Every omitted observation is checked before projection.
    require(read_input(decoded)==data,'input changed during replay')
    import unicorn,capstone
    result={'schema':1,'marker':'III-REGISTRY-PUBLIC-32','verified':True,'input':{'size':SIZE,'sha256':DECODED},'rtos_sha256':RTOS,
            'original_source_script_sha256':ORIGINAL_SCRIPT,'public_helper_sha256':FILES['helpers/native.py.inc'],
            'source_manifest_sha256':FILES['source-ranges.json'],'provenance_manifest_sha256':FILES['provenance.json'],
            'native_engine':{'name':'Unicorn','version':unicorn.__version__,'cpu_model':'Cortex-A7','vcpus_per_VM':1,'Capstone':capstone.__version__},'complete_witness':witness,'cases':[project_case(c) for c in full['cases']],
            'source_config':{'max_domain_id':100,'domain_record11_count_if_successful':101,'domain_initializer_executed':False},
            'host_initial_memory':{'original_data_copy':{'source':'0x53ce7d40','destination':'0x54500000','bytes':416384},'zero_global_mapping':['0x54500000','0x54c60000'],'synthetic_call_stack':['0x10000000','0x10010000'],'call_SP':'0x1000e000','call_LR':'0x1000f000','entry_CPSR':'0x13','core0_branch_selected_after_MPIDR_stop':True,'other11_registry_types_and_domain_init_omitted':True},
            'projection':{'full_witness_saved_to_disk':False,'firmware_bytes_or_disassembly_bundled':False,'record_digest_encoding':'UTF-8 JSON sort_keys=True separators=(comma,colon) ensure_ascii=True','write_log':'All guest stores including synthetic stack','read_log':'Only unproduced RMW reads and lookup/empty-control reads; not all guest reads','code_hooks':'May include predicated-false instructions; actual stores logged separately','adjacent_guard':'Final equality of eight bytes before/after fill, not proof of no intervening write'},'limits':full['limits']}
    guard_output(output,decoded)
    with output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('decoded',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    result=run(a.decoded,a.output)
    print(json.dumps({'verified':True,'native_cases':len(result['cases']),'full_witness_bytes':WITNESS_SIZE,'hash_pointer':result['cases'][0]['native_hash_pointer']}))
if __name__=='__main__':main()
