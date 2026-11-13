"""Original first-task stack path after native task-table initialization under explicit raw-byte controls.
No allocator result, free-list object, OS handle or task pointer is supplied.
"""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import argparse, hashlib, json, os, sys
from pathlib import Path
sys.dont_write_bytecode=True
import unicorn
from unicorn import Uc,UcError,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_INVALID,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
BASE=0x52500000;STACK=0x1000e000;STOP=0x1000f000
PINS={'decoded':'7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9','rtos':'342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4','boot':'0a9c086818b9d6e7531b93710c2cab2782c7f2c32bb5b1c26e3b5b5b69695900','m0':'63dd8f3b2668ef68f3ab0f8ecd0f4cda8c46a78c5388646fc9e1fe85e39a070e'}
sha=lambda b:hashlib.sha256(b).hexdigest()

def replay(rtos):
    cs=Cs(CS_ARCH_ARM,CS_MODE_ARM);results=[]
    for kind,pattern in [('stack_request',0),('stack_route',0),('stack_new_read',0),('hardware_boundary',0),('hardware_boundary',0xff),('hardware_boundary',0xa5),('hardware_boundary',0x5a)]:
        u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
        u.mem_map(BASE,(len(rtos)+4095)&~4095);u.mem_write(BASE,rtos);u.mem_protect(BASE,(len(rtos)+4095)&~4095,UC_PROT_READ|UC_PROT_EXEC)
        u.mem_map(0x10000000,0x10000);u.mem_map(0x54500000,0x760000)
        u.mem_write(0x54500000,rtos[0x53ce7d40-BASE:0x53ce7d40-BASE+0x65a80])
        stage='';last=0;stops=set();reason=None;trace={};writes=[];reads=[];faults=[];outcomes=[];cache={};region=None;produced=set();controls=set();list_entries=[];allocator_entries=[]
        def word(a):return int.from_bytes(u.mem_read(a,4),'little')
        def pair(i):return [word(region[0]+8*i),word(region[0]+8*i+4)]
        def code(uc,a,size,_):
            nonlocal last,reason
            last=a
            if a==STOP:reason='native_return';uc.emu_stop();return
            if a in stops:reason='declared_slice_boundary';uc.emu_stop();return
            assert BASE<=a and a+size<=BASE+len(rtos),hex(a)
            if a not in cache:cache[a]=next(cs.disasm(rtos[a-BASE:a-BASE+size],a))
            ins=cache[a]
            if ins.mnemonic in ('mrc','mcr','mrrc','mcrr','svc'):
                reason='before_'+ins.mnemonic;uc.emu_stop();return
            trace.setdefault(stage,[]).append(a)
            if a==0x525d95a8:
                args=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1)]
                assert args==([0x5dc00,0x54582f80] if not allocator_entries else [0x6000,0x54582f48]) and word(0x54c3fd2c)==3
                allocator_entries.append(dict(stage=stage,args=[hex(x) for x in args],routing_word='0x3'))
            if a==0x525d8554:
                args=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
                assert args in ([1,0x2f50,region[0]],[0xbd,0x2e94,region[0]],[0xca,0x2e87,region[0]]) and pair(0)==[0,0]
                list_entries.append(dict(stage=stage,args=[hex(x) for x in args],native_node0=pair(0)))
        def write(uc,access,a,size,value,_):
            dynamic=region is not None and region[0]<=a<a+size<=region[1]
            assert 0x10000000<=a<a+size<=0x10010000 or 0x54500000<=a<a+size<=0x54565a80 or 0x54565b00<=a<a+size<=0x54c52c14 or dynamic,(hex(last),hex(a))
            if dynamic:produced.update(range(a,a+size))
            if not 0x10000000<=a<0x10010000 or last==0x525bb2c0:writes.append(dict(stage=stage,pc=hex(last),address=hex(a),size=size,value=hex(value)))
        def read(uc,access,a,size,value,_):
            if region and a<region[1] and a+size>region[0]:
                assert region[0]<=a<a+size<=region[1],('bounds',hex(last),hex(a),size)
                missing=set(range(a,a+size))-produced
                assert missing<=controls,('unproduced_read',hex(last),hex(a),size)
                if missing:
                    allowed={0x525d8564,0x525d856c,0x525d8594,0x525d859c,0x525d85b8,0x525d85bc,0x525d85d8,0x525d85ec,0x525d85f8,0x525d8604,0x525d8620,0x525d8628,0x525d8774,0x525d8784,0x525d8790,0x525d879c}
                    assert last in allowed,('raw_control_read_outside_RMW',hex(last),hex(a))
                reads.append(dict(stage=stage,pc=hex(last),address=hex(a),size=size,raw_control_bytes=len(missing)))
        def invalid(uc,access,a,size,value,_):faults.append(dict(stage=stage,pc=hex(last),address=hex(a),size=size,access=access));return False
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_MEM_READ,read);u.hook_add(UC_HOOK_MEM_INVALID,invalid)
        def execute(label,entry,stop_at=(),reset_stack=True):
            nonlocal stage,stops,reason
            stage=label;stops=set(stop_at);reason=None
            if reset_stack:u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP)
            error=None
            try:u.emu_start(entry,STOP,count=50000)
            except UcError as exc:error=str(exc)
            pc=u.reg_read(UC_ARM_REG_PC)
            if pc==STOP:reason='native_return'
            assert reason or faults,(label,hex(pc),'instruction_budget')
            row=dict(stage=label,entry=hex(entry),stop=hex(pc),reason=reason,error=error,r0=hex(u.reg_read(UC_ARM_REG_R0)))
            outcomes.append(row);return row
        assert execute('original_config_init',0x525d6eb4)['reason']=='native_return'
        assert execute('original_core_prologue',0x525b5a50)['stop']=='0x525b5a54'
        assert execute('independent_core0_branch',0x525b5a6c,[0x525b5b48],False)['stop']=='0x525b5b48'
        assert u.reg_read(UC_ARM_REG_SP)==STACK and word(0x547d2cc0)==0x40000
        assert execute('original_platform_bounds',0x525d9e94,[0x525d9f10])['stop']=='0x525d9f10'
        region=(word(0x54c40e68),word(0x54c40e5c));assert region==(0x56492c80,0x57c52c80)
        low=region[0]&~4095;high=(region[1]+4095)&~4095;u.mem_map(low,high-low)
        # Raw controls are restricted to separately proved RMW pairs.
        indices=(1,2,0x2f50,0xbc,0xbd,0xbe) if kind!='hardware_boundary' else (1,2,0x2f50,0xbc,0xbd,0xbe,0xc9,0xca,0xcb)
        for i in indices:
            a=region[0]+8*i;u.mem_write(a,bytes([pattern])*8);controls.update(range(a,a+8))
        assert len(controls)==(72 if kind=='hardware_boundary' else 48)
        row=execute('original_page_region_init',0x525d8a34)
        assert row['reason']=='native_return' and row['r0']=='0x0',row
        page_pairs={hex(i):pair(i) for i in (0,1,2,0x2f50)}
        assert page_pairs=={'0x0':[4,4],'0x1':[1,0],'0x2':[0xbd41,0],'0x2f50':[0xbd41,0]}
        row=execute('original_arena_headers',0x525d9a64);assert row['reason']=='native_return' and row['r0']=='0x0',row
        assert word(0x54582f28)==0x800 and word(0x54582f98)==0x300
        # Fresh state: no earlier pool-table allocation or task pointer supplied.
        assert word(0x5457ec50)==0 and word(0x54c40620)==0 and word(0x54c3fd2c)==0
        row=execute('task_config_to_request',0x525b8830,[0x525b88d4])
        assert row['stop']=='0x525b88d4' and row['r0']=='0x5dc00',row
        parsed=[word(a) for a in (0x54c405b4,0x54c40e24,0x54c3fd2c)]
        assert parsed==[300,16384,3] and word(0x54c40620)==0
        nodes=[];final_pairs=None;boundary=None
        row=execute('task_init_continuation',0x525b88d4,(),False)
        assert row['reason']=='native_return' and row['r0']=='0x0',row
        pointer=word(0x54c40620);assert pointer==0x564aa808
        assert word(0x54c3f4ec)==pointer and word(0x54c3f4f0)==pointer+299*0x500
        for i in range(300):
            a=pointer+i*0x500;record=[word(a+o) for o in (0,4,8,0x74,0x80,0x8c)]+[u.mem_read(a+0x2b,1)[0]]
            ident=0x01000000|(i+1)
            assert record==[a+0x500 if i<299 else 0x54c3f4ec,a-0x500 if i else 0x54c3f4ec,ident,ident,0,0,0],(i,record)
            nodes.append(dict(address=hex(a),next=hex(record[0]),previous=hex(record[1]),id=hex(ident),status_byte=0,offset80=0,offset8c=0))
        final_pairs={hex(i):pair(i) for i in (0,1,2,0xbc,0xbd,0xbe,0x2f50)}
        assert final_pairs=={'0x0':[0x2f4,0x2f4],'0x1':[7,4],'0x2':[0x2f3,0],'0xbc':[0x2f3,0],'0xbd':[1,0],'0xbe':[0xba51,0],'0x2f50':[0xba51,0]}
        prefix_controls={a for i in (1,2,0x2f50,0xbc,0xbd,0xbe) for a in range(region[0]+8*i,region[0]+8*i+8)}
        assert word(0x54582f04)==0x2e94 and len(list_entries)==2 and prefix_controls<=produced
        for base in (0x54c405d8,0x54c405bc,0x54c40e28):assert [word(base+4*i) for i in range(4)]==[0,0,0,0]
        assert list_entries==[
            dict(stage='original_page_region_init',args=['0x1','0x2f50','0x56492c80'],native_node0=[0,0]),
            dict(stage='task_init_continuation',args=['0xbd','0x2e94','0x56492c80'],native_node0=[0,0])]
        assert allocator_entries==[dict(stage='task_init_continuation',args=['0x5dc00','0x54582f80'],routing_word='0x3')]
        expected_raw=[
            ('original_page_region_init',0x525d8564,0x56492c88,1,1),('original_page_region_init',0x525d856c,0x56492c8c,1,1),
            ('original_page_region_init',0x525d8594,0x56492c90,1,1),('original_page_region_init',0x525d859c,0x56492c94,1,1),
            ('original_page_region_init',0x525d85b8,0x56492c90,4,3),('original_page_region_init',0x525d85bc,0x56492c94,4,3),
            ('original_page_region_init',0x525d85d8,0x564aa700,1,1),('original_page_region_init',0x525d85ec,0x564aa700,4,3),
            ('original_page_region_init',0x525d85f8,0x564aa704,1,1),('original_page_region_init',0x525d8604,0x564aa704,4,3),
            ('original_page_region_init',0x525d8620,0x56492c88,4,3),('original_page_region_init',0x525d8628,0x56492c8c,4,3),
            ('task_init_continuation',0x525d8774,0x56493260,1,1),('task_init_continuation',0x525d8784,0x56493260,4,3),
            ('task_init_continuation',0x525d8790,0x56493264,1,1),('task_init_continuation',0x525d879c,0x56493264,4,3),
            ('task_init_continuation',0x525d8564,0x56493268,1,1),('task_init_continuation',0x525d856c,0x5649326c,1,1),
            ('task_init_continuation',0x525d8594,0x56493270,1,1),('task_init_continuation',0x525d859c,0x56493274,1,1),
            ('task_init_continuation',0x525d85b8,0x56493270,4,3),('task_init_continuation',0x525d85bc,0x56493274,4,3),
            ('task_init_continuation',0x525d8620,0x56493268,4,3),('task_init_continuation',0x525d8628,0x5649326c,4,3)]
        assert [(x['stage'],int(x['pc'],16),int(x['address'],16),x['size'],x['raw_control_bytes']) for x in reads if x['raw_control_bytes']]==expected_raw
        actual_zero=[(int(x['pc'],16),int(x['address'],16),x['size'],int(x['value'],16)) for x in writes if int(x['pc'],16) in (0x525b8908,0x525b8914,0x525b8918)]
        expected_zero=[(pc,base+4*i,4,0) for i in range(4) for pc,base in ((0x525b8908,0x54c405d8),(0x525b8914,0x54c405bc),(0x525b8918,0x54c40e28))]
        assert actual_zero==expected_zero
        assert word(0x5457ec50)==0
        table_before=bytes(u.mem_read(word(0x54c40620),0x5dc00))
        queue_before=[word(0x54c3f4ec),word(0x54c3f4f0)]
        lock_before=word(0x54c3fd04)
        # Only source ROM descriptor is supplied as a function argument.
        u.reg_write(UC_ARM_REG_R0,0x533e33f8)
        row=execute('creator_stack_request',0x525bb150,[0x525bb2b8])
        assert row['stop']=='0x525bb2b8' and row['r0']=='0x6000' and u.reg_read(UC_ARM_REG_R1)==0,row
        assert u.reg_read(UC_ARM_REG_R5)==0x533e33f8
        creator_sp=u.reg_read(UC_ARM_REG_SP);stack_pointer=None;stack_pairs=None
        request=dict(bytes='0x6000',flags='0x0',descriptor='0x533e33f8',creator_sp=hex(creator_sp))
        route=None
        if kind!='stack_request':
            row=execute('creator_stack_route',0x525bb2b8,[0x525d95a8],False)
            assert row['stop']=='0x525d95a8' and row['r0']=='0x6000' and u.reg_read(UC_ARM_REG_R1)==0x54582f48,row
            route=dict(request='0x6000',arena='0x54582f48',allocator_body_entered=False)
            if kind=='stack_new_read':
                row=execute('creator_allocator_to_new_read',0x525d95a8,[0x525d8774],False)
                r2=u.reg_read(UC_ARM_REG_R2);r3=u.reg_read(UC_ARM_REG_R3);address=(r3+(r2<<3))&0xffffffff
                assert row['stop']=='0x525d8774' and (r2,r3,address)==(0x2000000c,0x56493268,0x564932c8)
                assert u.reg_read(UC_ARM_REG_R6)==0xd and u.reg_read(UC_ARM_REG_R4)==0xbd
                assert address not in controls and address not in produced
                boundary=dict(pc='0x525d8774',r2=hex(r2),r3=hex(r3),index='0xbd',page_count='0xd',effective_address=hex(address),read_executed=False,byte_produced_or_controlled=False)
                route['allocator_body_entered']=True
            elif kind=='hardware_boundary':
                row=execute('creator_to_first_processor_read',0x525d95a8,(),False)
                assert row['stop']=='0x525b7a24' and row['reason']=='before_mrc',row
                route['allocator_body_entered']=True
                stack_pointer=word(creator_sp+0xc);assert stack_pointer==0x56508808
                assert u.reg_read(UC_ARM_REG_SP)==creator_sp-8 and u.reg_read(UC_ARM_REG_R0)==0x54c3fd04
                assert word(creator_sp+0x14)==0 and word(0x54c3fd04)==lock_before
                assert [x for x in writes if x['pc']=='0x525bb2c0']==[dict(stage='creator_to_first_processor_read',pc='0x525bb2c0',address=hex(creator_sp+0xc),size=4,value='0x56508808')]
                stack_pairs={hex(i):pair(i) for i in (0,0xbd,0xbe,0xc9,0xca,0xcb,0x2f50)}
                assert stack_pairs=={'0x0':[0x328,0x328],'0xbd':[0x2f7,0x2f4],'0xbe':[0x37,0],'0xc9':[0x37,0],'0xca':[1,0],'0xcb':[0xba1d,0],'0x2f50':[0xba1d,0]}
                assert word(0x54582f04)==0x2e87 and controls<=produced and len(list_entries)==3
                assert list_entries[-1]==dict(stage='creator_to_first_processor_read',args=['0xca','0x2e87','0x56492c80'],native_node0=[0,0])
                expected_stack_raw=[
                    (0x525d8774,0x564932c8,1,1),(0x525d8784,0x564932c8,4,3),
                    (0x525d8790,0x564932cc,1,1),(0x525d879c,0x564932cc,4,3),
                    (0x525d8564,0x564932d0,1,1),(0x525d856c,0x564932d4,1,1),
                    (0x525d8594,0x564932d8,1,1),(0x525d859c,0x564932dc,1,1),
                    (0x525d85b8,0x564932d8,4,3),(0x525d85bc,0x564932dc,4,3),
                    (0x525d8620,0x564932d0,4,3),(0x525d8628,0x564932d4,4,3)]
                assert [(int(x['pc'],16),int(x['address'],16),x['size'],x['raw_control_bytes']) for x in reads if x['stage']=='creator_to_first_processor_read' and x['raw_control_bytes']]==expected_stack_raw
                assert u.reg_read(UC_ARM_REG_CPSR)&0x80
                boundary=dict(pc='0x525b7a24',instruction='MPIDR read',executed=False,r0='0x54c3fd04',r0_is_lock_address_not_task_return=True,lock_word_before=hex(lock_before),lock_word_after=hex(word(0x54c3fd04)))
        assert word(0x54c40620)==pointer and bytes(u.mem_read(pointer,0x5dc00))==table_before
        assert [word(0x54c3f4ec),word(0x54c3f4f0)]==queue_before
        watched=[(pointer,pointer+0x5dc00),(0x54c3f4ec,0x54c3f4f4),(0x54c40620,0x54c40624),(0x54c3fd04,0x54c3fd18)]
        for x in writes:
            if x['stage'].startswith('creator_'):
                a=int(x['address'],16)
                assert not any(a<z and a+x['size']>start for start,z in watched),('unexpected_creator_task_or_lock_write',x)
        creator_code={a for name,seq in trace.items() if name.startswith('creator_') for a in seq}
        assert not creator_code.intersection({0x525bb310,0x525bb408,0x525bb420,0x525bb2e8})
        for base in (0x54c405d8,0x54c405bc,0x54c40e28):assert [word(base+4*i) for i in range(4)]==[0,0,0,0]
        assert not faults and bytes(u.mem_read(BASE,len(rtos)))==rtos
        addresses=sorted({a for seq in trace.values() for a in seq});ranges=[]
        for a in addresses:
            if ranges and ranges[-1][1]==a:ranges[-1][1]=a+4
            else:ranges.append([a,a+4])
        results.append(dict(kind=kind,raw_byte_pattern=hex(pattern),host_control_addresses=[hex(region[0]+8*i) for i in indices],host_control_bytes=len(controls),
            outcomes=outcomes,boundary=boundary,parsed_task_config=parsed,page_initializer_final_pairs=page_pairs,task_table_pairs=final_pairs,creator_stack_request=request,creator_stack_route=route,native_stack_pointer=hex(stack_pointer) if stack_pointer is not None else None,after_stack_pairs=stack_pairs,creator_returned=False,task_table_bytes_and_queue_unchanged=True,list_entry_preconditions=list_entries,allocator_entry_preconditions=allocator_entries,
            native_task_pointer=hex(word(0x54c40620)),task_nodes=nodes,remaining_pages=hex(word(0x54582f04)),pool_table_pointer=hex(word(0x5457ec50)),
            per_core_zero_words={hex(base):[word(base+4*i) for i in range(4)] for base in (0x54c405d8,0x54c405bc,0x54c40e28)},
            region=dict(start=hex(region[0]),end_exclusive=hex(region[1]),native_written_bytes=len(produced),all_raw_controls_overwritten=controls<=produced,final_bytes_sha256=sha(bytes(u.mem_read(region[0],region[1]-region[0])))),
            writes=writes,reads=reads,faults=faults,code_hook_addresses={k:[hex(a) for a in seq] for k,seq in trace.items()},
            native_ranges=[dict(start=hex(a),end=hex(z),sha256=sha(rtos[a-BASE:z-BASE])) for a,z in ranges],original_code_unchanged=True,hardware_or_SVC_executed=False))
    complete=[x for x in results if x['kind']=='hardware_boundary'];reference=complete[0]
    for case in complete[1:]:
        for field in ('outcomes','parsed_task_config','page_initializer_final_pairs','task_table_pairs','creator_stack_request','creator_stack_route','native_stack_pointer','after_stack_pairs','boundary','list_entry_preconditions','allocator_entry_preconditions','native_task_pointer','task_nodes','remaining_pages','pool_table_pointer','per_core_zero_words','region','reads','code_hook_addresses'):
            assert case[field]==reference[field],field
    assert any(c['writes']!=reference['writes'] for c in complete[1:])
    return dict(marker='III-TASK-CREATE-27',verified=True,cases=results,engine=dict(name='Unicorn',version=unicorn.__version__,cpu='Cortex-A7'),
        comparison='Hardware-boundary controls agree on stack pointer, final metadata, unchanged task table/queue, read/code traces; transient writes differ.',
        trace_semantics='Code hooks include conditionally false ARM instructions; not every listed instruction committed effects.',
        limits=['Initial config/page/arena producers are separate original-code entries before any pool-table allocation; not whole startup.',
            'Core0 branch separately entered after native prologue, without MPIDR substitution/execution. Physical mapping unproven.',
            'Raw48bytes for task-table setup plus24additionalstack-RMW bytes are explicit host controls, not source contents/free-list objects.',
            'Native task setup produces correct route3/table, then ROM descriptor yields6000 stack bytes/flags0/arena54582f48. Other full-startup dependencies remain unmodeled.',
            'Stack allocation completes only in last4controls; creator stops BEFORE lock helper MPIDR525b7a24, earlier than creator-local525bb310. No task record consumed, lock acquisition, creator return, scheduling or positive OS handle.',
            'No SVC,CP15,device,build,flash,patched code,fake returns or supplied task pointers; concurrent/interrupt observers outside proof.'])


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('decoded',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    if os.path.lexists(a.output):raise FileExistsError(a.output)
    d=a.decoded.read_bytes();assert sha(d)==PINS['decoded']
    images={'rtos':d[0x1c19c:0x1c19c+25483200],'boot':d[0x16ccc:0x16ccc+21696],'m0':d[1208:1208+92164]}
    for k,b in images.items():assert sha(b)==PINS[k]
    result=replay(images['rtos']);assert sha(a.decoded.read_bytes())==PINS['decoded']
    result.update(inputs=PINS,script_sha256=sha(Path(__file__).read_bytes()),disk_input_unchanged=True)
    with a.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(dict(verified=True,cases=len(result['cases']),stack_pointer=result['cases'][-1]['native_stack_pointer'],stop=result['cases'][-1]['outcomes'][-1]['stop'])))
if __name__=='__main__':main()
