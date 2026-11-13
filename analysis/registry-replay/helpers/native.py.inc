"""Original registry allocator and lookup on explicit single-vCPU synthetic RAM."""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import argparse,hashlib,json,os,sys
from pathlib import Path
sys.dont_write_bytecode=True
BASE=0x52500000;STACK=0x1000e000;STOP=0x1000f000
PIN='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RTOS_PIN='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
sha=lambda b:hashlib.sha256(b).hexdigest()

def replay(rtos,pattern):
    import unicorn as uc
    from unicorn import arm_const as ar
    from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
    from capstone.arm import ARM_INS_MRC,ARM_INS_MCR,ARM_INS_MRRC,ARM_INS_MCRR,ARM_INS_SVC,ARM_INS_LDREX,ARM_INS_STREX,ARM_INS_LDREXB,ARM_INS_LDREXH,ARM_INS_LDREXD,ARM_INS_STREXB,ARM_INS_STREXH,ARM_INS_STREXD
    u=uc.Uc(uc.UC_ARCH_ARM,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM_CORTEX_A7)
    size=(len(rtos)+4095)&~4095;u.mem_map(BASE,size);u.mem_write(BASE,rtos);u.mem_protect(BASE,size,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
    u.mem_map(0x10000000,0x10000);u.mem_map(0x54500000,0x760000);u.mem_write(0x54500000,rtos[0x17e7d40:0x17e7d40+0x65a80])
    cs=Cs(CS_ARCH_ARM,CS_MODE_ARM);cs.detail=True
    forbidden={ARM_INS_MRC,ARM_INS_MCR,ARM_INS_MRRC,ARM_INS_MCRR,ARM_INS_SVC}
    exclusive={ARM_INS_LDREX,ARM_INS_STREX,ARM_INS_LDREXB,ARM_INS_LDREXH,ARM_INS_LDREXD,ARM_INS_STREXB,ARM_INS_STREXH,ARM_INS_STREXD}
    reg=lambda n:u.reg_read(getattr(ar,'UC_ARM_REG_'+n));word=lambda a:int.from_bytes(u.mem_read(a,4),'little')
    stage='';last=0;stops=set();reason=None;region=None;mapping=None;produced=set();controls=set();trace=[];writes=[];reads=[];exclusive_events=[];exclusive_status=[];outcomes=[];fill=None;lookup_returns=[];cache={}
    def code(engine,a,size,unused):
        nonlocal last,reason,fill
        last=a
        if a==STOP or a in stops:reason='native_return' if a==STOP else 'declared_boundary';engine.emu_stop();return
        assert BASE<=a<a+size<=BASE+len(rtos),('non-ROM execution',hex(a))
        if a not in cache:cache[a]=next(cs.disasm(rtos[a-BASE:a-BASE+size],a))
        ins=cache[a]
        if ins.id in forbidden:reason='before_'+ins.mnemonic;engine.emu_stop();return
        if ins.id in exclusive:
            allowed={0x525da534:0x54c40e60,0x525da53c:0x54c40e60,0x525da59c:0x545011a0,0x525da5a4:0x545011a0,0x525da5c4:0x545011a0,0x525da5cc:0x545011a0}
            assert a in allowed and reg('R0')==allowed[a],(hex(a),hex(reg('R0')))
            if reg('R0')==0x54c40e60: assert any(x['pc']=='0x525da520' and x['address']=='0x54c40e60' and x['value']=='0x0' for x in writes),'no original lock initializer'
            else: assert rtos[0x17e8ee0:0x17e8ee4]==bytes.fromhex('ffffffff'),'original .data counter initializer'
            exclusive_events.append({'stage':stage,'pc':hex(a),'instruction':ins.mnemonic,'address':hex(reg('R0')),'word_before':hex(word(reg('R0')))})
        if a in (0x525da540,0x525da5a8,0x525da5d0):
            status=reg('R2');assert status in (0,1)
            exclusive_status.append({'stage':stage,'pc_after_strex':hex(a),'status':status})
        trace.append({'stage':stage,'pc':hex(a)})
        if stage=='table0_calloc_and_original_pointer_store' and a==0x525d9a20:
            ptr=reg('R0');assert ptr!=0 and reg('R1')==0 and reg('R2')==1200
            assert region[0]<=ptr<ptr+1200<=region[1]
            before=bytes(u.mem_read(ptr,1200));assert before==bytes([pattern])*1200
            fill={'pointer':hex(ptr),'bytes':1200,'before_sha256':sha(before),'before_pattern':hex(pattern),'guard_left_before':bytes(u.mem_read(ptr-8,8)).hex(),'guard_right_before':bytes(u.mem_read(ptr+1200,8)).hex()}
        if stage=='table0_calloc_and_original_pointer_store' and a==0x525d5bf4:
            assert fill is not None and reg('R0')==int(fill['pointer'],16)
            ptr=reg('R0');assert bytes(u.mem_read(ptr,1200))==bytes(1200)
            assert bytes(u.mem_read(ptr-8,8)).hex()==fill['guard_left_before'] and bytes(u.mem_read(ptr+1200,8)).hex()==fill['guard_right_before']
            fill['after_sha256']=sha(bytes(u.mem_read(ptr,1200)));fill['adjacent_bytes_unchanged_by_fill']=True
        if a==0x525d5770:lookup_returns.append({'stage':stage,'inner_lookup_r0':hex(reg('R0'))})
    def write(engine,access,a,size,value,unused):
        dynamic=region is not None and region[0]<=a<a+size<=region[1]
        assert 0x10000000<=a<a+size<=0x10010000 or 0x54500000<=a<a+size<=0x54565a80 or 0x54565b00<=a<a+size<=0x54c52c14 or dynamic,('unallowed store',hex(last),hex(a))
        if dynamic:produced.update(range(a,a+size))
        writes.append({'stage':stage,'pc':hex(last),'address':hex(a),'size':size,'value':hex(value)})
    def read(engine,access,a,size,value,unused):
        missing=set()
        if mapping is not None and a<mapping[1] and a+size>mapping[0]:
            assert region[0]<=a<a+size<=region[1],('mapped padding read',hex(last),hex(a),size)
        if region is not None and a<region[1] and a+size>region[0]:
            assert region[0]<=a<a+size<=region[1]
            missing=set(range(a,a+size))-produced
            assert missing<=controls,('unproduced dynamic read',stage,hex(last),hex(a),size)
            if missing:assert last in {0x525d8564,0x525d856c,0x525d8594,0x525d859c,0x525d85b8,0x525d85bc,0x525d85d8,0x525d85ec,0x525d85f8,0x525d8604,0x525d8620,0x525d8628,0x525d8774,0x525d8784,0x525d8790,0x525d879c}
        if missing or stage in ('original_first_name_lookup','empty_name_control'):
            reads.append({'stage':stage,'pc':hex(last),'address':hex(a),'size':size,'raw_control_bytes':len(missing)})
    u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.hook_add(uc.UC_HOOK_MEM_READ,read)
    def execute(label,entry,stop_at=(),reset_stack=True,args=None,stack_arg=None):
        nonlocal stage,stops,reason
        stage=label;stops=set(stop_at);reason=None
        if reset_stack:u.reg_write(ar.UC_ARM_REG_CPSR,0x13);u.reg_write(ar.UC_ARM_REG_SP,STACK);u.reg_write(ar.UC_ARM_REG_LR,STOP)
        for name,value in (args or {}).items():u.reg_write(getattr(ar,'UC_ARM_REG_'+name),value)
        if stack_arg is not None:u.mem_write(STACK,stack_arg.to_bytes(4,'little'))
        entry_registers={name:hex(reg(name)) for name in [*(f'R{i}' for i in range(13)),'SP','LR','CPSR']}
        u.emu_start(entry,STOP,count=100000)
        if reg('PC')==STOP:reason='native_return'
        assert reason,(label,'budget',hex(reg('PC')))
        row={'stage':label,'entry':hex(entry),'stop':hex(reg('PC')),'reason':reason,'r0':hex(reg('R0')),'entry_registers':entry_registers,'host_register_arguments':{name:hex(value) for name,value in (args or {}).items()},'host_stack_argument':hex(stack_arg) if stack_arg is not None else None,'reset_call_stack_and_CPSR':reset_stack};outcomes.append(row);return row
    assert execute('original_config_init',0x525d6eb4)['reason']=='native_return'
    assert execute('original_core_prologue',0x525b5a50)['stop']=='0x525b5a54'
    assert execute('independent_core0_branch',0x525b5a6c,[0x525b5b48],False)['stop']=='0x525b5b48'
    assert execute('original_platform_bounds',0x525d9e94,[0x525d9f10])['stop']=='0x525d9f10'
    region=(word(0x54c40e68),word(0x54c40e5c));assert region==(0x56492c80,0x57c52c80)
    low=region[0]&~4095;high=(region[1]+4095)&~4095;mapping=(low,high);u.mem_map(low,high-low);u.mem_write(region[0],bytes([pattern])*(region[1]-region[0]))
    for i in (1,2,0x2f50,0xbc,0xbd,0xbe,0xbf):controls.update(range(region[0]+8*i,region[0]+8*i+8))
    assert execute('original_page_region_init',0x525d8a34)['r0']=='0x0'
    assert execute('original_arena_headers',0x525d9a64)['r0']=='0x0'
    assert word(0x54c40e60)==0 and word(0x54582f98)==0x300
    assert execute('original_task_table_init',0x525b8830)['r0']=='0x0'
    task_table=word(0x54c40620);count=word(0x54c405b4);assert task_table==0x564aa808 and count==300 and word(0x54c3fd2c)==3
    task_before=bytes(u.mem_read(task_table,0x5dc00));queue_before=bytes(u.mem_read(0x54c3f4ec,8))
    assert word(0x5457ec90)==0 and word(0x5457ec94)==0
    row=execute('independent_table0_count_store',0x525d5bb8,[0x525d5bbc],args={'R0':count,'R4':0x5457ec90});assert row['stop']=='0x525d5bbc'
    assert [x for x in writes if x['stage']=='independent_table0_count_store']==[{'stage':'independent_table0_count_store','pc':'0x525d5bb8','address':'0x5457ec90','size':4,'value':'0x12c'}]
    row=execute('table0_calloc_and_original_pointer_store',0x525d5bec,[0x525d5bf8],args={'R0':word(0x5457ec90),'R5':0x5457ec90})
    assert row['stop']=='0x525d5bf8' and fill is not None
    ptr=word(0x5457ec94);assert ptr==reg('R0')==int(fill['pointer'],16)
    stores=[x for x in writes if x['stage']=='table0_calloc_and_original_pointer_store' and ptr<=int(x['address'],16)<ptr+1200]
    assert len(stores)==300 and all(x['pc']=='0x525da980' and x['size']==4 and x['value']=='0x0' for x in stores)
    assert [int(x['address'],16) for x in stores]==list(range(ptr,ptr+1200,4))
    assert [x for x in writes if x['pc']=='0x525d5bf4']==[{'stage':'table0_calloc_and_original_pointer_store','pc':'0x525d5bf4','address':'0x5457ec94','size':4,'value':hex(ptr)}]
    row=execute('original_first_name_lookup',0x525bb354,[0x525bb390],args={'R5':0x533e33f8});assert row['stop']=='0x525bb390' and row['r0']=='0x0'
    first=[x for x in reads if x['stage']=='original_first_name_lookup']
    assert [(int(x['address'],16),x['size']) for x in first if x['pc']=='0x525d53e0']==[(ptr+4*i,4) for i in range(300)]
    assert [x['address'] for x in first if x['pc']=='0x525d53dc']==['0x5457ec94']*300
    assert [(x['pc'],x['address'],x['size']) for x in first if x['pc'] in ('0x525d5398','0x525d53c8')]==[('0x525d5398','0x5457ec90',4)]+[('0x525d53c8','0x5457ec90',4)]*300
    assert [(int(x['address'],16),x['size']) for x in first if x['pc']=='0x525d5364']==[(0x533e3428+i,1) for i in range(8)]
    assert not any(task_table<=int(x['address'],16)<task_table+0x5dc00 for x in first)
    assert not any(x['stage']=='original_first_name_lookup' and x['pc'] in ('0x525d53ec','0x525d53f8') for x in trace)
    assert rtos[0x533e3353-BASE]==0
    row=execute('empty_name_control',0x525d575c,args={'R0':0,'R1':task_table+0xcc,'R2':0x500,'R3':0},stack_arg=0x533e3353)
    assert row['reason']=='native_return' and row['r0']=='0x0'
    empty=[x for x in reads if x['stage']=='empty_name_control'];assert [x['address'] for x in empty if x['pc']=='0x525d5364']==['0x533e3353']
    assert not any(x['pc'] in ('0x525d5398','0x525d53dc','0x525d53e0') for x in empty)
    assert lookup_returns==[{'stage':s,'inner_lookup_r0':'0xffffffff'} for s in ('original_first_name_lookup','empty_name_control')]
    assert bytes(u.mem_read(task_table,0x5dc00))==task_before and bytes(u.mem_read(0x54c3f4ec,8))==queue_before
    assert bytes(u.mem_read(ptr,1200))==bytes(1200) and word(0x54c40e60)==0 and controls<=produced, ('final',hex(ptr),hex(word(0x54c40e60)),[hex(a) for a in sorted(controls-produced)])
    assert bytes(u.mem_read(BASE,len(rtos)))==rtos
    assert [(x['pc'],x['address'],x['size'],x['raw_control_bytes']) for x in reads if x['stage']=='table0_calloc_and_original_pointer_store' and x['raw_control_bytes']]==[('0x525d8594','0x56493278',1,1),('0x525d859c','0x5649327c',1,1),('0x525d85b8','0x56493278',4,3),('0x525d85bc','0x5649327c',4,3)]
    for x in writes:
        if x['stage'] in ('original_first_name_lookup','empty_name_control'):assert 0x10000000<=int(x['address'],16)<0x10010000
    pcs=sorted({int(x['pc'],16) for x in trace});ranges=[]
    for a in pcs:
        if ranges and ranges[-1][1]==a:ranges[-1][1]=a+4
        else:ranges.append([a,a+4])
    return {'backing_ram_pattern':hex(pattern),'raw_read_control_bytes':56,'raw_control_addresses':[hex(region[0]+8*i) for i in (1,2,0x2f50,0xbc,0xbd,0xbe,0xbf)],'logical_heap':{'start':hex(region[0]),'end_exclusive':hex(region[1])},'outcomes':outcomes,'fill':fill,'native_hash_pointer':hex(ptr),'native_task_pointer':hex(task_table),'hash_zero_stores':len(stores),'hash_reads':300,'task_name_reads':0,'lookup_returns':lookup_returns,'empty_name_original_ROM':'0x533e3353','writes':writes,'reads':reads,'trace':trace,'exclusive_events':exclusive_events,'exclusive_status':exclusive_status,'executed_ranges':[{'start':hex(a),'end':hex(z),'sha256':sha(rtos[a-BASE:z-BASE])} for a,z in ranges],'task_records_and_queue_unchanged':True,'no_forced_exclusive_status':True,'MPIDR_CP15_SVC_executed':False,'original_code_unchanged':True}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('decoded',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert not os.path.lexists(a.output),'output exists';assert a.decoded.stat().st_size==78683892,'input size'
    with a.decoded.open('rb') as f:d=f.read(78683893)
    assert len(d)==78683892 and sha(d)==PIN,'input digest';r=d[0x1c19c:0x1c19c+25483200];assert sha(r)==RTOS_PIN
    cases=[replay(r,p) for p in (0,0xa5)]
    for key in ('outcomes','native_hash_pointer','native_task_pointer','hash_zero_stores','hash_reads','task_name_reads','lookup_returns','exclusive_events','exclusive_status','executed_ranges'):
        assert cases[0][key]==cases[1][key],key
    assert sha(a.decoded.read_bytes())==PIN
    result={'marker':'III-REGISTRY-RAM-31','decoded_sha256':PIN,'rtos_sha256':RTOS_PIN,'script_sha256':sha(Path(__file__).read_bytes()),'cases':cases,'limits':['Single-vCPU synthetic RAM only; original LDREX/STREX executes without forced return. No physical exclusivity/coherence proof.','Original config/platform/page/arena/task initialization use separate selected entries, including core0 branch after stopping MPIDR. Not wholeboot.','Table0 count and caller slice entered independently; earlier domain allocation and other11 registry count/pointer gates omitted.','Full original InitTask lookup reaches no-match; no task slot consumed or creator success. Empty-name control is original ROM NUL, not an empty task descriptor.','Only56 unproduced RMW control bytes may be read; entire synthetic heap backing is initially00 orA5, no allocated hash pointer or hash-array contents are host-injected; empty control takes the original native task pointer as an unused argument.','All guest stores are logged including synthetic call-stack stores; host initial memory staging is separate.']}
    with a.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'verified':True,'cases':len(cases),'pointer':cases[0]['native_hash_pointer'],'zero_bytes':1200,'hash_reads':300,'wrapper_return':0}))
if __name__=='__main__':main()
