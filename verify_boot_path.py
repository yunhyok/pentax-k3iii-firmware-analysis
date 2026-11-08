"""Execute bounded original BOOT selection fragments in synthetic RAM only."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import *
from inspect_firmware import named_records
from rtos_catalog import require
from verify_deep_analysis import verify_code

BASE=0x50b00000
SHA='0a9c086818b9d6e7531b93710c2cab2782c7f2c32bb5b1c26e3b5b5b69695900'

def run(blob):
    require(hashlib.sha256(blob).hexdigest()==SHA,'BOOT hash mismatch')
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
    for a,n in [(BASE,0x10000),(0x50b70000,0x20000),(0x50adf000,0x1000),
                (0x18004000,0x1000),(0x10000000,0x10000),(0x52500000,0x1000)]:u.mem_map(a,n)
    u.mem_write(BASE,blob)
    stack=0x1000f000;table=0x50b70100;marker=0x50adf000
    def put(a,v):u.mem_write(a,struct.pack('<I',v))
    def word(a):return struct.unpack('<I',u.mem_read(a,4))[0]
    stops=set()
    def hook(uc,a,size,data):
        if a in stops:uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook)
    def execute(start,targets,registers):
        stops.clear();stops.update(targets)
        for r in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(r,0)
        u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_SP,stack)
        for r,v in registers.items():u.reg_write(r,v)
        u.emu_start(start,BASE+len(blob),count=200)
        pc=u.reg_read(UC_ARM_REG_PC)
        require(pc in stops,'Fragment failed to reach the declared stop before I/O')
        return pc
    rows=[]
    for selector in [0,1,2,0xffffffff]:
        for offset,value in [(0x40,selector),(0x44,0x100),(0x48,0x200)]:put(0x18004000+offset,value)
        pc=execute(0x50b00bd4,[0x50b00c0c,0x50b0118c],{UC_ARM_REG_R4:0x18004000})
        if selector<2:
            order=list(struct.unpack('<HH',u.mem_read(stack+0x2c,4)))
            require(order==([1,2] if selector==0 else [2,1]),'Copy order mismatch')
            require(u.reg_read(UC_ARM_REG_R0)==(0x100 if selector==0 else 0x200),'First copy block mismatch')
        else:require(pc==0x50b0118c,'Invalid selector did not reach failure')
        rows.append(dict(group='partition_copy_order',selector=selector,stop=hex(pc)))
    for block in [0,0x1234,0xffff]:
        pc=execute(0x50b00c4c,[0x50b00c64,0x50b00fbc],{UC_ARM_REG_R0:block})
        require(pc==(0x50b00fbc if block==0xffff else 0x50b00c64),'Candidate sentinel mismatch')
        if block!=0xffff:require([u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]==[block,0x87,table],'Table read arguments mismatch')
        rows.append(dict(group='table_read_arguments',block=block,stop=hex(pc)))
    for result in [0,1,0xffffffff]:
        put(marker,0x11223344);put(stack+0xc,marker);put(table+0x870,1)
        pc=execute(0x50b00c68,[0x50b00c80,0x50b00fbc],{UC_ARM_REG_R0:result,UC_ARM_REG_R5:table,UC_ARM_REG_R7:0xa55a5aa5})
        require(word(marker)==(0xa55a5aa5 if result==0 else 0x11223344),'Slot2 marker condition mismatch')
        rows.append(dict(group='table_read_result_marker',result=result,marker=hex(word(marker))))
    for bank in [0,1]:
        put(table+0x874,bank)
        for size in [0,1,512,513]:
            for count in [0,3]:
                put(BASE+0x54c0,0)
                for offset,value in [(0x878,0x52500000),(0x880,0x1234),(0x884,size),(0x888,count)]:put(table+bank*0x434+offset,value)
                execute(0x50b00c84,[0x50b00ccc],{UC_ARM_REG_R4:BASE+0x54c0,UC_ARM_REG_R5:table})
                actual=[u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
                expected=[0x1234,count or ((size+511)//512),0x52500000]
                require(actual==expected,'RTOS bank read arguments mismatch')
                rows.append(dict(group='rtos_bank_read',bank=bank,size=size,stored_count=count,actual=actual))
        put(BASE+0x54c0,2)
        execute(0x50b00c84,[0x50b00cdc],{UC_ARM_REG_R4:BASE+0x54c0,UC_ARM_REG_R5:table})
        rows.append(dict(group='mode2_skips_read',bank=bank))
    # Execute only the entry-copy tail; storage-read success is an input assumption.
    for bank in [0,1]:
        for entry in [0,0x52500000,0x10000000]:
            put(table+bank*0x434+0x2a3c,entry)
            put(BASE+0x54c8,0xffffffff)
            execute(0x50b00f38,[0x50b00f58],{UC_ARM_REG_R3:bank,UC_ARM_REG_R6:table,UC_ARM_REG_R4:BASE+0x54c0})
            require(word(BASE+0x54c8)==entry,'Primary entry producer mismatch')
            rows.append(dict(group='record5_primary_entry',bank=bank,entry=hex(entry)))
    for entry in [0,0x52500000,0x10000000]:
        put(BASE+0x54c8,entry)
        pc=execute(0x50b00220,[0x50b00230,0x52500000,0x10000000],{})
        require(pc==(0x50b00230 if entry==0 else entry),'Primary entry zero guard mismatch')
        require(u.reg_read(UC_ARM_REG_R1)==entry,'Primary entry load mismatch')
        rows.append(dict(group='primary_entry_guard',entry=hex(entry),stop=hex(pc)))
    ranges=[(0x50b00bd4,0x50b00c0c),(0x50b0101c,0x50b01038),
            (0x50b00c4c,0x50b00c80),(0x50b00c84,0x50b00cdc),
            (0x50b00f38,0x50b00f58),(0x50b00220,0x50b00238)]
    return dict(passed=True,image_sha256=SHA,cases=len(rows),cases_detail=rows,
        ranges=[dict(start=hex(a),end=hex(z),sha256=hashlib.sha256(blob[a-BASE:z-BASE]).hexdigest()) for a,z in ranges],
        scope='Original A32 fragments, synthetic RAM. Stops before storage calls and fallback bodies. Entry-copy tail assumes prior read success; entry guard executes BXNE but stops before handoff-target instructions or WFE. No hardware, authentication or full-loader execution.')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('decoded',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    d=a.decoded.read_bytes()
    require(hashlib.sha256(d).hexdigest()=='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9','Decoded hash mismatch')
    records,_=named_records(d);record=next(r for r in records if r['name']=='BOOT')
    blob=d[record['payload_offset']:record['payload_offset']+record['size']]
    evidence=json.loads((Path(__file__).resolve().parent/'analysis/startup-storage-evidence.json').read_text(encoding='utf-8'))
    require(hashlib.sha256(blob).hexdigest()==SHA,'BOOT hash mismatch')
    counts=verify_code(blob,evidence['boot']['code'],base=BASE)
    result=run(blob)
    result['source_verification']=dict(zip(('ranges','transfers','words'),counts))
    entry=json.loads((Path(__file__).resolve().parent/'analysis/boot-entry-evidence.json').read_text(encoding='utf-8'))
    result['entry_source_verification']=dict(zip(('ranges','transfers','words'),verify_code(blob,entry['code'],base=BASE)))
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print({'passed':True,'cases':result['cases']})
if __name__=='__main__':main()
