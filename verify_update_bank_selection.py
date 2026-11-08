"""Original RTOS writer and BOOT selector, joined by an authored RAM-table fixture.

No device access, package mutation, actual table commit/reload, or reboot. Original
input files are read-only. Mock media is a Python dictionary of synthetic bytes.
"""
if not __debug__:
    raise RuntimeError('Assertions required; do not use -O')
import argparse, hashlib, json, os, struct, sys
from pathlib import Path
sys.dont_write_bytecode = True
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
SHA = '342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
BOOT_SHA = '0a9c086818b9d6e7531b93710c2cab2782c7f2c32bb5b1c26e3b5b5b69695900'
DECODED_SHA = '7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
BASE=0x52500000; BOOT_BASE=0x50b00000
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(path, boot_path=None):
    data=path.read_bytes(); h=sha(data)
    if h==DECODED_SHA:
        if boot_path is not None:
            raise ValueError('--boot is only accepted with split RTOS input')
        r,b=data[0x1c19c:0x1c19c+25483200],data[93388:93388+21696]
    elif h==SHA:
        if boot_path is None: raise ValueError('RTOS input requires --boot')
        r,b=data,boot_path.read_bytes()
    else: raise ValueError('Unrecognized original input hash')
    if sha(r)!=SHA or sha(b)!=BOOT_SHA: raise ValueError('RTOS/BOOT source hash mismatch')
    return r,b

R=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
TABLE=0x50b70100; OBJ=0x10001000; CTX=0x10002000; DRIVER=0x10003000; VT=0x10004000
SRC=0x10005000; PAYLOAD=0x10010000; STOP=0x1003f000; STACK=0x1003e000
MODE=0x50b054c0; MARKER=0x50adf000; ENTRY=0x4fffff20; N=0x10e00
RTOS_RANGES=[(0x52ff52d4,0x52ff5300),(0x52ff1ea8,0x52ff2060),(0x52ff586c,0x52ff59f4)]
BOOT_RANGES=[(0x50b00c70,0x50b00cf4)]
CASES=[
 dict(label='default-bank0-match'),
 dict(label='default-bank0-mismatch-bank1',record=1),
 dict(label='upper16-ignored-bank0',record=0xa55a0000),
 dict(label='upper16-ignored-bank1',record=0xffff0001),
 dict(label='resource-absent',present=False),
 dict(label='write-failure',write=0),
 dict(label='capacity-reject',tight=True),
 dict(label='boot-read-failure',read=1),
 dict(label='boot-mode2-skips-read',mode=2),
 dict(label='layout-preserves-mismatching-selector',layout=True,record=1),
 dict(label='synthetic-bank1-match-not-a-producer',bank=1,record=1),
 dict(label='failed-write-boot-ceil-fallback',write=0,old_count=0,old_length=513),
]

def run_checks(rtos,boot):
    assert sha(rtos)==SHA and sha(boot)==BOOT_SHA
    results=[]; entry_runs=0
    for spec in CASES:
        cfg=dict(bank=0,record=0,present=True,write=1,read=0,tight=False,mode=0,layout=False,old_count=2,old_length=1024);cfg.update(spec)
        u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        for a,size in [(BASE,(len(rtos)+4095)&~4095),(BOOT_BASE,0x10000),(0x50b70000,0x20000),(0x50adf000,0x1000),(0x4ffff000,0x1000),(0x10000000,0x40000),(0x11000000,0x10000)]:u.mem_map(a,size)
        u.mem_write(BASE,rtos);u.mem_write(BOOT_BASE,boot)
        def p(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
        def w(a):return struct.unpack('<I',u.mem_read(a,4))[0]
        def regargs():return [u.reg_read(x) for x in R]
        def ret(value):u.reg_write(R[0],value&0xffffffff);u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
        u.reg_write(UC_ARM_REG_CPSR,0x10)
        stage='ctor';trace=[];table_writes=[];media={}; io_writes=[]; io_reads=[]
        payload=bytes((i*29+7)&255 for i in range(513));u.mem_write(PAYLOAD,payload)
        def writehook(uc,access,a,size,value,data):
            if TABLE<=a<TABLE+N:table_writes.append(dict(stage=stage,address=hex(a),size=size,value=value))
        def hook(uc,a,size,data):
            if a==STOP:uc.emu_stop();return
            if stage=='boot' and a in (0x50b00cf4,0x50b01160):uc.emu_stop();return
            if a==0x532974a8:
                assert stage in ('layout','write') and regargs()[0]==DRIVER
                trace.append(dict(stage=stage,stub='ceil512',bytes=regargs()[1]));ret((regargs()[1]+511)//512);return
            if a==0x532971dc:
                assert stage=='layout' and regargs()[0]==DRIVER;ret(512);return
            if a==0x530fced4:
                assert stage in ('layout','write');trace.append(dict(stage=stage,stub='diagnostic-return0'));ret(0);return
            if a==0x52ff5708:
                args=regargs();assert stage=='write' and args[0]==OBJ and args[2:]==[len(payload),PAYLOAD]
                io_writes.append(args[:]);trace.append(dict(stage=stage,stub='media-write',arguments=args,returned=cfg['write']))
                if cfg['write']:
                    data=bytes(u.mem_read(args[3],args[2]));media[args[1]]=data+bytes((-len(data))%512)
                ret(cfg['write']);return
            if a==0x50b03f04:
                args=regargs();assert stage=='boot';io_reads.append(args[:3]);trace.append(dict(stage=stage,stub='media-read',arguments=args[:3],returned=cfg['read']))
                if not cfg['read']:
                    data=media[args[0]];assert len(data)>=args[1]*512
                    u.mem_write(args[2],data[:args[1]*512])
                ret(cfg['read']);return
            allowed=BOOT_RANGES if stage=='boot' else RTOS_RANGES
            assert any(x<=a<z for x,z in allowed),(stage,hex(a),'unexpected original instruction')
        u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_WRITE,writehook)
        def execute(a,args):
            nonlocal entry_runs
            entry_runs+=1;u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP)
            for rr,v in zip(R,args):u.reg_write(rr,v)
            u.emu_start(a,STOP,count=3000)
            assert u.reg_read(UC_ARM_REG_PC)==STOP,(stage,hex(u.reg_read(UC_ARM_REG_PC)))
            assert u.reg_read(UC_ARM_REG_SP)==STACK
            return u.reg_read(R[0])
        # Real ctor establishes zero. Only one explicitly labeled case overrides it.
        execute(0x52ff52d4,[OBJ]);assert bytes(u.mem_read(OBJ+0x10,1))==b'\0'
        if cfg['bank']:u.mem_write(OBJ+0x10,bytes([cfg['bank']]))
        p(OBJ+8,DRIVER);p(DRIVER,VT);p(VT+0x4c,0x532971dc);p(OBJ+0x14,TABLE)
        u.mem_write(TABLE,bytes(N))
        for bank,start,dest in [(0,100,0x11000000),(1,200,0x11001000)]:
            d=TABLE+0x870+bank*0x434
            for off,value in [(8,dest),(0xc,dest+0x100),(0x10,start),(0x14,cfg['old_length']),(0x18,cfg['old_count'])]:p(d+off,value)
            p(TABLE+2*0x870+bank*0x434+0x10,start+(1 if cfg['tight'] else 100))
            media[start]=bytes([0x30+bank])*1024
        p(TABLE+0x870,4096 if cfg['present'] else 0);p(TABLE+0x874,cfg['record'])
        selector_before=bytes(u.mem_read(TABLE+0x874,4))
        all_selectors_before=[w(TABLE+i*0x870+4) for i in range(32)]
        if cfg['layout']:
            stage='layout';p(CTX+8,DRIVER);p(CTX+0x40,SRC);p(CTX+0x48,3);p(CTX+0x4c,OBJ)
            for index in range(3):
                for off,value in [(0,10 if index==0 else 0x11000100),(4,4096),(8,0x11000000+index*0x2000),(12,1)]:p(SRC+16*index+off,value)
            p(SRC+48,0x11004100)
            execute(0x52ff1ea8,[CTX])
            assert bytes(u.mem_read(TABLE+0x874,4))==selector_before
            assert w(TABLE+0x870+0x10)==18 and w(TABLE+2*0x870+0x10)==26
        before=bytes(u.mem_read(TABLE,N));stage='write';write_return=execute(0x52ff586c,[OBJ,1,len(payload),PAYLOAD]);after=bytes(u.mem_read(TABLE,N))
        expected_success=bool(cfg['write'] and not cfg['tight']);assert write_return==int(expected_success)
        selected=0x870+cfg['bank']*0x434
        expected=bytearray(before)
        if expected_success:struct.pack_into('<II',expected,selected+0x14,len(payload),2)
        assert after==bytes(expected),'RTOS writer changed bytes beyond selected length/count'
        assert bytes(u.mem_read(TABLE+0x874,4))==selector_before
        assert len(io_writes)==(0 if cfg['tight'] else 1)
        # Authored cross-stage handoff: preserve exactly the table in synthetic RAM.
        # No table commit, physical reload, reset, BOOT prologue, or authentication executes.
        stage='boot';p(MODE,cfg['mode']);p(MODE+4,0xcccccccc);p(ENTRY,0xdddddddd);p(MARKER,0)
        u.reg_write(UC_ARM_REG_R4,MODE);u.reg_write(UC_ARM_REG_R5,TABLE);u.reg_write(UC_ARM_REG_R6,TABLE);u.reg_write(UC_ARM_REG_R7,0xa55a5aa5)
        u.reg_write(UC_ARM_REG_SP,STACK);p(STACK+0xc,MARKER)
        entry_runs+=1;u.emu_start(0x50b00c70,STOP,count=300)
        resource_present=w(TABLE+0x870)!=0;bs=cfg['record']&0xffff;ds=TABLE+0x870+bs*0x434
        expect_read=resource_present and cfg['mode']!=2
        assert len(io_reads)==int(expect_read)
        expected_blocks=w(ds+0x18) or ((w(ds+0x14)+511)//512)
        if expect_read:assert io_reads==[[w(ds+0x10),expected_blocks,w(ds+8)]]
        entry_written=resource_present and (cfg['mode']==2 or cfg['read']==0)
        assert w(ENTRY)==(w(ds+0xc) if entry_written else 0xdddddddd)
        assert w(MODE+4)==(w(ds+0xc) if entry_written else 0xcccccccc)
        assert w(MARKER)==0xa55a5aa5
        assert u.reg_read(UC_ARM_REG_PC)==(0x50b01160 if expect_read and cfg['read'] else 0x50b00cf4)
        new_bytes=bool(expect_read and cfg['read']==0 and bytes(u.mem_read(w(ds+8),len(payload)))==payload)
        assert new_bytes==bool(expected_success and cfg['bank']==bs and expect_read and cfg['read']==0)
        assert bytes(u.mem_read(TABLE,N))==after,'BOOT selection unexpectedly changed table'
        assert all_selectors_before==[w(TABLE+i*0x870+4) for i in range(32)]
        assert all(not (TABLE+0x874<=int(x['address'],0)<TABLE+0x878) for x in table_writes)
        results.append(dict(**cfg,ctor_bank=0,synthetic_override=bool(cfg['bank']),write_return=write_return,writer_descriptor_offset=hex(selected),boot_bank_low16=bs,read_arguments=io_reads,write_arguments=[x[:3] for x in io_writes],entry_written=entry_written,new_payload_bytes_in_synthetic_destination=new_bytes,common_record4_preserved=True,table_before_sha256=sha(before),table_after_sha256=sha(after),table_writes=table_writes,trace=trace))
    return dict(passed=True,cases=len(results),fixture_entry_runs=entry_runs,image_sha256=SHA,boot_sha256=BOOT_SHA,ranges=[dict(image=image,start=hex(a),end=hex(z),sha256=sha(data[a-base:z-base])) for image,base,data,ranges in [('rtos',BASE,rtos,RTOS_RANGES),('boot',BOOT_BASE,boot,BOOT_RANGES)] for a,z in ranges],explicit_stubs={'0x532974a8':'ceil(unsigned byte count/512), no driver; configured block size assumption backed by prior concrete Emmc getter','0x532971dc':'512 for layout virtual block-size call','0x530fced4':'diagnostic returns0; no logging IO','0x52ff5708':'captures object/start block/byte length/source; synthetic media map updated only on configured success, failure preserves map by fixture policy','0x50b03f04':'captures start block/block count/destination; synthetic RAM copy only on return0, failure preserves destination by fixture policy'},scope='Full original RTOS ctor/layout/indexed writer and selected BOOT 50b00c70..cf4 fragment. Cortex-A15 emulator, synthetic RAM. Explicit same-table bridge; no actual update commit/reload/reboot, media/OS/hardware, authentication, target CPU fidelity, or nonzero bank producer. BOOT mode2 is only the injected numeric read-skip branch, not proof of reachability from normal entry. Bank equality is required only for the distinct nonaliasing media locations in these fixtures; general condition is resolving the written payload location/range.',cases_detail=results)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--boot',type=Path,help='BOOT image for split RTOS input only');ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    if os.path.lexists(a.output):raise FileExistsError('Output already exists')
    r=run_checks(*load(a.input,a.boot))
    with a.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(passed=r['passed'],cases=r['cases'],fixture_entry_runs=r['fixture_entry_runs'])))
