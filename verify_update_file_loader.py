"""Original ARM update input-loader control flow with synthetic allocation/file IO.
Allocation callbacks only return a small mapped sentinel, never allocate the requested
size. File callbacks capture arguments; no firmware contents or storage are read.
Failure assertion/log boundaries return synthetically; actual fatal policy is unknown.
"""
if not __debug__:
 raise RuntimeError('Verification requires assertions; run without -O or PYTHONOPTIMIZE')
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
C,F,BIG,SMALL,FS,BVT,SVT,FVT,PATH=[0x10000000+i*0x1000 for i in range(9)]
BUFFER=0x12000000;STOP=0x30000000;OPEN=STOP+0x100;READ=STOP+0x120;CLOSE=STOP+0x140;ALLOC_BIG=STOP+0x200;ALLOC_SMALL=STOP+0x220;FREE=STOP+0x240;STAT=STOP+0x260
RANGES=[(0x52fee900,0x52fee9b4),(0x52ff6dd4,0x52ff6ef8),(0x52ff7014,0x52ff71bc),(0x52fef240,0x52fef488),(0x52ff7c38,0x52ff7d6c),(0x52ff3474,0x52ff3480),(0x52f50b24,0x52f50b28)]
STUBS={0x530f1a68:'mutex returns selected synthetic status',0x530f1bbc:'mutex release only records',0x530fced4:'log records only',0x530feb20:'assertion/log records even false and returns; actual fatal policy is not emulated',OPEN:'synthetic file open captures path/mode and supplies handle',READ:'synthetic read captures requested size/buffer, no IO or buffer fill',CLOSE:'synthetic close records handle',ALLOC_BIG:'large allocator captures size/alignment; returns sentinel only',ALLOC_SMALL:'small allocator captures size/alignment; returns sentinel only',FREE:'release captures pointer only'}
STUBS.update({STAT:'file stat supplies synthetic info+18 size, no IO',0x52f50b44:'file-info constructor replaced by zero initialization of0x3c bytes; no date conversion'})
sha=lambda b:hashlib.sha256(b).hexdigest();p32=lambda v:struct.pack('<I',v&0xffffffff)
def load(path):
 b=path.read_bytes()
 if sha(b)==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15);n=(len(b)+4095)&~4095
 u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 u.mem_map(C,0x10000);u.mem_map(BUFFER,4096);u.mem_map(0x20000000,0x10000);u.mem_map(STOP,4096)
 state={};rows=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,p32(v))
 def hook(uc,a,size,user):
  if a==STOP:uc.emu_stop();return
  if a in STUBS:
   r=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];r0,r1,r2,r3=r;ret=0
   state['calls'].append([hex(a),r])
   if a==0x530f1a68:assert r0==F+0x80;ret=state['mutex']
   elif a in (ALLOC_BIG,ALLOC_SMALL):
    assert a==(ALLOC_BIG if state['size']>0x80000 else ALLOC_SMALL)
    assert r0==(BIG if a==ALLOC_BIG else SMALL) and r1==state['size'] and r2==0x40 and r3==0x52ff70dc
    state['allocations']+=1;ret=0 if state['allocations']<=state['alloc_failures'] else BUFFER
   elif a==OPEN:
    assert [r0,r1,r2]==[FS,PATH,1];state['opens']+=1;ret=int(state['opens']>state['open_failures'])
    if ret:wr(r3,0x1234)
   elif a==READ:
    assert r==[FS,0x1234,BUFFER,state['size']];state['reads']+=1;ret=int(state['reads']>state['read_failures'])
   elif a==CLOSE:assert r0==FS and r1==0x1234;state['closes']+=1;ret=state['close_return']
   elif a==FREE:assert r0==(BIG if state['size']>0x80000 else SMALL) and r1==BUFFER;state['frees']+=1
   elif a==0x530feb20:state['assert_conditions'].append(r0)
   elif a==0x52f50b44:uc.mem_write(r0,bytes(0x3c));ret=r0
   elif a==STAT:
    assert r0==FS and r1==0x54796104;ret=state['stat_success'];wr(r2+0x18,state['size']);state['stat_calls']+=1
   uc.reg_write(UC_ARM_REG_R0,ret);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),hex(a)
 u.hook_add(UC_HOOK_CODE,hook)
 def run(size,mutex=1,alloc_failures=0,open_failures=0,read_failures=0,close_return=1,metadata=False,stat_success=1):
  u.mem_write(C,bytes(0x10000));wr(C+0x10,F);wr(C+0x40,PATH);wr(C+0x44,0xdeadbeef if metadata else size);wr(C+0x48,0xabcdef00)
  if metadata:wr(C+0x3c,0x55)
  wr(F+0x30,BIG);wr(F+0x34,SMALL);wr(F+0x38,FS);wr(F+0x40,F+0x80)
  for obj,vt,alloc in [(BIG,BVT,ALLOC_BIG),(SMALL,SVT,ALLOC_SMALL)]:wr(obj,vt);wr(vt+8,alloc);wr(vt+0xc,FREE)
  wr(FS,FVT);wr(FVT+0x20,OPEN);wr(FVT+0x24,CLOSE);wr(FVT+0x28,READ);wr(FVT+0x54,STAT);u.mem_write(PATH,b'/synthetic/firmware.bin\0')
  state.clear();state.update(size=size,mutex=mutex,alloc_failures=alloc_failures,open_failures=open_failures,read_failures=read_failures,close_return=close_return,stat_success=stat_success,stat_calls=0,calls=[],allocations=0,opens=0,reads=0,closes=0,frees=0,assert_conditions=[])
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,0x20008000);u.reg_write(UC_ARM_REG_LR,STOP);u.reg_write(UC_ARM_REG_R0,C)
  u.reg_write(UC_ARM_REG_R1,2 if metadata else 0)
  u.emu_start(0x52fef240 if metadata else 0x52fee900,STOP+4,count=100000);assert u.reg_read(UC_ARM_REG_PC)==STOP
  return u.reg_read(UC_ARM_REG_R0),rd(C+0x48)
 def record(group,inputs,result):
  rows.append(dict(group=group,inputs=inputs,result_sha256=sha(json.dumps(dict(result=result,trace=state),sort_keys=True).encode()),allocations=state['allocations'],opens=state['opens'],reads=state['reads'],closes=state['closes'],frees=state['frees'],assert_conditions=state['assert_conditions']))
 sizes=[0,1,0x7ffff,0x80000,0x80001,35106716,35136788,78690708,0x7fffffff,0x80000000,0xffffffff]
 for size in sizes:
  result=run(size);assert result==((1,BUFFER) if size else (0,0xabcdef00))
  assert state['allocations']==state['opens']==state['reads']==state['closes']==int(size!=0)
  assert state['frees']==0
  record('size-selection-argument-flow',dict(size=size,allocation_is_stub=True),result)
 for kind in ('alloc','open','read'):
  for failures in (1,2,3):
   kw={kind+'_failures':failures};result=run(35136788,**kw);success=failures<3
   assert result==((1,BUFFER) if success else (0,0))
   assert state['allocations']==min(failures+1,3)
   assert state['frees']==(0 if kind=='alloc' else failures)
   assert state['closes']==(min(failures+1,3) if kind=='read' else int(success))
   assert state['assert_conditions']==[int(success)]
   record('synthetic-retry-'+kind,dict(failures=failures),result)
 result=run(35136788,mutex=0);assert result==(0,0) and state['allocations']==0
 assert not any(a=='0x530f1bbc' for a,r in state['calls']);record('mutex-denied',{},result)
 result=run(35136788,close_return=0);assert result==(1,BUFFER) and state['closes']==1 and state['frees']==0
 record('close-return-not-propagated',dict(synthetic_close_return=0),result)
 for size,success in [(0,1),(35106716,1),(35136788,1),(78690708,1),(35136788,0)]:
  result=run(size,metadata=True,stat_success=success);accepted=bool(size and success)
  assert result==(int(accepted),0xabcdef00) and state['stat_calls']==1 and state['allocations']==0
  assert rd(C+0x44)==(size if accepted else 0xdeadbeef) and rd(C+0x40)==(0x54796104 if accepted else PATH)
  assert rd(C+0x3c)==(2 if accepted else 0x55)
  record('kind2-metadata-size-to-state',dict(size=size,stat_success=success),dict(result=result,state_length=rd(C+0x44),state_kind=rd(C+0x3c),state_path=hex(rd(C+0x40))))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),groups={g:sum(x['group']==g for x in rows) for g in sorted({x['group'] for x in rows})},scope=__doc__,cpu_model='Unicorn Cortex-A15; not camera fidelity',stubs={hex(a):s for a,s in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 if a.output.exists():raise FileExistsError('report exists')
 r=run_checks(load(a.input))
 with a.output.open('x',encoding='utf-8') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ['passed','cases','groups']})
