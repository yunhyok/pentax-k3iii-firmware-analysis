"""Original ARM component5 setup and update completion control flow.
All file/update execution, notification, release, OS and hardware boundaries are
synthetic. Slot1 uses the original ROM-to-RAM initial record; only small authored
bytes are copied in emulated RAM. No camera, storage or firmware write executes.
"""
if not __debug__:raise RuntimeError('Verification requires assertions; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
S,F,C,APP,APPCTX,EVENT,DEVICE,ERROR=[0x10000000+k*0x1000 for k in range(8)]
SOURCE=0x12000000;BUFFER=0x509df000;STACK=0x20008000;STOP=0x30000000
RANGES=[(0x52ff31c4,0x52ff3214),(0x52fee52c,0x52fee558),(0x52ff8de4,0x52ff8ed0),
 (0x52feffa8,0x52ff0198),(0x52ff3960,0x52ff399c),(0x533031a0,0x53303224)]
STUBS={0x526aac80:'copies at most16 authored bytes within emulated RAM only',0x530fced4:'records diagnostic only',
 0x52ff622c:'records input-release request and returns selected status; no allocation or OS release',
 0x52ff382c:'captures completion message only; no queue or notification dispatch',
 0x53156fec:'captures device/event flag argument only',0x53156fa4:'captures completion boundary and returns chosen sentinel',
 0x52eaacf4:'returns synthetic application root',0x52ff391c:'records update-start notification only',
 0x52fefe98:'records update execution boundary and returns chosen status; NO flash/write path executes',
 0x52feee48:'preflight boundary returns selected status',0x52fee900:'file-loader boundary returns selected status; no reads',
 0x52fefb84:'validation boundary returns selected status; no decoder or allocations',
 0x53302f6c:'postvalidation boundary returns selected status'}
sha=lambda b:hashlib.sha256(b).hexdigest();p32=lambda v:struct.pack('<I',v&0xffffffff)
def load(path):
 b=path.read_bytes()
 if sha(b)==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 if sha(b)!=SHA:raise ValueError('unrecognized RTOS SHA-256')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 for a,n in [(S,0x10000),(SOURCE,4096),(BUFFER,4096),(0x54525000,4096),(0x54796000,4096),(0x20000000,0x10000),(STOP,4096)]:u.mem_map(a,n)
 rows=[];state={}
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,p32(v))
 def hook(uc,a,size,user):
  if a==STOP:uc.emu_stop();return
  if a in STUBS:
   regs=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];r0,r1,r2,r3=regs
   state['calls'].append([hex(a),regs]);ret=0
   if a==0x526aac80:
    assert r0==BUFFER and r1==SOURCE and 0<r2<=16
    uc.mem_write(r0,bytes(uc.mem_read(r1,r2)));ret=state.get('copy_result',r0)
   elif a==0x52ff622c:assert r0==F and r1==state['input'];ret=state['release_result']
   elif a==0x52ff382c:assert [r0,r1,r2]==[EVENT,0x2640820b,0]
   elif a==0x53156fec:assert [r0,r1]==[DEVICE,0x20]
   elif a==0x53156fa4:assert r0==DEVICE;ret=0x77
   elif a==0x52eaacf4:ret=APP
   elif a==0x52ff391c:assert r0==EVENT
   elif a==0x52fefe98:assert r0==S;ret=state['operation_result']
   elif a in (0x52feee48,0x52fee900,0x52fefb84):assert r0==S;ret=state['statuses'][a]
   elif a==0x53302f6c:assert r0==APP;ret=state['statuses'][a]
   uc.reg_write(UC_ARM_REG_R0,ret);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),hex(a)
 u.hook_add(UC_HOOK_CODE,hook)
 def reset(kind=2,input=SOURCE,release=1,operation=1):
  u.mem_write(S,bytes(0x10000));u.mem_write(BUFFER,b'\xa5'*64);u.mem_write(SOURCE,bytes(range(16)))
  wr(S+0x10,F);wr(S+0x18,EVENT);wr(S+0x3c,kind);wr(S+0x44,0x1234);wr(S+0x48,input)
  wr(C+0xc,0xdead0000);wr(C+0x10,0x88);wr(APP+8,APPCTX);wr(EVENT+8,DEVICE);u.mem_write(ERROR,b'\xee')
  wr(0x54796094,1);wr(0x54796098+0x10,F);wr(0x54796098+0xc,S)
  # Source for initial slot1: sourceROM53ce7d40 + (RAM54525588 -54500000).
  u.mem_write(0x54525588,b[0x53d0d2c8-BASE:0x53d0d2d8-BASE]);assert rd(0x54525590)==BUFFER and rd(0x5452558c)==0x100000
  state.clear();state.update(calls=[],input=input,release_result=release,operation_result=operation,statuses={a:1 for a in (0x52feee48,0x52fee900,0x52fefb84,0x53302f6c)})
 def run(entry,args):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  for q,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(q,v)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(entry,STOP+4,count=100000);assert u.reg_read(UC_ARM_REG_PC)==STOP
  return u.reg_read(UC_ARM_REG_R0)
 def addresses():return [int(a,16) for a,r in state['calls']]
 def record(group,inputs,outputs):rows.append(dict(group=group,inputs=inputs,outputs=outputs,result_sha256=sha(json.dumps(dict(outputs=outputs,state=state),sort_keys=True).encode()),call_addresses=[hex(a) for a in addresses()]))
 for source,length in [(0,0),(0,16),(SOURCE,0),(SOURCE,1),(SOURCE,16)]:
  reset();ret=run(0x52ff31c4,[C,source,length]);copy=bool(source and length)
  assert ret==BUFFER and addresses()==([0x526aac80] if copy else [])
  assert (rd(C+0xc),rd(C+0x10))==((BUFFER,length) if copy else (0xdead0000,0x88))
  if copy:assert bytes(u.mem_read(BUFFER,length))==bytes(range(length))
  record('component5-fixed-slot1',dict(source=hex(source),length=length),dict(return_pointer=hex(ret),component_pointer=hex(rd(C+0xc)),component_length=rd(C+0x10)))
 for flag in (0,1):
  for release in (0,1):
   reset(release=release);ret=run(0x52feffa8,[S,flag]);calls=addresses()
   assert calls==[0x530fced4,0x52ff622c]+([0x52ff382c,0x53156fec,0x53156fa4] if flag else [])
   assert ret==(0x77 if flag else release) and rd(S+0x48)==SOURCE and rd(S+0x44)==0x1234
   record('finalize-release-and-notification',dict(flag=flag,release_result=release),dict(return_value=ret,input_pointer=hex(rd(S+0x48))))
 for kind in (2,5,8):
  for operation in (0,1):
   reset(kind=kind,operation=operation,release=0);ret=run(0x52ff0044,[S]);calls=addresses()
   assert ret==(0 if kind==8 else operation)
   if kind==5:assert calls.count(0x52fefe98)==1 and 0x52ff622c not in calls
   elif kind==8:assert 0x52fefe98 not in calls and calls.count(0x52ff622c)==1
   else:
    assert calls.count(0x52fefe98)==calls.count(0x52ff622c)==1
    assert (0x52ff382c in calls)==bool(operation)
    assert calls.index(0x52fefe98)<calls.index(0x52ff622c)
   assert rd(S+0x48)==SOURCE
   record('execute-wrapper-kind-branch',dict(kind=kind,operation_result=operation,release_result=0),dict(return_value=ret,input_pointer=hex(rd(S+0x48))))
 order=[0x52feee48,0x52fee900,0x52fefb84,0x53302f6c]
 for failing in [None]+order:
  reset()
  if failing:state['statuses'][failing]=0
  ret=run(0x533031a0,[APP,ERROR]);n=len(order) if failing is None else order.index(failing)+1
  assert addresses()==order[:n] and ret==int(failing is None)
  expected=0xee if failing is None else 0 if failing==order[0] else 1 if failing==order[2] else 3
  assert bytes(u.mem_read(ERROR,1))==bytes([expected]) and rd(S+0x48)==SOURCE
  record('load-validate-error-byte',dict(failing_boundary=hex(failing) if failing else None),dict(return_value=ret,error_byte=expected,input_pointer=hex(rd(S+0x48))))

 for kind in (6,7):
  reset(kind=kind,operation=2,release=0);ret=run(0x52ff0044,[S]);calls=addresses()
  assert ret==2 and calls.count(0x52fefe98)==calls.count(0x52ff622c)==1
  assert calls.index(0x52fefe98)<calls.index(0x52ff622c)<calls.index(0x52ff382c)
  assert rd(S+0x48)==SOURCE and rd(S+0x44)==0x1234
  record('edge-kind6-7-nonboolean-result',dict(kind=kind,operation=2,release=0),dict(return_value=ret))
 for flag in (0,2):
  reset(input=0,release=0xffffffff);ret=run(0x52feffa8,[S,flag])
  assert addresses()==[0x530fced4,0x52ff622c]+([0x52ff382c,0x53156fec,0x53156fa4] if flag else [])
  assert ret==(0x77 if flag else 0xffffffff) and rd(S+0x48)==0 and rd(S+0x44)==0x1234
  record('edge-null-input-finalization',dict(flag=flag,release=0xffffffff),dict(return_value=ret))
 reset();state['copy_result']=0x99;ret=run(0x52ff31c4,[C,SOURCE,16])
 assert ret==0x99 and rd(C+0xc)==BUFFER and rd(C+0x10)==16
 record('edge-component-copy-return-forwarded',dict(synthetic_copy_return=0x99),dict(return_value=ret,stored_component_base=hex(rd(C+0xc))))
 reset()
 for a in order:state['statuses'][a]=2
 state['statuses'][order[-1]]=0x77;ret=run(0x533031a0,[APP,ERROR])
 assert ret==0x77 and addresses()==order and bytes(u.mem_read(ERROR,1))==b'\xee'
 record('edge-postvalidation-result-forwarded',dict(early_status=2,post_status=0x77),dict(return_value=ret,error_byte=0xee))

 return dict(passed=True,image_sha256=SHA,cases=len(rows),groups={g:sum(r['group']==g for r in rows) for g in sorted({r['group'] for r in rows})},scope=__doc__,
  stubs={hex(a):s for a,s in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],
  initial_slot1=dict(source_start='0x53d0d2c8',ram_start='0x54525588',size=16,sha256=sha(b[0x53d0d2c8-BASE:0x53d0d2d8-BASE])),results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups')})
