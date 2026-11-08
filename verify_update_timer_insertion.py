"""Original ARM timer insertion and three metadata writers in synthetic RAM.
No stubs, OS, hardware, IRQ or callback execution. Authored unlinked new nodes and
valid circular lists only; signed modular comparisons do not imply a total order
for arbitrary 64-bit timestamps or prove caller input validation.
"""
if not __debug__:raise RuntimeError('Assertions required; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
HEAD=0x5457ec00;NEW=0x20001000;STACK=0x20008000;STOP=0x30000000;MASK=(1<<64)-1
RANGES=[(0x525b7e00,0x525b7e64),(0x525b7fcc,0x525b807c)]
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):
 b=p.read_bytes()
 if sha(b)==DSHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 if sha(b)!=SHA:raise ValueError('unrecognized RTOS SHA-256')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 for a,n in [(0x20000000,0x10000),(0x5457e000,0x1000),(0x54c40000,0x2000),(STOP,0x1000)]:u.mem_map(a,n)
 rows=[];comparisons=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
 def qr(a):return int.from_bytes(u.mem_read(a,8),'little')
 def qw(a,v):u.mem_write(a,struct.pack('<Q',v&MASK))
 def hook(uc,a,n,data):
  if a==STOP:uc.emu_stop();return
  assert any(x<=a<z for x,z in RANGES),hex(a)
  if a==0x525b7e40:
   current=uc.reg_read(UC_ARM_REG_R3);delta=(qr(NEW+8)-qr(current+8))&MASK;signed=delta if delta<1<<63 else delta-(1<<64)
   flags=uc.reg_read(UC_ARM_REG_CPSR);ge=((flags>>31)&1)==((flags>>28)&1);assert ge==(signed>=0);comparisons.append(dict(delta=delta,signed_delta=signed,continue_scan=ge))
 u.hook_add(UC_HOOK_CODE,hook)
 def reset(deadlines=()):
  u.mem_write(0x20000000,b'\xa5'*0x10000);u.mem_write(0x54c40000,b'\0'*0x2000);comparisons.clear()
  nodes=[0x20002000+i*0x100 for i in range(len(deadlines))];alln=[HEAD]+nodes
  for i,n in enumerate(alln):wr(n,alln[(i+1)%len(alln)]);wr(n+4,alln[(i-1)%len(alln)])
  for node,deadline in zip(nodes,deadlines):qw(node+8,deadline)
  for r in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(r,0)
  for r in [UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7]:u.reg_write(r,0x12345678+r)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP)
  return nodes
 def run(entry,args):
  for r,v in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3],args):u.reg_write(r,v&0xffffffff)
  u.emu_start(entry,STOP+4,count=1000);assert u.reg_read(UC_ARM_REG_PC)==STOP and u.reg_read(UC_ARM_REG_SP)==STACK
  for r in [UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7]:assert u.reg_read(r)==0x12345678+r
  assert rd(NEW-4)==rd(NEW+0x18)==0xa5a5a5a5
 def walk():
  out=[];p=HEAD
  while True:
   nxt=rd(p);assert rd(nxt+4)==p
   if nxt==HEAD:return out
   assert nxt not in out and len(out)<20;out.append(nxt);p=nxt
 cases=[([],5),([5,10,10,20],0),([5,10,10,20],5),([5,10,10,20],10),([5,10,10,20],15),([5,10,10,20],20),([5,10,10,20],30),([MASK-5,MASK-2,3,7],0),([0],(1<<63)-1),([0],1<<63)]
 for deadlines,new in cases:
  nodes=reset(deadlines);qw(NEW+8,new);saved_meta=bytes(u.mem_read(NEW+8,16));run(0x525b7e00,[NEW]);index=len(nodes)
  for i,d in enumerate(deadlines):
   difference=(new-d)&MASK
   if difference>=1<<63:index=i;break
  assert walk()==nodes[:index]+[NEW]+nodes[index:] and bytes(u.mem_read(NEW+8,16))==saved_meta
  rows.append(dict(group='ordered-insert',deadlines=deadlines,new_deadline=new,insert_index=index,comparisons=list(comparisons)))
 for entry,signed,inputs in [(0x525b7fcc,True,[(100,1,0),(100,1,0xffffffff),(100,1,0xfffffffe),(0,1,0x80000000),(MASK,1,1)]),(0x525b801c,False,[(100,1,0xffffffff),(MASK,1,1)])]:
  for now,period,delay in inputs:
   reset();qw(0x54c40e50,now);wr(0x54c40580,period);before=qr(NEW+8);run(entry,[NEW,delay,0x11223344,0x55667788])
   assert rd(NEW+0x10)==0x11223344 and rd(NEW+0x14)==0x55667788 and qr(0x54c40e50)==now and rd(0x54c40580)==period
   special=signed and delay==0xffffffff
   if special:assert rd(NEW)==rd(NEW+4)==NEW and qr(NEW+8)==before and walk()==[];deadline=None
   else:
    delta=delay-(1<<32) if signed and delay>=1<<31 else delay;deadline=(now+delta+period)&MASK;assert qr(NEW+8)==deadline and walk()==[NEW]
   rows.append(dict(group='signed-delay' if signed else 'unsigned-delay',now=now,period=period,delay_word=delay,sentinel_minus_one=special,deadline=deadline,metadata_preserved=True))
 reset();deadline=0xfedcba9876543210;wr(STACK,0x11223344);wr(STACK+4,0x55667788);run(0x525b805c,[NEW,0,deadline&0xffffffff,deadline>>32])
 assert qr(NEW+8)==deadline and rd(NEW+0x10)==0x11223344 and rd(NEW+0x14)==0x55667788 and walk()==[NEW]
 rows.append(dict(group='absolute-deadline',deadline=deadline,stack_callback=0x11223344,stack_argument=0x55667788,linked=True))
 assert len(rows)==18
 return dict(passed=True,cases=18,image_sha256=SHA,scope=__doc__,stubs={},groups={g:sum(r['group']==g for r in rows) for g in sorted({r['group'] for r in rows})},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ['passed','cases','groups']})
