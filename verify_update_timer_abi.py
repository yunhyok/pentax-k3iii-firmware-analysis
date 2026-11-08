"""Original ARM fragments: timer syscall table, deadline and status arithmetic.
Synthetic RAM only. No SVC exception, scheduler, real clock, IRQ, device or media runs.
Only lower timer queue insertion is stubbed; its preceding metadata stores execute.
"""
if not __debug__:raise RuntimeError('Verification requires assertions; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RANGES=[(0x525d78c0,0x525d7904),(0x525d088c,0x525d08dc),(0x525b805c,0x525b807c),(0x525d0bfc,0x525d0c54)]
OBJ=0x20001000;OUT=0x20002000;STACK=0x20008000;NOW=0x54c40e50;BIAS=0x54c40580;MASK64=(1<<64)-1
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
 u.mem_map(0x20000000,0x10000);u.mem_map(0x54c40000,0x2000)
 rows=[];events=[];stops=set()
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
 def qwr(a,v):u.mem_write(a,struct.pack('<Q',v&MASK64))
 def code(uc,a,size,user):
  if a in stops:uc.emu_stop();return
  if a==0x525b7e00:
   events.append([uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1)]);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),hex(a)
 u.hook_add(UC_HOOK_CODE,code)
 def reset():
  u.mem_write(0x20000000,b'\xa5'*0x10000);u.mem_write(0x54c40000,b'\0'*0x2000);events.clear()
  u.reg_write(UC_ARM_REG_CPSR,0x13)
  for r in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(r,0)
  u.reg_write(UC_ARM_REG_SP,STACK)
 def execute(entry,stop):
  stops.clear();stops.add(stop);u.emu_start(entry,0xffffffff,count=1000);assert u.reg_read(UC_ARM_REG_PC)==stop
 for fn,target in [(0x805a0200,0x525d0590),(0x805b0100,0x525d0980),(0x805c0200,0x525d0ae4)]:
  reset();u.reg_write(UC_ARM_REG_LR,fn);u.reg_write(UC_ARM_REG_FP,STACK);wr(STACK,0x13);u.reg_write(UC_ARM_REG_R0,0x01000001);u.reg_write(UC_ARM_REG_R1,1000)
  execute(0x525d78c0,target);assert u.reg_read(UC_ARM_REG_R0)==0x01000001 and u.reg_read(UC_ARM_REG_R1)==1000
  index=(fn>>16)-65536;entry=0x525f7660+index*4;assert rd(entry)==target
  rows.append(dict(group='dispatch-fragment',function_code=hex(fn),entry=hex(entry),target=hex(target),arguments_preserved=True))
 for now,delay,bias in [(100,1000,1),(0xffffffff,1,0),(0xfffffffe,1,2),(MASK64-1,1,1),(0,0xffffffff,0xffffffff)]:
  reset();qwr(NOW,now);wr(BIAS,bias);wr(OBJ+0xc,0x20);u.reg_write(UC_ARM_REG_R6,OBJ);u.reg_write(UC_ARM_REG_R7,delay)
  execute(0x525d088c,0x525d065c);deadline=(now+delay+bias)&MASK64
  assert int.from_bytes(u.mem_read(OBJ+0x18,8),'little')==deadline and rd(OBJ+0x20)==0x525cdfa0 and rd(OBJ+0x24)==OBJ
  assert rd(OBJ+0xc)==0x21 and events==[[OBJ+0x10,0x525cdfa0]]
  assert int.from_bytes(u.mem_read(NOW,8),'little')==now and rd(BIAS)==bias
  rows.append(dict(group='deadline-fragment',now=now,delay=delay,offset=bias,deadline=deadline,flags=rd(OBJ+0xc),queue_insertion_stub=True))
 cases=[(1,111,100,1),(1,101,100,1),(1,100,100,1),(1,0x100000001,0,0),(1,0x8000000000000000,0,0),(0,111,100,1),(7,111,100,1),(0x81,111,100,1),(1,0,1,0)]
 for flags,deadline,now,bias in cases:
  reset();wr(OBJ,0x12345678);wr(OBJ+0xc,flags);qwr(OBJ+0x18,deadline);qwr(NOW,now);wr(BIAS,bias)
  for r,v in [(UC_ARM_REG_R6,OUT),(UC_ARM_REG_R7,OBJ),(UC_ARM_REG_R5,0),(UC_ARM_REG_R8,OBJ)]:u.reg_write(r,v)
  saved=bytes(u.mem_read(OBJ,0x40));execute(0x525d0bfc,0x525d0bb0)
  remaining=(deadline-now-bias)&MASK64;expected=0 if not flags&1 or remaining>>63 else remaining&0xffffffff
  assert [rd(OUT+i*4) for i in range(3)]==[0x12345678,expected,flags&~6]
  assert bytes(u.mem_read(OBJ,0x40))==saved and rd(OUT-4)==rd(OUT+12)==0xa5a5a5a5
  rows.append(dict(group='status-fragment',flags=flags,deadline=deadline,now=now,offset=bias,remaining=expected,status=flags&~6))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),groups={g:sum(r['group']==g for r in rows) for g in sorted({r['group'] for r in rows})},scope=__doc__,stubs={'0x525b7e00':'timer queue insertion returns without scheduler operation'},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ['passed','cases','groups']})
