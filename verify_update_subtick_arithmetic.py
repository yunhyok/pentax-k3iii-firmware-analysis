"""Original ARM subtick conversion over authored timer register values.
Exhaustive sweep is one group, not proof of actual counter range or timestamp behavior.
IRQ mask/restore are stubs. No actual MMIO, OS, hardware clock or elapsed time runs.
"""
if not __debug__:raise RuntimeError('Verification requires assertions; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
START=0x525b5c60;END=0x525b5c9c;STOP=0x30000000;MMIO=0x1e000000
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
 for a,n in [(MMIO,4096),(0x20000000,0x10000),(STOP,4096)]:u.mem_map(a,n)
 calls=[]
 def hook(uc,a,size,data):
  if a==STOP:uc.emu_stop();return
  if a in (0x525b6144,0x525b6154):
   calls.append(a);uc.reg_write(UC_ARM_REG_R0,0x13 if a==0x525b6144 else 0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert START<=a<END,hex(a)
 u.hook_add(UC_HOOK_CODE,hook)
 def one(reload,current):
  calls.clear();u.mem_write(MMIO+0xd4,struct.pack('<II',current,reload));before=bytes(u.mem_read(MMIO,4096))
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,0x20008000);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(START,STOP+4,count=1000);assert u.reg_read(UC_ARM_REG_PC)==STOP and calls==[0x525b6144,0x525b6154]
  difference=(reload-current)&0xffffffff;product=(difference*1000000)&0xffffffff;expected=(product*0x9b5e1bb1)>>44
  actual=u.reg_read(UC_ARM_REG_R0);assert actual==expected and bytes(u.mem_read(MMIO,4096))==before
  return actual
 values=[one(6749,6749-i) for i in range(6750)];drops=[i for i in range(1,len(values)) if values[i]<values[i-1]];assert drops==[4295]
 assert values[4294]==636242 and values[4295]==4 and values[6749]==363614
 rows=[dict(group='synthetic-register-sweep',samples=6750,reload=6749,difference_min=0,difference_max=6749,drop_indices=drops,boundary_outputs={str(i):values[i] for i in [0,1,4294,4295,6749]},all_outputs_sha256=sha(struct.pack('<6750I',*values)))]
 for reload,current in [(0,0),(0,1),(0xffffffff,0),(0xffffffff,0xffffffff)]:
  actual=one(reload,current);rows.append(dict(group='synthetic-wrap-edges',reload=reload,current=current,result=actual))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),arm_executions=6754,groups={'synthetic-register-sweep':1,'synthetic-wrap-edges':4},scope=__doc__,stubs={'0x525b6144':'IRQ mask boundary returns synthetic13','0x525b6154':'IRQ restore boundary returns0'},ranges=[dict(start=hex(START),end=hex(END),sha256=sha(b[START-BASE:END-BASE]))],results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ['passed','cases','arm_executions']})
