"""Original ARM clock readers with authored state and synthetic timer registers.
Lock/IRQ helpers are stubs. Emulated MPIDR selects CPU0; no IRQ, time or device runs.
Guard failure stops at the unresolved boundary, not an assertion policy emulation.
"""
if not __debug__:raise RuntimeError('Assertions required; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RANGES=[(0x525ce390,0x525ce518),(0x525b5c60,0x525b5c9c)];STOP=0x30000000;OUT=0x20002000;FINE=OUT+0x20;TASK=0x20003000;MASK=(1<<64)-1
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
 for a,n in [(0x20000000,0x10000),(0x54c3f000,0x3000),(0x1e000000,0x1000),(STOP,0x1000)]:u.mem_map(a,n)
 state={};rows=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
 def qw(a,v):u.mem_write(a,struct.pack('<Q',v&MASK))
 def code(uc,a,n,data):
  if a in (STOP,0x525d724c):state['stop']=a;uc.emu_stop();return
  if a in (0x525b6144,0x525b6154,0x525b7a20,0x525b7aa4):
   arg=uc.reg_read(UC_ARM_REG_R0);state['calls'].append([hex(a),arg]);ret=0
   if a==0x525b6144:
    ret=0x13+len(state['tokens'])*0x80;state['tokens'].append(ret)
   elif a==0x525b6154:assert arg==state['tokens'].pop()
   else:assert arg==0x54c3fd04
   for reg in [UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R12]:uc.reg_write(reg,0xdeadbeef)
   uc.reg_write(UC_ARM_REG_R0,ret);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),hex(a)
 def write(uc,access,a,n,v,data):
  if OUT<=a<OUT+0x30:state['writes'].append([hex(a),n,v])
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write)
 cases=[('zero',0,0,0,0,0,0),('carry',0xffffffff,2,4294,0,0,0),('wrap',MASK,2,4295,0,0,0),('flag-allows',123,456,6749,TASK,1,0),('count-allows',123,456,1,TASK,8,1),('guard-failure',123,456,1,TASK,8,0)]
 for entry,offset_used in [(0x525ce390,True),(0x525ce45c,False)]:
  for label,now,offset,d,task,flags,nesting in cases:
   u.mem_write(0x20000000,b'\xa5'*0x10000);u.mem_write(0x54c3f000,b'\0'*0x3000)
   qw(0x54c40e50,now);qw(0x54c3fd20,offset);wr(0x54c405bc,task);wr(0x54c3f4dc,nesting);u.mem_write(TASK+0x2b,bytes([flags]));wr(0x1e0000d8,6749);wr(0x1e0000d4,6749-d)
   for r in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(r,0)
   u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,0x20008000);u.reg_write(UC_ARM_REG_LR,STOP);u.reg_write(UC_ARM_REG_R0,OUT);u.reg_write(UC_ARM_REG_R1,FINE)
   state.clear();state.update(stop=None,tokens=[],calls=[],writes=[]);mmio=bytes(u.mem_read(0x1e000000,0x1000));saved=bytes(u.mem_read(0x54c3f000,0x3000))
   u.emu_start(entry,0xffffffff,count=1000);failure=label=='guard-failure'
   assert bytes(u.mem_read(0x1e000000,0x1000))==mmio and bytes(u.mem_read(0x54c3f000,0x3000))==saved
   assert rd(OUT-4)==rd(OUT+8)==rd(FINE-4)==rd(FINE+4)==0xa5a5a5a5
   if failure:
    assert state['stop']==0x525d724c and state['writes']==[] and state['tokens']==[0x13]
    assert [a for a,v in state['calls']]==['0x525b6144','0x525b7a20'];observed={'guard_boundary':hex(state['stop']),'outputs_unchanged':True}
   else:
    coarse=(now+(offset if offset_used else 0))&MASK;fine=(((d*1000000)&0xffffffff)*0x9b5e1bb1)>>44
    assert state['stop']==STOP and not state['tokens'] and u.reg_read(UC_ARM_REG_R0)==0
    assert [rd(OUT),rd(OUT+4),rd(FINE)]==[coarse>>32,coarse&0xffffffff,fine]
    expected=[FINE,OUT,OUT+4] if offset_used else [FINE,OUT+4,OUT]
    assert [int(a,0) for a,n,v in state['writes']]==expected
    assert [a for a,v in state['calls']]==['0x525b6144','0x525b7a20','0x525b6144','0x525b6154','0x525b7aa4','0x525b6154']
    observed={'coarse_high_word':rd(OUT),'coarse_low_word':rd(OUT+4),'fine_integer':rd(FINE),'write_addresses':state['writes'],'return_value':0}
   rows.append(dict(group='with-offset' if offset_used else 'counter-only',case=label,now=now,offset=offset,synthetic_counter_difference=d,task_present=bool(task),flags=flags,nesting=nesting,observed=observed))
 assert len(rows)==12
 return dict(passed=True,cases=12,image_sha256=SHA,groups={'with-offset':6,'counter-only':6},scope=__doc__,stubs={'0x525b6144':'nested authored IRQ tokens','0x525b6154':'check/pop authored token','0x525b7a20':'lock argument capture only','0x525b7aa4':'unlock argument capture only'},stop_boundary='0x525d724c',ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ['passed','cases','groups']})
