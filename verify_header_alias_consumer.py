"""Original ARM header-parameter builder and actual caller prefix on authored RAM.
No physical controller, NAND/media, OS, bootloader or firmware write executes.
The controller word is synthetic RAM; the caller stops immediately after builder.
"""
if not __debug__:raise RuntimeError('Verification requires assertions; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
START,END=0x53323ce4,0x533240ac;CALL,CALLSTOP=0x525e012c,0x525e01a0
HEADER=0x50b70020;TABLE=0x50b70100;DEFAULT=0x545653dc;INFO=0x54c40ee0;OUT=0x54c40f3c;CTRL=0x1910080c;STACK=0x20008000;STOP=0x30000000
RANGES=[(START,END),(CALL,CALLSTOP)]
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
 for a,n in [(0x50b70000,0x20000),(0x54565000,4096),(0x54c40000,0x2000),(0x19100000,4096),(0x20000000,0x10000),(STOP,4096)]:u.mem_map(a,n)
 rows=[];writes=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
 def code(uc,a,size,user):
  if a in (STOP,CALLSTOP):uc.emu_stop();return
  assert any(x<=a<z for x,z in RANGES),hex(a)
 def write(uc,access,a,size,value,user):
  if not 0x20000000<=a<0x20010000:writes.append([hex(a),size,value])
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write)
 defaults=[0xa1010000+i*0x101 for i in range(9)]
 def reset(gate,maker=0,device=0,ctrl=0):
  u.mem_write(0x50b70000,b'\xa5'*0x20000);u.mem_write(0x54c40000,b'\xcc'*0x2000)
  for i,v in enumerate(defaults):wr(DEFAULT+4*i,v)
  for i in range(24):wr(HEADER+4*i,0x11110000+i*0x010101)
  wr(HEADER+8,gate);wr(INFO,maker);wr(INFO+4,device);wr(CTRL,ctrl);writes.clear()
 def run(entry,args):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  for q,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(q,v)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(entry,STOP+4,count=10000);assert u.reg_read(UC_ARM_REG_PC)==(CALLSTOP if entry==CALL else STOP)
 def check(want_prefix=False):
  assert [rd(OUT+4*i) for i in range(9)]==defaults
  expected_addresses={OUT+4*i for i in range(32)}|({INFO+8} if want_prefix else set())
  assert {int(a,16) for a,n,v in writes}==expected_addresses
  assert all(n==4 for a,n,v in writes)
  assert bytes(u.mem_read(TABLE,0x10f00))==b'\xa5'*0x10f00
 def record(group,inputs):rows.append({'group':group,'inputs':inputs,'output_sha256':sha(bytes(u.mem_read(OUT,128))),'write_trace_sha256':sha(json.dumps(writes).encode()),'record4_write_target':hex(OUT+4),'table_unchanged':True})
 for gate,maker,device in [(0,0,0),(0,1,0xac),(0,0xc2,0xac),(1,0,0),(0xffffffff,1,0xac)]:
  reset(gate,maker,device);saved=bytes(u.mem_read(HEADER,0x60));run(START,[maker,device,OUT]);check();assert bytes(u.mem_read(HEADER,0x60))==saved
  if gate:
   assert rd(OUT+0x24)==((rd(HEADER)>>22)&31)
   mapping={0x28:4,0x2c:8,0x30:0xc,0x34:0x10,0x38:0x14,0x3c:0x18,0x40:0x1c,0x44:0x20,0x48:0x24,0x4c:0x28,0x50:0x2c,0x54:0x30,0x58:0x34,0x5c:0x38,0x60:0x3c,0x64:0x40,0x68:0x44,0x6c:0x48,0x70:0x4c,0x74:0x50,0x78:0x54,0x7c:0x5c}
   assert all(rd(OUT+x)==rd(HEADER+y) for x,y in mapping.items())
  else:assert rd(OUT+0x24)==rd(OUT+0x28)==0 and rd(OUT+0x5c)==({1:0x00380001,0xc2:0x00300001}.get(maker,0x00480001))
  record('builder-header-gate-and-fallback',dict(gate=gate,maker=maker,device=device))
 for ctrl in [0,0x40000000,0x80000000,0xc0000000]:
  reset(1,0x25,0x76,ctrl);run(CALL,[]);check(True);assert rd(INFO+8)==int(ctrl!=0x40000000)
  record('actual-caller-fixed-output',dict(controller_word=ctrl,selected_mode=rd(INFO+8)))
 return {'passed':True,'image_sha256':SHA,'cases':len(rows),'groups':{g:sum(x['group']==g for x in rows) for g in sorted({x['group'] for x in rows})},'scope':__doc__,'stubs':{},'ranges':[{'start':hex(a),'end':hex(z),'sha256':sha(b[a-BASE:z-BASE])} for a,z in RANGES],'results':rows}
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ['passed','cases','groups']})
