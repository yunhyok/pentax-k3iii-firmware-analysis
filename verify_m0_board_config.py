"""Original M0 Thumb fixed-store sequences. MMIO is isolated synthetic RAM only."""
if not __debug__:raise RuntimeError('Assertions required; do not use -O')
import argparse,hashlib,json,os,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_MODE_MCLASS,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
BASE=0x3ffe0300;SHA='63dd8f3b2668ef68f3ab0f8ecd0f4cda8c46a78c5388646fc9e1fe85e39a070e'
DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
H=lambda b:hashlib.sha256(b).hexdigest()
RANGES=[(0x3ffe11a0,0x3ffe14a0,0x3ffe17a0),(0x3ffe2f98,0x3ffe3298,0x3ffe3594)]
MMIO=[(0x4d020000,0x4000),(0x4dff4000,0x1000),(0x4dffb000,0x1000),(0x4dffe000,0x1000)]
STOP=0x10000f00;SP=0x10000e00
def load(p):
 b=p.read_bytes();h=H(b)
 if h==DECODED_SHA:b=b[1208:1208+92164]
 if H(b)!=SHA:raise ValueError('Original M0 source hash required')
 return b
def run_case(b,entry,end,pool_end,fill):
 assert H(b)==SHA
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M0)
 u.mem_map(0x3ffe0000,0x20000);u.mem_write(BASE,b);u.mem_map(0x10000000,0x1000)
 for addr,size in MMIO:u.mem_map(addr,size);u.mem_write(addr,bytes([fill])*size)
 u.reg_write(UC_ARM_REG_SP,SP);u.reg_write(UC_ARM_REG_LR,STOP|1)
 for r,v in [(UC_ARM_REG_R0,0x12345678),(UC_ARM_REG_R1,0x87654321)]:u.reg_write(r,v)
 saved={r:0xa5070000+n for n,r in enumerate([UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11])}
 for r,v in saved.items():u.reg_write(r,v)
 writes=[];read_count=0;code_count=0;loops={entry+0xb6:0,entry+0xca:0}
 def code(uc,a,n,data):
  nonlocal code_count
  assert entry<=a<a+n<=end,(hex(a),'unexpected original instruction')
  code_count+=1
  if a in loops:loops[a]+=1
 def read(uc,access,a,n,value,data):
  nonlocal read_count
  assert end<=a<a+n<=pool_end,(hex(a),'nonliteral data read')
  read_count+=1
 def write(uc,access,a,n,value,data):
  assert n==4 and any(x<=a<a+n<=x+z for x,z in MMIO),(hex(a),n)
  writes.append((uc.reg_read(UC_ARM_REG_PC),a,n,value))
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ,read);u.hook_add(UC_HOOK_MEM_WRITE,write)
 u.emu_start(entry|1,STOP,count=130000)
 assert u.reg_read(UC_ARM_REG_PC)==STOP and u.reg_read(UC_ARM_REG_SP)==SP
 assert all(u.reg_read(r)==v for r,v in saved.items())
 assert len(writes)==125 and len(set(a for _,a,_,_ in writes))==123
 assert code_count==120378 and list(loops.values())==[20000,20000]
 # Source-backed request values, not actual hardware readback semantics.
 assert [v for _,a,_,v in writes if a==0x4dffb208]==[0x20]
 assert [v for _,a,_,v in writes if a==0x4d021090]==[0x3f]
 assert struct.unpack('<I',u.mem_read(0x4dffb208,4))[0]==0x20
 trace_bytes=b''.join(struct.pack('<4I',*w) for w in writes)
 result=dict(entry=hex(entry),initial_mmio_byte=fill,passed=True,instructions_executed=code_count,store_requests=len(writes),unique_store_addresses=123,literal_data_reads=read_count,nonliteral_data_reads=0,countdown_iterations=list(loops.values()),store_trace_sha256=H(trace_bytes),requested_4dffb208='0x20',requested_4d021090='0x3f',callee_saved_and_sp_preserved=True)
 return result,writes
def run_checks(b):
 rows=[]
 for a,z,p in RANGES:
  first=None
  for fill in (0,255):
   row,trace=run_case(b,a,z,p,fill)
   if first is None:first=trace
   else:assert trace==first
   rows.append(row)
 return dict(passed=True,image_sha256=SHA,cases=len(rows),fixture_entry_runs=len(rows),ranges=[dict(start=hex(a),code_end=hex(z),end=hex(p),sha256=H(b[a-BASE:p-BASE]),code_sha256=H(b[a-BASE:z-BASE])) for a,z,p in RANGES],explicit_stubs={},scope='Four full original Thumb body executions (default and selector0, synthetic MMIO initially00/ff). Cortex-M0 emulator, no external calls, no instruction skips, no targetOS/IRQ/device. All data reads required to resolve inside source literal pools. Fixed countdowns are instruction counts, not physical delay/time units. No actual reset/selector sampling/launch or SRAM alias.',cases_detail=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 if os.path.lexists(a.output):raise FileExistsError('Output already exists')
 r=run_checks(load(a.input))
 with a.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print(json.dumps(dict(passed=True,cases=r['cases'])))
