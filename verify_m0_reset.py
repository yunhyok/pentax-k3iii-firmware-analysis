"""CPU-only original M0 Thumb checks. All addresses are emulated RAM, never device I/O."""
import argparse, hashlib, json, struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
BASE=0x3ffe0300
SHA='63dd8f3b2668ef68f3ab0f8ecd0f4cda8c46a78c5388646fc9e1fe85e39a070e'
DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
H=lambda x:hashlib.sha256(x).hexdigest()
STOP=0x1001f800;STACK=0x1001e000;TASK_STACK=0x10002000;TCB=0x10004000
RANGES=[(0x3ffe0446,0x3ffe0468),(0x3ffe04a4,0x3ffe0500),
 (0x3ffe0838,0x3ffe084c),(0x3ffe08dc,0x3ffe0ac6),(0x3ffe3594,0x3ffe35ca),
 (0x3ffe4e74,0x3ffe4e94),(0x3fff1f6c,0x3fff1f94),(0x3fff1d10,0x3fff1f18),
 (0x3fff19a8,0x3fff19c4),(0x3fff28a8,0x3fff28be),(0x3fff28c0,0x3fff28c6),
 (0x3fff28c8,0x3fff28e0),(0x3fff1988,0x3fff19a2),(0x3fff2010,0x3fff2062)]
def run(blob):
 assert len(blob)==92164 and H(blob)==SHA
 rows=[]
 def fresh(allowed, intercept=None):
  u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M0)
  for a,n in [(0x3ffe0000,0x20000),(0x10000000,0x20000),(0x4d020000,0x3000),(0x4dffb000,0x1000),(0x4dfff000,0x1000)]:u.mem_map(a,n)
  u.mem_write(BASE,blob);u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP|1)
  writes=[];pcs=[]
  def put(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
  def word(a):return struct.unpack('<I',u.mem_read(a,4))[0]
  def hook(uc,a,n,data):
   if intercept and intercept(uc,a,n):return
   assert any(x<=a and a+n<=z for x,z in allowed),hex(a)
   pcs.append(a)
  def write(uc,access,a,n,v,data):
   if 0x4d000000<=a<0x4e000000:writes.append((a,n,v))
  u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_WRITE,write)
  return u,put,word,writes,pcs
 def ret(uc,value=None):
  if value is not None:uc.reg_write(UC_ARM_REG_R0,value)
  uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 def execute(u,a,end=STOP,count=60000):
  u.emu_start(a|1,end,count=count)
  assert u.reg_read(UC_ARM_REG_PC)==end,hex(u.reg_read(UC_ARM_REG_PC))
  return u.reg_read(UC_ARM_REG_R0)
 def digest(v):return H(json.dumps(v,separators=(',',':')).encode())
 # Exact initialized-data copy and BSS clear; stop before reset's child calls.
 u,put,word,w,pcs=fresh([RANGES[0]])
 u.mem_write(0x3fff7000,b'\xa7'*(0x3fffed98-0x3fff7000))
 execute(u,0x3ffe0446,0x3ffe0468)
 assert bytes(u.mem_read(0x3fff7000,0xc0))==blob[0x3fff6a44-BASE:0x3fff6b04-BASE]
 assert bytes(u.mem_read(0x3fff70c0,0x7cd8))==bytes(0x7cd8)
 assert word(0x3fff7014)==1 and word(0x3fff7004)==100000000
 rows.append(dict(group='reset_data_copy',copied_bytes=192,cleared_bytes=31960,selector_gate=1))
 # Board input is synthetic and stable across repeated reads. Delay and printf are stubbed.
 for index in range(32):
  calls=[]
  def hook(uc,a,n):
   if a in (0x3ffe0494,0x3fff0630):calls.append(a);ret(uc);return True
   return False
  u,put,word,w,pcs=fresh([RANGES[3]],hook)
  put(0x3fff7014,1);put(0x4d022024,((index&15)<<11)|((index>>4)<<9));put(0x4d022014,(index&15)<<8)
  for off in [0x2114,0x2124,0x2314,0x2324,0x2414,0x2424]:put(0x4d020000+off,0x55aa55aa)
  result=execute(u,0x3ffe08dc);expected=blob[0x3fff4de0-BASE+index] if index<=24 else 27
  assert result==expected and u.mem_read(0x3fff70e8,1)[0]==expected and word(0x3fff7014)==0
  assert calls==[0x3ffe0494,0x3ffe0494,0x3fff0630] and len(w)==15
  rows.append(dict(group='board_sample',synthetic_index=index,result=result,write_trace_sha256=digest(w)))
 for gate,cached in [(0,0),(0,255),(2,16),(0xffffffff,27)]:
  u,put,word,w,pcs=fresh([RANGES[3]]);put(0x3fff7014,gate);u.mem_write(0x3fff70e8,bytes([cached]))
  assert execute(u,0x3ffe08dc)==cached and word(0x3fff7014)==gate and not w
  rows.append(dict(group='board_cached',gate=hex(gate),cached=cached))
 # Cached selectors exercise original computed table dispatch, stopping each external body.
 for selector in list(range(13))+[13,27]:
  calls=[]
  def hook(uc,a,n):
   if a in (0x3ffe2f98,0x3ffe23a4,0x3ffe11a0,0x3ffe17a0,0x3ffe29a0,0x3ffe1da4):calls.append(a);ret(uc);return True
   return False
  u,put,word,w,pcs=fresh([RANGES[3],RANGES[4]],hook);put(0x3fff7014,0);u.mem_write(0x3fff70e8,bytes([selector]))
  execute(u,0x3ffe3594);expected={0:0x3ffe11a0,3:0x3ffe17a0,6:0x3ffe1da4,9:0x3ffe23a4,12:0x3ffe29a0}.get(selector,0x3ffe2f98)
  assert calls==[expected]
  rows.append(dict(group='board_dispatch',selector=selector,stubbed_target=hex(expected)))
 # Early MMIO writes run as original Thumb against RAM; status can skip/wait/finish.
 for bit7,delay in [(1,0),(0,0),(0,3),(0,None)]:
  polls=[]
  def hook(uc,a,n):
   if a==0x3ffe04f2:
    polls.append(a)
    if delay is not None and len(polls)>delay:put(0x4dfff00c,0x10)
   return False
  u,put,word,w,pcs=fresh([RANGES[1]],hook);put(0x4dfff018,bit7<<7);put(0x4dfff000,0x12000000)
  if delay is None:
   u.emu_start(0x3ffe04a5,STOP,count=1000);assert u.reg_read(UC_ARM_REG_PC) in (0x3ffe04f2,0x3ffe04f4,0x3ffe04f6)
  else:execute(u,0x3ffe04a4)
  prefix=[(0x4dfff0a0,4,0),(0x4dfff0b0,4,0),(0x4dfff0c0,4,0x02210200),(0x4dfff054,4,0xf0000000)]
  extra=[(0x4dfff020,4,0x80),(0x4dfff084,4,0xffffff),(0x4dfff084,4,0x1fffffff),(0x4dfff010,4,0x10),(0x4dfff008,4,0x10),(0x4dfff000,4,0x1200aa01)]
  assert w==prefix+([] if bit7 else extra+([] if delay is None else [(0x4dfff010,4,0x10)]))
  rows.append(dict(group='early_register_setup',synthetic_bit7=bit7,poll_delay=delay,returned=delay is not None,polls=len(polls),write_trace_sha256=digest(w)))
 for seed in (0,0xffffffff):
  calls=[]
  def hook(uc,a,n):
   if a==0x3ffe7698:calls.append(a);ret(uc);return True
   return False
  u,put,word,w,pcs=fresh([RANGES[2]],hook);put(0x4dffb208,seed);execute(u,0x3ffe0838)
  assert word(0x4dffb208)==seed|32 and calls==[0x3ffe7698]
  rows.append(dict(group='early_bit_setup',seed=hex(seed),result=hex(word(0x4dffb208))))
 # Full register wrapper -> checked creator -> core -> real initial-stack/list routines.
 # Heap, memset, critical enter/leave and free are synthetic. No scheduler/device entry runs.
 for scenario in ['success','stack_fail','tcb_fail','provided_stack','priority_clamp','existing_lower','existing_equal','existing_higher']:
  alloc=[];freed=[];stubs=[]
  def hook(uc,a,n):
   if a==0x3fff1b38:
    size=uc.reg_read(UC_ARM_REG_R0);alloc.append(size)
    value=TASK_STACK if size==1600 else TCB
    if scenario=='stack_fail' and size==1600 or scenario=='tcb_fail' and size==1168:value=0
    stubs.append(hex(a));ret(uc,value);return True
   if a==0x3fff04e2:
    dest,val,size=[uc.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
    assert (dest,size) in [(TASK_STACK,1600),(TCB+0x60,1064)]
    uc.mem_write(dest,bytes([val&255])*size);stubs.append(hex(a));ret(uc);return True
   if a in (0x3fff1a38,0x3fff1a50):stubs.append(hex(a));ret(uc);return True
   if a==0x3fff1c50:freed.append(uc.reg_read(UC_ARM_REG_R0));stubs.append(hex(a));ret(uc);return True
   return False
  u,put,word,w,pcs=fresh(RANGES[5:12],hook)
  start=0x3ffe4e74;priority=3
  existing=scenario.startswith('existing_')
  previous_priority={'existing_lower':2,'existing_equal':3,'existing_higher':4}.get(scenario)
  if existing:
   put(0x3fffeaac,0x10006000);put(0x1000602c,previous_priority);put(0x3fffeb00,1)
   for i in range(16):
    head=0x3fffe968+20*i;put(head,0);put(head+4,head+8);put(head+8,0xffffffff);put(head+12,head+8);put(head+16,head+8)
  if scenario in ['provided_stack','priority_clamp']:
   start=0x3fff1d10;priority=31 if scenario=='priority_clamp' else 3
   for reg,val in [(UC_ARM_REG_R0,0x3ffe4df5),(UC_ARM_REG_R1,0x3fff4ed4),(UC_ARM_REG_R2,400),(UC_ARM_REG_R3,0)]:u.reg_write(reg,val)
   put(STACK,priority);put(STACK+4,0);put(STACK+8,TASK_STACK if scenario=='provided_stack' else 0)
  result=execute(u,start);ok=scenario not in ['stack_fail','tcb_fail']
  assert result==(1 if ok else 0xffffffff) and not w
  if ok:
   top=(TASK_STACK+1600-4)&~7;initial_sp=top-0x40;effective_priority=min(priority,15)
   assert word(TCB)==initial_sp and word(TCB+0x30)==TASK_STACK and word(TCB+0x2c)==effective_priority
   assert word(top-8)==0x3ffe4df5 and word(top-4)==0x01000000 and word(top-12)==0x3fff1975 and word(top-32)==0
   assert word(0x3fffeaac)==(0x10006000 if scenario=='existing_higher' else TCB) and word(0x3fffeb00)==(2 if existing else 1)
   assert word(0x3fffe968+effective_priority*20)==1 and word(TCB+0x14)==0x3fffe968+effective_priority*20
  else:
   assert word(0x3fffeb00)==0 and word(0x3fffeaac)==0
   assert freed==([TASK_STACK] if scenario=='tcb_fail' else [])
  rows.append(dict(group='task_registration',scenario=scenario,result=hex(result),previous_current_priority=previous_priority,current_tcb=hex(word(0x3fffeaac)),allocation_sizes=alloc,freed=[hex(v) for v in freed],stubbed_calls=stubs))
 # Independent initial-frame restore: current TCB is deliberately the synthetic loader TCB.
 u,put,word,w,pcs=fresh([RANGES[8],RANGES[12]])
 top=TASK_STACK+0x638
 for reg,val in [(UC_ARM_REG_R0,top),(UC_ARM_REG_R1,0x3ffe4df5),(UC_ARM_REG_R2,0x12345678)]:u.reg_write(reg,val)
 sp=execute(u,0x3fff19a8);put(TCB,sp);put(0x3fffeaac,TCB)
 execute(u,0x3fff1988,0x3ffe4df4)
 assert u.reg_read(UC_ARM_REG_R0)==0x12345678 and u.reg_read(UC_ARM_REG_LR)==0x3fff1975
 assert u.reg_read(UC_ARM_REG_CONTROL)==2
 rows.append(dict(group='first_task_restore',assumed_current_tcb=hex(TCB),entry=hex(0x3ffe4df5),parameter=hex(0x12345678),stop_before_target=True))
 # Scheduler gates: creation helpers stubbed; stop before port-start hardware setup.
 for idle,timer in [(1,1),(0,None),(0xffffffff,None),(1,0),(1,0xffffffff)]:
  calls=[]
  def hook(uc,a,n):
   if a in (0x3fff1d10,0x3fff2fb0):calls.append(hex(a));ret(uc,idle if a==0x3fff1d10 else timer);return True
   if a==0x3fff19cc:uc.emu_stop();return True
   return False
  u,put,word,w,pcs=fresh([RANGES[13]],hook);put(0x3fffeaac,TCB)
  u.emu_start(0x3fff2011,STOP,count=1000);pc=u.reg_read(UC_ARM_REG_PC)
  success=idle==1 and timer==1
  if success:
   assert pc==0x3fff19cc and word(0x3fff70a8)==TCB+0x60 and word(0x3fffeab0)==0xffffffff and word(0x3fffe934)==1 and word(0x3fffeab8)==0
  else:
   value=idle if idle!=1 else timer
   assert pc==(0x3fff2034 if value==0 else STOP) and word(0x3fffe934)==0
  rows.append(dict(group='scheduler_gate',idle_result=hex(idle),timer_result=None if timer is None else hex(timer),reached_port_start=success,stopped_pc=hex(pc),stubbed_calls=calls))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),cases_detail=rows,ranges=[dict(start=hex(a),end=hex(z),sha256=H(blob[a-BASE:z-BASE])) for a,z in RANGES],scope='Original Thumb on Cortex-M0 emulation only. MMIO backed by RAM; synthetic board/poll inputs; external selected board bodies, delay, printf, heap, memset, critical/free and scheduler-creation helpers substituted as disclosed per group. Task create core, list helpers, initial frame and restore run original code. Restore assumes loader is current and stops before target instruction. No hardware, real boot, remap, authentication policy or complete scheduler proof.',decompiler_discrepancy='Raw angr task_create_core returns0xfffffffe in allocation failure; original Thumb returns0xffffffff and synthetic cases confirm it.')
if __name__=='__main__':
 from verify_m0_memory import load_decoded,verify_metadata
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('decoded',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 d=load_decoded(a.decoded);b=d[1208:1208+92164];e=json.loads((Path(__file__).resolve().parent/'analysis/m0-reset-evidence.json').read_text())
 result=run(b);result['metadata']=verify_metadata(b,e)
 a.output.write_text(json.dumps(result,indent=2)+'\n');print('Passed',result['cases'],'M0 reset cases and source metadata')
