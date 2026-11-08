"""Original ARM pool construction/registration and allocation arithmetic.
OS create/allocate and debug metadata are explicit stubs; no OS service executes.
The initializer fragment receives r5=0x40 and a synthetic frame. This is not a
full startup replay. Allocation success returns a small synthetic pointer only;
requested large buffers are never allocated. No device, file, or camera IO.
"""
if not __debug__:
 raise RuntimeError('Verification requires assertions; run without -O or PYTHONOPTIMIZE')
import argparse, hashlib, json, struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
OBJ=0x547ba638; REG=0x547ba300; BUFFER=0x10000000; VALIDATOR=BUFFER+0x1000
STACK=0x20008000; STOP=0x30000000; SIZE=0x31b00000; REGION=0x6e500000
RANGES=[(0x530f04ac,0x530f05cc),(0x530ef264,0x530ef288),
 (0x530ef2c4,0x530ef2d4),(0x530efb8c,0x530efc80),
 (0x530f5890,0x530f58cc),(0x52ff4a1c,0x52ff4aa8)]
STUBS={0x525b6a58:'capture seven creation descriptor words and return synthetic signed handle',
 0x525b7214:'capture allocation request and return synthetic OS status/pointer; no allocation',
 0x530ef42c:'capture debug metadata arguments only; metadata writes are not executed',
 0x530fdfc4:'capture ctor assertion condition and return; fatal policy not emulated'}
sha=lambda b:hashlib.sha256(b).hexdigest()
p32=lambda v:struct.pack('<I',v&0xffffffff)
def load(path):
 b=path.read_bytes()
 if sha(b)==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 assert sha(b)==SHA
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 for a,n in [(BUFFER,0x3000),(0x20000000,0x10000),(STOP,4096),(0x54525000,4096),(0x547ba000,4096)]:u.mem_map(a,n)
 state={};rows=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,p32(v))
 def hook(uc,a,size,user):
  if a in (STOP,0x530f58cc):uc.emu_stop();return
  if a in STUBS:
   regs=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
   r0,r1,r2,r3=regs;ret=0
   if a==0x525b6a58:
    state['descriptor']=[rd(r0+4*k) for k in range(7)];ret=state['create_status']
   elif a==0x525b7214:
    state['allocation_args']=regs;ret=state['allocation_status']
    if ret==0:wr(r2,state['raw'])
   elif a==0x530ef42c:
    sp=uc.reg_read(UC_ARM_REG_SP);state['debug_args']=regs+[rd(sp),rd(sp+4)]
   elif a==0x530fdfc4:state['assert_conditions'].append(r0)
   uc.reg_write(UC_ARM_REG_R0,ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),hex(a)
 u.hook_add(UC_HOOK_CODE,hook)
 def run(entry,args=(),fragment=False):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  for q,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(q,v&0xffffffff)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP)
  if fragment:u.reg_write(UC_ARM_REG_R5,0x40);u.reg_write(UC_ARM_REG_R11,STACK+0x400)
  u.emu_start(entry,STOP+4,count=10000)
  assert u.reg_read(UC_ARM_REG_PC)==(0x530f58cc if fragment else STOP)
  return u.reg_read(UC_ARM_REG_R0)
 def record(group,inputs,outputs):
  rows.append(dict(group=group,inputs=inputs,result_sha256=sha(json.dumps(dict(outputs=outputs,state=state),sort_keys=True).encode())))
 def reset():
  u.mem_write(0x547ba000,bytes(4096));u.mem_write(BUFFER,bytes(0x3000));wr(0x54525f1c,0x12345000)
  state.clear();state.update(assert_conditions=[])
  assert run(0x530f04ac,[OBJ])==OBJ
  assert rd(OBJ)==0x53a6b038 and rd(OBJ+8)==0x53a6b05c and rd(OBJ+0x14)==0xffee0000
  assert bytes(u.mem_read(OBJ+4,1))==b'\xff' and rd(OBJ+0x1c)==rd(OBJ+0x20)==rd(OBJ+0x24)==0
 for status in (1,0x1234,0x7fffffff,0,0xffffffff,0x80000000):
  reset();wr(REG+14*4,0xdeadbeef);state['create_status']=status
  result=run(0x530f5890,fragment=True);success=0<status<0x80000000
  assert state['descriptor']==[0,0x20,SIZE-16,REGION,0,0,0]
  assert result==int(success)
  assert rd(REG+14*4)==(OBJ if success else 0xdeadbeef)
  if success:
   assert [rd(OBJ+k) for k in (0x14,0x18,0x1c,0x20,0x24)]==[status,0x53a6ad50,SIZE-16,0x40,REGION]
   assert bytes(u.mem_read(OBJ+4,1))==bytes(u.mem_read(OBJ+12,1))==b'\x0e'
   assert run(0x530ef264,[14])==OBJ
  else:assert rd(OBJ+0x14)==0xffee0000 and rd(OBJ+0x1c)==0
  record('initializer-fragment-create-registration',dict(synthetic_os_create_status=status,incoming_r5=64),result)
 reset();state['create_status']=77;run(0x530f5890,fragment=True)
 assert run(0x52ff4a1c,[VALIDATOR])==VALIDATOR
 assert rd(VALIDATOR+4)==OBJ and state['assert_conditions']==[1]
 record('validator-ctor-shared-registry',{},rd(VALIDATOR+4))
 sizes=[0,1,63,64,65,0x80000,35106716,35136788,78690708,0xffffffff]
 for size in sizes:
  for status in (0,0xffffffff):
   state.clear();state.update(allocation_status=status,raw=BUFFER+0x207)
   result=run(0x530efb8c,[OBJ,size,0x40,0x12345678])
   total=(((size+63)&0xffffffff)&0xffffffc0)+96;total&=0xffffffff
   assert state['allocation_args'][0:2]==[77,total] and state['allocation_args'][3]==0
   aligned=(state['raw']+0x18+0x40+7)&0xffffffc0
   assert result==(aligned if status==0 else 0)
   if status==0:
    assert rd(aligned-8)==state['raw']+0x18
    assert state['debug_args']==[OBJ+8,state['raw'],aligned,total,size,0x12345678]
   else:assert 'debug_args' not in state
   record('allocate-size-success-failure',dict(requested_bytes=size,alignment=64,synthetic_os_status=status),result)
 for offset,requested in [(n,35136788) for n in (0,1,31,32,63,64,127)]+[(0,78683892)]:
  state.clear();state.update(allocation_status=0,raw=BUFFER+0x100+offset)
  result=run(0x530efb8c,[OBJ,requested,0,0])
  assert result==(state['raw']+95)&0xffffffc0
  assert result%64==0 and rd(result-8)==state['raw']+24
  assert state['debug_args'][-1]==STOP
  assert state['allocation_args'][1]==((requested+63)&~63)+96
  record('default-alignment-raw-pointer-caller-fallback',dict(requested_bytes=requested,raw_offset=offset,alignment_argument=0,caller_argument=0),result)
 candidates=[]
 for name,size in [('original',35106716),('selected',35136788),('all_stored',78690708),('decoded',78683892)]:
  candidates.append(dict(name=name,file_bytes=size,allocator_request_bytes=((size+63)&~63)+96))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),groups={g:sum(r['group']==g for r in rows) for g in sorted({r['group'] for r in rows})},scope=__doc__,cpu_model='Unicorn Cortex-A15; no camera fidelity claim',stubs={hex(k):v for k,v in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],candidates=candidates,results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
 if args.output.exists():raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups','candidates')})
