"""Original ARM CPU-only capability producer checks. No device access or firmware changes.
Unicorn Cortex-A15 model is not camera fidelity. External heap, memory primitives,
packet send/receive, event clear/wait and free are explicit synthetic stubs.
Synthetic received bytes and wait-return values are test inputs, not observed lens data.
"""
if not __debug__:
 raise RuntimeError('Verification requires assertions; run without -O or PYTHONOPTIMIZE')
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RANGES=[(0x5315a894,0x5315ba7c),(0x52f182d4,0x52f18490),(0x5315dc68,0x5315e2f0),(0x52f18128,0x52f182c8),(0x5313432c,0x53134334),(0x531346d8,0x531346e8)]
F,C,D,Q,O,P,A,H=0x10000000,0x10010000,0x10020000,0x10021000,0x10028000,0x10030000,0x10031000,0x10040000
STACK=0x20008000;STOP=0x30000000;sha=lambda b:hashlib.sha256(b).hexdigest();p32=lambda n:struct.pack('<I',n&0xffffffff)
STUBS={0x530f2668:'synthetic allocator',0x526ab2a8:'memset',0x526aac80:'memcpy',0x530ed0f4:'event-clear returns0',0x52f3a74c:'send records packet only',0x52f180a0:'wait returns supplied synthetic value',0x52f3a754:'receive injects synthetic 32-byte buffer',0x530f26a4:'free no-op',0x5315e2f0:'rejection handler records only in forced-error case'}
def load(path):
 b=path.read_bytes()
 if sha(b)==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b

def run_checks(b):
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15);n=(len(b)+4095)&~4095
 u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 u.mem_map(F,0x60000);u.mem_map(0x20000000,0x10000);u.mem_map(STOP,0x1000)
 state={};cases=[];stops=set()
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def hook(uc,a,size,user):
  if a==STOP or a in stops:uc.emu_stop();return
  if a==0x52f18128 and state.get('forced_status') is not None:
   state['forced_calls']+=1;uc.reg_write(UC_ARM_REG_R0,state['forced_status']);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  if a in STUBS:
   r=[uc.reg_read(x) for x in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]];ret=0;state['calls'].append(hex(a))
   if a==0x530f2668:
    assert r[0]==32;r0=state['heap'];state['heap']+=0x100;ret=r0
   elif a==0x526ab2a8:
    assert r[2]==32;uc.mem_write(r[0],bytes([r[1]&255])*r[2]);ret=r[0]
   elif a==0x526aac80:
    assert r[2]==32;uc.mem_write(r[0],bytes(uc.mem_read(r[1],r[2])));ret=r[0]
   elif a==0x52f3a74c:
    packet=bytes(uc.mem_read(r[1],20));assert packet[4:7]==bytes([0x63,5,0x82]);assert rd(r[1]+8)==32;state['sent']=bytes(uc.mem_read(rd(r[1]+16),32))
   elif a==0x52f180a0:ret=state['wait_return']
   elif a==0x52f3a754:
    assert uc.mem_read(r[1]+4,1)==b'\x63' and rd(r[1]+8)==32;uc.mem_write(rd(r[1]+16),state['response'])
   elif a==0x5315e2f0:state['rejected']+=1
   uc.reg_write(UC_ARM_REG_R0,ret);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  if not any(x<=a<z for x,z in RANGES):raise AssertionError('unexpected execution '+hex(a))
 u.hook_add(UC_HOOK_CODE,hook)
 def run(a,args,stop=(),stack_words=(),forced_status=None,wait_return=1,response=bytes(32)):
  state.clear();state.update(heap=H,calls=[],forced_status=forced_status,forced_calls=0,wait_return=wait_return,response=response,rejected=0)
  stops.clear();stops.update(stop)
  for reg in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(reg,0)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP);u.mem_write(STACK-0x200,bytes(0x400))
  for j,v in enumerate(stack_words):u.mem_write(STACK+4*j,p32(v))
  for r,v in args.items():u.reg_write(r,v&0xffffffff)
  u.emu_start(a,STOP+4,count=100000);assert u.reg_read(UC_ARM_REG_PC)==STOP or u.reg_read(UC_ARM_REG_PC) in stops
  return u.reg_read(UC_ARM_REG_R0)
 def rec(group,inputs,result):cases.append(dict(group=group,inputs=inputs,result_sha256=sha(json.dumps(result,sort_keys=True).encode())))
 u.mem_write(F+0x44,p32(D));u.mem_write(F+0x54,p32(C));u.mem_write(F+0x60,p32(P));u.mem_write(C+0x5260,p32(D))
 # Actual lookup, no metadata stub.
 ret=run(0x5315a8a0,{UC_ARM_REG_R0:O,UC_ARM_REG_R1:0x8205,UC_ARM_REG_R2:O+4,UC_ARM_REG_R3:O+8},stack_words=(O+12,O+16))
 meta=[ret,rd(O+4),int.from_bytes(u.mem_read(O+8,1),'little'),int.from_bytes(u.mem_read(O+12,1),'little'),int.from_bytes(u.mem_read(O+16,2),'little')];assert meta==[1,0x26,2,1,0];rec('full-metadata-8205',{},meta)
 for value in range(256):
  data=bytes([value])+bytes(range(1,32));u.mem_write(Q,bytes([0xa5])*32);u.mem_write(C+0x5272,b'\xee');u.mem_write(D+6,b'\xee');u.mem_write(C+0x4f8,bytes([0xcc])*32)
  wait=0 if value&1 else 1
  ret=run(0x52f182d4,{UC_ARM_REG_R0:F,UC_ARM_REG_R1:0x8205,UC_ARM_REG_R2:Q,UC_ARM_REG_R3:32},response=data,wait_return=wait)
  assert ret==0 and bytes(u.mem_read(C+0x4f8,32))==data and u.mem_read(C+0x5272,1)==u.mem_read(D+6,1)==data[:1]
  assert state['sent']==bytes([0xa5])*32 and state['rejected']==0
  rec('full-handler-lookup-exchange-copy-unpack-with-transport-stubs',dict(response_byte0=value,wait_return=wait),dict(return_value=ret,capability=value,cache_sha256=sha(data),calls=state['calls']))
 for length in [0,1,31,32,33]:
  orig=bytes([0xaa])*32;data=bytes(range(32));u.mem_write(Q,orig)
  ret=run(0x52f18128,{UC_ARM_REG_R0:F,UC_ARM_REG_R1:0x8205,UC_ARM_REG_R2:Q,UC_ARM_REG_R3:length},response=data)
  expected=data[:min(length,32)]+orig[min(length,32):];assert ret==0 and bytes(u.mem_read(Q,32))==expected and state['sent']==orig
  rec('full-exchange-copy-length-with-transport-stubs',dict(requested_length=length),dict(return_value=ret,buffer_sha256=sha(expected)))
 for index in [0,0x26,0x86,0x87,-1]:
  u.mem_write(C-0x100,bytes([0xee])*0x1400);u.mem_write(Q,bytes(range(32)));off=(0x38+((index&0xffffffff)<<5))&0xffffffff;dst=(C+off)&0xffffffff
  before=bytes(u.mem_read(dst,32));run(0x5315dc68,{UC_ARM_REG_R0:C,UC_ARM_REG_R1:index,UC_ARM_REG_R2:Q})
  expected=before if index>0x86 else bytes(range(32));assert bytes(u.mem_read(dst,32))==expected
  rec('full-cache-copy-synthetic-index-boundaries',dict(index=index,valid_lookup_producer=(index==0x26)),dict(destination=hex(dst),copied=index<=0x86))
 # Force an otherwise unobserved nonzero exchange return to check the handler's conditional branch only.
 u.mem_write(C+0x5260,p32(D));u.mem_write(C+0x5272,b'\x40');u.mem_write(D+6,b'\x40');u.mem_write(C+0x4f8,bytes([0x33])*32)
 ret=run(0x52f182d4,{UC_ARM_REG_R0:F,UC_ARM_REG_R1:0x8205,UC_ARM_REG_R2:Q,UC_ARM_REG_R3:32},forced_status=7)
 assert ret==7 and state['forced_calls']==1 and state['rejected']==1 and u.mem_read(C+0x5272,1)==b'\x40' and u.mem_read(C+0x4f8,32)==bytes([0x33])*32
 rec('full-handler-forced-nonzero-return-branch-only',dict(synthetic_return=7),dict(capability=0x40,rejection_called=True))
 for value in [0,0x40,0x80,0xff]:
  u.mem_write(P,p32(A));u.mem_write(P+8,p32(A));u.mem_write(A+0x10,p32(D));u.mem_write(D+8,bytes([value]));u.mem_write(O+0x1272,b'\xee');u.mem_write(C+0x5272,b'\x55')
  run(0x5313432c,{UC_ARM_REG_R0:P,UC_ARM_REG_R1:O},stop=[0x53134334]);r3=u.reg_read(UC_ARM_REG_R3);assert r3==O+0x1000
  run(0x531346d8,{UC_ARM_REG_R0:P,UC_ARM_REG_R3:r3},stop=[0x531346e8]);assert u.mem_read(O+0x1272,1)==bytes([value]) and u.mem_read(C+0x5272,1)==b'\x55'
  rec('non-AF-packer-two-disjoint-fragments',dict(value=value),dict(destination_offset='0x1272',capability_unchanged=True))
 return dict(passed=True,image_sha256=SHA,cases=len(cases),groups={g:sum(c['group']==g for c in cases) for g in sorted({x['group'] for x in cases})},scope=__doc__,cpu_model='Unicorn Cortex-A15; not camera fidelity',stubs={hex(k):v for k,v in STUBS.items()},additional_forced_stub='52f18128 only in one structural nonzero-return test; its observed ordinary original path returns0',ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=cases)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 if a.output.exists():raise FileExistsError('report exists')
 r=run_checks(load(a.input))
 with a.output.open('x',encoding='utf-8') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ['passed','cases','groups']})
