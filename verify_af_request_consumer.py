"""Original ARM request-copy/queue-consumer checks with synthetic buffers.
No device access or firmware changes. Unicorn Cortex-A15 is not camera fidelity.
The OS queue is synthetic: enqueue captures a request, receive supplies its node.
The task loop runs through one wake/drain and stops at its second wait. Packet
exchange and completion children are explicit stubs, not physical completion.
"""
if not __debug__:
 raise RuntimeError('Verification requires assertions; run without -O or PYTHONOPTIMIZE')
import argparse, hashlib, json, struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RANGES=[(0x52efc7a0,0x52efc858),(0x52eff608,0x52eff618),(0x52efeec0,0x52eff17c),
 (0x52eff524,0x52eff5e0),(0x52f148fc,0x52f14a08),(0x52efebdc,0x52efec34),
 (0x530f3c10,0x530f3c50),(0x52f16588,0x52f166f4),(0x530edfa0,0x530ee30c),
 (0x52f15e2c,0x52f16588),(0x52eff330,0x52eff444),(0x52f15100,0x52f15178),
 (0x52f182d4,0x52f18544),(0x5315a894,0x5315ba7c)]
L,CTX,C,READER,BUILDER,OPT,NODE,ALLOC,AVT,OUT= [0x10000000+x*0x10000 for x in range(10)]
SP=0x20008000;STOP=0x30000000;FREE=STOP+0x100
sha=lambda b:hashlib.sha256(b).hexdigest()
p32=lambda v:struct.pack('<I',v&0xffffffff)
STUBS={0x530f1a68:'mutex lock returns0',0x530f1bbc:'mutex unlock returns0',
 0x526ab2a8:'memset used only by original constructor loop',
 0x530edc60:'queue-push captures request, returns1; no real OS queue',
 0x530ed03c:'event-set records only',0x530ecb88:'task-event setup returns0',
 0x530ed1ac:'first wait supplies mask 0x1 (bit 0); second wait stops bounded task run',
 0x530ed0f4:'event-clear records only',0x530ee680:'queue count returns1 then0',
 0x525b73a0:'receive injects synthetic node or chosen failure status',
 FREE:'synthetic allocator free records only',0x530feb20:'assert/log records only',
 0x530fced4:'diagnostic log records only',0x52f14c9c:'arbitration returns selected synthetic 0/1',
 0x52f14db8:'arbitration release records only',
 0x52f18128:'packet-exchange boundary records args and returns selected status; no transport',
 0x5315dc68:'cache child records args only',0x5315e480:'post-exchange child records args only',
 0x52efde0c:'completion payload child records args only',0x52eff2c8:'completion cleanup child records args only'}

def load(path):
 b=path.read_bytes()
 if sha(b)==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b

def run_checks(b):
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 u.mem_map(L,0xb0000);u.mem_map(0x20000000,0x10000);u.mem_map(STOP,0x1000);u.mem_map(0x54700000,0x100000)
 state={};cases=[];stops=set()
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def hook(uc,a,size,user):
  if a==STOP or a in stops:uc.emu_stop();return
  regs=[uc.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
  if a==0x52eff608:state['source_descriptor']=bytes(uc.mem_read(regs[2],16))
  if a==0x52f15ec0:state['completion_dispatch']=[regs[0],regs[1],regs[2],regs[3]]
  if a==0x52f166ec:state['task_thunk']=regs[0]
  if a in STUBS:
   r0,r1,r2,r3=regs;ret=0;state['calls'].append([hex(a),regs])
   if a==0x526ab2a8:uc.mem_write(r0,bytes([r1&255])*r2);ret=r0
   elif a==0x530edc60:
    assert r0==CTX+0x74 and r2==r3==0;state['request']=r1;ret=1
   elif a==0x530ed03c:assert r0==CTX+0x88 and r1==1
   elif a==0x530ed1ac:
    assert r0==CTX+0x88 and r1==0x2f
    state['waits']+=1
    if state['waits']==2:uc.emu_stop();return
    uc.mem_write(r2,p32(1));ret=1
   elif a==0x530ee680:
    assert r0==CTX+0x74;ret=int(state['counts']==0);state['counts']+=1
   elif a==0x525b73a0:
    ret=state['receive_status']
    if ret==0:uc.mem_write(r1,p32(NODE))
   elif a==FREE:assert r0==ALLOC and r1==NODE and r2==0
   elif a==0x52f14c9c:assert regs[:3]==[CTX,4,2];ret=state['arbitration']
   elif a==0x52f18128:state['exchange']=regs;ret=state['exchange_status']
   uc.reg_write(UC_ARM_REG_R0,ret);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  if not any(x<=a<z for x,z in RANGES):raise AssertionError('unexpected execution '+hex(a))
 u.hook_add(UC_HOOK_CODE,hook)
 def run(start,args,stop=(),stack=(),arbitration=1,exchange_status=0,receive_status=0):
  state.clear();state.update(calls=[],waits=0,counts=0,arbitration=arbitration,exchange_status=exchange_status,receive_status=receive_status)
  stops.clear();stops.update(stop)
  for reg in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(reg,0)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,SP);u.reg_write(UC_ARM_REG_LR,STOP)
  u.mem_write(SP-0x800,bytes(0x1000))
  for j,v in enumerate(stack):u.mem_write(SP+j*4,p32(v))
  for reg,value in args.items():u.reg_write(reg,value&0xffffffff)
  u.emu_start(start,STOP+4,count=100000)
  pc=u.reg_read(UC_ARM_REG_PC)
  assert pc==STOP or pc in stops or (pc==0x530ed1ac and state['waits']==2),hex(pc)
  return u.reg_read(UC_ARM_REG_R0)
 def record(group,inputs,output):cases.append(dict(group=group,inputs=inputs,result_sha256=sha(json.dumps(output,sort_keys=True).encode())))
 def setup(slot=0,option=0):
  u.mem_write(L,bytes(0xb0000));u.mem_write(L+0x1d4,p32(0x538f0568));u.mem_write(L+0x1d8,p32(CTX))
  u.mem_write(CTX+4,p32(0x538f3c68));u.mem_write(CTX+0x5c,p32(READER))
  u.mem_write(READER+0x44,p32(OUT));u.mem_write(READER+0x54,p32(C))
  u.mem_write(BUILDER+4,p32(L));u.mem_write(BUILDER+8,p32(C));u.mem_write(C+0x5272,b'\x40')
  u.mem_write(OPT+4,p32(option));u.mem_write(ALLOC,p32(AVT));u.mem_write(AVT+0xc,p32(FREE))
  u.mem_write(0x547ba2f8,p32(ALLOC));u.mem_write(0x547ba2fc,p32(1))
  for i in range(slot):u.mem_write(L+0x20c+i*0xbc,b'\x01')
 # Constructor subrange: actual loop writes all 32 slot areas. memset is explicit.
 setup();u.mem_write(L+0x20c,b'\xa5'*(32*0xbc))
 run(0x52efebdc,{UC_ARM_REG_R4:L,UC_ARM_REG_R5:L+0x20c,UC_ARM_REG_R6:0,UC_ARM_REG_R7:L+0x198c,UC_ARM_REG_R8:int.from_bytes(b[0x52efecd4-BASE:0x52efecd8-BASE],'little')},stop=[0x52efec34])
 assert all(rd(L+i*0xbc+0x2bc)==0 for i in range(32))
 record('constructor-slot-loop-fragment',{'slots':32},{'extra_pointers_zero':True,'memsets':len(state['calls'])})
 # Complete builder -> opcode wrapper -> slot allocation -> request -> enqueue wrapper.
 for slot,value,direction,option in [(0,0,0,0),(1,1,1,0),(31,0x3fff,2,0),(0,0x4000,0,1),(1,0xffff,1,0xff),(31,0x12345678,0,0x42)]:
  setup(slot,option)
  ret=run(0x52efc7a0,{UC_ARM_REG_R0:BUILDER,UC_ARM_REG_R1:value,UC_ARM_REG_R2:direction,UC_ARM_REG_R3:OPT})
  req=L+slot*0xbc+0x29c;d=L+slot*0xbc+0x2b0;payload=L+slot*0xbc+0x212
  expected=(value&0x3fff)|(0x8000 if direction else 0)
  assert ret==slot and state['request']==req
  assert state['source_descriptor'][:8]==bytes.fromhex('0200008900000000')
  assert rd(req+4)==L+0x1d4 and rd(req+8)==d and rd(req+0xc)==0x1b
  assert rd(req+0x10)==(0x89000000+(option<<8)+slot)&0xffffffff
  assert bytes(u.mem_read(payload,2))==expected.to_bytes(2,'big') and rd(d+8)==payload
  assert u.mem_read(d+0x12,1)==b'\x02' and bytes(u.mem_read(d+0x14,2))==b'\x00\x89' and rd(d+0xc)==0
  record('full-builder-copy-request-enqueue-with-OS-push-stub',dict(slot=slot,value=value,direction=direction,option_word4=option),dict(token=rd(req+0x10),request_sha256=sha(bytes(u.mem_read(req,0x2c))),calls=[c[0] for c in state['calls']]))
 # Null extra pointer preserves existing D+c; this is not proof a real stale pointer occurs.
 setup();u.mem_write(L+0x2bc,p32(0x11223344))
 run(0x52efc7a0,{UC_ARM_REG_R0:BUILDER,UC_ARM_REG_R1:5,UC_ARM_REG_R2:0,UC_ARM_REG_R3:OPT})
 assert rd(L+0x2bc)==0x11223344;record('null-extra-preserves-synthetic-existing-field',{},[rd(L+0x2bc)])
 setup(32)
 ret=run(0x52efc7a0,{UC_ARM_REG_R0:BUILDER,UC_ARM_REG_R1:5,UC_ARM_REG_R2:0,UC_ARM_REG_R3:OPT})
 assert ret==0xff and 'request' not in state;record('all-32-slots-busy',{},[ret,[c[0] for c in state['calls']]])
 # Full queue receive wrapper; only underlying OS receive and deallocation are stubs.
 for status in [0,1,0xffce0000]:
  setup();u.mem_write(NODE+8,p32(L+0x29c));u.mem_write(OUT,p32(0xabcdef01))
  ret=run(0x530edfa0,{UC_ARM_REG_R0:CTX+0x74,UC_ARM_REG_R1:OUT,UC_ARM_REG_R2:0,UC_ARM_REG_R3:0},stack=(0,0,0,0),receive_status=status)
  assert ret==int(status==0) and rd(OUT)==(L+0x29c if status==0 else 0xabcdef01)
  record('full-queue-pop-with-synthetic-OS-result',dict(status=status),[ret,rd(OUT)])
 # Real vtable task entry -> thunk -> loop -> real pop -> opcode1b dispatcher ->
 # forwarder -> metadata8900/type3 -> exchange boundary -> completion thunk/body.
 for label,gate,arbitration,commgate,exchange_status in [('normal',0,1,0,0),('context-gate',1,1,0,0),('arbitration-denied',0,0,0,0),('communication-gate',0,1,1,0),('synthetic-exchange-error',0,1,0,7)]:
  setup(1,0x42)
  run(0x52efc7a0,{UC_ARM_REG_R0:BUILDER,UC_ARM_REG_R1:0x1234,UC_ARM_REG_R2:1,UC_ARM_REG_R3:OPT})
  req=state['request'];u.mem_write(NODE+8,p32(req));u.mem_write(CTX+0x9b,bytes([gate]));u.mem_write(C+0x52f3,bytes([commgate]))
  run(0x530f3c10,{UC_ARM_REG_R0:CTX+4},arbitration=arbitration,exchange_status=exchange_status)
  assert state['task_thunk']==CTX+4 and state['counts']==2 and state['waits']==2
  assert state['completion_dispatch']==[L+0x1d4,0x0409001a,0x89004201,0x52eff43c]
  calls=[x[0] for x in state['calls']];should_exchange=not gate and arbitration and not commgate
  assert ('exchange' in state)==bool(should_exchange)
  if should_exchange:
   assert state['exchange']==[READER,0x8900,L+0xbc+0x212,2]
   assert next(x[1] for x in state['calls'] if x[0]=='0x5315dc68')[:2]==[C,0x49]
   assert ('0x5315e480' in calls)==(exchange_status==0)
  assert next(x[1] for x in state['calls'] if x[0]=='0x52efde0c')[:3]==[L+0x50,0x8900,L+0xbc+0x212]
  assert next(x[1] for x in state['calls'] if x[0]=='0x52eff2c8')[:3]==[L,0x42,1]
  record('entry-through-one-queue-drain-and-completion',dict(case=label,context_gate=gate,arbitration=arbitration,communication_gate=commgate,synthetic_exchange_status=exchange_status),dict(dispatch=state['completion_dispatch'],calls=calls))
 # Command token mismatch in completion does not invoke completion children.
 setup();u.mem_write(L+0x210,struct.pack('<H',0x8900))
 run(0x52eff43c,{UC_ARM_REG_R0:L+0x1d4,UC_ARM_REG_R1:0x0409001a,UC_ARM_REG_R2:0x89010000})
 assert [x[0] for x in state['calls']]==['0x530fced4']
 record('completion-descriptor-command-mismatch',{},[c[0] for c in state['calls']])
 return dict(passed=True,image_sha256=SHA,cases=len(cases),groups={g:sum(x['group']==g for x in cases) for g in sorted({x['group'] for x in cases})},scope=__doc__,cpu_model='Unicorn Cortex-A15; not camera fidelity',stubs={hex(a):s for a,s in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=cases)

if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 if a.output.exists():raise FileExistsError('report exists')
 result=run_checks(load(a.input))
 with a.output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
 print({k:result[k] for k in ['passed','cases','groups']})
