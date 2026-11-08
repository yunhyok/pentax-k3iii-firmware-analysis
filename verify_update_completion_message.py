"""Original ARM update notification publishing, UI routing and bounded queue writes.
Publishing and receiving are separate probes: no claim of transport delivery.
Only initialized singleton fast paths execute. Locks/events/transport/assertions
are synthetic and no camera, OS queue, storage, allocator or update code executes.
"""
if not __debug__:raise RuntimeError('Verification requires assertions; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
S,NOTIFY,PIPE,TRANSPORT,MSG,QBUF,EVENT=[0x10000000+i*0x1000 for i in range(7)]
ROOT=0x545a0184;QUEUE=0x545a4698;INFO=0x545acf48;STOP=0x30000000
RANGES=[(0x52ff382c,0x52ff391c),(0x52ff3960,0x52ff399c),(0x5330b29c,0x5330b2a4),
 (0x528e761c,0x528e7980),(0x528e74b4,0x528e7590),(0x528e9b64,0x528e9b98),
 (0x52a64b3c,0x52a64e34),(0x528e8de4,0x528e8eb0),
 (0x528c4fcc,0x528c4ff8),(0x528c51a0,0x528c51cc),(0x528c6730,0x528c675c)]
STUBS={0x53309c10:'capture publishing envelope and return chosen transport status; NO delivery or OS call',
 0x53156fec:'capture completion event flag only',0x53156fa4:'capture final notification boundary and return sentinel',
 0x530f1a68:'record lock request and return selected status',0x530f1bbc:'record unlock only',
 0x530ed03c:'capture UI queue wake flag and return chosen status; no event API',
 0x530fdfc4:'false assertion stops unless explicit returning-assertion fixture',0x532fb9c8:'stack guard boundary must remain unreachable'}
sha=lambda b:hashlib.sha256(b).hexdigest();p32=lambda n:struct.pack('<I',n&0xffffffff)
def load(p):
 b=p.read_bytes()
 if sha(b)==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 if sha(b)!=SHA:raise ValueError('unrecognized RTOS SHA-256')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 for a,n in [(S,0x10000),(0x54590000,0x20000),(0x20000000,0x10000),(STOP,4096)]:u.mem_map(a,n)
 state={};rows=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,p32(v))
 def rh(a):return int.from_bytes(u.mem_read(a,2),'little')
 def wh(a,v):u.mem_write(a,struct.pack('<H',v&0xffff))
 def hook(uc,a,size,user):
  if a==STOP:uc.emu_stop();return
  if a not in STUBS:assert any(x<=a<z for x,z in RANGES),hex(a);return
  regs=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];r0,r1,r2,r3=regs;ret=0
  state['calls'].append([hex(a),regs])
  if a==0x53309c10:
   assert r0==TRANSPORT
   words=list(struct.unpack('<7I',uc.mem_read(r1,28)));assert words==[0x2640820b,0,0,0,0,0,0]
   state['published']=words;ret=state['transport_status']
  elif a==0x53156fec:assert (r0,r1)==(EVENT,0x20)
  elif a==0x53156fa4:assert r0==EVENT;ret=0x77
  elif a==0x530f1a68:assert r0==QUEUE+0x28;ret=state['lock_status']
  elif a==0x530f1bbc:assert r0==QUEUE+0x28
  elif a==0x530ed03c:assert (r0,r1)==(QUEUE+0xc,1);ret=state['wake_status']
  elif a==0x530fdfc4:
   assert r0==0;state['assertions']+=1
   if not state['return_assertion']:state['stopped_at_assertion']=True;uc.emu_stop();return
  else:raise AssertionError('stack guard unexpectedly changed')
  uc.reg_write(UC_ARM_REG_R0,ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook)
 def reset(count=0,tail=0,transport=1,lock=1,wake=1,return_assertion=False):
  u.mem_write(S,bytes(0x10000));u.mem_write(0x54590000,bytes(0x20000));u.mem_write(QBUF,b'\xa5'*96)
  wr(NOTIFY+4,PIPE);wr(NOTIFY+8,EVENT);wr(PIPE,TRANSPORT)
  for a in (0x5459e484,0x5459fdf4,0x545a47e0):wr(a,1)
  wr(QUEUE+0x18,QBUF);wh(QUEUE+0x1c,count);wh(QUEUE+0x1e,8);wh(QUEUE+0x22,tail);wh(QUEUE+0x24,7)
  wr(INFO+8,0xfeedface);wr(INFO+0xc,0x12345678);wr(MSG,0x2640820b)
  state.clear();state.update(calls=[],published=None,transport_status=transport,lock_status=lock,wake_status=wake,return_assertion=return_assertion,assertions=0,stopped_at_assertion=False)
 def run(a,args):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  for q,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(q,v&0xffffffff)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,0x20008000);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(a,STOP+4,count=100000)
  assert state['stopped_at_assertion'] or u.reg_read(UC_ARM_REG_PC)==STOP
  return u.reg_read(UC_ARM_REG_R0)
 def add(group,inputs,out):rows.append(dict(group=group,inputs=inputs,observed=out,result_sha256=sha(json.dumps(dict(out=out,state=state),sort_keys=True).encode())))
 for status in (0,1,0xffffffff):
  reset(transport=status);ret=run(0x52ff382c,[NOTIFY,0x2640820b,0]);assert ret==status and len(state['calls'])==1
  add('publish-envelope-transport-result',dict(transport=status),dict(return_value=ret,published=state['published']))
  reset(transport=status);ret=run(0x52ff3960,[NOTIFY]);assert ret==0x77
  assert [a for a,r in state['calls']]==['0x53309c10','0x53156fec','0x53156fa4']
  add('completion-notification-order',dict(transport=status),dict(return_value=ret,published=state['published']))
 for message,expected in [(0x2640820b,3),(0x2640820c,5),(0x2640820d,4),(0x2640820e,2)]:
  reset();wr(MSG,message);run(0x528e761c,[S,MSG])
  assert rd(INFO+8)==expected and rh(QUEUE+0x1c)==1 and rh(QUEUE+0x22)==1,(hex(message),rd(INFO+8),rh(QUEUE+0x1c),rh(QUEUE+0x22))
  assert rh(QBUF)==0x128 and rd(QBUF+4)==rd(QBUF+8)==0
  add('router-update-state-and-ui-work',dict(message=hex(message)),dict(state=rd(INFO+8),work_id=rh(QBUF),queue_count=rh(QUEUE+0x1c)))
 for count,tail,lock,wake in [(0,0,1,1),(6,7,1,1),(0,0,0,0)]:
  reset(count=count,tail=tail,lock=lock,wake=wake);ret=run(0x528e761c,[S,MSG])
  at=QBUF+12*tail;assert rd(INFO+8)==3 and rh(QUEUE+0x1c)==count+1 and rh(QUEUE+0x22)==(tail+1)&7
  assert rh(at)==0x128 and rd(at+4)==rd(at+8)==0 and ret==wake
  add('completion-queue-wrap-and-status',dict(count=count,tail=tail,lock=lock,wake=wake),dict(count=rh(QUEUE+0x1c),tail=rh(QUEUE+0x22),return_value=ret))
 for returning in (False,True):
  reset(count=7,tail=3,return_assertion=returning);before=bytes(u.mem_read(QBUF,96));run(0x528e761c,[S,MSG])
  assert state['assertions']==1 and rd(INFO+8)==3 and rh(QUEUE+0x1c)==7 and rh(QUEUE+0x22)==3 and bytes(u.mem_read(QBUF,96))==before
  calls=[a for a,r in state['calls']];assert ('0x530ed03c' in calls)==returning and ('0x530f1bbc' in calls)==returning
  add('completion-queue-full-assertion',dict(returning_assertion=returning),dict(state=rd(INFO+8),queue_unchanged=True,stopped=state['stopped_at_assertion']))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),groups={g:sum(r['group']==g for r in rows) for g in sorted({r['group'] for r in rows})},scope=__doc__,stubs={hex(a):s for a,s in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups')})
