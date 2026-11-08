"""Original ARM bounded UI queue dispatch and conditional UserFwUpdateController handling.
No publisher-to-receiver transport is executed. Initialized singleton guards and a cached
controller are synthetic. OS locks/events, UI observers/rendering/configuration, scheduling,
cancel and the post-drain predicate are explicit stubs. No actual device or reboot action.
"""
if not __debug__: raise RuntimeError('Assertions required; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000; SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
S=0x10000000;CTRL=S;CTRL2=S+0x1000;REC=S+0x2000;QBUF=S+0x3000;OBS=S+0x4000;CB=S+0x5000;TIMER=S+0x6000;VT=S+0x7000
QUEUE=0x545a4698;REGISTRY=0x5459408c;MODEL=0x545acf48;STOP=0x30000000;OBSFN=STOP+4;CBFN=STOP+8
RANGES=[(0x528e8fa0,0x528e9170),(0x526dbdac,0x526dbddc),(0x526dbe14,0x526de3dc),
 (0x526d95c4,0x526d960c),(0x526d8ccc,0x526d8f44),(0x5274f010,0x5274f16c),(0x5274efd4,0x5274f010),(0x5274e834,0x5274e860),
 (0x5274e88c,0x5274e8cc),(0x528c4fcc,0x528c4ff8),(0x528c51a0,0x528c51cc),(0x528c6730,0x528c675c)]
STUBS={0x530ed1ac:'record wait, return chosen status; no OS',0x530ed0f4:'record clear; no OS',0x530f1a68:'record mutex lock, return chosen status; no OS',0x530f1bbc:'record unlock, return sentinel; no OS',0x530ed03c:'record post-drain flag2 wake only',0x526d8f44:'post-drain predicate returns chosen value; no UI traversal',
 0x528c66d0:'return synthetic observer',0x528c5080:'return synthetic observer',0x528c5b08:'return synthetic observer',0x528c5020:'return synthetic observer',0x528c5920:'return synthetic observer',OBSFN:'capture observer work only',CBFN:'capture callback, optionally change cached controller pointer',
 0x5274ef44:'record refresh boundary; no UI rendering',0x526d9870:'initialize synthetic 28-byte settings output',0x526d9804:'capture settings byte+2 only',0x528c52c0:'return synthetic service',0x528eb490:'capture prior handle cancel boundary',0x528eb758:'capture args1000/controller+188 and return synthetic handle',0x5274e860:'capture follow-up work producer boundary, no enqueue',0x532fb9c8:'unexpected stack guard failure'}
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
 for a,n in [(S,0x10000),(0x54580000,0x40000),(0x20000000,0x10000),(STOP,4096)]:u.mem_map(a,n)
 st={};rows=[];trace=set()
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def rh(a):return int.from_bytes(u.mem_read(a,2),'little')
 def wr(a,v):u.mem_write(a,p32(v))
 def wh(a,v):u.mem_write(a,struct.pack('<H',v&65535))
 def hook(uc,a,size,user):
  if a==STOP:uc.emu_stop();return
  if a not in STUBS:
   assert any(x<=a<z for x,z in RANGES),hex(a)
   trace.add(a)
   if a in (0x528e8ff0,0x526d8f0c):st['dispatch_sites'].append([hex(a),uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1)])
   return
  r=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];r0,r1,r2,r3=r;ret=0
  st['calls'].append([hex(a),r])
  if a in (0x530ed1ac,0x530ed0f4):assert (r0,r1)==(QUEUE+12,1);ret=st['os_status']
  elif a==0x530f1a68:assert r0 in (QUEUE+0x28,QUEUE+0x3c);ret=st['os_status']
  elif a==0x530f1bbc:assert r0 in (QUEUE+0x28,QUEUE+0x3c);ret=0x66
  elif a==0x530ed03c:assert (r0,r1)==(QUEUE+12,2);ret=0x55
  elif a==0x526d8f44:assert r0 in (CTRL,CTRL2);ret=st['post']
  elif a in (0x528c66d0,0x528c5080,0x528c5b08,0x528c5020,0x528c5920):ret=OBS
  elif a==OBSFN:assert r0==OBS;st['observer_ids'].append(rh(r1))
  elif a==CBFN:
   assert r0==CB;st['callbacks'].append([r1,r2]);ret=0xffffffff
   if st['switch']:wr(REGISTRY+0x54,CTRL2)
  elif a==0x5274ef44:assert r0 in (CTRL,CTRL2);st['refresh'].append(r0)
  elif a==0x526d9870:u.mem_write(r0,b'\xa5'*28)
  elif a==0x526d9804:st['setting_flags'].append(u.mem_read(r1+2,1)[0]);ret=0
  elif a==0x528c52c0:ret=TIMER
  elif a==0x528eb490:assert r0==TIMER;st['cancel'].append(r1)
  elif a==0x528eb758:
   assert r0==TIMER and r1==1000 and r2 in (CTRL+0x188,CTRL2+0x188)
   assert rd(r2-0x188+0x1a8)==0
   st['schedule'].append([r1,r2]);ret=st['new_handle']
  elif a==0x5274e860:st['followup']+=1
  else:raise AssertionError('stack guard changed')
  uc.reg_write(UC_ARM_REG_R0,ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook)
 def reset(model=3,old=0,new=0x76543210,ad=0,post=0,os_status=1,switch=False):
  u.mem_write(S,bytes(0x10000));u.mem_write(0x54580000,bytes(0x40000))
  for a in (0x54592da8,0x5459e484,0x5459fdf4,0x545a47e0):wr(a,1)
  wr(REGISTRY+0x54,CTRL);wr(QUEUE+4,0x0100000f);wr(QUEUE+0x18,QBUF);wh(QUEUE+0x1e,8);wh(QUEUE+0x24,7)
  for c in (CTRL,CTRL2):
   wr(c,0x53639f38);wr(c+4,0x0100000f);wr(c+0x1a8,old);u.mem_write(c+0x1ac,bytes([0,ad,1]))
  wr(MODEL+8,model);wr(OBS,VT);wr(VT+8,OBSFN);wr(CB,VT+0x100);wr(VT+0x100,CBFN)
  st.clear();st.update(calls=[],callbacks=[],observer_ids=[],dispatch_sites=[],refresh=[],setting_flags=[],cancel=[],schedule=[],followup=0,post=post,os_status=os_status,switch=switch,new_handle=new)
 def record(a,id=0x128,arg=0,callback=0):u.mem_write(a,struct.pack('<HHII',id,0xabcd,arg,callback))
 def run(a,args):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  for q,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(q,v&0xffffffff)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,0x20008000);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(a,0xffffffff,count=100000);assert u.reg_read(UC_ARM_REG_PC)==STOP
  return u.reg_read(UC_ARM_REG_R0)
 def add(group,inputs,out):rows.append(dict(group=group,inputs=inputs,observed=out,result_sha256=sha(json.dumps(dict(out=out,calls=st),sort_keys=True).encode())))
 for sid in (0,0x0100000f,0xffffffff):
  reset();u.mem_write(0x5458f264,b'\xa5'*0x48);run(0x526d9604,[CTRL,sid])
  assert rd(CTRL+4)==sid and rd(QUEUE+4)==sid and bytes(u.mem_read(0x5458f264,0x48))==bytes(0x48)
  add('state-id-publish',dict(id=hex(sid)),dict(queue_id=hex(rd(QUEUE+4)),cleared_bytes=0x48))
 reset();ret=run(0x528e8fa0,[QUEUE]);assert ret==CTRL
 add('cached-user-state-resolver',dict(id='0x0100000f'),dict(return_value=ret))
 for model,old,new,ad in [(2,0,7,0),(3,0,7,0),(3,0x1234,7,0),(3,0x1234,0,0),(4,0,7,0),(5,0,7,0),(5,0,7,1),(0xffffffff,0,7,0)]:
  reset(model,old,new,ad);record(REC);ret=run(0x528e8fc4,[QUEUE,REC]);assert ret==1
  assert st['setting_flags']==[0 if model==2 else 1] and st['refresh']==[CTRL]
  assert len(st['schedule'])==(model==3) and st['cancel']==([old] if model==3 and old else [])
  assert st['followup']==int(model==5 and ad!=0)
  assert rd(CTRL+0x1a8)==(new if model==3 else old)
  if model in (4,5):assert bytes(u.mem_read(CTRL+0x1ac,3))==bytes([1,1 if model==4 else ad,0])
  add('conditional-update-work',dict(model=model,old_handle=old,new_handle=new,prior_ad=ad),dict(return_value=ret,setting_flag=st['setting_flags'][0],schedule_count=len(st['schedule']),cancel_count=len(st['cancel']),followup_count=st['followup']))
 for id,cb in [(0x1bc,0),(0x1bc,CB),(0x128,CB),(0x129,CB)]:
  reset(model=2);record(REC,id,0xabcdef01,cb);ret=run(0x528e8fc4,[QUEUE,REC]);assert ret==1
  assert st['callbacks']==([[id,0xabcdef01]] if cb else [])
  assert bool(st['dispatch_sites'])==(id!=0x1bc)
  if id==0x1bc:assert not st['observer_ids'] and not st['refresh']
  add('dispatch-and-completion-callback',dict(id=id,has_callback=bool(cb)),dict(return_value=ret,state_dispatches=len(st['dispatch_sites']),callbacks=st['callbacks']))
 for head,count,post,os_status in [(0,0,0,1),(0,0,1,0),(0,1,0,1),(7,2,1,1),(6,3,0,0)]:
  reset(model=2,post=post,os_status=os_status);wh(QUEUE+0x20,head);wh(QUEUE+0x22,(head+count)&7);wh(QUEUE+0x1c,count)
  for k in range(count):record(QBUF+12*((head+k)&7),0x128,k,CB)
  before=bytes(u.mem_read(QBUF,96));ret=run(0x528e901c,[QUEUE]);assert ret==0x66 and rh(QUEUE+0x1c)==0 and rh(QUEUE+0x20)==(head+count)&7
  assert st['callbacks']==[[0x128,k] for k in range(count)] and len(st['refresh'])==count and bytes(u.mem_read(QBUF,96))==before
  assert sum(a=='0x530ed03c' for a,r in st['calls'])==bool(post)
  add('queue-drain-wrap-and-os-status',dict(head=head,count=count,post=post,os_status=os_status),dict(return_value=ret,read_index=rh(QUEUE+0x20),count=0,callbacks=len(st['callbacks']),source_records_preserved=True))
 reset(model=2,switch=True);wh(QUEUE+0x1c,2);wh(QUEUE+0x22,2);record(QBUF,callback=CB);record(QBUF+12,callback=CB)
 run(0x528e901c,[QUEUE]);assert st['refresh']==[CTRL,CTRL2]
 add('resolve-current-state-per-record',{},dict(controller_sequence=st['refresh']))
 reset(model=2);wh(QUEUE+0x1c,0);wh(QUEUE+0x22,1);record(QBUF)
 run(0x528e901c,[QUEUE]);assert rh(QUEUE+0x1c)==65535 and len(st['refresh'])==1
 add('inconsistent-count-is-not-drain-guard',dict(count=0,head=0,tail=1),dict(count_after=65535,processed=1))
 for old,received,ac,ae in [(9,8,1,0),(9,9,0,0),(9,9,1,0),(9,9,1,1),(0,0,1,0)]:
  reset(old=old);u.mem_write(CTRL+0x1ac,bytes([ac,0,ae]));run(0x5274e8c4,[CTRL+0x188,received])
  match=old==received
  assert rd(CTRL+0x1a8)==(0 if match else old) and u.mem_read(CTRL+0x1ad,1)[0]==int(match)
  assert st['followup']==int(match and ac!=0 and ae==0)
  add('callback-handle-and-flags',dict(old=old,received=received,ac=ac,ae=ae),dict(handle_after=rd(CTRL+0x1a8),ad=u.mem_read(CTRL+0x1ad,1)[0],followup_count=st['followup']))
 return dict(passed=True,cases=len(rows),image_sha256=SHA,scope=__doc__,emulator='Unicorn Cortex-A15 model; not camera CPU/peripheral fidelity',stubs={hex(a):v for a,v in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],executed_addresses=[hex(a) for a in sorted(trace)],groups={g:sum(x['group']==g for x in rows) for g in sorted({x['group'] for x in rows})},results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('output already exists')
 result=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,indent=2);f.write('\n')
 print({k:result[k] for k in ('passed','cases','groups')})
