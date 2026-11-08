"""Original ARM AppTimerModel scheduling/cancellation/poll and bounded event-task iteration.
Synthetic RAM only. OS timer syscalls, lock/event APIs and assertion/log function are
explicit stubs. A false assertion stops by default; separate cases allow it to return.
No physical delay, real event delivery, reboot or media action is demonstrated.
"""
if not __debug__:raise RuntimeError('Assertions required; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
S=0x10000000;VEC=S+0x1000;SLOT=S+0x2000;TIMER=S+0x3000;CB=S+0x4000;VT=S+0x5000;USER=S+0x6000;QBUF=S+0x7000
QUEUE=0x545a4698;STOP=0x30000000;CALLBACK=STOP+4
RANGES=[(0x528eb490,0x528eb500),(0x528eb6b4,0x528eb830),(0x528eb420,0x528eb490),(0x528c0f30,0x528c0f44),(0x528c0fe0,0x528c0fe8),(0x530eb960,0x530ebbc0),(0x530eb5d0,0x530eb5ec),(0x528e8de4,0x528e8eb0),(0x528e8fc4,0x528e901c),(0x528c4fcc,0x528c4ff8),(0x528c51a0,0x528c51cc),(0x5274e88c,0x5274e8cc)]
STUBS={0x525b7844:'timer start syscall: capture(handle,duration), chosen raw OS return',0x525b78b0:'timer stop syscall: capturehandle, chosen raw OS return',0x525b73c4:'timer status syscall: fill authored12byte output; chosen raw OS return',0x530feb20:'assert/log wrapper: recordcondition; false stops unless returning_assertion fixture',0x530ed03c:'record event set only',0x530ed1ac:'record wait; second entry stops event-task single-iteration fixture',0x530ed0f4:'record event clear only',0x530f1a68:'record lock, return1',0x530f1bbc:'record unlock, return1',0x530fdfc4:'unexpected queue assertion',0x532fb9c8:'unexpected canary failure',CALLBACK:'record cleared slot and savedID; optional authored slot/vector mutations',0x5274e860:'record UserFwUpdate follow-up boundary only'}
sha=lambda b:hashlib.sha256(b).hexdigest();p32=lambda x:struct.pack('<I',x&0xffffffff)
def load(p):
 b=p.read_bytes()
 if sha(b)==DSHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 if sha(b)!=SHA:raise ValueError('unrecognized RTOS SHA-256')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 for a,n in [(S,0x10000),(0x54590000,0x20000),(0x547ba000,0x1000),(0x20000000,0x10000),(STOP,0x1000)]:u.mem_map(a,n)
 st={};rows=[];trace=set()
 def wr(a,v):u.mem_write(a,p32(v))
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wh(a,v):u.mem_write(a,struct.pack('<H',v&65535))
 def rh(a):return int.from_bytes(u.mem_read(a,2),'little')
 def hook(uc,a,n,data):
  if a==STOP:uc.emu_stop();return
  if a not in STUBS:assert any(x<=a<z for x,z in RANGES),hex(a);trace.add(a);return
  r=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];r0,r1,r2,r3=r;ret=0
  st['calls'].append([hex(a),r])
  if a==0x530feb20:
   st['assert_conditions'].append(r0)
   if r0==0 and not st['return_assertion']:st['stop']='assert';uc.emu_stop();return
  elif a==0x525b7844:st['starts'].append([r0,r1]);ret=st['os_result']
  elif a==0x525b78b0:st['stops'].append(r0);ret=st['os_result']
  elif a==0x525b73c4:
   st['statuses'].append(r0);u.mem_write(r1,struct.pack('<III',0xa1,0xb2,st['status_word']));ret=st['os_result']
  elif a==0x530ed03c:st['events'].append([r0,r1]);ret=1
  elif a==0x530ed1ac:
   assert (r0,r1,r2)==(S+0x2c,1,0);st['waits']+=1
   if st['waits']==2:st['stop']='second-wait';uc.emu_stop();return
   ret=1
  elif a==0x530ed0f4:assert (r0,r1)==(S+0x2c,0xffffffff);ret=1
  elif a in (0x530f1a68,0x530f1bbc):assert r0==QUEUE+0x28;ret=1
  elif a==CALLBACK:
   assert r0==CB;st['callbacks'].append(r1)
   i=len(st['callbacks'])-1;at=SLOT+0x100*i
   assert rd(at+4)==rd(at+8)==0
   if st['mutate'] and i==0:
    wr(SLOT+4,0x99);wr(SLOT+8,CB);wr(S+0x40,VEC+8)
   ret=0xffffffff
  elif a==0x5274e860:st['followup']+=1
  else:raise AssertionError('unexpected assertion/canary')
  uc.reg_write(UC_ARM_REG_R0,ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook)
 def reset(counter=1,os_result=0,status_word=0,return_assertion=False,nslots=1):
  u.mem_write(S,bytes(0x10000));u.mem_write(0x54590000,bytes(0x20000));wr(0x547ba2ec,S+0x9000)
  wr(S,0x5368eec8);wr(S+0x24,0x5368eee4);wr(S+0x28,0x5368eef8);wr(S+0x3c,VEC);wr(S+0x40,VEC+4*nslots);wr(S+0x50,counter)
  for i in range(3):
   sl=SLOT+0x100*i;tm=TIMER+0x100*i;wr(VEC+4*i,sl);wr(sl,tm);wr(tm,0x5368e5b0);wr(tm+4,100+i);wr(tm+8,0);wr(tm+0x10,S+0x24)
  wr(CB,VT);wr(VT+8,CALLBACK);wr(USER+0x188,0x53639f84)
  for a in (0x5459e484,0x5459fdf4):wr(a,1)
  wr(QUEUE+0x18,QBUF);wh(QUEUE+0x1e,4);wh(QUEUE+0x24,3)
  st.clear();st.update(calls=[],assert_conditions=[],starts=[],stops=[],statuses=[],callbacks=[],events=[],waits=0,followup=0,stop=None,os_result=os_result,status_word=status_word,return_assertion=return_assertion,mutate=False)
 def active(i,id,cb=CB):wr(SLOT+0x100*i+4,id);wr(SLOT+0x100*i+8,cb)
 def run(a,args):
  st['stop']=None
  for r in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(r,0)
  for r,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(r,v&0xffffffff)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,0x20008000);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(a,0xffffffff,count=100000)
  assert st['stop'] or u.reg_read(UC_ARM_REG_PC)==STOP
  return u.reg_read(UC_ARM_REG_R0)
 def add(group,inputs,out):rows.append(dict(group=group,inputs=inputs,observed=out,result_sha256=sha(json.dumps(dict(state=st,out=out),sort_keys=True).encode())))
 for counter in (0,1,0xfffffffe,0xffffffff):
  reset(counter);ret=run(0x528eb758,[S,1000,CB]);want=1 if counter==0xffffffff else counter+1
  assert ret==rd(S+0x50)==rd(SLOT+4)==want and rd(SLOT+8)==CB and st['starts']==[[100,1000]]
  add('schedule-counter',dict(counter=counter),dict(handle=ret))
 for id,cb in [(0,CB),(7,0),(0,0)]:
  reset();active(0,id,cb);ret=run(0x528eb758,[S,0,CB]);assert ret==2 and st['starts']==[[100,0]]
  add('cached-slot-free-OR-condition',dict(prior_id=id,prior_callback=cb),dict(handle=ret))
 for raw,returning in [(1,False),(1,True),(0xffffffff,True)]:
  reset(os_result=raw,return_assertion=returning);ret=run(0x528eb758,[S,1000,CB]);assert rd(SLOT+4)==2 and rd(SLOT+8)==CB
  assert (st['stop']=='assert')== (not returning)
  if returning:assert ret==2
  add('schedule-OS-error-assertion',dict(raw=raw,assertion_returns=returning),dict(stopped=st['stop'],stored_handle=rd(SLOT+4),returned_handle=ret if returning else None))
 for ids,query,want in [([7],7,1),([7],8,0),([0],0,1),([7,7],7,1),([],7,0)]:
  reset(nslots=len(ids))
  for i,id in enumerate(ids):active(i,id)
  ret=run(0x528eb490,[S,query]);assert ret==want and len(st['stops'])==want
  if want:assert rd(SLOT+4)==rd(SLOT+8)==0
  if len(ids)==2:assert rd(SLOT+0x104)==7
  add('cancel-first-match-and-zero',dict(ids=ids,query=query),dict(return_value=ret,stops=st['stops']))
 for returning in (False,True):
  reset(os_result=1,return_assertion=returning);active(0,7);ret=run(0x528eb490,[S,7])
  assert rd(SLOT+4)==(0 if returning else 7) and rd(SLOT+8)==(0 if returning else CB)
  if returning:assert ret==1
  add('cancel-error-assertion-before-clear',dict(assertion_returns=returning),dict(stopped=st['stop'],id_after=rd(SLOT+4)))
 for raw,word,returning in [(0,0,False),(0,1,False),(0,2,False),(0,0xffffffff,False),(1,1,False),(1,1,True)]:
  reset(os_result=raw,status_word=word,return_assertion=returning);ret=run(0x530ebac8,[TIMER])
  if raw and not returning:assert st['stop']=='assert'
  else:assert ret==int(raw==0 and word==1)
  add('status-wrapper-result-and-error',dict(raw=raw,word=word,assertion_returns=returning),dict(stopped=st['stop'],return_value=ret if not st['stop'] else None))
 for id,cb,word in [(0,CB,0),(7,0,0),(0,0,0),(7,CB,1),(7,CB,0),(7,CB,2)]:
  reset(status_word=word);active(0,id,cb);run(0x528eb7a4,[S]);eligible=bool(id and cb);fired=eligible and word!=1
  assert len(st['statuses'])==eligible and len(st['callbacks'])==fired
  assert rd(SLOT+4)==(0 if fired else id) and rd(SLOT+8)==(0 if fired else cb)
  add('poll-gates-status-and-clear-before-callback',dict(id=id,callback=cb,word=word),dict(status_calls=len(st['statuses']),callbacks=st['callbacks']))
 for returning in (False,True):
  reset(os_result=1,status_word=1,return_assertion=returning);active(0,7);run(0x528eb7a4,[S]);assert st['callbacks']==([7] if returning else [])
  add('poll-error-only-fires-if-assertion-returns',dict(assertion_returns=returning),dict(callbacks=st['callbacks'],stopped=st['stop']))
 reset();active(0,7);active(1,8);st['mutate']=True;run(0x528eb7a4,[S]);assert st['callbacks']==[7,8] and rd(SLOT+4)==0x99 and rd(SLOT+8)==CB
 add('callback-authored-reuse-and-vector-end-growth',{},dict(callbacks=st['callbacks'],current_slot_new_id=rd(SLOT+4)))
 for saved,issued,ac,ae in [(7,7,0,0),(7,7,1,0),(8,7,1,0)]:
  reset();active(0,issued,USER+0x188);wr(USER+0x1a8,saved);u.mem_write(USER+0x1ac,bytes([ac,0,ae]));run(0x528eb7a4,[S])
  assert rd(SLOT+4)==rd(SLOT+8)==0 and rd(USER+0x1a8)==(0 if saved==issued else saved)
  assert u.mem_read(USER+0x1ad,1)[0]==int(saved==issued) and st['followup']==int(saved==issued and ac and not ae)
  add('actual-user-secondary-vtable-callback',dict(saved=saved,issued=issued,ac=ac,ae=ae),dict(saved_after=rd(USER+0x1a8),ad=u.mem_read(USER+0x1ad,1)[0],followup=st['followup']))
 for work in (0x1bb,0x1bc,0x1bd):
  reset();active(0,7);run(0x528eb828,[S+0x28,work,0]);assert st['callbacks']==([7] if work==0x1bc else [])
  add('work-receiver-filter',dict(work=work),dict(callbacks=st['callbacks']))
 reset();active(0,7,USER+0x188);wr(USER+0x1a8,7)
 run(0x530eb5d0,[TIMER]);assert st['events']==[[S+0x2c,1]]
 run(0x528eb420,[S]);assert st['stop']=='second-wait' and rh(QUEUE+0x1c)==1 and rh(QBUF)==0x1bc and rd(QBUF+4)==0 and rd(QBUF+8)==S+0x28
 run(0x528e8fc4,[QUEUE,QBUF]);assert rd(USER+0x1a8)==0 and u.mem_read(USER+0x1ad,1)[0]==1 and rd(SLOT+4)==rd(SLOT+8)==0
 add('explicitly-sequenced-signal-task-queue-dispatch-usercallback',{},dict(queue_work=rh(QBUF),record_callback=rd(QBUF+8),saved_handle=rd(USER+0x1a8),ad=1))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),scope=__doc__,emulator='Unicorn Cortex-A15 model; no camera/peripheral fidelity claim',stubs={hex(a):s for a,s in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],groups={g:sum(x['group']==g for x in rows) for g in sorted({x['group'] for x in rows})},executed_addresses=[hex(a) for a in sorted(trace)],results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups')})
