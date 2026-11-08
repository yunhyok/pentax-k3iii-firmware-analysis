"""Original ARM event-to-list-focus checks with synthetic objects/geometry.
No device or GUI execution. Cortex-A15 emulation is not camera fidelity.
Geometry copy/height/position functions, scan, focus setter and animation setup
execute original bytes. Render invalidation, scheduler, clock and supplied callback
targets are explicit stubs. Item eligibility+178 is not labelled visibility+8a.
"""
if not __debug__:
 raise RuntimeError('Verification requires assertions; run without -O or PYTHONOPTIMIZE')
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RANGES=[(0x5278ef84,0x5278f10c),(0x5278d9b0,0x5278dac0),(0x5277620c,0x52776214),
 (0x52c0e948,0x52c0ec04),(0x52c0e25c,0x52c0e394),(0x52c0e838,0x52c0e948),(0x52c0e528,0x52c0e5b8),
 (0x52c0dacc,0x52c0db88),(0x52c0dbb8,0x52c0dbc4),(0x52c0dd14,0x52c0ddbc),(0x52c0ddec,0x52c0de4c),
 (0x52c0dc54,0x52c0dc84),(0x52c0e1c0,0x52c0e25c),(0x52c01cbc,0x52c01cd4),
 (0x530fa244,0x530fa24c),(0x530fa798,0x530fa7a0),(0x530fa05c,0x530fa084),(0x530fa774,0x530fa778),(0x530f9ddc,0x530f9de0),(0x52c0205c,0x52c0206c),
 (0x5278dcd0,0x5278dd54),(0x5278b7b0,0x5278b830),(0x52c0dfcc,0x52c0e0ac),(0x5278ec04,0x5278ecdc)]
M,L,ARRAY,VT,EV,F=0x10000000,0x10001000,0x10002000,0x10003000,0x10004000,0x10005000
ITEMS=[0x10010000+i*0x1000 for i in range(8)]
STOP=0x30000000;ENTER=STOP+0x100;LEAVE=STOP+0x120;NOTIFY=STOP+0x140;SP=0x20008000
STUBS={0x52c0201c:'render invalidation boundary: records only, no drawing',0x528c4fcc:'returns synthetic factory',0x528c53e0:'returns synthetic animation service',0x528f8228:'animation registration records only; no ticks',0x528f818c:'animation removal records only',0x530f2fa8:'clock captures only and writes synthetic zero timestamp',0x530fdfc4:'assertion requires true then returns',ENTER:'supplied item vslot6c callback records focus',LEAVE:'supplied item vslot70 callback records focus',NOTIFY:'supplied list+220 function records focus; no menu mutation',0x530f25f4:'synthetic allocation only for original callback installation',0x530f2630:'synthetic free records only',0x5278e4ac:'color row presentation-update boundary records current focus only'}
sha=lambda b:hashlib.sha256(b).hexdigest();p32=lambda v:struct.pack('<I',v&0xffffffff)
def load(path):
 b=path.read_bytes()
 if sha(b)==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized firmware SHA-256')
 return b
def run_checks(b):
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15);n=(len(b)+4095)&~4095
 u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 u.mem_map(M,0x20000);u.mem_map(0x20000000,0x10000);u.mem_map(STOP,0x1000)
 state={};cases=[];trace=[];stops=set()
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def half(a):return int.from_bytes(u.mem_read(a,2),'little')
 def wh(a,v):u.mem_write(a,struct.pack('<H',v&0xffff))
 def wr(a,v):u.mem_write(a,p32(v))
 def mem_hook(uc,access,a,size,value,user):
  if a==L+0x1ce:state['writes'].append(value);trace.append(['focus-write',value])
 def hook(uc,a,size,user):
  if a==STOP or a in stops:uc.emu_stop();return
  if a==0x5278ecd0:state['real_menu_callbacks']+=1
  if a in (0x52c0e948,0x52c0e25c,0x52c0e838):state['entries'].append(hex(a))
  if a in STUBS:
   regs=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];r0,r1,r2,r3=regs;ret=0
   state['calls'].append([hex(a),regs]);trace.append([hex(a),r0,r1,half(L+0x1ce)])
   if a in (0x528c4fcc,0x528c53e0):ret=F
   elif a==0x530f2fa8:uc.mem_write(r0,bytes(8));ret=r0
   elif a==0x530fdfc4:assert r0!=0,'unexpected false assertion'
   elif a==0x530f25f4:assert r0==4;ret=state['heap'];state['heap']+=0x100
   elif a==0x5278e4ac:assert r0==M;state['presentation_focus'].append(half(L+0x1ce))
   elif a in (0x528f8228,0x528f818c):assert r0==F and r1==L+0x11c
   elif a==NOTIFY:assert r0==L+0x214 and r1==half(L+0x1ce)
   uc.reg_write(UC_ARM_REG_R0,ret);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),'unexpected execution '+hex(a)
 u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_WRITE,mem_hook)
 def setup(current,count=2,eligible=None,visible=None,disabled=None,enter=1,notify=0,custom=True):
  u.mem_write(M,bytes(0x20000));wr(M+4,0x0200009f);wr(M+0x1c8,L);wh(M+0x1d4,72)
  wr(L+0x1b8,ARRAY);wr(L+0x1bc,ARRAY+4*count);wh(L+0x1cc,count);wh(L+0x1ce,current)
  wr(L+0x2c,120);wr(L+0x23c,count*60);wr(L+0x1d8,current*60);wr(L+0x240,60)
  u.mem_write(L+0x1d0,bytes([enter]));u.mem_write(L+0x224,bytes([notify]));wr(L+0x21c,1);wr(L+0x220,NOTIFY)
  wr(VT+0x6c,ENTER);wr(VT+0x70,LEAVE)
  for i in range(count):
   item=ITEMS[i];wr(ARRAY+4*i,item);wr(item,VT if custom else 0x53872b08);wr(item+0x2c,60)
   u.mem_write(item+0x178,bytes([(eligible or [1]*count)[i]]));u.mem_write(item+0x8a,bytes([(visible or [1]*count)[i]]));u.mem_write(item+0x17a,bytes([(disabled or [0]*count)[i]]))
  state.clear();state.update(calls=[],writes=[],entries=[],heap=0x10018000,real_menu_callbacks=0,presentation_focus=[]);trace.clear()
 def run(start,r0=L,r1=0,r2=0,stop=()):
  stops.clear();stops.update(stop)
  for r in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(r,0)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,SP);u.reg_write(UC_ARM_REG_LR,STOP)
  for r,v in [(UC_ARM_REG_R0,r0),(UC_ARM_REG_R1,r1),(UC_ARM_REG_R2,r2)]:u.reg_write(r,v&0xffffffff)
  u.emu_start(start,STOP+4,count=100000);assert u.reg_read(UC_ARM_REG_PC)==STOP or u.reg_read(UC_ARM_REG_PC) in stops
 def record(group,inputs):
  out=dict(focus=half(L+0x1ce),motion_state=u.mem_read(L+0x1dc,1)[0],writes=state['writes'],entries=state['entries'],calls=[c[0] for c in state['calls']],trace=trace,real_menu_callbacks=state['real_menu_callbacks'],presentation_focus=state['presentation_focus'])
  cases.append(dict(group=group,inputs=inputs,result_sha256=sha(json.dumps(out,sort_keys=True).encode()),focus=out['focus'],motion_state=out['motion_state'],focus_write_count=len(state['writes'])))
 # Actual menu event -> direction wrapper -> original list scanner/transition/setter.
 for event,delta,noedge in [(0xdf,-1,False),(0xe3,-1,True),(0xe0,1,False),(0xe4,1,True)]:
  for current in (0,1):
   setup(current);wh(EV,event);run(0x5278ef84,r0=M,r1=EV)
   blocked=noedge and ((delta<0 and current==0) or (delta>0 and current==1));expected=current if blocked else (current+delta)%2
   assert half(L+0x1ce)==expected
   assert len(state['writes'])==int(not blocked)
   calls=[c[0] for c in state['calls']]
   if blocked:assert '0x52c0e948' not in state['entries']
   else:
    assert trace.index(['focus-write',expected])>next(i for i,t in enumerate(trace) if t[0]==hex(LEAVE))
    assert next(t for t in trace if t[0]==hex(LEAVE))[3]==current
    assert next(t for t in trace if t[0]==hex(ENTER))[3]==expected
   wrapped=not blocked and ((delta<0 and current==0) or (delta>0 and current==1))
   assert ('0x528f8228' in calls)==(not blocked and not wrapped)
   record('full-menu-direction-events',dict(event=hex(event),current=current,delta=delta,edge_suppressed=blocked))
 # More rows exercise original geometry and signed traversal in both directions.
 for current in range(4):
  for delta in (-1,1):
   for animate in (0,1):
    setup(current,count=4);run(0x52c0e948,r1=delta,r2=animate);expected=(current+delta)%4
    assert half(L+0x1ce)==expected
    record('full-list-step-four-rows',dict(current=current,delta=delta,animate=animate))
 # Eligibility+178 determines the scan; zero entries are skipped, current remains
 # if it is the only eligible entry. All-zero lists are outside this valid setup.
 for current,delta,flags,expected in [(0,1,[1,0,1,1],2),(2,-1,[1,0,1,1],0),(0,-1,[1,1,0,0],1),(3,1,[0,1,0,1],1),(1,1,[0,1,0,0],1),(1,-1,[0,1,0,0],1)]:
  for animate in (0,1):
   setup(current,count=4,eligible=flags);run(0x52c0e948,r1=delta,r2=animate);assert half(L+0x1ce)==expected
   record('full-list-eligibility-scan',dict(current=current,delta=delta,animate=animate,eligibility=flags))
 # Retained synthetic rows: changing+8a or+17a does not replace+178 eligibility.
 # This does not assert hidden-row membership in an actual rebuilt UI list.
 for field in ('visibility8a','confirm_block17a'):
  for delta,current in [(1,0),(-1,1)]:
   target=1-current;v=[1,1];d=[0,0]
   if field=='visibility8a':v[target]=0
   else:d[target]=1
   setup(current,visible=v,disabled=d);run(0x52c0e948,r1=delta,r2=0);assert half(L+0x1ce)==target
   record('retained-row-independent-flags',dict(field=field,current=current,delta=delta))
 # Focus setter directly: denied candidate, unchanged index, callback gating,
 # default base vslots, and optional function-object notification.
 for label,current,target,eligible,enter,notify,custom in [
  ('ineligible-target',0,1,[1,0],1,0,True),('same-target',0,0,[1,1],1,0,True),
  ('enter-disabled',0,1,[1,1],0,0,True),('enter-and-notify',0,1,[1,1],1,1,True),
  ('base-vtable-noop',1,0,[1,1],1,0,False)]:
  setup(current,eligible=eligible,enter=enter,notify=notify,custom=custom);run(0x52c0e25c,r1=target)
  expected=target if eligible[target] else current;assert half(L+0x1ce)==expected
  calls=[c[0] for c in state['calls']];changed=eligible[target] and current!=target
  assert (hex(LEAVE) in calls)==bool(changed and custom)
  assert (hex(ENTER) in calls)==bool(changed and custom and enter)
  assert (hex(NOTIFY) in calls)==bool(changed and notify)
  record('full-focus-setter',dict(case=label,current=current,target=target,eligibility=eligible,enter_enabled=enter,notify_enabled=notify,custom_callbacks=custom))
 # A second event reaching list_step clears pending state2 before moving.
 # No asynchronous animation ticks are delivered.
 scheduler=['0x528f8228','0x528f818c']
 setup(0);wh(EV,0xe0);run(0x5278ef84,r0=M,r1=EV);assert half(L+0x1ce)==1 and u.mem_read(L+0x1dc,1)==b'\x02'
 run(0x5278ef84,r0=M,r1=EV);assert half(L+0x1ce)==0 and u.mem_read(L+0x1dc,1)==b'\x00'
 assert [a for a,_ in state['calls'] if a in scheduler]==scheduler
 record('two-events-with-pending-state2',dict(events=['0xe0','0xe0'],initial=0))
 # Edge suppression returns in the direction wrapper, before list_step.
 for initial,first,edge,target in [(0,0xe0,0xe4,1),(1,0xdf,0xe3,0)]:
  setup(initial);wh(EV,first);run(0x5278ef84,r0=M,r1=EV)
  assert half(L+0x1ce)==target and u.mem_read(L+0x1dc,1)==b'\x02'
  entry_count=len(state['entries'])
  wh(EV,edge);run(0x5278ef84,r0=M,r1=EV)
  assert half(L+0x1ce)==target and u.mem_read(L+0x1dc,1)==b'\x02'
  assert len(state['entries'])==entry_count and state['writes']==[target]
  assert [a for a,_ in state['calls'] if a in scheduler]==[scheduler[0]]
  record('edge-events-retain-pending-state2',dict(events=[hex(first),hex(edge)],initial=initial))
 # Original first registration block, not the complete three-action binder.
 # Its actual function-object manager copies the menu pointer and actual installer
 # writes +214/+21c/+220/+224. Next event invokes the real menu callback/thunk.
 for current,event,target in [(0,0xe0,1),(1,0xdf,0)]:
  setup(current);wr(L+0x21c,0);wr(L+0x220,0)
  run(0x5278dcd0,r0=M,stop=[0x5278dd54])
  assert rd(rd(L+0x214))==M and rd(L+0x21c)==0x5278b7b0 and rd(L+0x220)==0x5278ecd0 and u.mem_read(L+0x224,1)==b'\x01'
  wh(EV,event);run(0x5278ef84,r0=M,r1=EV)
  assert half(L+0x1ce)==target and state['real_menu_callbacks']==1 and state['presentation_focus']==[target]
  assert hex(NOTIFY) not in [c[0] for c in state['calls']]
  record('original-install-fragment-to-real-menu-focus-callback',dict(current=current,event=hex(event),target=target))
 return dict(passed=True,image_sha256=SHA,cases=len(cases),groups={g:sum(c['group']==g for c in cases) for g in sorted({x['group'] for x in cases})},scope=__doc__,cpu_model='Unicorn Cortex-A15; not camera fidelity',stubs={hex(a):s for a,s in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=cases)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 if a.output.exists():raise FileExistsError('report exists')
 r=run_checks(load(a.input))
 with a.output.open('x',encoding='utf-8') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ['passed','cases','groups']})
