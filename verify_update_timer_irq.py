"""Original ARM timer deadline drain, CPU0 descriptor producer and deferred alarm route.
Synthetic RAM only; no privileged IRQ/SVC, physical MMIO, OS or time runs. Handler
executes only selected queue slices after its earlier gates. Deferred drain begins
after MPIDR read/prologue with authored CPU index and stops before epilogue. Callback
delivery is explicitly sequenced by the fixture, not actual scheduler/IRQ delivery.
"""
if not __debug__:raise RuntimeError('Assertions required; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
S=0x20000000;STOP=0x30000000;CB=STOP+0x100;USER=STOP+0x200;HEAD=0x5457ec00;NOW=0x54c40e50;Q=0x54c405e8;DESC=0x54c40e70;OBJ=S+0x4000
RANGES=[(0x525d9e94,0x525d9f10),(0x525b5b4c,0x525b5be0),(0x525ce770,0x525ce7bc),(0x525b819c,0x525b81f4),(0x525b831c,0x525b8328),(0x525cdfa0,0x525ce050),(0x525ce7bc,0x525ce80c),(0x525ce814,0x525ce87c),(0x525cde48,0x525cdeb0)]
STUBS={0x525da92c:'standard memset for descriptor CPU0 prefix only',0x525b6144:'IRQ mask returns authored token; no CPSR/IRQ operation',0x525b6154:'IRQ restore boundary only; no IRQ operation',0x525b7a20:'lock acquire boundary only; no OS',0x525b7aa4:'lock release boundary only; no OS',CB:'authored due callback, verifies unlink before invocation; optional authored NOW mutation',USER:'authored application callback verifies deferred unlink/flags; optional generation mutation'}
sha=lambda b:hashlib.sha256(b).hexdigest();p32=lambda v:struct.pack('<I',v&0xffffffff)
def load(p):
 b=p.read_bytes()
 if sha(b)==DSHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 if sha(b)!=SHA:raise ValueError('unrecognized RTOS SHA-256')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 for a,n in [(S,0x10000),(STOP,0x1000),(0x5457e000,0x1000),(0x54c30000,0x12000),(0x547d2000,0x1000)]:u.mem_map(a,n)
 st={};trace=set();rows=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,p32(v))
 def qb(a):return int.from_bytes(u.mem_read(a,8),'little')
 def qw(a,v):u.mem_write(a,struct.pack('<Q',v&0xffffffffffffffff))
 def links_valid(head):
  cur=head;seen=set()
  while True:
   nxt=rd(cur);assert rd(nxt+4)==cur
   if nxt==head:return
   assert nxt not in seen;seen.add(nxt);cur=nxt
 def hook(uc,a,n,data):
  if a in st['stops']:st['stop']=a;uc.emu_stop();return
  if a==0x525b81c0:
   node=uc.reg_read(UC_ARM_REG_R12);delta=(qb(node+8)-qb(NOW))&0xffffffffffffffff
   signed=delta if delta<2**63 else delta-2**64;cpsr=uc.reg_read(UC_ARM_REG_CPSR);ge=((cpsr>>31)&1)==((cpsr>>28)&1)
   assert ge==(signed>=1);st['comparisons'].append(dict(delta=delta,signed_delta=signed,bge=ge))
  if a in STUBS:
   r0=uc.reg_read(UC_ARM_REG_R0);st['calls'].append([hex(a),r0])
   if a==0x525da92c:
    assert r0==DESC and uc.reg_read(UC_ARM_REG_R1)==0 and uc.reg_read(UC_ARM_REG_R2)==0x30
    uc.mem_write(r0,b'\0'*0x30)
   elif a==0x525b6144:uc.reg_write(UC_ARM_REG_R0,0x93)
   elif a==CB:
    assert rd(HEAD)!=r0;links_valid(HEAD);st['callbacks'].append(r0)
    if st['advance_now'] is not None:qw(NOW,st['advance_now'])
   elif a==USER:
    assert r0==0x12345678 and rd(OBJ+0xc)&3==2
    h=Q+st['cpu']*12+4;assert rd(h)!=OBJ+0x10;links_valid(h);st['user_callbacks']+=1
    if st['generation_change']:wr(OBJ+0x38,rd(OBJ+0x38)+1)
   uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),hex(a);trace.add(a)
 u.hook_add(UC_HOOK_CODE,hook)
 def reset():
  u.mem_write(S,b'\0'*0x10000);u.mem_write(0x54c30000,b'\0'*0x12000);u.mem_write(0x5457e000,b'\0'*0x1000)
  wr(HEAD,HEAD);wr(HEAD+4,HEAD);st.clear();st.update(stops=set(),stop=None,calls=[],callbacks=[],comparisons=[],advance_now=None,cpu=0,user_callbacks=0,generation_change=False)
 def run(entry,args=(),stops=(STOP,),regs=None):
  for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]:u.reg_write(r,0)
  for r,v in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3],args):u.reg_write(r,v)
  for r,v in (regs or {}).items():u.reg_write(r,v)
  st['stops']=set(stops);st['stop']=None;u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,S+0x9000);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(entry,0xffffffff,count=10000);assert st['stop'] in st['stops'];return u.reg_read(UC_ARM_REG_R0)
 def add(group,inputs,out):rows.append(dict(group=group,inputs=inputs,observed=out,result_sha256=sha(json.dumps(dict(out=out,calls=st['calls'],comparisons=st['comparisons']),sort_keys=True).encode())))
 def chain(nodes):
  alln=[HEAD]+[n for n,d,c in nodes]
  for i,n in enumerate(alln):wr(n,alln[(i+1)%len(alln)]);wr(n+4,alln[(i-1)%len(alln)])
  for n,d,c in nodes:qw(n+8,d);wr(n+0x10,c);wr(n+0x14,n)
 def drain():run(0x525b819c,stops=(0x525b81f4,),regs={UC_ARM_REG_R5:NOW})
 reset();wr(0x547d2cc0,0x1234567);run(0x525d9e94,stops=(0x525d9f10,))
 expected={0:0x525b5bf0,4:0x525b5c34,8:0x525b5c48,12:0x525b5c4c,0x14:0x525b5214,0x18:0x1d002000,0x1c:0x1d001000,0x20:0x83,0x24:0x140,0x28:0x576871e7,0x2c:0x57c52c80}
 assert all(rd(DESC+k)==v for k,v in expected.items()) and rd(DESC+0x10)==0
 for addr,off in [(0x54c40ea4,0x18),(0x54c40eac,0x1c),(0x54c40ea0,0x20),(0x54c40ea8,0x24),(0x54c40e68,0x28),(0x54c40e5c,0x2c)]:assert rd(addr)==expected[off]
 add('cpu0-descriptor-producer',dict(entry='0x525d9e94',assumed_prior_cpu0_branch=True,memset_value_r1=0),dict(callbacks_match=True,alias_copies_match=True))
 reset();u.mem_write(Q,b'\xa5'*48);run(0x525ce770)
 for cpu in range(4):
  q=Q+12*cpu;assert bytes(u.mem_read(q,4))==b'\xa4\xa5\xa5\xa5' and rd(q+4)==rd(q+8)==q+4
 add('deferred-queues-initialize',dict(authored_fill=0xa5),dict(entries=4,low_two_bits_cleared=True,other_bytes_preserved=True))
 cases=[('empty',0,[],[],None),('future1',0,[(1,CB)],[],None),('equal',5,[(5,CB)],[0],None),('past1',5,[(4,CB)],[0],None),('signed-max',0,[(2**63-1,CB)],[],None),('signed-min',0,[(2**63,CB)],[0],None),('wrap-future',2**64-1,[(0,CB)],[],None),('wrap-past',0,[(2**64-1,CB)],[0],None),('two-due-one-future',10,[(9,CB),(10,CB),(11,CB)],[0,1],None),('null-callback',10,[(9,0),(10,CB)],[1],None),('future-head-blocks-tail',10,[(11,CB),(9,CB)],[],None),('callback-advances-now',0,[(0,CB),(5,CB)],[0,1],10)]
 for name,now,values,indices,advance in cases:
  reset();qw(NOW,now);nodes=[(S+0x2000+0x100*i,d,c) for i,(d,c) in enumerate(values)];chain(nodes);st['advance_now']=advance;drain()
  assert st['callbacks']==[nodes[i][0] for i in indices];links_valid(HEAD)
  remaining=[];p=rd(HEAD)
  while p!=HEAD:remaining.append((p-S-0x2000)//0x100);p=rd(p)
  expected_remaining={'future1':[0],'signed-max':[0],'wrap-future':[0],'two-due-one-future':[2],'future-head-blocks-tail':[0,1]}.get(name,[])
  assert remaining==expected_remaining
  add('deadline-drain',dict(label=name,now=now,deadlines=[d for d,c in values],callback_null=[c==0 for d,c in values],authored_now_change=advance),dict(callback_indices=indices,remaining_indices=remaining,comparisons=st['comparisons']))
 for mask,cpu,change in [(0,0,False),(1,0,False),(4,2,False),(8,3,True)]:
  reset();run(0x525ce770);qw(NOW,10);wr(OBJ,0x12345678);wr(OBJ+4,0x20000);wr(OBJ+8,USER);wr(OBJ+0xc,0x81);wr(OBJ+0x34,mask);wr(OBJ+0x38,11)
  chain([(OBJ+0x10,10,0x525cdfa0)]);wr(OBJ+0x24,OBJ);st['cpu']=cpu;st['generation_change']=change;drain()
  h=Q+cpu*12+4;assert rd(HEAD)==HEAD and rd(h)==rd(h+4)==OBJ+0x10 and rd(OBJ+0x20)==0x525cde48 and rd(OBJ+0x24)==OBJ and u.mem_read(Q+cpu*12,1)==b'\x01'
  bits=run(0x525ce7bc);assert bits==1<<cpu and u.mem_read(Q+cpu*12,1)==b'\x02'
  run(0x525ce814,stops=(0x525ce87c,),regs={UC_ARM_REG_R7:cpu});assert rd(h)==rd(h+4)==h and st['user_callbacks']==1 and u.mem_read(Q+cpu*12,1)==b'\0'
  assert [a for a,v in st['calls']]==[hex(a) for a in [0x525b7aa4,0x525b6154,USER,0x525b6144,0x525b7a20]] and st['calls'][1][1]==0
  assert rd(OBJ+0xc)==(0x82 if change else 0x80)
  add('alarm-route-mark-deferred-drain',dict(flag4=0x20000,mask34=mask,authored_cpu=cpu,generation_changed_by_stub=change),dict(mark_mask=bits,user_callback_count=1,final_flags=rd(OBJ+0xc),deadline_queue_empty=True,deferred_queue_empty=True))
 reset();run(0x525ce770)
 for cpu,v in enumerate([1,3,0,2]):u.mem_write(Q+cpu*12,bytes([v]))
 result=run(0x525ce7bc);assert result==1 and [u.mem_read(Q+i*12,1)[0] for i in range(4)]==[2,2,0,2]
 add('deferred-mark-flags',dict(flags=[1,3,0,2]),dict(mask=result,after=[2,2,0,2]))
 reset();run(0x525ce770);u.mem_write(Q+12+0,bytes([0xa6]));run(0x525ce814,stops=(0x525ce87c,),regs={UC_ARM_REG_R7:1});assert u.mem_read(Q+12,1)==b'\xa4' and st['user_callbacks']==0
 add('empty-deferred-drain',dict(authored_cpu=1,flags=0xa6),dict(flags_after=0xa4,callbacks=0))
 assert len(rows)==20
 return dict(passed=True,cases=len(rows),image_sha256=SHA,scope=__doc__,emulator='Unicorn Cortex-A15; no target/IRQ/peripheral fidelity claim',stubs={hex(a):s for a,s in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],executed_addresses=[hex(a) for a in sorted(trace)],groups={g:sum(x['group']==g for x in rows) for g in sorted({x['group'] for x in rows})},results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups')})
