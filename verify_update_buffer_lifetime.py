"""Original ARM buffer ownership with synthetic decoder, allocation and OS release.
The input, decoder output and pool metadata occupy small mapped fixtures only.
No storage, device, decoder hardware, OS or real large allocations execute.
Assertions stop on false unless a case explicitly models a returning assertion;
that continuation does not establish the camera's fatal-error policy.
"""
if not __debug__:
 raise RuntimeError('Verification requires assertions; run without -O or PYTHONOPTIMIZE')
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
S,F,P,V,CPU,SUB7,SUB9,A,B,AVT,D=[0x10000000+0x1000*k for k in range(11)]
INPUT=0x6e501000;OUTPUT=0x6e503000;OLD=0x6e505000;STACK=0x20008000;STOP=0x30000000;ALLOC=STOP+0x100
RANGES=[(0x52fefb84,0x52fefd08),(0x52ff2dec,0x52ff2f1c),(0x52ff4b0c,0x52ff4b24),
 (0x52ff4c44,0x52ff5194),(0x52ff1a18,0x52ff1a44),(0x52ff0934,0x52ff094c),
 (0x52ff109c,0x52ff10b4),(0x52feec18,0x52feecf8),(0x52ff622c,0x52ff62fc),
 (0x530efb60,0x530efb8c),(0x530efee8,0x530f0080),(0x530ef2d4,0x530ef2dc)]
STUBS={ALLOC:'returns a mapped sentinel, records requested size/alignment; no allocation',
 0x53100d84:'returns synthetic cache object',0x53100d90:'cache operation captures pointer/size only',
 0x53100e00:'cache completion captures pointer/size only',0x53102ce8:'returns synthetic decoder context',
 0x530fa6b4:'supplies chosen decoder result/length and small authored output bytes; no hardware or codec execution',
 0x530fdfc4:'records assertion; false stops unless explicitly configured to return',
 0x530feb20:'records assertion; false stops unless explicitly configured to return',
 0x530fced4:'records diagnostic only',0x52ff0b50:'subcomponent validation returns synthetic zero',
 0x52ff1248:'subcomponent validation returns synthetic zero',0x530f1a68:'synthetic mutex result',
 0x530f1bbc:'records mutex release',0x530ef540:'captures pool debug removal only',
 0x525b75e0:'records pool handle/raw pointer, returns chosen OS release status',
 0x52ff31c4:'component5 reset boundary captured; singleton and resource-slot query not executed'}
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
 for a,n in [(S,0x10000),(0x6e500000,0x10000),(0x16000000,0x10000),(0x547ba000,0x1000),(0x20000000,0x10000),(STOP,4096)]:u.mem_map(a,n)
 state={};rows=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,p32(v))
 def regs():return [u.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
 def hook(uc,a,size,user):
  if a==STOP:uc.emu_stop();return
  if a in STUBS:
   r=regs();r0,r1,r2,r3=r;ret=0;state['calls'].append([hex(a),r])
   if a==ALLOC:
    assert r0==A and r1==state['length'] and r2==r3==0
    assert rd(S+0x48)==INPUT and rd(V+8)==INPUT
    state['coexisting_input_at_allocation']=True;ret=OUTPUT if state['alloc_ok'] else 0
   elif a in (0x530fdfc4,0x530feb20):
    state['assertions'].append([hex(a),r0])
    if not r0 and not state['return_assert']:
     state['stopped_assert']=True;uc.emu_stop();return
   elif a==0x53100d84:ret=D+0x100
   elif a==0x53102ce8:ret=D
   elif a==0x530fa6b4:
    assert r==[0x12345678,INPUT+0x80,OUTPUT,0x68]
    assert rd(S+0x48)==INPUT and rd(V+8)==INPUT
    state['decoder_input_live']=True
    uc.mem_write(OUTPUT,state['payload']);wr(rd(uc.reg_read(UC_ARM_REG_SP)),state['actual_length']);ret=state['decoder_ok']
   elif a==0x530f1a68:assert r0==F+0x80;ret=state['mutex']
   elif a==0x525b75e0:state['os_releases'].append([r0,r1]);ret=state['os_release_status']
   elif a==0x530ef540:state['debug_removals'].append(r)
   elif a==0x52ff31c4:assert r==[S+0xf00,0,0,0];state['component5_resets']+=1
   uc.reg_write(UC_ARM_REG_R0,ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),hex(a)
 u.hook_add(UC_HOOK_CODE,hook)
 def reset(payload=None,**kw):
  u.mem_write(S,bytes(0x10000));u.mem_write(0x6e500000,bytes(0x10000));u.mem_write(0x16000000,bytes(0x10000))
  if payload is None:payload=struct.pack('<4I',1,2,3,0xfffffffa)
  state.clear();state.update(calls=[],assertions=[],os_releases=[],debug_removals=[],component5_resets=0,
   stopped_assert=False,return_assert=False,coexisting_input_at_allocation=False,decoder_input_live=False,
   alloc_ok=1,decoder_ok=1,payload=payload,length=len(payload),actual_length=len(payload),mutex=1,os_release_status=0)
  state.update(kw)
  wr(S+0x10,F);wr(S+0x20,CPU);wr(S+0x24,SUB7);wr(S+0x28,SUB9);wr(S+0x2c,P);wr(S+0x30,S+0xf00)
  wr(S+0x34,0x233b);wr(S+0x3c,2);wr(S+0x40,0x45670000);wr(S+0x44,0x100);wr(S+0x48,INPUT)
  wr(P+0xc,V);wr(P+0x10,CPU);wr(P+0x14,SUB7);wr(P+0x18,SUB9);wr(P+0x24,OLD);wr(P+0x28,0x55)
  wr(V+4,A);wr(V+8,INPUT);wr(V+0xc,0x100);wr(V+0x10,OLD);wr(V+0x14,0x55);wr(V+0x18,0x233b);wr(V+0x1c,2);wr(V+0x24,INPUT+0xe8)
  wr(CPU+0x24,OLD);wr(CPU+0x28,0x55)
  wr(F+0x30,A);wr(F+0x34,B);wr(F+0x40,F+0x80)
  wr(A,AVT);wr(AVT+8,ALLOC);wr(AVT+0xc,0x530efee8);wr(AVT+0x18,0x530efb60)
  wr(A+0x14,0x1001);wr(A+0x1c,0x10000);wr(A+0x24,0x6e500000)
  wr(B,AVT);wr(B+0x14,0x1002);wr(B+0x1c,0x10000);wr(B+0x24,0x16000000)
  wr(0x547ba3c0,1);wr(D+0x1c,0x12345678)
  for ptr in (INPUT,OUTPUT,OLD,0x16001000):wr(ptr-8,ptr-0x28)
  wr(INPUT+0x30,0x233b);wr(INPUT+0x78,0x233b233b);wr(INPUT+0x7c,0xa55a5aa5)
  for off,val in [(0,0x233b233b),(4,0xa55a5aa5),(8,2),(0xc,0x68),(0x10,len(payload)),(0x14,0xffffffff)]:wr(INPUT+0xe8+off,val)
 def run(entry,args):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  for q,val in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(q,val)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(entry,STOP+4,count=100000)
  assert state['stopped_assert'] or u.reg_read(UC_ARM_REG_PC)==STOP
  return u.reg_read(UC_ARM_REG_R0)
 def record(group,inputs,ret):
  observed=dict(ret=ret,state_input=rd(S+0x48),state_kind=rd(S+0x3c),state_path=rd(S+0x40),state_length=rd(S+0x44),
   validator_input=rd(V+8),validator_output=rd(V+0x10),validator_length=rd(V+0x14),context_output=rd(P+0x24),cpu_output=rd(CPU+0x24),
   os_releases=state['os_releases'],stopped_assert=state['stopped_assert'],component5_resets=state['component5_resets'])
  serial={k:(v.hex() if isinstance(v,bytes) else v) for k,v in state.items()}
  rows.append(dict(group=group,inputs=inputs,observed=observed,result_sha256=sha(json.dumps(dict(observed=observed,state=serial),sort_keys=True).encode())))
 # Decode failures before publication free only the new allocation. Inner-sum
 # failure occurs after publication and does not release it in this function.
 for name,kw,ret,out,free in [
  ('balanced',{},1,OUTPUT,0),('decoder-failure',dict(decoder_ok=0),0,OLD,1),
  ('length-short',dict(actual_length=12),0,OLD,1),('length-long',dict(actual_length=20),0,OLD,1),
  ('checksum-failure',dict(payload=struct.pack('<4I',1,2,3,4)),0,OUTPUT,0),
  ('checksum-sentinel-zero',dict(payload=struct.pack('<4I',1,2,3,0)),1,OUTPUT,0),
  ('checksum-sentinel-ones',dict(payload=struct.pack('<4I',1,2,3,0xffffffff)),1,OUTPUT,0)]:
  reset(**kw);actual=run(0x52ff4f88,[V]);assert actual==ret and rd(V+0x10)==out
  assert len(state['os_releases'])==free and rd(S+0x48)==rd(V+8)==INPUT and state['decoder_input_live']
  if free:assert state['os_releases']==[[0x1001,OUTPUT-0x40]] and rd(OUTPUT-8)==0
  record('decoder-lifetime',dict(case=name),actual)
 reset(alloc_ok=0);ret=run(0x52ff4f88,[V]);assert state['stopped_assert'] and not state['decoder_input_live'] and rd(V+0x10)==OLD
 record('allocation-failure-assertion',{},ret)
 # Execute kind2 dispatch, header/type/outer validation, decode, inner checksum,
 # output getters and ordinary setters. Subcomponent validation is stubbed.
 payload=bytearray(32);struct.pack_into('<H',payload,8,7);struct.pack_into('<H',payload,24,9)
 for invalid in (None,'project','footer-type','missing-section7','inner-checksum'):
  p=bytearray(payload)
  if invalid=='missing-section7':struct.pack_into('<H',p,8,8)
  if invalid=='inner-checksum':struct.pack_into('<I',p,28,1)
  reset(payload=bytes(p))
  if invalid=='project':wr(INPUT+0x30,0)
  if invalid=='footer-type':wr(INPUT+0xf0,3)
  ret=run(0x52fefb84,[S]);assert ret==int(invalid is None)
  decoded=invalid not in ('project','footer-type')
  assert rd(S+0x48)==rd(V+8)==INPUT and rd(V+0x10)==(OUTPUT if decoded else OLD)
  handoff=decoded and invalid!='inner-checksum'
  assert rd(P+0x24)==rd(CPU+0x24)==(OUTPUT if handoff else OLD)
  assert not state['os_releases'];record('kind2-connected-validation',dict(invalid=invalid),ret)
 # Cleanup keeps earlier decoded aliases; component5 reset is an explicit boundary.
 for flag,ptr,mutex,os_status,return_assert in [
  (0,INPUT,1,0,False),(1,INPUT,1,0,False),(1,INPUT,0,0,False),
  (1,0,1,0,False),(0,0,0,0,False),(1,0x16001000,1,0,False),
  (1,INPUT,1,0xffff0001,False),(1,INPUT,1,0xffff0001,True),
  (1,S+0xe00,1,0,False),(1,S+0xe00,1,0,True)]:
  reset(mutex=mutex,os_release_status=os_status,return_assert=return_assert);wr(S+0x48,ptr)
  ret=run(0x52feec18,[S,flag]);invalid=ptr==S+0xe00
  stopped=bool(flag and ptr and mutex and (os_status or invalid) and not return_assert)
  cleaned=not stopped and not(flag and ptr and not mutex)
  assert state['stopped_assert']==stopped
  assert rd(S+0x48)==(0 if cleaned else ptr) and rd(S+0x3c)==(8 if cleaned else 2)
  assert state['component5_resets']==int(cleaned)
  assert rd(V+0x10)==rd(P+0x24)==rd(CPU+0x24)==OLD
  if not stopped:assert ret==int(cleaned)
  frees=int(bool(flag and ptr and mutex and not invalid));assert len(state['os_releases'])==frees
  if frees:assert state['os_releases']==[[0x1002 if ptr==0x16001000 else 0x1001,ptr-0x40]]
  record('input-cleanup',dict(flag=flag,pointer=hex(ptr),mutex=mutex,os_release_status=os_status,assertion_returns=return_assert),ret)
 for ptr,expected in [(0x6e4fffff,0),(0x6e500000,1),(0x6e50ffff,1),(0x6e510000,0),(0xffffffff,0)]:
  reset();ret=run(0x530efb60,[A,ptr]);assert ret==expected;record('pool-membership-end-exclusive',dict(pointer=hex(ptr)),ret)
 for ptr,expected in [(0x6e4fffff,0),(0x6e500000,1),(0x9fffffef,1),(0x9ffffff0,0),(0xa0000000,0)]:
  reset();wr(A+0x1c,0x31affff0);ret=run(0x530efb60,[A,ptr]);assert ret==expected
  record('configured-image1-membership',dict(pointer=hex(ptr),pool_size=0x31affff0),ret)
 return dict(passed=True,image_sha256=SHA,cases=len(rows),groups={g:sum(x['group']==g for x in rows) for g in sorted({x['group'] for x in rows})},scope=__doc__,
  stubs={hex(k):v for k,v in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
 if args.output.exists():raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups')})
