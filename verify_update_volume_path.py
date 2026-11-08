"""Original ARM volume registration and authored filename-to-volume CPU checks.
Factory runs from its real entry to 52f514f0, before backend construction.
Formatting, allocation, descriptor notifications and factory query helpers are
explicit stubs. No filesystem, mount, OS, hardware or device code executes.
"""
if not __debug__:raise RuntimeError('Verification requires assertions; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
FACT,VM,ARR,PROVIDER,DESC,VT,FS,TABLE,STATE,MODEL,TEXT=[0x10000000+k*0x1000 for k in range(11)]
STOP=0x30000000;NOTIFY=STOP+0x100;END=0x52f514f0
RANGES=[(0x52f510e8,END),(0x52f5177c,0x52f5178c),(0x52f52334,0x52f524b0),(0x52f524b8,0x52f52674),(0x52f5212c,0x52f521d8),
 (0x5327f710,0x5327f71c),(0x52ff32ac,0x52ff33bc),(0x5310b748,0x5310b75c),(0x5310b7f0,0x5310b804),
 (0x52ff3474,0x52ff3480),(0x52ff34d0,0x52ff34dc),(0x52fef240,0x52fef488),(0x52f4fd70,0x52f4fe18)]
STUBS={0x532980e8:'returns synthetic query object',0x530f25f4:'bounded mapped allocation sentinel for volume manager/default descriptor/counter',
0x530f2668:'array allocation captures requested bytes; mapped buffer only',0x52f13e70:'base constructor returns; derived code supplies tested fields',
0x5327f4e4:'default descriptor constructor boundary; fields unused by registered C/R routes',0x530fdfc4:'false assertion stops; success returns',
0x5327f6b0:'returns authored descriptor-provider object; actual indexed getter executes',0x52f51028:'factory per-volume query/config boundary',
0x52f5107c:'factory descriptor/config query boundary',NOTIFY:'descriptor vslot+c notification returns1',
0x526ac000:'bounded synthetic formatting; captures template, limit and numeric argument, no libc execution',
0x526ac9c0:'bounded strlen of mapped NUL fixture',0x52ff7d10:'captures selected path and returns chosen synthetic length; no stat/filesystem'}
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):
 b=p.read_bytes()
 if sha(b)==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 if sha(b)!=SHA:raise ValueError('unrecognized RTOS SHA-256')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 for a,n in [(FACT,0x20000),(0x20000000,0x10000),(STOP,4096),(0x54796000,0x1000),(0x547bb000,0x1000)]:u.mem_map(a,n)
 state={};rows=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
 def string(a):
  o=bytearray()
  for k in range(256):
   c=bytes(u.mem_read(a+k,1))
   if c==b'\0':return bytes(o)
   o+=c
  raise AssertionError('unterminated fixture')
 def hook(uc,a,size,user):
  if a in (STOP,END):uc.emu_stop();return
  if a not in STUBS:
   assert any(x<=a<z for x,z in RANGES),hex(a);return
  r=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];r0,r1,r2,r3=r;ret=1
  state['trace'].append([hex(a),r])
  if a==0x532980e8:ret=FACT+0x400
  elif a==0x530f25f4:
   state['allocs'].append(r0)
   ret=VM if len(state['allocs'])==1 else DESC+0x800 if r0==0x24 else DESC+0x900
  elif a==0x530f2668:state['array_bytes']=r0;ret=ARR
  elif a in (0x52f13e70,0x5327f4e4):ret=r0
  elif a==0x530fdfc4:
   assert r0!=0,('false firmware assertion',r);ret=0
  elif a==0x5327f6b0:ret=PROVIDER
  elif a==NOTIFY:assert r1==VM+4 and r2==0
  elif a==0x526ac000:
   template=string(r2).decode('ascii');number=r3 if r3<0x80000000 else r3-0x100000000
   rendered=template.replace('%ld',str(number)).encode('ascii');assert r1==0x14
   uc.mem_write(r0,rendered[:r1-1]+b'\0');ret=len(rendered)
   state['formats'].append(dict(destination=hex(r0),template=template,number=number,limit=r1))
  elif a==0x526ac9c0:ret=len(string(r0))
  elif a==0x52ff7d10:state['stat_path']=r1;assert r2==0;ret=state['size']
  uc.reg_write(UC_ARM_REG_R0,ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook)
 def run(a,args=()):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  for q,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(q,v&0xffffffff)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,0x20008000);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(a,STOP+4,count=100000);assert u.reg_read(UC_ARM_REG_PC)==(END if a==0x52f510e8 else STOP)
  return u.reg_read(UC_ARM_REG_R0)
 def reset():
  u.mem_write(FACT,bytes(0x20000));u.mem_write(0x54796000,bytes(0x1000));state.clear();state.update(trace=[],allocs=[],formats=[],array_bytes=0,size=35136788)
  for k in range(6):wr(PROVIDER+4+4*k,DESC+0x100*k);wr(DESC+0x100*k,VT)
  wr(VT+0xc,NOTIFY);wr(0x547bb198,MODEL);wr(MODEL+8,1234);wr(MODEL+0x18,9067)
 def record(g,inputs,observed):rows.append(dict(group=g,inputs=inputs,observed=observed,result_sha256=sha(json.dumps(dict(observed=observed,state=state),sort_keys=True).encode())))
 reset();run(0x52f510e8,[FACT]);letters=bytes(u.mem_read(ARR+8+0x18*k+4,1)[0] for k in range(12))
 provider_indices=[0,1,3,4,2,2,2,2,2,2,2,5]
 assert letters==b'CDXYABEFGHRW' and rd(VM+0x20)==12 and rd(VM+0x14)==ARR+8 and state['array_bytes']==12*0x18+8
 assert [rd(ARR+8+0x18*k) for k in range(12)]==[DESC+0x100*k for k in provider_indices]
 assert [u.mem_read(ARR+8+0x18*k+6,1)[0] for k in range(12)]==[0,0,1,1,0,0,0,0,0,0,0,0]
 record('factory-entry-to-volume-registration',{},dict(letters=letters.decode(),provider_indices=provider_indices,capacity=12,array_bytes=state['array_bytes']))
 for model in (0,9067,2147483647):
  wr(MODEL+0x18,model);state['formats']=[];run(0x52ff32ac,[STATE+0x200])
  assert len(state['formats'])==8
  for dest,letter in [(0x54796104,'C'),(0x54796140,'R')]:
   assert string(dest)==(letter+':\\FWDC'+str(model)+'B.BIN').encode()[:19]
   idx=run(0x52f52554,[VM,dest]);assert idx==(0 if letter=='C' else 10)
   desc=run(0x52f52630,[VM,dest]);assert desc==DESC+(0 if letter=='C' else 0x200)
   record('filename-constructor-to-real-record',dict(model_fixture=model,path_letter=letter),dict(path=string(dest).decode(),index=idx,descriptor_provider_index=0 if letter=='C' else 2))
 # Actual kind2 selector sees the C getter. Failure preserves prior state fields.
 for length in (0,35136788):
  state['size']=length;wr(STATE+0x10,FACT);wr(STATE+0x14,STATE+0x200)
  for off in (0x3c,0x40,0x44):wr(STATE+off,0xdeadbeef)
  ret=run(0x52fef240,[STATE,2]);assert ret==int(bool(length)) and state['stat_path']==0x54796104
  values=[rd(STATE+x) for x in (0x3c,0x40,0x44)]
  assert values==([2,0x54796104,length] if length else [0xdeadbeef]*3)
  record('kind2-c-path-size-gate',dict(synthetic_length=length),dict(ret=ret,state=values))
 wr(FS+8,VM);wr(FS+0xc,FS+0x100);wr(FS+0x10,FS+0x200);wr(FS+0x14,FS+0x300);wr(FS+0x18,TABLE)
 for letter,path,index,desc in [('C',0x54796104,0,DESC),('R',0x54796140,10,DESC+0x200)]:
  for field14 in (0,4):
   for field18 in (0x0403ffff,0x04040000):
    u.mem_write(desc+0x14,bytes([field14]));wr(desc+0x18,field18)
    run(0x52f4fd70,[FS,path]);expected=FS+0x300 if field14==4 else FS+0x200 if field18>0x0403ffff else FS+0x100
    assert rd(TABLE+4*index)==expected
    record('generated-path-record-backend-condition',dict(letter=letter,descriptor_byte14=field14,descriptor_word18=field18),dict(index=index,backend_offset=expected-FS))
 u.mem_write(TEXT,b'Z\0');before=bytes(u.mem_read(ARR,0x128));ret=run(0x52f524b8,[VM,DESC,TEXT,7]);assert ret==0 and bytes(u.mem_read(ARR,0x128))==before
 record('registration-full',{},dict(ret=ret,unchanged=True))
 wr(ARR+8+0x18*4,0);ret=run(0x52f524b8,[VM,DESC+0x500,TEXT,7]);assert ret==1
 assert rd(ARR+8+0x18*4)==DESC+0x500 and u.mem_read(ARR+8+0x18*4+4,1)==b'Z'
 assert run(0x52f52554,[VM,TEXT])==4 and rd(VM+0x20)==12
 record('registration-first-empty-slot',{},dict(index=4,capacity_unchanged=12))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),scope=__doc__,groups={g:sum(x['group']==g for x in rows) for g in sorted({x['group'] for x in rows})},stubs={hex(k):v for k,v in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups')})
