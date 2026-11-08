"""Original ARM constructors, CSD arithmetic, conditional SD capacity import and
per-volume record writes on authored buffers. Cortex-A15 Unicorn is a CPU model,
not the camera. Base/task lookup/cast, media acquisition, memcpy and diagnostics
are explicit stubs. No allocation, filesystem, OS, media or hardware executes.
"""
if not __debug__:raise RuntimeError('Verification requires assertions; do not use -O')
import argparse,hashlib,json,os,struct,random
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
OBJ,BUF,FACT,VM,ARR,PART,TEXT=[0x10000000+4096*k for k in range(7)]
STOP=0x30000000
RANGES=[(0x5327f4e4,0x5327f538),(0x53281698,0x5328172c),(0x53297454,0x532974a4),
 (0x53282460,0x5328247c),(0x53282480,0x53282488),(0x532824d4,0x532825d8),
 (0x53281cf8,0x53281f18),(0x53297fac,0x532980e4),(0x53298148,0x53298290),
 (0x52f51028,0x52f510e8),(0x52f52554,0x52f52674),(0x52f52788,0x52f527d4),(0x52f5288c,0x52f528e8)]
STUBS={0x52f13e70:'base constructor returns this; base/task fields outside tested derived fields',
 0x53281ca0:'gate returns authored boolean',0x53281bd4:'media setup boundary returns',
 0x532829b0:'returns authored bus pointer',0x53284094:'bus selection boundary returns',
 0x53281b20:'media acquisition returns authored boolean; source bytes are preloaded synthetic buffers',
 0x526aac80:'bounded memcpy of 16 synthetic bytes, no original memcpy implementation execution',
 0x530fced4:'diagnostic no-op',0x52f137f0:'task manager returns authored pointer',
 0x52f1390c:'task lookup returns authored Emmc sentinel',0x533aada0:'dynamic cast returns authored Emmc sentinel',
 0x530fdfc4:'assertion succeeds only when condition is nonzero',0x526ac9c0:'bounded strlen of authored NUL-terminated path'}
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):
 b=p.read_bytes()
 if sha(b)==DSHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def expected(b):
 s=b[0]>>6
 if s==0:
  c=((b[6]&3)<<10)|(b[7]<<2)|(b[8]>>6);r=b[5]&15;m=((b[9]&3)<<1)|(b[10]>>7)
  shift=(r-1)&255;x=0 if shift>=32 else (2<<shift)&0xffffffff
  return c,((c+1)*(x>>9)*(2<<(m+1)))&0xffffffff
 if s==1:
  c=((b[7]&63)<<16)|(b[8]<<8)|b[9];return c,((c+1)<<10)&0xffffffff
 return 0,0
def fixture(s,c=0,r=9,m=0):
 b=bytearray(16);b[0]=s<<6
 if s==0:b[5]=r;b[6]=(c>>10)&3;b[7]=(c>>2)&255;b[8]=(c&3)<<6;b[9]=(m>>1)&3;b[10]=(m&1)<<7
 elif s==1:b[7]=(c>>16)&63;b[8]=(c>>8)&255;b[9]=c&255
 return bytes(b)
def run_checks(b):
 if sha(b)!=SHA:raise ValueError('unrecognized RTOS SHA-256')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 for a,n in [(OBJ,0x10000),(0x20000000,0x10000),(STOP,4096),(0x547be000,4096),(0x54564000,4096),(0x54583000,4096)]:u.mem_map(a,n)
 state={};rows=[]
 def wr(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def hook(uc,a,size,user):
  if a==STOP:uc.emu_stop();return
  if a not in STUBS:assert any(x<=a<z for x,z in RANGES),hex(a);return
  r=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];r0,r1,r2,r3=r;ret=1
  state['trace'].append([hex(a),r])
  if a==0x52f13e70:ret=r0
  elif a==0x53281ca0:ret=state.get('gate',1)
  elif a==0x532829b0:ret=BUF
  elif a==0x53281b20:ret=state.get('acquire',1);state['attempts']+=1
  elif a==0x526aac80:
   assert r2==16 and r1 in (0x54583af0,0x54583ae0) and r0 in (OBJ+0x28,OBJ+0x38)
   uc.mem_write(r0,bytes(uc.mem_read(r1,16)));ret=r0
  elif a in (0x52f137f0,0x52f1390c,0x533aada0):ret=OBJ
  elif a==0x530fdfc4:assert r0!=0;ret=0
  elif a==0x526ac9c0:
   raw=bytes(uc.mem_read(r0,128));assert b'\0' in raw;ret=raw.index(0)
  uc.reg_write(UC_ARM_REG_R0,ret);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook)
 def run(a,args):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  for q,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(q,v&0xffffffff)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,0x20008000);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(a,STOP+4,count=30000);assert u.reg_read(UC_ARM_REG_PC)==STOP
  return u.reg_read(UC_ARM_REG_R0)
 def reset():u.mem_write(OBJ,bytes(0x10000));state.clear();state.update(trace=[],attempts=0)
 def record(g,inputs,obs):rows.append(dict(group=g,inputs=inputs,observed=obs,result_sha256=sha(json.dumps(dict(observed=obs,trace=state['trace']),sort_keys=True).encode())))
 for entry,kind,vptr in [(0x53281698,0,0x53cb0710),(0x53297454,3,0x53cb1638)]:
  reset();u.mem_write(OBJ,b'\xa5'*0x100);ret=run(entry,[OBJ])
  assert ret==OBJ and rd(OBJ)==vptr and u.mem_read(OBJ+0x14,1)==bytes([kind]) and rd(OBJ+0x18)==0 and rd(OBJ+0x10)==0x1b2
  record('derived-constructor',dict(entry=hex(entry)),dict(byte14=kind,word18=0,vptr=hex(vptr)))
 cases=[fixture(s) for s in range(4)]
 cases += [fixture(0,c,r,m) for c in (0,4095) for r in (0,8,9,10,15) for m in (0,7)]
 cases += [fixture(1,c) for c in (0,1,0x100fe,0x100ff,0x3fffff)]
 rng=random.Random(42500);cases += [bytes(rng.randrange(256) for _ in range(16)) for k in range(16)]
 for k,data in enumerate(cases):
  reset();u.mem_write(BUF,data);c,q=expected(data);gotc=run(0x532824fc,[BUF]);gotq=run(0x53282554,[BUF])
  assert (gotc,gotq)==(c,q),(k,gotc,gotq,c,q)
  record('csd-fields-and-count',dict(case=k,synthetic_csd_hex=data.hex()),dict(size_field=c,count=q))
 for name,data,gate,acquire,ready,present in [('type0',fixture(0,4095,9,7),1,1,0,1),('type1-below',fixture(1,0x100fe),1,1,0,1),('type1-above',fixture(1,0x100ff),1,1,0,1),('gate-false',fixture(1,5),0,1,0,1),('acquisition-fails',fixture(1,5),1,0,0,1),('already-ready',fixture(1,5),1,1,1,1),('not-present',fixture(1,5),1,1,0,0)]:
  reset();run(0x53281698,[OBJ]);state['trace']=[];state.update(gate=gate,acquire=acquire)
  wr(OBJ+0x18,0xdeadbeef);u.mem_write(OBJ+0x79,bytes([ready,0,present]));u.mem_write(0x54583af0,data);u.mem_write(0x54583ae0,bytes(range(16)))
  ret=run(0x53281cf8,[OBJ]);writes=bool(gate and acquire and not ready and present);q=expected(data)[1] if writes else 0xdeadbeef
  assert rd(OBJ+0x18)==q and ret==int(bool(ready or writes)) and rd(0x547be0c0)==0
  assert state['attempts']==(1 if writes else 3 if gate and not acquire and not ready and present else 0)
  if writes:assert bytes(u.mem_read(OBJ+0x28,16))==data
  record('conditional-capacity-import',dict(case=name),dict(word18=q,ret=ret,acquisition_attempts=state['attempts'],updated=writes))
 # Distinct partition object; actual constructor writes constants after explicit task/cast stubs.
 reset();run(0x53297fac,[PART]);assert rd(PART)==0x53cb16e8 and rd(PART+4)==OBJ and rd(PART+0x24)==0x348000 and rd(PART+0x44)==0x38c000
 record('separate-emmc-partition-ctor',{},dict(vptr=hex(rd(PART)),R_field24=rd(PART+0x24),R_field44=rd(PART+0x44)))
 for letter,kind in [('C',0),('R',3)]:
  wr(FACT+4,VM);wr(FACT+0x1c,PART);wr(VM+0x14,ARR);wr(VM+0x20,1);wr(ARR,OBJ);u.mem_write(ARR+4,letter.encode());u.mem_write(TEXT,letter.encode()+b':\\authored.bin\0')
  u.mem_write(OBJ+0x14,bytes([kind]));wr(OBJ+0x18,0x11223344);u.mem_write(OBJ+0x1c,struct.pack('<HH',0x1234,0x5678));before=bytes(u.mem_read(OBJ,0x24))
  state['trace']=[];run(0x52f51028,[FACT,TEXT]);run(0x52f5107c,[FACT,TEXT])
  got=(rd(ARR+0xc),rd(ARR+0x10),*struct.unpack('<HH',u.mem_read(ARR+0x14,4)));want=(0,0x11223344,0x1234,0x5678) if kind==0 else (0x348000,0x38c000,0,0)
  assert got==want and bytes(u.mem_read(OBJ,0x24))==before
  record('descriptor-kind-to-volume-record',dict(letter=letter,descriptor_byte14=kind),dict(record_c_10_14_16=list(got),descriptor_unchanged=True))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),scope=__doc__,cpu_model='Unicorn Cortex-A15; not camera fidelity',stubs={hex(k):v for k,v in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],groups={g:sum(x['group']==g for x in rows) for g in sorted({x['group'] for x in rows})},results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups')})
