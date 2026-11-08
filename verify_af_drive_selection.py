"""CPU-only original ARM checks. Read-only verified RTOS or decoded input; no device access.
Unicorn Cortex-A15 is an execution model, not a claim about the camera CPU.
Facade helper commands are explicit return stubs; only dispatch and argument flow are tested.
Import checks execute a six-instruction copy fragment, not communication or the full reader.
"""
if not __debug__:
 raise RuntimeError('Verification requires assertions; run without -O or PYTHONOPTIMIZE')
import argparse,hashlib,json,os,struct,sys
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RANGES=[(0x52efda40,0x52efda54),(0x52eff628,0x52eff640),(0x52ef89f4,0x52ef8d94),(0x52f18808,0x52f18820),(0x52f18730,0x52f1874c)]
LEAVES=[0x52ef8178,0x52ef81d0,0x52ef8238,0x52ef828c,0x52ef829c,0x52ef82b8,0x52ef8368,0x52ef8418,0x52ef84c8,0x52ef8520,0x52ef8578,0x52ef85fc,0x52ef863c,0x52ef86ec,0x52ef8744,0x52f00ba0]
F,L,J,I,C,R,D,Q=0x10000000,0x10001000,0x10003000,0x10004000,0x10010000,0x10020000,0x10021000,0x10022000
STACK=0x20008000;STOP=0x30000000
sha=lambda b:hashlib.sha256(b).hexdigest()
p32=lambda x:struct.pack('<I',x)
def load(path):
 b=path.read_bytes();h=sha(b)
 if h==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('Input is neither verified RTOS nor verified decoded.bin')
 return b

def run_checks(b):
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 u.mem_map(BASE,(len(b)+4095)&~4095);u.mem_write(BASE,b);u.mem_protect(BASE,(len(b)+4095)&~4095,UC_PROT_READ|UC_PROT_EXEC)
 u.mem_map(F,0x30000);u.mem_map(0x20000000,0x10000);u.mem_map(STOP,0x1000)
 calls=[];stops=set();cases=[]
 def hook(uc,a,size,user):
  if a==STOP or a in stops:uc.emu_stop();return
  if a in LEAVES:
   calls.append([hex(a)]+[uc.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]])
   uc.reg_write(UC_ARM_REG_R0,0x55);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  if not any(x<=a<z for x,z in RANGES):raise AssertionError('Unexpected executed address '+hex(a))
 u.hook_add(UC_HOOK_CODE,hook)
 def start(a,args,stop=None):
  calls.clear();stops.clear();stops.update(stop or [])
  for reg in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(reg,0)
  u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP);u.reg_write(UC_ARM_REG_CPSR,0x13)
  u.mem_write(STACK-0x100,bytes(0x300))
  for r,v in args.items():u.reg_write(r,v)
  u.emu_start(a,STOP+4,count=10000)
  assert u.reg_read(UC_ARM_REG_PC)==STOP or u.reg_read(UC_ARM_REG_PC) in stops
  return u.reg_read(UC_ARM_REG_R0)
 def record(group,inputs,output):cases.append(dict(group=group,inputs=inputs,output_sha256=sha(json.dumps(output,sort_keys=True).encode())))
 u.mem_write(L+0x58,p32(C));u.mem_write(F+4,p32(J)+p32(L)+p32(I))
 for v in range(256):
  u.mem_write(C+0x5272,bytes([v]));got=start(0x52efda40,{UC_ARM_REG_R0:L+0x50});assert got==(v>>6)&1
  record('full-capability-getter',dict(byte=v),got)
 fields={11:(0x54,1),12:(0x88,4),13:(0x8c,4),14:(0x90,4),15:(0x94,1),16:(0x95,1),17:(0x55,1)}
 for obj,val in [(J,0x11),(I,0x22)]:
  for off,n in fields.values():u.mem_write(obj+off,bytes([val])*n)
 for v in [0,0x40]:
  for op in list(range(1,23))+[0,23,0xffffffff]:
   u.mem_write(C+0x5272,bytes([v]));selected=I if v else J
   got=start(0x52ef89f4,{UC_ARM_REG_R0:F,UC_ARM_REG_R1:2,UC_ARM_REG_R2:op,UC_ARM_REG_R3:0x7a00})
   if op in fields:
    off,n=fields[op];assert got==int.from_bytes(u.mem_read(selected+off,n),'little') and not calls
   elif op not in range(1,23):assert got==0 and not calls
   else:
    assert calls and calls[0][1]==selected,(op,v,calls)
    if op==18:assert calls[0][0]=='0x52ef8578' and calls[0][3]==(0 if v else 0x7a)
    assert got==(1 if op in (2,3) else 0x55),(op,v,got,calls)
   record('full-facade-with-explicit-command-stubs',dict(byte=v,command=op,client=2),dict(result=got,calls=calls))
 for v in range(256):
  u.mem_write(R+0x4c,p32(D));u.mem_write(R+0x54,p32(C));u.mem_write(Q+6,bytes([v]));u.mem_write(D+6,b'\xee');u.mem_write(C+0x5272,b'\xee')
  start(0x52f18808,{UC_ARM_REG_R7:R,UC_ARM_REG_R12:Q},[0x52f18820]);assert u.mem_read(D+6,1)==u.mem_read(C+0x5272,1)==bytes([v])
  record('six-instruction-response-copy',dict(byte=v),v)
 for mode in range(5):
  for sub in range(5):
   start(0x52f18730,{UC_ARM_REG_R4:mode,UC_ARM_REG_R8:0,UC_ARM_REG_R9:sub},[0x52f1874c,0x52f18908]);got=u.reg_read(UC_ARM_REG_PC)==0x52f1874c
   assert got==(mode==3 or(mode==0 and sub==3));record('response-import-gate-fragment',dict(mode=mode,submode=sub),got)
 return dict(passed=True,image_sha256=SHA,cases=len(cases),groups={g:sum(x['group']==g for x in cases) for g in sorted({x['group'] for x in cases})},cpu_model='Unicorn Cortex-A15; not camera fidelity',scope=__doc__,explicit_return_stubs=[hex(x) for x in LEAVES],ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=cases)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 if args.output.exists():raise FileExistsError('report exists')
 result=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
 print({k:v for k,v in result.items() if k in ['passed','cases','groups']})
