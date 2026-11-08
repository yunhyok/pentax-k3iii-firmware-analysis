"""CPU-only AF loop and request encoding checks; no device or lens access.
Requires Unicorn and the independently supplied verified RTOS or decoded image.
"""
if not __debug__:
 raise RuntimeError('Verification requires assertions; run without -O or PYTHONOPTIMIZE')
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_MODE_LITTLE_ENDIAN,UC_HOOK_CODE
from unicorn.arm_const import *
BASE=0x52500000
SHA="342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4"
DECODED_SHA="7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9"
def load(path):
 b=path.read_bytes()
 if hashlib.sha256(b).hexdigest()==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if hashlib.sha256(b).hexdigest()!=SHA:raise ValueError("verified RTOS/decoded input required")
 return b

def run_loops(B):
 OBJ=0x10001000;EVENT=0x10002000;STOP=0x10007ff0;STACK=0x10007000
 R=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
 KINDS={
  'InMotor':(0x52ef9d50,0x52ef9ef8,0x19fc3,[(1,0x52ef9b14),(0x40,0x52ef9378),(0x80,0x52ef93d8),(0x100,0x52ef9510),(0x200,0x52ef961c),(0x400,0x52f0019c),(0x8000,0x52ef9718),(0x10000,0x52ef9860),(0x1000,0x52ef9cf4),(0x800,0x52ef9be8),(2,0x52ef88dc)]),
  'Joint':(0x52f08828,0x52f08a5c,0x3feff,[(4,0x52f0823c),(8,0x52f082c4),(0x10,0x52f08634),(0x20,0x52f08320),(1,0x52f087c4),(0x20000,0x52f07fd4),(0x40,0x52f08000),(0x80,0x52f0853c),(0x200,0x52f08578),(0x400,0x52f08060),(0x8000,0x52f08158),(0x10000,0x52f07eb8),(0x2000,0x52f080a0),(0x1000,0x52f08370),(0x800,0x52f08714),(0x4000,0x52f080ec),(2,0x52f083bc)])}
 rows=[]
 for name,(start,end,waitmask,dispatch) in KINDS.items():
  for busy in (0,1):
   for flags in [0]+[1<<i for i in range(18)]+[waitmask,0x3ffff,0x80000000]:
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
    u.mem_map(BASE,(len(B)+4095)&~4095);u.mem_write(BASE,B);u.mem_map(0x10000000,0x8000)
    u.mem_write(OBJ+0x50,struct.pack('<I',EVENT));u.mem_write(OBJ+0x54,bytes([busy]));u.mem_write(OBJ+0xc0,struct.pack('<I',0x10003000))
    u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP);u.reg_write(R[0],OBJ)
    waits=[];clears=[];calls=[]
    def hook(uc,a,size,_):
     if a==0x530ed1ac:
      assert uc.reg_read(R[0])==EVENT and uc.reg_read(R[1])==waitmask
      waits.append(1)
      if len(waits)==2:uc.reg_write(UC_ARM_REG_PC,STOP);uc.emu_stop();return
      uc.mem_write(uc.reg_read(R[2]),struct.pack('<I',flags))
     elif a==0x530ed0f4:
      assert uc.reg_read(R[0])==EVENT and uc.reg_read(R[1])==flags;clears.append(flags)
     elif a in {t for _,t in dispatch}:calls.append(a)
     else:
      assert start<=a<end,hex(a);return
     uc.reg_write(R[0],0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    u.hook_add(UC_HOOK_CODE,hook);u.emu_start(start,STOP,count=10000)
    expected=[t for bit,t in dispatch if flags&bit and not (not busy and ((name=='InMotor' and bit==1) or (name=='Joint' and bit==0x10000)))]
    assert calls==expected and len(waits)==2 and clears==[flags],(name,busy,hex(flags),calls,expected)
    rows.append({'kind':name,'busy_byte':busy,'injected_flags':hex(flags),'handler_calls':[hex(t) for t in calls]})
 result={'passed':True,'original_arm_cases':len(rows),'image_sha256':SHA,'loops':[{'kind':n,'start':hex(v[0]),'end':hex(v[1]),'sha256':hashlib.sha256(B[v[0]-BASE:v[1]-BASE]).hexdigest(),'wait_mask':hex(v[2]),'dispatch':[{'bit':hex(b),'target':hex(t)} for b,t in v[3]]} for n,v in KINDS.items()],
  'cases':rows,'scope':'Complete original loop body from entry through one wait/clear/dispatch iteration to next wait; explicit stubs for wait530ed1ac,clear530ed0f4 and all called handlers. Stub injects flags directly; unsupported flags test branch behavior, not RTOS delivery. No handler, scheduler, actuator or hardware execution.'}
 return result

def run_packet(B):
 OBJ=0x10001000;COMPLETE=0x10003000;PARENT=0x10004000;COMM=0x10010000;STACK=0x1000f000;STOP=0x1000fff0
 R=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
 specs=[(c,0x2345,1) for c in range(256)]+[(c,v,d) for c in (0,0x40) for v in (0,1,0x3fff,0x4000,0x7fff,0x8000,0xffff,0x12345678) for d in (0,1,2,0xffffffff)]
 rows=[]
 for cap,value,direction in specs:
  u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15);u.mem_map(BASE,(len(B)+4095)&~4095);u.mem_write(BASE,B);u.mem_map(0x10000000,0x20000)
  u.mem_write(OBJ+4,struct.pack('<II',PARENT,COMM));u.mem_write(COMM+0x5272,bytes([cap]));u.mem_write(OBJ+0x88,bytes.fromhex('aabbccddeeff'))
  for r,v in zip(R,[OBJ,value,direction,COMPLETE]):u.reg_write(r,v)
  u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP);calls=[]
  def hook(uc,a,size,_):
   if a==0x52eff524:
    assert [uc.reg_read(r) for r in R[:3]]==[PARENT,0x1b,COMPLETE]
    p=uc.reg_read(R[3]);desc=bytes(uc.mem_read(p,16));payload=bytes(uc.mem_read(struct.unpack_from('<I',desc,8)[0],2))
    assert desc[:8]==bytes.fromhex('0200008900000000') and desc[12:]==bytes(4)
    word=(value&0x3fff)|(0x8000 if direction else 0);assert payload==struct.pack('>H',word)
    calls.append({'descriptor_command':'0x8900','payload_hex':payload.hex(),'request_opcode':'0x1b'});uc.reg_write(R[0],0x23);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
   assert 0x52efc7a0<=a<0x52efc858 or 0x52eff608<=a<0x52eff618,hex(a)
  u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x52efc7a0,STOP,count=2000);assert u.reg_read(UC_ARM_REG_PC)==STOP
  if cap&0x40:
   assert len(calls)==1 and u.reg_read(R[0])==0x23
   assert bytes(u.mem_read(OBJ+0x88,6))==struct.pack('<IH',direction,value&0x3fff)
  else:assert not calls and u.reg_read(R[0])==0xff and bytes(u.mem_read(OBJ+0x88,6))==bytes.fromhex('aabbccddeeff')
  rows.append({'capability_byte':cap,'input_value':value,'direction_argument':direction,'return':u.reg_read(R[0]),'requests':calls})
 return {'passed':True,'original_arm_cases':len(rows),'image_sha256':SHA,'ranges':[{'start':hex(a),'end':hex(z),'sha256':hashlib.sha256(B[a-BASE:z-BASE]).hexdigest()} for a,z in [(0x52efc7a0,0x52efc858),(0x52eff608,0x52eff618)]],'cases':rows,'scope':'Complete original 8900 request builder and opcode1b wrapper; 52eff524 queue entry explicitly stubbed. Command descriptor and two payload bytes captured before stack lifetime ends. No transport, lens bus, timing, units or actual movement validated.'}

if __name__=="__main__":
 p=argparse.ArgumentParser();p.add_argument("input",type=Path);p.add_argument("--output",required=True,type=Path);a=p.parse_args()
 if a.output.exists():raise FileExistsError("report exists")
 b=load(a.input);result={"event_loops":run_loops(b),"packet_builder":run_packet(b)}
 with a.output.open("x",encoding="utf-8") as f:json.dump(result,f,indent=2);f.write("\n")
 print({"passed":True,"loop_cases":result["event_loops"]["original_arm_cases"],"packet_cases":result["packet_builder"]["original_arm_cases"]})
