"""Standalone original-ARM alias checks; every external effect is explicit."""
import argparse, hashlib, json, struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
from unicorn.arm_const import *
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
sha=lambda b:hashlib.sha256(b).hexdigest()
R=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
ranges=[(0x52eca00c,0x52eca034),(0x52eca1a8,0x52eca26c),(0x53107ffc,0x531080fc)]

def run(b):
 assert sha(b)==SHA
 ctx=0x10001000;obj=0x10002000;buf=0x10003000;src=0x10004000;manager=0x10005000;driver=0x10006000;tab=0x10010000;stop=0x1004f000
 records=[]
 def fresh(allowed,mocks):
  u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
  u.mem_map(BASE,(len(b)+4095)&~4095);u.mem_write(BASE,b);u.mem_map(0x10000000,0x50000);u.mem_map(0x547bb000,0x1000)
  u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_SP,0x1004e000);u.reg_write(UC_ARM_REG_LR,stop)
  def p(a,v):u.mem_write(a,struct.pack('<I',v))
  def hook(uc,a,n,data):
   if a in mocks:
    v=mocks[a](uc,[uc.reg_read(r) for r in R]);uc.reg_write(R[0],v&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
   assert any(x<=a<z for x,z in allowed),(hex(a),'unapproved code')
  u.hook_add(UC_HOOK_CODE,hook)
  u.mem_write(obj,bytes([0xa7])*0x1c);u.mem_write(tab,bytes([0x96])*0x10e00)
  return u,p
 def execute(u,a,args):
  for r,v in zip(R,args):u.reg_write(r,v&0xffffffff)
  u.emu_start(a,stop,count=10000);assert u.reg_read(UC_ARM_REG_PC)==stop
 for count in [-1,0,1,2,64]:
  u,p=fresh([ranges[0]],{});p(ctx+4,buf);initial=bytes([0xb5])*0x110;source=bytes((11*k+3)&255 for k in range(0x100));u.mem_write(buf,initial);u.mem_write(src,source)
  ob=bytes(u.mem_read(obj,0x1c));tb=bytes(u.mem_read(tab,0x10e00));execute(u,0x52eca00c,[ctx,src,count]);out=bytes(u.mem_read(buf,len(initial)));expected=bytearray(initial)
  if count>0:expected[4:4+4*count]=source[:4*count]
  assert out==expected and bytes(u.mem_read(obj,0x1c))==ob and bytes(u.mem_read(tab,0x10e00))==tb
  records.append(dict(group='full_word_copy_no_stubs',signed_word_count=count,payload_sha256=sha(out)))
 for first,second in [(0,0),(0,1),(1,0),(1,1)]:
  trace=[]
  def write(u,a):
   assert a==[obj,0x1000 if not trace else 0x1800,0x200,buf]
   trace.append(dict(block=a[1],payload_sha256=sha(bytes(u.mem_read(buf,0x110)))))
   return first if len(trace)==1 else second
  u,p=fresh([ranges[1]],{0x52ff5ad0:write});p(ctx+4,buf);p(ctx+0x14,obj);p(ctx+0x1c,0x110);p(ctx+0x20,0x200)
  initial=bytearray((17*k+9)&255 for k in range(0x200));u.mem_write(buf,bytes(initial));ob=bytes(u.mem_read(obj,0x1c));tb=bytes(u.mem_read(tab,0x10e00))
  execute(u,0x52eca200,[ctx]);expected=bytearray(initial);struct.pack_into('<I',expected,0x108,0xa55a5aa5);s=sum(struct.unpack_from('<66I',initial,0))&0xffffffff;struct.pack_into('<I',expected,0x10c,s)
  out=bytes(u.mem_read(buf,len(initial)));assert out==expected and len(trace)==2 and trace[0]['payload_sha256']==trace[1]['payload_sha256'];assert u.reg_read(R[0])==(first&second)
  assert bytes(u.mem_read(obj,0x1c))==ob and bytes(u.mem_read(tab,0x10e00))==tb
  records.append(dict(group='full_dual_write_and_checksum_mocked_storage',first_result=first,second_result=second,call_order=[q['block'] for q in trace],return_value=u.reg_read(R[0]),payload_sha256=sha(out)))
 for bank in [0,1]:
  mocks={0x52fee52c:lambda u,a:manager,0x530fdfc4:lambda u,a:0,0x52f137f0:lambda u,a:0x10007000,0x52f1390c:lambda u,a:driver,0x533aada0:lambda u,a:driver}
  u,p=fresh([ranges[2]],mocks);p(manager+8,obj);p(obj+0x14,tab);u.mem_write(obj+0x10,bytes([bank]));values=[0x123000+bank*0x8000+i*0x100 for i in range(5)]
  for i,v in enumerate(values):p(tab+(26+i)*0x870+bank*0x434+0x10,v)
  ob=bytes(u.mem_read(obj,0x1c));tb=bytes(u.mem_read(tab,0x10e00));execute(u,0x53107ffc,[]);out=bytes(u.mem_read(0x547bb104,20))
  assert struct.unpack('<5I',out)==tuple(values);assert struct.unpack('<I',u.mem_read(0x547bb11c,4))[0]==obj;assert bytes(u.mem_read(obj,0x1c))==ob and bytes(u.mem_read(tab,0x10e00))==tb
  records.append(dict(group='full_exception_cache_init_mocked_registry',synthetic_bank=bank,cache_sha256=sha(out)))
 return dict(passed=True,cases=len(records),image_sha256=SHA,ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in ranges],cases_detail=records,explicit_stubs={'0x52ff5ad0':'capture boot1 write arguments and return chosen boolean; no lower driver or IO','0x52fee52c':'return synthetic manager','0x530fdfc4':'diagnostic/assertion no-op; supplied objects nonnull','0x52f137f0':'return synthetic registry','0x52f1390c':'return synthetic driver','0x533aada0':'return synthetic dynamic-cast result'},scope='Original complete word-copy, dual-write including checksum, and Exception initialization functions run on Unicorn Cortex-A15 with synthetic buffers. External manager/registry/cast/assertion and storage explicitly stubbed. Synthetic bank1 is an input, not a producer. No lower driver/media IO, full-device behavior, or physical fidelity asserted.')

if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('decoded',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();d=a.decoded.read_bytes();assert sha(d)=='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9','Decoded hash mismatch';r=run(d[0x1c19c:0x1c19c+25483200]);a.output.write_text(json.dumps(r,indent=2)+'\n');print(dict(passed=r['passed'],cases=r['cases']))
