"""Original ARM, synthetic objects and intercepted external reads; no real IO."""
import argparse,hashlib,json,struct
from pathlib import Path
from rtos_catalog import require
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_MODE_LITTLE_ENDIAN,UC_HOOK_CODE
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
sha=lambda b:hashlib.sha256(b).hexdigest();R=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
ranges=[(0x52575ce4,0x52575d18),(0x52fee13c,0x52fee2a8),(0x530f25f4,0x530f2630),(0x530ef264,0x530ef274),(0x52ff52d4,0x52ff5300),(0x52ff8de4,0x52ff8ed0),(0x52ff5638,0x52ff568c),(0x52ff553c,0x52ff5638),(0x532971dc,0x532971e4)]
def run(b):
 require(sha(b)==SHA, 'RTOS hash mismatch')
 records=[];manager=0x10001000;obj=0x10002000;heap=0x10003000;driver=0x10004000;vt=0x10005000;stop=0x1003f000;table=0x50b70100
 def fresh(allowed,mocks):
  u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15);u.mem_map(BASE,(len(b)+4095)&~4095);u.mem_write(BASE,b)
  for a,n in [(0x10000000,0x40000),(0x50b70000,0x20000),(0x54520000,0x10000),(0x547ba000,0x1000)]:u.mem_map(a,n)
  u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_SP,0x1003e000);u.reg_write(UC_ARM_REG_LR,stop);trace=[]
  def p(a,v):u.mem_write(a,struct.pack('<I',v))
  def hook(uc,a,n,data):
   if a in mocks:
    args=[uc.reg_read(r) for r in R];ret=mocks[a](uc,args,trace);uc.reg_write(R[0],ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
   assert any(x<=a<z for x,z in allowed),(hex(a),'unexpected code')
  u.hook_add(UC_HOOK_CODE,hook);return u,p,trace
 for pattern in [0,0xa5,0xff]:
  def alloc(u,a,t):assert a[:3]==[heap,0x1c,0];t.append('allocator_2');return obj
  def create(u,a,t):assert a[0]==obj;t.append('Create_stub');return 1
  u,p,t=fresh(ranges[1:5],{0x10008000:alloc,0x52ff51a4:create,0x530fdfc4:lambda u,a,t:0});p(0x547ba308,heap);p(heap,vt);p(vt+8,0x10008000);u.mem_write(obj,bytes([pattern])*0x1c);p(manager+8,0x12345678)
  u.reg_write(R[0],manager);u.reg_write(R[1],6);u.emu_start(0x52fee13c,stop,count=400);assert u.reg_read(UC_ARM_REG_PC)==stop
  out=bytes(u.mem_read(obj,0x1c));assert struct.unpack_from('<I',out,0)[0]==0x53912568 and out[0x10]==0;assert out[0x11:0x14]==bytes([pattern])*3;assert struct.unpack_from('<I',u.mem_read(manager+8,4))[0]==obj;assert t==['allocator_2','Create_stub']
  records.append(dict(group='factory6_allocator2_constructor',prefill=pattern,call_order=t,object_sha256=sha(out)))
 # Initial slot2 is fixed; executing its getter must not call any allocator or external function.
 u,p,t=fresh([ranges[5]],{});p(0x54525598+8,table);p(0x54525598+4,0x10f00);before=bytes(u.mem_read(0x54525598,16));u.reg_write(R[0],manager);u.reg_write(R[1],2);u.emu_start(0x52ff8de4,stop,count=100);assert u.reg_read(UC_ARM_REG_PC)==stop and u.reg_read(R[0])==table and bytes(u.mem_read(0x54525598,16))==before
 records.append(dict(group='fixed_slot2_no_allocation',returned=hex(table),record_sha256=sha(before)))
 for seed in [0,1,0xffff]:
  for result in [0,1]:
   source=bytearray([0x5b])*0x10e00
   for i in range(32):struct.pack_into('<I',source,i*0x870+4,((seed+i)&0xffff)|0x83ab0000)
   def read(u,a,t):
    assert a==[driver,0,135,table];t.append('read_stub')
    if result:u.mem_write(table,bytes(source))
    return result
   def ceil(u,a,t):assert a[:2]==[driver,0x10e00];return 135
   def rem(u,a,t):assert a[:2]==[0x10e00,512];u.reg_write(R[1],0);return 135
   def dump(u,a,t):assert a[0]==obj;t.append('dump_stub');return 0
   u,p,t=fresh([ranges[0],ranges[6],ranges[7],ranges[8]],{0x52fee52c:lambda u,a,t:manager,0x532974a8:ceil,0x526a834c:rem,0x53297938:read,0x52ff5494:dump,0x530fced4:lambda u,a,t:0});p(manager+8,obj);p(obj+8,driver);p(obj+0x14,table);p(obj+0x18,0x10e00);u.mem_write(obj+0x10,b'\0');p(driver,vt);p(vt+0x30,0x53297938);p(vt+0x4c,0x532971dc);u.mem_write(table,bytes([0xa7])*0x10f00);before=bytes(u.mem_read(obj,0x1c))
   u.emu_start(0x52575ce4,stop,count=400);assert u.reg_read(UC_ARM_REG_PC)==stop and u.reg_read(R[0])==0
   out=bytes(u.mem_read(table,0x10f00));assert out[:0x10e00]==(bytes(source) if result else bytes([0xa7])*0x10e00);assert out[0x10e00:]==bytes([0xa7])*0x100;assert bytes(u.mem_read(obj,0x1c))==before;assert t==(['read_stub','dump_stub'] if result else ['read_stub'])
   records.append(dict(group='diagnostic_reload_mocked_media',source_record_seed=seed,read_result=result,call_order=t,table_sha256=sha(out),object_sha256=sha(before)))
 return dict(passed=True,cases=len(records),image_sha256=SHA,ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in ranges],cases_detail=records,explicit_stubs={'0x10008000':'allocator ID2 returns prefilled synthetic object','0x52ff51a4':'Create returns1 without running driver discovery','0x530fdfc4':'diagnostic no-op','0x52fee52c':'synthetic manager pointer','0x532974a8':'fixed ceil(0x10e00/512)=135','0x526a834c':'fixed quotient135 remainder0','0x53297938':'synthetic read copies supplied bytes on success only','0x52ff5494':'dump callback count only','0x530fced4':'diagnostic no-op'},scope='Unicorn Cortex-A15, synthetic RAM. Actual factory6+allocator wrapper+registry getter+constructor, fixed slot2 getter, and diagnostic handler+table wrapper+read argument plumbing. Emmc read and all external effects explicitly intercepted. Failure stub leaves destination unchanged by design; no real-media failure atomicity claim. No hardware fidelity or device IO.')
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('decoded',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();d=a.decoded.read_bytes();require(sha(d)=='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9', 'Decoded hash mismatch');r=run(d[0x1c19c:0x1c19c+25483200]);a.output.write_text(json.dumps(r,indent=2)+'\n');print(dict(passed=r['passed'],cases=r['cases']))
