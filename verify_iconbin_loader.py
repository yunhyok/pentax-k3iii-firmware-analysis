"""Actual ARM fragments with synthetic RAM; never calls a storage write/read driver."""
import argparse,hashlib,json,struct
from pathlib import Path
from rtos_catalog import require
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_MODE_LITTLE_ENDIAN
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
def run(blob,header):
 require(hashlib.sha256(blob).hexdigest()==SHA,'RTOS hash mismatch')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 u.mem_map(BASE,(len(blob)+4095)&~4095);u.mem_write(BASE,blob)
 for a,n in [(0x10000000,0x40000),(0x54500000,0x40000),(0x50adf000,0x1000)]:u.mem_map(a,n)
 ram=0x10000000;ctx=ram+0x1000;tab=ram+0x10000;hdr=ram+0x2000;stop=ram+0x3f000;marker=0x50adf00c
 def p(a,v):u.mem_write(a,struct.pack('<I',v))
 def reset():
  for r in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(r,0)
  u.reg_write(UC_ARM_REG_SP,ram+0x3e000);u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_LR,stop)
 records=[]
 p(0x545255c8+12,marker)
 for value in [0,1,2,0xffffffff]:
  reset();u.reg_write(UC_ARM_REG_R1,5);u.reg_write(UC_ARM_REG_R2,value);u.emu_start(0x52ff8f04,stop,count=100)
  actual=struct.unpack('<I',u.mem_read(marker,4))[0];assert actual==(0xa55a5aa5 if value else 0xffffffff)
  reset();u.reg_write(UC_ARM_REG_R1,5);u.emu_start(0x52ff8ed0,stop,count=100);assert u.reg_read(UC_ARM_REG_R0)==bool(value)
  records.append(dict(group='marker_set_and_ready',input=value,output_sha256=hashlib.sha256(struct.pack('<II',actual,u.reg_read(UC_ARM_REG_R0))).hexdigest()))
 p(0x545255c8+12,0);reset();u.reg_write(UC_ARM_REG_R1,5);u.reg_write(UC_ARM_REG_R2,1);u.emu_start(0x52ff8f04,stop,count=100)
 reset();u.reg_write(UC_ARM_REG_R1,5);u.emu_start(0x52ff8ed0,stop,count=100);assert u.reg_read(UC_ARM_REG_R0)==0
 records.append(dict(group='null_marker_pointer',passed=True))
 for bank in [0,1]:
  for index in [0,4,10]:
   cap=0x1800;start=0x2000+index*0x100;dest=ram+0x30000
   p(ctx+0x14,tab);u.mem_write(ctx+0x10,bytes([bank]));p(tab+index*0x870,cap);p(tab+index*0x870+bank*0x434+0x10,start)
   for size in [0,cap-1,cap,cap+1,0xffffffff]:
    reset()
    for r,v in [(UC_ARM_REG_R0,ctx),(UC_ARM_REG_R1,index),(UC_ARM_REG_R2,size),(UC_ARM_REG_R3,dest)]:u.reg_write(r,v)
    u.emu_start(0x52ff568c,0x52ff56cc,count=100)
    actual=[u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]
    assert actual==[ctx,start,min(size,cap),dest]
    records.append(dict(group='indexed_read_arguments',bank=bank,index=index,size=size,output_sha256=hashlib.sha256(struct.pack('<4I',*actual)).hexdigest()))
 for index in [0,4,31,32]:
  h=bytearray(header);struct.pack_into('<H',h,10,index);u.mem_write(hdr,bytes(h));p(ctx+0x48,32)
  reset();u.reg_write(UC_ARM_REG_R4,0x2000000);u.reg_write(UC_ARM_REG_R5,hdr);u.reg_write(UC_ARM_REG_R6,ctx)
  end=0x52ff2c28 if index<32 else 0x52ff2b78
  u.emu_start(0x52ff2a24,end,count=100)
  assert u.reg_read(UC_ARM_REG_PC)==end
  if index<32:assert [u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]==[ctx,index,26219192,hdr+16]
  records.append(dict(group='kind4_record_dispatch',index=index,accepted=index<32))
 ranges=[(0x52ff8f04,0x52ff8f34),(0x52ff8ed0,0x52ff8f04),(0x52ff568c,0x52ff56cc),(0x52ff2a24,0x52ff2a60),(0x52ff2b68,0x52ff2b78),(0x52ff2c18,0x52ff2c28)]
 return dict(passed=True,cases=len(records),image_sha256=SHA,header_sha256=hashlib.sha256(header).hexdigest(),cases_detail=records,ranges=[dict(start=hex(a),end=hex(z),sha256=hashlib.sha256(blob[a-BASE:z-BASE]).hexdigest()) for a,z in ranges],scope='Unicorn Cortex-A15, synthetic RAM. Marker getter/setter full functions and bounded indexed-read/record-dispatch fragments. All storage calls stopped before execution. No hardware, package installation, cryptographic validation, or full-loader execution.')
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('decoded',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();d=a.decoded.read_bytes()
 require(hashlib.sha256(d).hexdigest()=='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9','Decoded hash mismatch')
 r=run(d[0x1c19c:0x1c19c+25483200],d[47623484:47623500]);a.output.write_text(json.dumps(r,indent=2)+'\n');print({'passed':r['passed'],'cases':r['cases']})
