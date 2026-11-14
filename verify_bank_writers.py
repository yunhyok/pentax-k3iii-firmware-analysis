"""Original ARM clear/header routines with synthetic buffers and intercepted storage effects."""
import argparse,hashlib,json,os,struct,sys
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_MODE_LITTLE_ENDIAN,UC_HOOK_CODE
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';sha=lambda x:hashlib.sha256(x).hexdigest();R=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
ranges=[(0x52ff5348,0x52ff5494),(0x532971dc,0x532971e4),(0x52eac328,0x52eac3e4)]
def run(b):
 assert sha(b)==SHA
 obj=0x10001000;driver=0x10002000;alloc=0x10003000;vtd=0x10004000;vta=0x10005000;buf=0x10006000;ctx=0x10007000;tag=0x10008000;tab=0x10010000;stop=0x1004f000;records=[]
 def fresh(allowed,mocks):
  u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15);u.mem_map(BASE,(len(b)+4095)&~4095);u.mem_write(BASE,b);u.mem_map(0x10000000,0x50000);u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_SP,0x1004e000);u.reg_write(UC_ARM_REG_LR,stop);trace=[]
  def p(a,v):u.mem_write(a,struct.pack('<I',v))
  def hook(uc,a,n,data):
   if a in mocks:
    args=[uc.reg_read(r) for r in R];ret=mocks[a](uc,args,trace);uc.reg_write(R[0],ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
   assert any(x<=a<z for x,z in allowed),(hex(a),'unapproved code')
  u.hook_add(UC_HOOK_CODE,hook);return u,p,trace
 cases=[(bank,index,result,False,False) for bank in [0,1] for index in [4,10] for result in [0,1]]+[(0,4,0,True,False),(0,4,0,False,True)]
 for bank,index,result,zero,allocfail in cases:
  cap=0 if zero else 512 if index==4 else 1025;blocks=(cap+511)//512;start=0x700+index;desc=tab+index*0x870+bank*0x434
  def ceil(u,a,t):assert a[:2]==[driver,cap];return blocks
  def malloc(u,a,t):assert a==[alloc,blocks*512,0,0];t.append('allocate');return 0 if allocfail else buf
  def memset(u,a,t):assert a==[buf,255,blocks*512,a[3]];u.mem_write(a[0],bytes([a[1]])*a[2]);return a[0]
  def write(u,a,t):assert a==[driver,start,blocks,buf];assert bytes(u.mem_read(buf,blocks*512))==bytes([255])*blocks*512;t.append('write');return result
  def free(u,a,t):assert a[:3]==[alloc,buf,0];t.append('free');return 0
  u,p,t=fresh(ranges[:2],{0x532974a8:ceil,0x10009000:malloc,0x10009004:free,0x526ab2a8:memset,0x53297a84:write,0x530fced4:lambda u,a,t:0});u.mem_write(tab,bytes([0xa7])*0x10e00);p(obj+4,alloc);p(obj+8,driver);u.mem_write(obj+0x10,bytes([bank]));p(obj+0x14,tab);p(driver,vtd);p(vtd+0x4c,0x532971dc);p(vtd+0x2c,0x53297a84);p(alloc,vta);p(vta+8,0x10009000);p(vta+0xc,0x10009004);p(tab+index*0x870,cap);p(tab+index*0x870+4,0xabcd1234);p(desc+0x10,start);p(desc+0x14,0x12345);p(desc+0x18,0x99)
  before=bytes(u.mem_read(tab,0x10e00));objbefore=bytes(u.mem_read(obj,0x1c));u.reg_write(R[0],obj);u.reg_write(R[1],index);u.emu_start(0x52ff5348,stop,count=500);assert u.reg_read(UC_ARM_REG_PC)==stop
  expected=bytearray(before)
  if cap and not allocfail and result:struct.pack_into('<II',expected,index*0x870+bank*0x434+0x14,0,0)
  out=bytes(u.mem_read(tab,0x10e00));assert out==bytes(expected) and bytes(u.mem_read(obj,0x1c))==objbefore
  assert u.reg_read(R[0])==(result if cap and not allocfail else 0)
  records.append(dict(group='full_clear_mocked_IO',bank=bank,index=index,write_result=result,zero_capacity=zero,allocator_failure=allocfail,call_order=t,table_sha256=sha(out)))
 for index in range(4):
  size=0x20+4*index;captured=[]
  def memcpy(u,a,t):u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));return a[0]
  def write(u,a,t):assert a==[obj,10+index,size,buf];captured.append(bytes(u.mem_read(buf,size)));t.append('payload_write');return 1
  def commit(u,a,t):assert a[0]==obj;t.append('table_commit');return 1
  u,p,t=fresh([ranges[2]],{0x526aac80:memcpy,0x52ff586c:write,0x52ff5818:commit});u.mem_write(buf,bytes((k*11+7)&255 for k in range(size)));u.mem_write(tag,b'TEST');row=ctx+32*index;p(ctx+0x49c,obj);p(row+0x424,buf);p(row+0x428,size);p(row+0x430,tag);u.mem_write(row+0x41c,bytes([10+index]));u.mem_write(row+0x43a,b'\1');u.reg_write(R[0],ctx);u.reg_write(R[1],index);u.emu_start(0x52eac328,stop,count=500);assert u.reg_read(UC_ARM_REG_PC)==stop
  out=captured[0];assert out[:4]==b'TEST' and struct.unpack_from('<III',out,4)==(index,0xa55a5aa5,size);assert sum(struct.unpack('<%dI'%(size//4),out))&0xffffffff==0;assert t==['payload_write','table_commit'];assert bytes(u.mem_read(row+0x43a,1))==b'\0'
  records.append(dict(group='full_adjust_payload_header_mocked_IO',local_index=index,storage_index=10+index,size=size,call_order=t,payload_sha256=sha(out)))
 return dict(passed=True,cases=len(records),image_sha256=SHA,ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in ranges],cases_detail=records,explicit_stubs={'0x532974a8':'synthetic ceil(capacity/512)','0x10009000':'synthetic allocator','0x10009004':'synthetic free','0x526ab2a8':'synthetic memset','0x53297a84':'capture write arguments and return selected result, no IO','0x530fced4':'diagnostic no-op','0x526aac80':'synthetic memcpy','0x52ff586c':'capture payload write, return1','0x52ff5818':'capture table commit, return1'},scope='Unicorn Cortex-A15 synthetic objects. Actual complete clear and AdjustManager payload-header ARM; all allocation, memory-library and storage calls explicitly mocked. Clear field stores and checksum/header arithmetic execute original bytes. Input bank1 is synthetic and is not a nonzero producer. No device IO or hardware fidelity claim.')
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('decoded',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();d=a.decoded.read_bytes();assert sha(d)=='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9','Decoded hash mismatch';r=run(d[0x1c19c:0x1c19c+25483200]);a.output.write_text(json.dumps(r,indent=2)+'\n');print(dict(passed=r['passed'],cases=r['cases']))
