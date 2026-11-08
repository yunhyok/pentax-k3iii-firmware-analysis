"""Isolated original ARM with synthetic RAM and intercepted external calls; no device IO."""
import argparse,hashlib,json,struct
from pathlib import Path
from rtos_catalog import require
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_MODE_LITTLE_ENDIAN,UC_HOOK_CODE
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
R=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
sha=lambda b:hashlib.sha256(b).hexdigest()
def run(b):
 require(sha(b)==SHA,'RTOS hash mismatch')
 records=[];ranges=[(0x52ff20d0,0x52ff21c8),(0x52ff5304,0x52ff5314),(0x52ff5638,0x52ff568c),(0x52ff5818,0x52ff586c),(0x52ff5ad0,0x52ff5bac),(0x52ff2ae4,0x52ff2b50)]
 ctx=0x10001000;obj=0x10002000;src=0x10003000;payload=0x10004000;buf=0x10005000;driver=0x10006000;vt=0x10007000;stop=0x1003f000
 def fresh(allowed,mocks,ends=()):
  u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
  u.mem_map(BASE,(len(b)+4095)&~4095);u.mem_write(BASE,b);u.mem_map(0x10000000,0x40000)
  def p(a,v):u.mem_write(a,struct.pack('<I',v))
  u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_SP,0x1003e000);u.reg_write(UC_ARM_REG_LR,stop)
  trace=[]
  def hook(uc,a,n,data):
   if a in ends:uc.emu_stop();return
   if a in mocks:
    args=[uc.reg_read(r) for r in R];ret=mocks[a](uc,args,trace)
    uc.reg_write(UC_ARM_REG_R0,ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
   assert any(x<=a<z for x,z in allowed),(hex(a),'unexpected executable address')
  u.hook_add(UC_HOOK_CODE,hook);return u,p,trace
 for bank in [0,1,255]:
  for result in [0,1]:
   captured=[]
   def wr(u,a,t):
    assert a[:3]==[obj,0,0x278];captured.append(bytes(u.mem_read(a[3],0x278)));return result
   def alloc(u,a,t):assert a[0]==0x278;return buf
   def copy(u,a,t):u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));return a[0]
   mocks={0x530fced4:lambda u,a,t:0,0x530f25f4:alloc,0x526aac80:copy,0x52ff5ad0:wr,0x530f2630:lambda u,a,t:0}
   u,p,t=fresh(ranges[:2],mocks);p(ctx+0x3c,src);p(ctx+0x4c,obj);p(ctx+0x38,payload);u.mem_write(obj+0x10,bytes([bank]));head=bytes(range(20));tail=bytes((i*17+3)&255 for i in range(0x22c));u.mem_write(src,head);u.mem_write(payload,tail);u.mem_write(buf,bytes([0xa7])*0x278)
   u.reg_write(R[0],ctx);u.emu_start(0x52ff20d0,stop,count=500);assert u.reg_read(UC_ARM_REG_PC)==stop
   out=captured[0];assert out[:20]==head and out[0x4c:]==tail and struct.unpack_from('<III',out,0x40)==(bank,0,0xffff);assert out[20:0x40]==bytes([0xa7])*0x2c;assert u.reg_read(R[0])==result
   records.append(dict(group='full_header_staging_mocked_external_calls',bank=bank,write_result=result,output_sha256=sha(out)))
 for entry,target in [(0x52ff5638,0x52ff553c),(0x52ff5818,0x52ff5708)]:
  for result in [0,1]:
   def io(u,a,t):t.append(a);return result
   u,p,t=fresh(ranges[2:4],{target:io,0x530fced4:lambda u,a,t:0});p(obj+0x14,buf);p(obj+0x18,0x10e00);u.reg_write(R[0],obj);u.emu_start(entry,stop,count=200);assert u.reg_read(UC_ARM_REG_PC)==stop;assert t==[[obj,0,0x10e00,buf]] and u.reg_read(R[0])==result
   records.append(dict(group='full_table_transfer_mocked_IO',entry=hex(entry),io_result=result,arguments_sha256=sha(struct.pack('<4I',*t[0]))))
 for lock,select,write,restore in [(0,1,1,1),(1,0,1,1),(1,1,0,1),(1,1,1,1),(1,1,1,0)]:
  def mode(u,a,t):t.append('select1' if a[1] else 'restore0');return select if a[1] else restore
  def io(u,a,t):t.append('write');assert a==[obj,7,33,buf];return write
  def lk(u,a,t):t.append('lock');return lock
  def ul(u,a,t):t.append('unlock');return 1
  u,p,t=fresh([ranges[4]],{0x532971e4:lk,0x532971f8:ul,0x53297bc0:mode,0x52ff5708:io,0x530fced4:lambda u,a,t:0});p(obj+8,driver);p(driver,vt);p(vt+0x6c,0x532971e4);p(vt+0x70,0x532971f8)
  for r,v in zip(R,[obj,7,33,buf]):u.reg_write(r,v)
  u.emu_start(0x52ff5ad0,stop,count=300);assert u.reg_read(UC_ARM_REG_PC)==stop
  expected=['lock'] if not lock else ['lock','select1','unlock'] if not select else ['lock','select1','write','restore0','unlock'];assert t==expected;assert u.reg_read(R[0])==(write if lock and select else 0)
  records.append(dict(group='full_boot1_wrapper_mocked_IO',lock_result=lock,select_result=select,write_result=write,restore_result=restore,call_order=t,returned=u.reg_read(R[0])))
 for failed in ['table','header','image',None]:
  def stage(label):
   def f(u,a,t):t.append(label);return 0 if failed==label else 1
   return f
  mocks={0x52ff375c:lambda u,a,t:0,0x52ff2060:stage('table'),0x52ff20d0:stage('header'),0x52ff21c8:stage('image'),0x52ff2970:stage('finalize'),0x52ff3a64:stage('progress_end')}
  u,p,t=fresh([ranges[5]],mocks,[0x52ff2bf4,0x52ff2b50]);p(ctx+0x10,src);u.reg_write(UC_ARM_REG_R6,ctx);u.reg_write(R[0],src);u.emu_start(0x52ff2ae4,stop,count=300)
  expected=['table'] if failed=='table' else ['table','header'] if failed=='header' else ['table','header','image'] if failed=='image' else ['table','header','image','finalize','progress_end'];assert t==expected;assert u.reg_read(UC_ARM_REG_PC)==(0x52ff2bf4 if failed else 0x52ff2b50)
  records.append(dict(group='completion_fragment_mocked_stage_returns',failed_stage=failed,call_order=t))
 return dict(explicit_stubs={'0x530fced4':'diagnostic return0','0x530f25f4':'synthetic fixed allocation','0x530f2630':'free no-op','0x526aac80':'synthetic RAM memcpy','0x52ff5ad0':'header test capture write arguments and synthetic return only','0x52ff553c':'table read captured, no IO','0x52ff5708':'table/wrapper write captured, no IO','0x532971e4':'synthetic lock result','0x532971f8':'synthetic unlock result','0x53297bc0':'synthetic partition select/restore result','0x52ff375c':'progress no-op','0x52ff2060':'completion test stage return','0x52ff20d0':'completion test stage return','0x52ff21c8':'completion test stage return','0x52ff2970':'completion test finalize no-op','0x52ff3a64':'completion test progress end no-op'},passed=True,cases=len(records),image_sha256=SHA,scope='Unicorn Cortex-A15 synthetic RAM. Full header/table/wrapper functions with explicit mocked external calls, plus completion ARM fragment. Pure52ff5304 executes actual bytes. No storage driver/controller executes; no camera hardware fidelity claim.',ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in ranges],cases_detail=records)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('decoded',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();d=a.decoded.read_bytes();require(sha(d)=='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9','Decoded hash mismatch');r=run(d[0x1c19c:0x1c19c+25483200]);a.output.write_text(json.dumps(r,indent=2)+'\n');print(dict(passed=r['passed'],cases=r['cases']))
