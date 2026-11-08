"""Standalone original-ARM Log alias checks. All storage effects are stubbed."""
import argparse, hashlib, json, struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
from unicorn.arm_const import *
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
sha=lambda b:hashlib.sha256(b).hexdigest()
R=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
RANGES=[(0x530fe23c,0x530fe358),(0x530fe358,0x530fe3f0),(0x530fbec0,0x530fbf70),(0x530fd1b4,0x530fd27c),(0x530fc3c0,0x530fc444),(0x530fc014,0x530fc128)]

def run(b):
 assert sha(b)==SHA
 C=0x547baefc;CACHE=0x547bae98;FW=0x10001000;MAN=0x10002000;DRV=0x10003000;ALLOC=0x10004000;AVT=0x10004100;STATE=0x10005000;PAY=0x10006000;STAGE=0x10007000;HEAD=0x10008000;DATE=0x10009000;TAB=0x10010000;STOP=0x1004f000
 ALLOC_FN=0x1004d000;FREE_FN=0x1004d004;WRITE_FN=0x53297a84;READ_FN=0x53297938
 records=[]
 def fresh(allowed,mocks):
  u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
  u.mem_map(BASE,(len(b)+4095)&~4095);u.mem_write(BASE,b);u.mem_map(0x10000000,0x50000);u.mem_map(0x547ba000,0x1000)
  u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_SP,0x1004c000);u.reg_write(UC_ARM_REG_LR,STOP)
  def p(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
  def hook(uc,a,n,data):
   if a in mocks:
    v=mocks[a](uc,[uc.reg_read(r) for r in R]);uc.reg_write(R[0],v&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
   assert any(x<=a<z for x,z in allowed),(hex(a),'unapproved code')
  u.hook_add(UC_HOOK_CODE,hook)
  u.mem_write(FW,bytes([0xa7])*0x1c);u.mem_write(TAB,bytes([0x96])*0x10e00)
  p(FW+0x14,TAB);u.mem_write(FW+0x10,b'\0');p(MAN+8,FW);p(MAN+4,0x1000a000);p(DATE+4,0x1000b000)
  p(DRV,0x53cb1638);p(ALLOC,AVT);p(AVT+8,ALLOC_FN);p(AVT+12,FREE_FN)
  p(C+0x54,FW);p(C+0x58,DRV);p(C+0x64,ALLOC);p(C+0x4c,STATE);p(C+0x18,STAGE);p(C+0x1c,2)
  for i in range(6):
   for j,v in enumerate([2000+100*i,2001+100*i,2099+100*i,100]):p(CACHE+16*i+4*j,v)
  for j,v in enumerate([2201,0,512,PAY]):p(STATE+4*j,v)
  u.mem_write(PAY,bytes([0xb5])*0x800);u.mem_write(HEAD,bytes([0xcc])*0x200)
  u.mem_write(STAGE,bytes((13*i+7)&255 for i in range(0x440)))
  return u,p
 def execute(u,a,args):
  for r,v in zip(R,args):u.reg_write(r,v&0xffffffff)
  u.emu_start(a,STOP,count=40000);assert u.reg_read(UC_ARM_REG_PC)==STOP
 def snap(u):return bytes(u.mem_read(FW,0x1c)),bytes(u.mem_read(TAB,0x10e00))
 def unchanged(u,s):assert snap(u)==s,'FwPartition or table unexpectedly modified'
 def ceil(u,a):assert a[0]==DRV;return (a[1]+511)//512
 def newbuf(u,a):assert a[0]==ALLOC and a[1]==512 and a[2:]==[0,0];return HEAD
 def free(u,a):assert a[:3]==[ALLOC,HEAD,0];return 0
 common={0x532974a8:ceil,0x530ef264:lambda u,a:ALLOC,ALLOC_FN:newbuf,FREE_FN:free}

 for bank in [0,1]:
  mocks={0x53102ce8:lambda u,a:DATE,0x52f137f0:lambda u,a:0x1000c000,0x52f1390c:lambda u,a:DRV,0x52fee52c:lambda u,a:MAN,0x530fdfc4:lambda u,a:0,0x532974a8:ceil}
  u,p=fresh([RANGES[0]],mocks);u.mem_write(FW+0x10,bytes([bank]));expected=[]
  for i in range(6):
   cap=0x1000+i*513;start=0x12300+bank*0x8000+i*0x100;p(TAB+(20+i)*0x870,cap);p(TAB+(20+i)*0x870+bank*0x434+0x10,start);n=(cap+511)//512;expected.extend([start,start+1,start+n-1,n])
  before=snap(u);execute(u,0x530fe23c,[]);out=bytes(u.mem_read(CACHE,96));assert struct.unpack('<24I',out)==tuple(expected);assert struct.unpack('<I',u.mem_read(C+0x54,4))[0]==FW;unchanged(u,before)
  records.append(dict(group='full_initialize_data_mocked_registry',synthetic_bank=bank,cache_sha256=sha(out)))

 mocks={0x52fee52c:lambda u,a:MAN,0x530fdfc4:lambda u,a:0,0x532971dc:lambda u,a:512,ALLOC_FN:lambda u,a:PAY if a==[ALLOC,512,0,0] else (_ for _ in ()).throw(AssertionError(a))}
 u,p=fresh([RANGES[1]],mocks);p(STATE+8,0);p(STATE+12,0);before=snap(u);execute(u,0x530fe358,[]);assert struct.unpack('<II',u.mem_read(STATE+8,8))==(512,PAY);unchanged(u,before);records.append(dict(group='full_payload_initialize_mocked_allocator',state_sha256=sha(bytes(u.mem_read(STATE,16)))))

 for result in [0,1]:
  calls=[]
  def copy(u,a):
   assert a==[HEAD,0x53a6c14c,16,0];raw=bytes(u.mem_read(a[1],16)).split(b'\0',1)[0];u.mem_write(HEAD,raw.ljust(16,b'\0'));return HEAD
  def write(u,a):assert a==[DRV,2200,1,HEAD];calls.append(sha(bytes(u.mem_read(HEAD,512))));return result
  mocks={**common,0x526acd04:copy,WRITE_FN:write}
  u,p=fresh([RANGES[2]],mocks);before=snap(u);execute(u,0x530fbec0,[2,0x123456,377]);out=bytes(u.mem_read(HEAD,512));assert struct.unpack_from('<II',out,16)==(0x123456,377) and out[15]==0 and len(calls)==1 and u.reg_read(R[0])==result;unchanged(u,before);records.append(dict(group='full_header_write_mocked_copy_allocator_media',write_result=result,header_sha256=sha(out)))

 for used,count,selection,result in [(0,0,2,1),(0,-1,2,1),(0,10,-1,1),(0,1,2,1),(511,1,2,0),(511,1,2,1),(0,512,2,0),(0,513,2,1),(0,1024,2,0)]:
  calls=[];headers=[];oldused=used
  def write(u,a):assert a[0]==DRV and a[2:]==[1,PAY];calls.append((a[1],sha(bytes(u.mem_read(PAY,512)))));return result
  def header(u,a):headers.append(a[:3]);return 1
  mocks={0x530fcf28:lambda u,a:selection,0x532974a8:ceil,WRITE_FN:write,0x530fbec0:header}
  u,p=fresh([RANGES[3]],mocks);p(STATE+4,used);before=snap(u);payload=bytearray(u.mem_read(PAY,0x800));src=bytes(u.mem_read(STAGE,0x440));block=2201;expectedwrites=[]
  if count>0 and selection!=-1:
   for v in src[:count]:
    payload[used]=v;used+=1
    if used>=512:expectedwrites.append((block,sha(payload[:512])));used=0;block+=1
  execute(u,0x530fd1b4,[count]);assert bytes(u.mem_read(PAY,0x800))==payload and calls==expectedwrites;assert struct.unpack('<II',u.mem_read(STATE,8))==(block,used);assert headers==[[2,2202+i,0] for i in range(len(calls))];unchanged(u,before)
  records.append(dict(group='full_append_mocked_area_selection_and_media',initial_used=oldused,signed_count=count,selected_area=selection,write_result=result,writes=len(calls),header_calls=len(headers),state_sha256=sha(bytes(u.mem_read(STATE,16))),payload_sha256=sha(payload)))

 for wr,hr in [(0,0),(0,1),(1,0),(1,1)]:
  trace=[]
  def write(u,a):assert a==[DRV,2201,1,PAY];trace.append('data');return wr
  def header(u,a):assert a[:3]==[2,2201,17];trace.append('header');return hr
  u,p=fresh([RANGES[4]],{0x532974a8:ceil,WRITE_FN:write,0x530fbec0:header});p(STATE+4,17);before=snap(u);state=bytes(u.mem_read(STATE,16));execute(u,0x530fc3c0,[]);assert trace==['data','header'] and u.reg_read(R[0])==hr and bytes(u.mem_read(STATE,16))==state;unchanged(u,before);records.append(dict(group='full_flush_null_callback_mocked_media',data_result=wr,header_result=hr,call_order=trace,return_value=u.reg_read(R[0])))

 for valid,readok,used in [(0,0,0),(1,0,17),(1,1,0),(1,1,17)]:
  calls=[];headers=[]
  def read(u,a):
   calls.append(a[1:]);assert a[0]==DRV
   if len(calls)==1:
    assert a[1:]==[2200,1,HEAD]
    if readok:u.mem_write(HEAD+16,struct.pack('<II',2250,used))
   else:
    assert a[1:]==[2250,1,PAY]
    if readok:u.mem_write(PAY,bytes([0x39])*512)
   return readok
  def header(u,a):headers.append(a[:3]);return 1
  mocks={**common,0x530fbf70:lambda u,a:valid,READ_FN:read,0x530fbec0:header}
  u,p=fresh([RANGES[5]],mocks);p(STATE,2222);p(STATE+4,99);before=snap(u);execute(u,0x530fc014,[2]);expected=(2201,0) if not valid else ((2250,used) if readok else (2222,99));assert struct.unpack('<II',u.mem_read(STATE,8))==expected;assert len(calls)==(0 if not valid else (2 if readok and used else 1));assert headers==([[2,2201,0]] if not valid else []);unchanged(u,before);records.append(dict(group='full_header_load_mocked_probe_and_reads',probe_valid=valid,read_result=readok,external_header_used=used,read_calls=len(calls),state_sha256=sha(bytes(u.mem_read(STATE,16)))))

 return dict(passed=True,cases=len(records),image_sha256=SHA,ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],cases_detail=records,explicit_stubs={'0x53102ce8':'synthetic DateTime owner','0x52fee52c':'synthetic manager with FwPartition at +8','0x52f137f0 / 0x52f1390c':'synthetic registry and Emmc return','0x530fdfc4':'assertion no-op; supplied pointers nonnull','0x530ef264 / synthetic allocator +8/+c':'allocator identity, 512-byte buffer allocation and free no-op','0x532971dc':'512-byte block size','0x532974a8':'ceil(bytes/512), separately source-proven prior Emmc helper; not executed in these cases','0x526acd04':'bounded 16-byte tag copy model only, actual copy helper not executed','0x530fcf28':'returns synthetic selected log area; rotation function not executed','0x530fbf70':'returns supplied header-probe boolean','0x530fbec0':'captures header arguments in append/flush/load checks; separately executed in header checks','0x53297a84':'captures write arguments/data hash and returns supplied boolean; no storage IO','0x53297938':'supplies synthetic header/data bytes on success and leaves destination unchanged on failure; source-content and failure preservation are stub assumptions'},scope='Six original complete ARM function ranges on Unicorn Cortex-A15 with explicit dependencies stubbed. Flush tests cover null callback only; append area selection and header probe are stubbed. Firmware instructions perform cache/state/payload stores; synthetic reads supply external content. All cases assert FwPartition and full synthetic partition table remain unchanged under these aliases. Synthetic bank1 is an input, not its producer. No real media, device execution, atomicity, firmware authentication or camera hardware fidelity is claimed.')

if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('decoded',type=Path);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args();d=a.decoded.read_bytes();assert sha(d)==DECODED_SHA,'Decoded hash mismatch';r=run(d[0x1c19c:0x1c19c+25483200]);a.output.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8');print(dict(passed=r['passed'],cases=r['cases']))
