"""Original ARM FAT volume-to-Emmc sector flow on authored buffers.
Real filesystem/media/OS/cache operations are explicit stubs. No camera or
storage access. Cortex-A15 Unicorn is a numerical CPU model, not target fidelity.
"""
if not __debug__:raise RuntimeError('Assertions required; do not use -O')
import argparse,hashlib,json,struct,os
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
VM,REC,DESC,PATH,HANDLE,GEOM,OUT=[0x10000000+0x1000*k for k in range(7)]
BUF=0x10010000;WB=0x10020000;RB=0x10030000;STOP=0x30000000
RANGES=[(0x52f52554,0x52f52674),(0x52f527d4,0x52f5285c),(0x52f4bb70,0x52f4be50),(0x52f4bec0,0x52f4bfcc),
 (0x532971b8,0x532971c0),(0x52f494e4,0x52f494ec),(0x53297510,0x53297728),(0x53297938,0x53297bc0),(0x53366838,0x533668c0)]
STUBS={0x526ac9c0:'bounded strlen of authored path',0x530fdfc4:'require true assertion; no assertion implementation',
 0x530f1a68:'lock returns selected fixture boolean',0x530f1bbc:'unlock returns0',0x530fced4:'diagnostic no-op',
 0x5331b9e8:'read sector boundary: capture(start,count,buffer), synthesize bytes only on chosen success0',
 0x5331b99c:'write sector boundary: capture(start,count,buffer), hash authored bytes, return chosen status; NO IO',
 0x53100d84:'returns synthetic cache object',0x53100e14:'capture buffer/byte count, no cache operation',
 0x526aac80:'bounded synthetic memcpy, no original libc',0x526ab2a8:'bounded synthetic memset',
 0x5336fdac:'handle lookup returns authored FS record or0',0x53366610:'writes authored R volume string into6-byte destination',
 0x53371228:'geometry initialization stub zeros requested100-byte fixture',0x533711b8:'geometry output copy stub100 bytes',
 0x53375e34:'registration volume lookup returns authored pointer',0x5336f240:'registration record lookup returns authored handle',
 0x53366768:'registration setup reports success',0x53368030:'registration subobject initialization no-op'}
sha=lambda b:hashlib.sha256(b).hexdigest();p32=lambda v:struct.pack('<I',v&0xffffffff)
def load(p):
 b=p.read_bytes()
 if sha(b)==DSHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 if sha(b)!=SHA:raise ValueError('unrecognized RTOS SHA-256')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 for a,n in [(VM,0x50000),(0x20000000,0x10000),(0x54787000,4096),(STOP,4096)]:u.mem_map(a,n)
 state={};rows=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,p32(v))
 def hook(uc,a,size,user):
  if a==STOP:uc.emu_stop();return
  if a not in STUBS:assert any(x<=a<z for x,z in RANGES),hex(a);return
  r=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];r0,r1,r2,r3=r;ret=0
  state['trace'].append([hex(a),r])
  if a==0x526ac9c0:
   data=bytes(uc.mem_read(r0,64));assert b'\0' in data;ret=data.index(0)
  elif a==0x530fdfc4:assert r0!=0,('unexpected assertion',r)
  elif a==0x530f1a68:assert r0==DESC+0x80;ret=state['lock']
  elif a in (0x5331b9e8,0x5331b99c):
   assert r1<=8 and VM<=r2<VM+0x50000
   statuses=state['statuses'];ret=statuses[min(len(state['io']),len(statuses)-1)]
   if a==0x5331b9e8 and ret==0:uc.mem_write(r2,bytes(((r0*7+k)&255) for k in range(r1*512)))
   state['io'].append(dict(kind='read' if a==0x5331b9e8 else 'write',sector=r0,count=r1,buffer=r2,status=ret,data_sha256=sha(bytes(uc.mem_read(r2,r1*512)))))
  elif a==0x53100d84:ret=GEOM
  elif a==0x53100e14:assert r0==GEOM;state['cache_bytes'].append(r2)
  elif a in (0x526aac80,0x533711b8):
   assert r2<=8192;uc.mem_write(r0,bytes(uc.mem_read(r1,r2)));ret=r0;state['copies'].append([r0,r1,r2])
  elif a in (0x526ab2a8,0x53371228):assert r2<=100;uc.mem_write(r0,bytes([r1&255])*r2);ret=r0
  elif a==0x5336fdac:ret=HANDLE if state['handle'] else 0
  elif a==0x53366610:uc.mem_write(r1,b'R:\0\0\0\0');ret=0
  elif a==0x53375e34:ret=PATH
  elif a==0x5336f240:ret=HANDLE
  elif a==0x53366768:ret=1
  uc.reg_write(UC_ARM_REG_R0,ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook)
 def run(a,args):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  for q,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(q,v&0xffffffff)
  for k,v in enumerate(args[4:]):wr(0x20008000+4*k,v)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,0x20008000);u.reg_write(UC_ARM_REG_LR,STOP);u.emu_start(a,STOP+4,count=100000)
  assert u.reg_read(UC_ARM_REG_PC)==STOP;return u.reg_read(UC_ARM_REG_R0)
 def reset():
  u.mem_write(VM,bytes(0x50000));wr(0x54787078,VM);wr(VM+0x14,REC);wr(VM+0x20,1);wr(VM+0x1c,GEOM)
  wr(REC,DESC);u.mem_write(REC+4,b'R');wr(REC+0xc,0x348000);wr(REC+0x10,0x38c000);wr(GEOM,0x12345678)
  wr(DESC,0x53cb1638);u.mem_write(DESC+0x14,b'\x03');wr(DESC+0x24,DESC+0x80);u.mem_write(DESC+0x30,b'\x01')
  wr(DESC+0x34,WB);wr(DESC+0x38,2);wr(DESC+0x3c,RB);wr(DESC+0x40,2)
  u.mem_write(PATH,b'R:\0');u.mem_write(BUF,bytes((k*11+3)&255 for k in range(8192)))
  state.clear();state.update(trace=[],io=[],copies=[],cache_bytes=[],statuses=[0],lock=1,handle=True)
 def add(group,inputs,out):rows.append(dict(group=group,inputs=inputs,observed=out,result_sha256=sha(json.dumps(dict(out=out,state=state),sort_keys=True).encode())))
 reset();assert run(0x52f527d4,[VM,PATH])==0x348000 and run(0x52f4bb70,[PATH])==0x38c000
 add('R-record-base-and-total-sectors',{},dict(base=0x348000,sectors=0x38c000))
 reset();u.mem_write(PATH,b'Z:\0');assert run(0x52f527d4,[VM,PATH])==0xffffffff and run(0x52f52818,[VM,PATH])==GEOM and run(0x52f4bb70,[PATH])==0x12345678
 add('unknown-path-fallback',{},dict(base=0xffffffff,geometry_pointer=GEOM,total_from_fallback=0x12345678))
 reset();ret=run(0x53366838,[PATH,0x52f4bd7c,0x52f4bec0]);assert ret==1 and rd(HANDLE+0x400)==0x52f4bd7c and rd(HANDLE+0x404)==0x52f4bec0
 add('actual-callback-registration-stores',{},dict(io=hex(rd(HANDLE+0x400)),geometry=hex(rd(HANDLE+0x404))))
 reset();ret=run(0x52f4bec0,[7,5,OUT]);assert ret==0 and rd(OUT+0x10)==0x38c000
 add('geometry-command5-total-sectors',{},dict(return_value=ret,total_sectors=rd(OUT+0x10)))
 for read in (0,1):
  for unaligned in (0,1):
   for count in (1,5):
    reset();buf=BUF+unaligned;initial=bytes(u.mem_read(buf,count*512));ret=run(0x52f4bd7c,[7,9,buf,count,read]);assert ret==1
    expected=[count] if not unaligned else ([2]*(count//2)+([1] if count%2 else []))
    assert [v['count'] for v in state['io']]==expected and all(v['kind']==('read' if read else 'write') for v in state['io'])
    n=0
    for v in state['io']:assert v['sector']==0x348009+n;n+=v['count']
    if not read:
     n=0
     for v in state['io']:assert v['data_sha256']==sha(initial[n*512:(n+v['count'])*512]);n+=v['count']
    else:
     data=b''.join(bytes(((v['sector']*7+k)&255) for k in range(v['count']*512)) for v in state['io']);assert bytes(u.mem_read(buf,count*512))==data
     assert state['cache_bytes']==[v*512 for v in expected]
    if unaligned:assert [q[2] for q in state['copies']]==[v*512 for v in expected]
    add('FAT-callback-through-Emmc',dict(read=bool(read),unaligned=bool(unaligned),count=count),dict(return_value=ret,io=state['io'],copy_bytes=[q[2] for q in state['copies']]))
  for name,statuses,lock,ready in [('retry-success',[8,0],1,1),('three-failures',[8],1,1),('lock-failure',[0],0,1),('not-initialized',[0],1,0)]:
   reset();state.update(statuses=statuses,lock=lock);u.mem_write(DESC+0x30,bytes([ready]));ret=run(0x52f4bd7c,[7,0,BUF,1,read]);want=1 if name=='retry-success' else 0
   assert ret==want and len(state['io'])==(2 if name=='retry-success' else 3 if name=='three-failures' else 0)
   assert all(v['sector']==0x348000 for v in state['io'])
   add('Emmc-gates-and-retries',dict(read=bool(read),case=name),dict(return_value=ret,io_attempts=len(state['io'])))
  reset();ret=run(0x52f4bd7c,[7,0x38bfff,BUF,2,read]);assert ret==1 and state['io'][0]['sector']==0x6d3fff and state['io'][0]['count']==2
  add('selected-chain-does-not-check-partition-end',dict(read=bool(read),relative_sector=0x38bfff,count=2),dict(forwarded_sector=0x6d3fff,count=2))
  reset();ret=run(0x52f4bd7c,[7,0,BUF,0,read]);assert ret==0 and not state['io']
  add('callback-zero-count',dict(read=bool(read)),dict(return_value=ret,io_attempts=0))
 reset();state['handle']=False;ret=run(0x52f4bd7c,[7,0,BUF,1,1]);assert ret==0 and not state['io'];add('callback-invalid-handle',{},dict(return_value=0))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),groups={g:sum(q['group']==g for q in rows) for g in sorted({q['group'] for q in rows})},scope=__doc__,stubs={hex(a):s for a,s in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=rows)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('input',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if os.path.lexists(a.output):raise FileExistsError('output exists')
 r=run_checks(load(a.input))
 with a.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups')})
